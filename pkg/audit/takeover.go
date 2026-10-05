package audit

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/alexandrmotologa/dnswatch/pkg/resolver"
	"github.com/miekg/dns"
)

// ServiceFingerprint maps known cloud and hosting providers to takeover signatures.
type ServiceFingerprint struct {
	Service      string
	CNAMESuffixes []string
	Signatures   []string
	NXDOMAIN     bool
}

// Fingerprints contains detection patterns for popular cloud providers.
var Fingerprints = []ServiceFingerprint{
	{
		Service: "GitHub Pages",
		CNAMESuffixes: []string{
			"github.io",
			"github.map.fastly.net",
		},
		Signatures: []string{
			"There isn't a GitHub Pages site here",
			"For root domain, use an A record",
		},
	},
	{
		Service: "Amazon S3",
		CNAMESuffixes: []string{
			"s3.amazonaws.com",
			"s3-website",
			"s3.dualstack",
		},
		Signatures: []string{
			"The specified bucket does not exist",
			"NoSuchBucket",
		},
	},
	{
		Service: "Heroku",
		CNAMESuffixes: []string{
			"herokuapp.com",
			"herokussl.com",
			"herokudns.com",
		},
		Signatures: []string{
			"No such app",
			"Heroku | Welcome to your new app!",
			"There's nothing here, yet.",
		},
	},
	{
		Service: "Vercel",
		CNAMESuffixes: []string{
			"vercel.app",
			"cname.vercel-dns.com",
			"alias.zeit.co",
		},
		Signatures: []string{
			"The deployment could not be found",
			"404: NOT_FOUND",
			"DEPLOYMENT_NOT_FOUND",
		},
	},
	{
		Service: "Netlify",
		CNAMESuffixes: []string{
			"netlify.app",
			"netlify.com",
		},
		Signatures: []string{
			"Not Found - Request ID",
			"page not found",
		},
	},
	{
		Service: "Cloudflare Pages",
		CNAMESuffixes: []string{
			"pages.dev",
		},
		Signatures: []string{
			"Project not found",
			"pages-not-found",
		},
	},
	{
		Service: "Shopify",
		CNAMESuffixes: []string{
			"myshopify.com",
			"shops.myshopify.com",
		},
		Signatures: []string{
			"Sorry, this shop is currently unavailable",
			"Only one step left to start selling",
		},
	},
	{
		Service: "Ghost",
		CNAMESuffixes: []string{
			"ghost.io",
		},
		Signatures: []string{
			"The thing you were looking for is no longer here",
		},
	},
	{
		Service: "Surge.sh",
		CNAMESuffixes: []string{
			"surge.sh",
		},
		Signatures: []string{
			"project not found",
		},
	},
	{
		Service: "Bitbucket",
		CNAMESuffixes: []string{
			"bitbucket.io",
		},
		Signatures: []string{
			"Repository not found",
		},
	},
	{
		Service: "Fastly",
		CNAMESuffixes: []string{
			"fastly.net",
		},
		Signatures: []string{
			"Fastly error: unknown domain",
		},
	},
	{
		Service: "WordPress",
		CNAMESuffixes: []string{
			"wordpress.com",
		},
		Signatures: []string{
			"Do you want to register",
			"doesn't exist",
		},
	},
	{
		Service: "Zendesk",
		CNAMESuffixes: []string{
			"zendesk.com",
		},
		Signatures: []string{
			"Help Center Closed",
			"No such help center",
		},
	},
	{
		Service: "Azure App Service / Traffic Manager",
		CNAMESuffixes: []string{
			"azurewebsites.net",
			"trafficmanager.net",
			"cloudapp.net",
		},
		Signatures: []string{
			"404 Web Site not found",
		},
	},
}

// TakeoverAuditor scans domains and subdomains for dangling CNAME pointers.
type TakeoverAuditor struct {
	client     *resolver.Client
	httpClient *http.Client
	server     string
}

// NewTakeoverAuditor creates a takeover scanner.
func NewTakeoverAuditor(client *resolver.Client, server string) *TakeoverAuditor {
	if server == "" {
		server = "1.1.1.1:53"
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     nil,
	}
	return &TakeoverAuditor{
		client: client,
		server: server,
		httpClient: &http.Client{
			Transport: tr,
			Timeout:   3 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

// AuditTakeovers inspects the apex domain and high-risk subdomains for dangling CNAME pointers.
func (t *TakeoverAuditor) AuditTakeovers(ctx context.Context, domain string) ([]Finding, bool) {
	var findings []Finding
	domain = strings.TrimSuffix(domain, ".")

	// Target apex and prominent subdomains
	targets := []string{
		domain,
		"www." + domain,
		"blog." + domain,
		"api." + domain,
		"app." + domain,
		"dev." + domain,
		"docs." + domain,
		"cdn." + domain,
		"help." + domain,
		"status." + domain,
	}

	opts := resolver.DefaultOptions()
	opts.RecursionDesired = true
	var foundRisk bool

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return findings, foundRisk
		default:
		}

		resp, err := t.client.Exchange(ctx, t.server, target, dns.TypeCNAME, &opts)
		if err != nil || resp == nil || resp.Msg == nil {
			continue
		}

		for _, rr := range resp.Msg.Answer {
			cnameRR, ok := rr.(*dns.CNAME)
			if !ok {
				continue
			}

			cnameTarget := strings.TrimSuffix(strings.ToLower(cnameRR.Target), ".")
			matchedFP := t.matchFingerprint(cnameTarget)
			if matchedFP == nil {
				continue
			}

			// Check if target is dangling by HTTP inspection
			isDangling, signature := t.checkDanglingHTTP(ctx, target, matchedFP)
			if isDangling {
				foundRisk = true
				findings = append(findings, Finding{
					Category:       "SubdomainTakeover",
					Title:          fmt.Sprintf("Dangling CNAME to %s Detected", matchedFP.Service),
					Description:    fmt.Sprintf("Subdomain %s points to %s (%s) which returns an unclaimed resource signature: '%s'. An attacker could register the unclaimed asset and gain control of this subdomain.", target, cnameTarget, matchedFP.Service, signature),
					Severity:       SeverityCritical,
					Recommendation: fmt.Sprintf("Remove the CNAME record or claim the '%s' resource in %s.", cnameTarget, matchedFP.Service),
					Record:         fmt.Sprintf("%s CNAME %s", target, cnameTarget),
				})
			} else {
				// CNAME is mapped and actively served
				findings = append(findings, Finding{
					Category:       "SubdomainTakeover",
					Title:          fmt.Sprintf("Managed CNAME to %s", matchedFP.Service),
					Description:    fmt.Sprintf("%s properly delegates to active %s target %s.", target, matchedFP.Service, cnameTarget),
					Severity:       SeverityGood,
					Recommendation: "Verify CNAME pointers whenever decommissioning cloud services.",
					Record:         fmt.Sprintf("%s CNAME %s", target, cnameTarget),
				})
			}
		}
	}

	return findings, foundRisk
}

// matchFingerprint checks if target matches any known cloud provider suffix.
func (t *TakeoverAuditor) matchFingerprint(cnameTarget string) *ServiceFingerprint {
	for _, fp := range Fingerprints {
		for _, suffix := range fp.CNAMESuffixes {
			if strings.HasSuffix(cnameTarget, suffix) {
				return &fp
			}
		}
	}
	return nil
}

// checkDanglingHTTP requests the target host to see if an unclaimed signature is returned.
func (t *TakeoverAuditor) checkDanglingHTTP(ctx context.Context, hostname string, fp *ServiceFingerprint) (bool, string) {
	// Try HTTPS first, then HTTP
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, hostname)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; DNSWatch/1.0; +https://github.com/alexandrmotologa/dnswatch)")

		resp, err := t.httpClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Read up to 64KB of body
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
		if err != nil {
			continue
		}
		bodyStr := string(bodyBytes)

		for _, sig := range fp.Signatures {
			if strings.Contains(bodyStr, sig) {
				return true, sig
			}
		}
	}

	return false, ""
}
