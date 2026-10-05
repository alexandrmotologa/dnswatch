package audit

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/alexandrmotologa/dnswatch/pkg/resolver"
	"github.com/miekg/dns"
)

// Auditor coordinates all security, hygiene, and nameserver consistency evaluations.
type Auditor struct {
	client   *resolver.Client
	email    *EmailAuditor
	takeover *TakeoverAuditor
	server   string
}

// NewAuditor creates a unified domain auditor.
func NewAuditor(timeout time.Duration) *Auditor {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	opts := resolver.DefaultOptions()
	opts.Timeout = timeout
	client := resolver.NewClient(opts)
	server := "1.1.1.1:53"

	return &Auditor{
		client:   client,
		email:    NewEmailAuditor(client, server),
		takeover: NewTakeoverAuditor(client, server),
		server:   server,
	}
}

// Run executes complete domain hygiene, security, and nameserver audits.
func (a *Auditor) Run(ctx context.Context, domain string) (*AuditReport, error) {
	domain = strings.TrimSuffix(domain, ".")
	now := time.Now()

	var allFindings []Finding

	// 1. Email hygiene audit (SPF, DMARC, MX)
	emailFindings, spfStatus, dmarcStatus, mxStatus := a.email.AuditEmail(ctx, domain)
	allFindings = append(allFindings, emailFindings...)

	// 2. Subdomain takeover audit
	takeoverFindings, takeoverRisk := a.takeover.AuditTakeovers(ctx, domain)
	allFindings = append(allFindings, takeoverFindings...)

	// 3. Nameserver parity and lame delegation audit
	nsFindings, nsConsistent := a.auditNameservers(ctx, domain)
	allFindings = append(allFindings, nsFindings...)

	// Calculate score and grade
	score, grade := calculateScoreAndGrade(allFindings)

	report := &AuditReport{
		Domain:        domain,
		Score:         score,
		Grade:         grade,
		Findings:      allFindings,
		SPFStatus:     spfStatus,
		DMARCStatus:   dmarcStatus,
		MXStatus:      mxStatus,
		TakeoverRisk:  takeoverRisk,
		NSConsistency: nsConsistent,
		CheckedAt:     now,
	}

	return report, nil
}

// auditNameservers checks for NS redundancy, serial parity, and lame delegations.
func (a *Auditor) auditNameservers(ctx context.Context, domain string) ([]Finding, bool) {
	var findings []Finding
	opts := resolver.DefaultOptions()
	opts.RecursionDesired = true

	resp, err := a.client.Exchange(ctx, a.server, domain, dns.TypeNS, &opts)
	if err != nil || resp == nil || resp.Msg == nil {
		findings = append(findings, Finding{
			Category:       "Nameserver",
			Title:          "Failed to Query NS Records",
			Description:    fmt.Sprintf("Could not retrieve nameserver records for %s: %v", domain, err),
			Severity:       SeverityMedium,
			Recommendation: "Check domain registration status and DNS resolver connectivity.",
		})
		return findings, false
	}

	var nsHostnames []string
	for _, rr := range resp.Msg.Answer {
		if nsRR, ok := rr.(*dns.NS); ok {
			nsHostnames = append(nsHostnames, strings.TrimSuffix(strings.ToLower(nsRR.Ns), "."))
		}
	}

	if len(nsHostnames) == 0 {
		findings = append(findings, Finding{
			Category:       "Nameserver",
			Title:          "No NS Records Found",
			Description:    "Domain does not return any authoritative nameservers.",
			Severity:       SeverityCritical,
			Recommendation: "Configure authoritative nameservers at your domain registrar.",
		})
		return findings, false
	}

	// Redundancy check (RFC 2182 recommends at least 2 distinct nameservers)
	if len(nsHostnames) < 2 {
		findings = append(findings, Finding{
			Category:       "Nameserver",
			Title:          "Insufficient Nameserver Redundancy",
			Description:    fmt.Sprintf("Domain only configures %d nameserver. RFC 2182 requires at least two distinct nameservers to guarantee availability.", len(nsHostnames)),
			Severity:       SeverityHigh,
			Recommendation: "Add at least two authoritative nameservers in distinct network subnets.",
		})
	} else {
		findings = append(findings, Finding{
			Category:       "Nameserver",
			Title:          "Nameserver Redundancy OK",
			Description:    fmt.Sprintf("Domain configures %d authoritative nameservers.", len(nsHostnames)),
			Severity:       SeverityGood,
			Recommendation: "Maintain nameservers across separate autonomous systems (ASNs).",
		})
	}

	// Query each nameserver directly for SOA serial and authoritativeness
	serials := make(map[uint32][]string)
	var lameCount int

	for _, nsHost := range nsHostnames {
		// Resolve NS IP
		aResp, err := a.client.Exchange(ctx, a.server, nsHost, dns.TypeA, &opts)
		if err != nil || aResp == nil || len(aResp.Msg.Answer) == 0 {
			continue
		}
		var nsIP string
		for _, rr := range aResp.Msg.Answer {
			if aRR, ok := rr.(*dns.A); ok {
				nsIP = aRR.A.String()
				break
			}
		}
		if nsIP == "" {
			continue
		}

		// Direct non-recursive query to authoritative nameserver
		directOpts := resolver.TraceOptions()
		soaResp, err := a.client.Exchange(ctx, nsIP, domain, dns.TypeSOA, &directOpts)
		if err != nil || soaResp == nil || soaResp.Msg == nil {
			lameCount++
			findings = append(findings, Finding{
				Category:       "Nameserver",
				Title:          "Lame Delegation / Nameserver Timeout",
				Description:    fmt.Sprintf("Nameserver %s (%s) failed to answer direct query for %s: %v", nsHost, nsIP, domain, err),
				Severity:       SeverityHigh,
				Recommendation: "Ensure all declared nameservers are running and allow UDP/TCP port 53 traffic.",
				Record:         nsHost,
			})
			continue
		}

		// Check AA flag
		if !soaResp.Msg.Authoritative {
			lameCount++
			findings = append(findings, Finding{
				Category:       "Nameserver",
				Title:          "Non-Authoritative Answer (Lame Delegation)",
				Description:    fmt.Sprintf("Nameserver %s (%s) answered without the Authoritative Answer (AA) flag set.", nsHost, nsIP),
				Severity:       SeverityHigh,
				Recommendation: "Configure nameserver zone as authoritative master or secondary.",
				Record:         nsHost,
			})
			continue
		}

		// Extract SOA serial
		var foundSOA bool
		for _, rr := range soaResp.Msg.Answer {
			if soaRR, ok := rr.(*dns.SOA); ok {
				serials[soaRR.Serial] = append(serials[soaRR.Serial], nsHost)
				foundSOA = true
				break
			}
		}
		if !foundSOA {
			for _, rr := range soaResp.Msg.Ns {
				if soaRR, ok := rr.(*dns.SOA); ok {
					serials[soaRR.Serial] = append(serials[soaRR.Serial], nsHost)
					foundSOA = true
					break
				}
			}
		}
	}

	// Check serial consistency
	if len(serials) > 1 {
		var serialDetails []string
		for s, hosts := range serials {
			serialDetails = append(serialDetails, fmt.Sprintf("Serial %d: %s", s, strings.Join(hosts, ", ")))
		}
		findings = append(findings, Finding{
			Category:       "Nameserver",
			Title:          "SOA Serial Inconsistency Across Nameservers",
			Description:    fmt.Sprintf("Different nameservers return conflicting SOA serial numbers (%s). This indicates a broken zone transfer or replica sync delay.", strings.Join(serialDetails, "; ")),
			Severity:       SeverityCritical,
			Recommendation: "Verify AXFR/IXFR replication between primary and secondary nameservers.",
		})
		return findings, false
	} else if len(serials) == 1 && lameCount == 0 {
		var singleSerial uint32
		for s := range serials {
			singleSerial = s
		}
		findings = append(findings, Finding{
			Category:       "Nameserver",
			Title:          "SOA Serial Parity Verified",
			Description:    fmt.Sprintf("All active nameservers share identical SOA serial %d.", singleSerial),
			Severity:       SeverityGood,
			Recommendation: "Continue monitoring zone replication health.",
		})
		return findings, true
	}

	return findings, lameCount == 0
}

// calculateScoreAndGrade evaluates findings and determines score and letter grade.
func calculateScoreAndGrade(findings []Finding) (int, string) {
	score := 100

	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			score -= 35
		case SeverityHigh:
			score -= 20
		case SeverityMedium:
			score -= 10
		case SeverityLow:
			score -= 5
		}
	}

	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}

	var grade string
	switch {
	case score >= 95:
		grade = "A+"
	case score >= 90:
		grade = "A"
	case score >= 80:
		grade = "B"
	case score >= 70:
		grade = "C"
	case score >= 60:
		grade = "D"
	default:
		grade = "F"
	}

	return score, grade
}
