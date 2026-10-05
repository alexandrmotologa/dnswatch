package trace

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/alexandrmotologa/dnswatch/pkg/resolver"
	"github.com/miekg/dns"
)

// WalkerConfig configures the recursive trace engine.
type WalkerConfig struct {
	Timeout       time.Duration
	MaxHops       int
	MaxCNAMEHops  int
	PreferIPv4    bool
	RootServerIP  string
	FallbackDNS   string
}

// DefaultWalkerConfig returns production-ready default walker settings.
func DefaultWalkerConfig() WalkerConfig {
	return WalkerConfig{
		Timeout:      3 * time.Second,
		MaxHops:      16,
		MaxCNAMEHops: 8,
		PreferIPv4:   true,
		FallbackDNS:  "1.1.1.1:53",
	}
}

// Walker performs iterative root-to-leaf delegation traversal.
type Walker struct {
	cfg    WalkerConfig
	client *resolver.Client
}

// NewWalker creates a new recursive delegation walker.
func NewWalker(cfg WalkerConfig) *Walker {
	clientOpts := resolver.TraceOptions()
	clientOpts.Timeout = cfg.Timeout
	return &Walker{
		cfg:    cfg,
		client: resolver.NewClient(clientOpts),
	}
}

// Trace executes iterative resolution starting from IANA root servers.
func (w *Walker) Trace(ctx context.Context, domain string, qtype uint16) (*TraceResult, error) {
	startTime := time.Now()
	domain = dns.Fqdn(domain)
	qtypeStr := dns.TypeToString[qtype]
	if qtypeStr == "" {
		qtypeStr = fmt.Sprintf("TYPE%d", qtype)
	}

	result := &TraceResult{
		Domain:    domain,
		QueryType: qtypeStr,
		Hops:      make([]*TraceHop, 0),
		Success:   false,
	}

	currentQname := domain
	currentQtype := qtype
	cnameHops := 0

	for {
		// Pick initial root server
		initialRoot := GetRandomRoot()
		currentServerIP := initialRoot.IPv4
		currentServerName := initialRoot.Name
		if w.cfg.RootServerIP != "" {
			currentServerIP = w.cfg.RootServerIP
			currentServerName = "custom-root"
		}

		currentZone := "."
		visitedServers := make(map[string]bool)
		hopCount := 0

		for hopCount < w.cfg.MaxHops {
			select {
			case <-ctx.Done():
				result.TotalRTT = time.Since(startTime)
				result.Error = "trace cancelled by context timeout"
				return result, ctx.Err()
			default:
			}

			serverKey := fmt.Sprintf("%s:%s", currentServerIP, currentQname)
			if visitedServers[serverKey] {
				hop := &TraceHop{
					Step:       len(result.Hops) + 1,
					Zone:       currentZone,
					ServerName: currentServerName,
					ServerIP:   currentServerIP,
					Error:      fmt.Sprintf("referral loop detected at %s", currentServerName),
				}
				result.Hops = append(result.Hops, hop)
				result.TotalRTT = time.Since(startTime)
				result.Error = hop.Error
				return result, fmt.Errorf("loop detected at %s", currentServerName)
			}
			visitedServers[serverKey] = true
			hopCount++

			// Send non-recursive query
			opts := resolver.TraceOptions()
			opts.Timeout = w.cfg.Timeout
			resp, err := w.client.Exchange(ctx, currentServerIP, currentQname, currentQtype, &opts)
			if err != nil {
				hop := &TraceHop{
					Step:       len(result.Hops) + 1,
					Zone:       currentZone,
					ServerName: currentServerName,
					ServerIP:   currentServerIP,
					Error:      fmt.Sprintf("query error: %v", err),
				}
				result.Hops = append(result.Hops, hop)
				result.TotalRTT = time.Since(startTime)
				result.Error = hop.Error
				return result, err
			}

			hop := &TraceHop{
				Step:          len(result.Hops) + 1,
				Zone:          currentZone,
				ServerName:    currentServerName,
				ServerIP:      currentServerIP,
				RTT:           resp.RTT,
				Flags:         resolver.ExtractFlags(resp.Msg),
				Rcode:         resp.Msg.Rcode,
				RcodeStr:      dns.RcodeToString[resp.Msg.Rcode],
				Authoritative: resp.Msg.Authoritative,
				Answers:       ParseRRs(resp.Msg.Answer),
				Authority:     ParseRRs(resp.Msg.Ns),
				Additional:    ParseRRs(resp.Msg.Extra),
			}

			// Count RRSIGs
			rrsigCount := 0
			for _, rr := range resp.Msg.Answer {
				if rr.Header().Rrtype == dns.TypeRRSIG {
					rrsigCount++
				}
			}
			for _, rr := range resp.Msg.Ns {
				if rr.Header().Rrtype == dns.TypeRRSIG {
					rrsigCount++
				}
			}
			hop.RRSIGCount = rrsigCount
			hop.HasDNSSEC = rrsigCount > 0

			result.Hops = append(result.Hops, hop)

			// 1. Check for NXDOMAIN
			if resp.Msg.Rcode == dns.RcodeNameError {
				result.TotalRTT = time.Since(startTime)
				result.Success = true // Resolution completed: domain does not exist
				return result, nil
			}

			// 2. Check for Direct Answer
			var finalRRs []RecordInfo
			var cnameTarget string

			for _, rr := range resp.Msg.Answer {
				if rr.Header().Rrtype == currentQtype && strings.EqualFold(rr.Header().Name, currentQname) {
					finalRRs = append(finalRRs, ParseRR(rr))
				}
				if rr.Header().Rrtype == dns.TypeCNAME && strings.EqualFold(rr.Header().Name, currentQname) {
					if cnameRR, ok := rr.(*dns.CNAME); ok {
						cnameTarget = dns.Fqdn(cnameRR.Target)
					}
				}
			}

			if len(finalRRs) > 0 {
				result.FinalAnswers = finalRRs
				result.TotalRTT = time.Since(startTime)
				result.Success = true
				return result, nil
			}

			// If CNAME matched but query was not CNAME, follow CNAME target
			if cnameTarget != "" && currentQtype != dns.TypeCNAME {
				result.CNAMEChain = append(result.CNAMEChain, fmt.Sprintf("%s -> %s", currentQname, cnameTarget))
				cnameHops++
				if cnameHops > w.cfg.MaxCNAMEHops {
					result.TotalRTT = time.Since(startTime)
					result.Error = "exceeded maximum CNAME redirection hops"
					return result, fmt.Errorf("cname loop or chain too long")
				}
				currentQname = cnameTarget
				// Restart resolution from root for new CNAME target
				break
			}

			// 3. Check for Authoritative NODATA (empty answer with SOA in authority)
			if resp.Msg.Authoritative && len(resp.Msg.Answer) == 0 {
				result.TotalRTT = time.Since(startTime)
				result.Success = true
				return result, nil
			}

			// 4. Handle Delegation (Referral)
			var nsNames []string
			for _, rr := range resp.Msg.Ns {
				if nsRR, ok := rr.(*dns.NS); ok {
					nsNames = append(nsNames, strings.TrimSuffix(nsRR.Ns, "."))
					currentZone = strings.ToLower(nsRR.Header().Name)
				}
			}
			hop.Delegation = nsNames

			if len(nsNames) == 0 {
				result.TotalRTT = time.Since(startTime)
				result.Success = true
				return result, nil
			}

			// Find glue in Additional section
			glueMap := make(map[string][]string)
			for _, rr := range resp.Msg.Extra {
				header := rr.Header()
				cleanName := strings.TrimSuffix(strings.ToLower(header.Name), ".")
				switch r := rr.(type) {
				case *dns.A:
					glueMap[cleanName] = append(glueMap[cleanName], r.A.String())
					hop.Glue = append(hop.Glue, fmt.Sprintf("%s A %s", cleanName, r.A.String()))
				case *dns.AAAA:
					if !w.cfg.PreferIPv4 {
						glueMap[cleanName] = append(glueMap[cleanName], r.AAAA.String())
					}
					hop.Glue = append(hop.Glue, fmt.Sprintf("%s AAAA %s", cleanName, r.AAAA.String()))
				}
			}

			// Select next server to query
			var nextServerIP string
			var nextServerName string

			for _, ns := range nsNames {
				cleanNS := strings.ToLower(ns)
				if ips, found := glueMap[cleanNS]; found && len(ips) > 0 {
					nextServerIP = ips[0]
					nextServerName = ns
					break
				}
			}

			// If no glue was provided, resolve out-of-bailiwick nameserver using fallback DNS
			if nextServerIP == "" && len(nsNames) > 0 {
				targetNS := nsNames[0]
				resolvedIP, err := w.resolveOutBailiwickNS(ctx, targetNS)
				if err == nil && resolvedIP != "" {
					nextServerIP = resolvedIP
					nextServerName = targetNS
					hop.Glue = append(hop.Glue, fmt.Sprintf("%s (resolved out-of-bailiwick: %s)", targetNS, resolvedIP))
				}
			}

			if nextServerIP == "" {
				hop.Error = fmt.Sprintf("no reachable glue IP for delegation to %v", nsNames)
				result.TotalRTT = time.Since(startTime)
				result.Error = hop.Error
				return result, fmt.Errorf("glue resolution failed for %s", currentZone)
			}

			currentServerIP = nextServerIP
			currentServerName = nextServerName
		}

		if hopCount >= w.cfg.MaxHops {
			result.TotalRTT = time.Since(startTime)
			result.Error = "exceeded maximum delegation hops without reaching authoritative answer"
			return result, fmt.Errorf("exceeded max hops")
		}
	}
}

// resolveOutBailiwickNS queries the fallback recursive resolver to find the IP of an out-of-bailiwick NS.
func (w *Walker) resolveOutBailiwickNS(ctx context.Context, nsHostname string) (string, error) {
	fallbackServer := w.cfg.FallbackDNS
	if fallbackServer == "" {
		fallbackServer = "1.1.1.1:53"
	}
	opts := resolver.DefaultOptions()
	opts.RecursionDesired = true
	opts.Timeout = 2 * time.Second

	resp, err := w.client.Exchange(ctx, fallbackServer, nsHostname, dns.TypeA, &opts)
	if err != nil || resp.Msg == nil {
		return "", fmt.Errorf("fallback resolution failed: %w", err)
	}

	for _, rr := range resp.Msg.Answer {
		if aRecord, ok := rr.(*dns.A); ok {
			return aRecord.A.String(), nil
		}
	}

	return "", fmt.Errorf("no A record returned for %s", nsHostname)
}
