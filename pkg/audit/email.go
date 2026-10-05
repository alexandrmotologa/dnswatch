package audit

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/alexandrmotologa/dnswatch/pkg/resolver"
	"github.com/miekg/dns"
)

// EmailAuditor performs hygiene and security audits on SPF, DMARC, and MX records.
type EmailAuditor struct {
	client *resolver.Client
	server string
}

// NewEmailAuditor creates an email record auditor.
func NewEmailAuditor(client *resolver.Client, server string) *EmailAuditor {
	if server == "" {
		server = "1.1.1.1:53"
	}
	return &EmailAuditor{
		client: client,
		server: server,
	}
}

// AuditEmail performs comprehensive checks on SPF, DMARC, and MX configurations.
func (a *EmailAuditor) AuditEmail(ctx context.Context, domain string) ([]Finding, string, string, string) {
	var findings []Finding
	domain = strings.TrimSuffix(domain, ".")

	spfStatus := a.auditSPF(ctx, domain, &findings)
	dmarcStatus := a.auditDMARC(ctx, domain, &findings)
	mxStatus := a.auditMX(ctx, domain, &findings)

	return findings, spfStatus, dmarcStatus, mxStatus
}

// auditSPF inspects and validates Sender Policy Framework configuration.
func (a *EmailAuditor) auditSPF(ctx context.Context, domain string, findings *[]Finding) string {
	opts := resolver.DefaultOptions()
	opts.RecursionDesired = true

	resp, err := a.client.Exchange(ctx, a.server, domain, dns.TypeTXT, &opts)
	if err != nil || resp == nil || resp.Msg == nil {
		*findings = append(*findings, Finding{
			Category:       "Email",
			Title:          "Failed to Query SPF Records",
			Description:    fmt.Sprintf("DNS query for TXT records on %s failed: %v", domain, err),
			Severity:       SeverityMedium,
			Recommendation: "Check authoritative nameserver availability.",
		})
		return "ERROR"
	}

	var spfRecords []string
	for _, rr := range resp.Msg.Answer {
		if txtRR, ok := rr.(*dns.TXT); ok {
			fullTxt := strings.Join(txtRR.Txt, "")
			if strings.HasPrefix(strings.ToLower(fullTxt), "v=spf1") {
				spfRecords = append(spfRecords, fullTxt)
			}
		}
	}

	// 1. Multiple SPF records check (RFC 7208 Section 3.2)
	if len(spfRecords) > 1 {
		*findings = append(*findings, Finding{
			Category:       "Email",
			Title:          "Multiple SPF Records Detected",
			Description:    fmt.Sprintf("The domain publishes %d SPF records. RFC 7208 specifies that multiple SPF records cause a PermError, invalidating all SPF protection.", len(spfRecords)),
			Severity:       SeverityCritical,
			Recommendation: "Merge all SPF rules into a single v=spf1 TXT record.",
			Record:         strings.Join(spfRecords, " | "),
		})
		return "MULTIPLE_RECORDS"
	}

	// 2. Missing SPF record
	if len(spfRecords) == 0 {
		*findings = append(*findings, Finding{
			Category:       "Email",
			Title:          "Missing SPF Record",
			Description:    "The domain does not publish an SPF policy. Malicious actors can send spoofed emails claiming to originate from this domain.",
			Severity:       SeverityHigh,
			Recommendation: "Publish a v=spf1 TXT record defining authorized outbound mail servers.",
		})
		return "MISSING"
	}

	spf := spfRecords[0]
	terms := strings.Fields(spf)

	// 3. Mechanism analysis
	var hasAll bool
	var allModifier string
	var lookupCount int

	for _, term := range terms[1:] {
		lowerTerm := strings.ToLower(term)

		// Check for 'all' mechanism
		if strings.HasSuffix(lowerTerm, "all") {
			hasAll = true
			if strings.HasPrefix(lowerTerm, "+") || lowerTerm == "all" {
				allModifier = "+all"
			} else if strings.HasPrefix(lowerTerm, "-") {
				allModifier = "-all"
			} else if strings.HasPrefix(lowerTerm, "~") {
				allModifier = "~all"
			} else if strings.HasPrefix(lowerTerm, "?") {
				allModifier = "?all"
			}
		}

		// Count mechanisms requiring DNS lookups (RFC 7208 Section 4.6.4 limits this to 10)
		for _, prefix := range []string{"include:", "a", "mx", "ptr", "exists:", "redirect="} {
			cleanTerm := strings.TrimLeft(lowerTerm, "+-~?")
			if cleanTerm == prefix || strings.HasPrefix(cleanTerm, prefix) {
				lookupCount++
				break
			}
		}

		// Check for deprecated ptr mechanism
		cleanTerm := strings.TrimLeft(lowerTerm, "+-~?")
		if cleanTerm == "ptr" || strings.HasPrefix(cleanTerm, "ptr:") {
			*findings = append(*findings, Finding{
				Category:       "Email",
				Title:          "Deprecated SPF ptr Mechanism",
				Description:    fmt.Sprintf("The SPF record contains '%s'. RFC 7208 deprecates the 'ptr' mechanism because it causes excessive reverse DNS queries and is unreliable.", term),
				Severity:       SeverityLow,
				Recommendation: "Replace 'ptr' mechanisms with explicit 'ip4:' or 'ip6:' CIDR blocks.",
				Record:         spf,
			})
		}
	}

	// Lookup limit check
	if lookupCount > 10 {
		*findings = append(*findings, Finding{
			Category:       "Email",
			Title:          "SPF DNS Lookup Limit Exceeded",
			Description:    fmt.Sprintf("The SPF record requires approximately %d DNS lookups, exceeding the RFC 7208 hard limit of 10. Receiving mail servers may abort evaluation with PermError.", lookupCount),
			Severity:       SeverityHigh,
			Recommendation: "Flatten SPF includes or replace domain lookups with direct IP ranges.",
			Record:         spf,
		})
	}

	// Check final all mechanism
	if !hasAll {
		*findings = append(*findings, Finding{
			Category:       "Email",
			Title:          "SPF Missing Default 'all' Mechanism",
			Description:    "The SPF record does not specify an explicit fallback qualifier (such as -all or ~all). Behavior for non-matching IPs is ambiguous.",
			Severity:       SeverityMedium,
			Recommendation: "Append '-all' or '~all' at the end of the SPF record.",
			Record:         spf,
		})
		return "INCOMPLETE"
	}

	switch allModifier {
	case "+all":
		*findings = append(*findings, Finding{
			Category:       "Email",
			Title:          "Dangerous SPF '+all' Mechanism",
			Description:    "The SPF record ends with '+all', explicitly permitting any IP address in the world to send mail on behalf of this domain.",
			Severity:       SeverityCritical,
			Recommendation: "Immediately replace '+all' with '-all' or '~all'.",
			Record:         spf,
		})
		return "DANGEROUS"
	case "?all":
		*findings = append(*findings, Finding{
			Category:       "Email",
			Title:          "Neutral SPF Policy (?all)",
			Description:    "The record ends with '?all', stating that sender authenticity cannot be verified. This provides minimal protection against phishing.",
			Severity:       SeverityMedium,
			Recommendation: "Upgrade policy to '~all' (SoftFail) or '-all' (HardFail).",
			Record:         spf,
		})
		return "NEUTRAL"
	case "~all":
		*findings = append(*findings, Finding{
			Category:       "Email",
			Title:          "SoftFail SPF Policy (~all)",
			Description:    "The SPF record specifies SoftFail (~all). Messages from unauthorized servers are accepted but marked as suspicious.",
			Severity:       SeverityGood,
			Recommendation: "Consider moving to strict HardFail (-all) once all valid sending services are verified.",
			Record:         spf,
		})
		return "SOFTFAIL"
	case "-all":
		*findings = append(*findings, Finding{
			Category:       "Email",
			Title:          "Strict HardFail SPF Policy (-all)",
			Description:    "The SPF record strictly rejects all unauthorized sending IPs.",
			Severity:       SeverityGood,
			Recommendation: "Maintain authorized IP lists as outbound mail infrastructure evolves.",
			Record:         spf,
		})
		return "STRICT"
	}

	return "VALID"
}

// auditDMARC inspects and evaluates DMARC record policies.
func (a *EmailAuditor) auditDMARC(ctx context.Context, domain string, findings *[]Finding) string {
	dmarcDomain := "_dmarc." + domain
	opts := resolver.DefaultOptions()
	opts.RecursionDesired = true

	resp, err := a.client.Exchange(ctx, a.server, dmarcDomain, dns.TypeTXT, &opts)
	if err != nil || resp == nil || resp.Msg == nil {
		*findings = append(*findings, Finding{
			Category:       "Email",
			Title:          "Failed to Query DMARC Record",
			Description:    fmt.Sprintf("DNS query for %s failed: %v", dmarcDomain, err),
			Severity:       SeverityMedium,
			Recommendation: "Verify nameserver connectivity.",
		})
		return "ERROR"
	}

	var dmarcRecord string
	for _, rr := range resp.Msg.Answer {
		if txtRR, ok := rr.(*dns.TXT); ok {
			fullTxt := strings.Join(txtRR.Txt, "")
			if strings.HasPrefix(strings.ToLower(fullTxt), "v=dmarc1") {
				dmarcRecord = fullTxt
				break
			}
		}
	}

	if dmarcRecord == "" {
		*findings = append(*findings, Finding{
			Category:       "Email",
			Title:          "Missing DMARC Policy",
			Description:    fmt.Sprintf("No DMARC record found at %s. Receiving mail servers have no instructions on how to treat SPF or DKIM validation failures.", dmarcDomain),
			Severity:       SeverityHigh,
			Recommendation: "Publish a TXT record at _dmarc." + domain + " with policy p=quarantine or p=reject.",
		})
		return "MISSING"
	}

	// Parse DMARC tags
	tags := make(map[string]string)
	for _, part := range strings.Split(dmarcRecord, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			tags[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
		}
	}

	policy := strings.ToLower(tags["p"])
	rua := tags["rua"]
	pct := tags["pct"]

	// Missing reporting address
	if rua == "" {
		*findings = append(*findings, Finding{
			Category:       "Email",
			Title:          "DMARC Missing Aggregate Reporting (rua)",
			Description:    "The DMARC record does not define a 'rua' reporting URI. You will not receive aggregate reports detailing who sends mail using your domain.",
			Severity:       SeverityLow,
			Recommendation: "Add a rua=mailto:dmarc-reports@example.com tag to receive visibility reports.",
			Record:         dmarcRecord,
		})
	}

	// Check percentage enforcement
	if pct != "" {
		if pctVal, err := strconv.Atoi(pct); err == nil && pctVal < 100 {
			*findings = append(*findings, Finding{
				Category:       "Email",
				Title:          "Partial DMARC Enforcement",
				Description:    fmt.Sprintf("The DMARC policy applies to only %d%% of messages. The remaining %d%% are subject to recipient default policy.", pctVal, 100-pctVal),
				Severity:       SeverityMedium,
				Recommendation: "Increase pct to 100 once authentication issues are resolved.",
				Record:         dmarcRecord,
			})
		}
	}

	switch policy {
	case "none":
		*findings = append(*findings, Finding{
			Category:       "Email",
			Title:          "DMARC Policy Set to None (Monitoring Only)",
			Description:    "The DMARC policy is set to 'p=none'. Unauthenticated spoofed emails will still be delivered to inboxes.",
			Severity:       SeverityMedium,
			Recommendation: "Upgrade policy from p=none to p=quarantine or p=reject after monitoring reports.",
			Record:         dmarcRecord,
		})
		return "MONITORING"
	case "quarantine":
		*findings = append(*findings, Finding{
			Category:       "Email",
			Title:          "DMARC Quarantine Policy Active",
			Description:    "Messages failing SPF and DKIM authentication are directed to the recipient's spam/junk folder.",
			Severity:       SeverityGood,
			Recommendation: "Transition to p=reject when legitimate sending pipelines are verified.",
			Record:         dmarcRecord,
		})
		return "QUARANTINE"
	case "reject":
		*findings = append(*findings, Finding{
			Category:       "Email",
			Title:          "Strict DMARC Reject Policy Active",
			Description:    "Messages failing authentication are rejected during the SMTP conversation.",
			Severity:       SeverityGood,
			Recommendation: "Continue monitoring aggregate reports for legitimate misconfigured senders.",
			Record:         dmarcRecord,
		})
		return "REJECT"
	default:
		*findings = append(*findings, Finding{
			Category:       "Email",
			Title:          "Invalid or Missing DMARC 'p=' Policy Tag",
			Description:    fmt.Sprintf("The DMARC record contains unrecognized policy '%s'. Valid options are none, quarantine, or reject.", policy),
			Severity:       SeverityHigh,
			Recommendation: "Set a valid policy tag such as p=quarantine.",
			Record:         dmarcRecord,
		})
		return "INVALID"
	}
}

// auditMX inspects Mail Exchange records for availability and best practices.
func (a *EmailAuditor) auditMX(ctx context.Context, domain string, findings *[]Finding) string {
	opts := resolver.DefaultOptions()
	opts.RecursionDesired = true

	resp, err := a.client.Exchange(ctx, a.server, domain, dns.TypeMX, &opts)
	if err != nil || resp == nil || resp.Msg == nil {
		return "ERROR"
	}

	var mxRecords []*dns.MX
	for _, rr := range resp.Msg.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			mxRecords = append(mxRecords, mx)
		}
	}

	if len(mxRecords) == 0 {
		*findings = append(*findings, Finding{
			Category:       "Email",
			Title:          "No MX Records Configured",
			Description:    "The domain has no MX records. Inbound email delivery will fail or fall back to the domain A record if present.",
			Severity:       SeverityInfo,
			Recommendation: "If this domain receives email, configure MX records pointing to your mail provider.",
		})
		return "NONE"
	}

	// Check for Null MX (RFC 7505)
	if len(mxRecords) == 1 && mxRecords[0].Preference == 0 && (mxRecords[0].Mx == "." || mxRecords[0].Mx == "") {
		*findings = append(*findings, Finding{
			Category:       "Email",
			Title:          "Null MX Configured (RFC 7505)",
			Description:    "The domain explicitly declares it does not accept email by publishing a Null MX record (. 0).",
			Severity:       SeverityGood,
			Recommendation: "No action required. This protects non-email domains from backscatter.",
		})
		return "NULL_MX"
	}

	// Verify each MX host resolves
	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Mx, ".")
		aResp, err := a.client.Exchange(ctx, a.server, host, dns.TypeA, &opts)
		if err != nil || aResp == nil || aResp.Msg == nil || len(aResp.Msg.Answer) == 0 {
			*findings = append(*findings, Finding{
				Category:       "Email",
				Title:          "Unresolvable MX Host",
				Description:    fmt.Sprintf("MX host %s (preference %d) does not resolve to an IPv4 address.", mx.Mx, mx.Preference),
				Severity:       SeverityHigh,
				Recommendation: "Ensure MX targets point to valid, reachable mail server hostnames.",
				Record:         fmt.Sprintf("%d %s", mx.Preference, mx.Mx),
			})
		}
	}

	*findings = append(*findings, Finding{
		Category:       "Email",
		Title:          "MX Records Active",
		Description:    fmt.Sprintf("The domain publishes %d active MX mail exchanger(s).", len(mxRecords)),
		Severity:       SeverityGood,
		Recommendation: "Maintain redundant MX records with distinct priorities.",
	})
	return "ACTIVE"
}
