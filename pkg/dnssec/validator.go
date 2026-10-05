package dnssec

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/alexandrmotologa/dnswatch/pkg/resolver"
	"github.com/miekg/dns"
)

// Validator orchestrates full DNSSEC chain of trust inspection.
type Validator struct {
	client *resolver.Client
}

// NewValidator creates a DNSSEC validator using standard resolvers.
func NewValidator(timeout time.Duration) *Validator {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	opts := resolver.DefaultOptions()
	opts.Timeout = timeout
	opts.DNSSECOk = true
	opts.RecursionDesired = true
	return &Validator{
		client: resolver.NewClient(opts),
	}
}

// ValidateDomain inspects the trust chain from Root to Domain.
func (v *Validator) ValidateDomain(ctx context.Context, domain string, qtype uint16) (*ValidationResult, error) {
	now := time.Now()
	domain = dns.Fqdn(domain)
	qtypeStr := dns.TypeToString[qtype]
	if qtypeStr == "" {
		qtypeStr = fmt.Sprintf("TYPE%d", qtype)
	}

	res := &ValidationResult{
		Domain:        domain,
		QueryType:     qtypeStr,
		OverallStatus: StatusInsecure,
		Chain:         make([]*ChainNode, 0),
		Errors:        make([]string, 0),
		Warnings:      make([]string, 0),
		CheckedAt:     now,
	}

	// 1. Root Zone (.) check
	rootNode := v.inspectZone(ctx, ".", "", now)
	res.Chain = append(res.Chain, rootNode)

	// 2. Identify TLD and Parent zones
	labels := dns.SplitDomainName(domain)
	if len(labels) == 0 {
		res.OverallStatus = StatusBogus
		res.Errors = append(res.Errors, "invalid domain name")
		return res, nil
	}

	tld := labels[len(labels)-1] + "."
	tldNode := v.inspectZone(ctx, tld, ".", now)
	res.Chain = append(res.Chain, tldNode)

	// 3. Domain zone
	var domainNode *ChainNode
	if strings.EqualFold(tld, domain) {
		domainNode = tldNode
	} else {
		// Parent of domain is TLD or higher level
		parentZone := tld
		if len(labels) > 2 {
			parentZone = strings.Join(labels[len(labels)-2:], ".") + "."
		}
		domainNode = v.inspectZone(ctx, domain, parentZone, now)
		res.Chain = append(res.Chain, domainNode)
	}

	// Determine overall status
	if domainNode.Status == StatusSecure {
		res.OverallStatus = StatusSecure
	} else if domainNode.Status == StatusBogus {
		res.OverallStatus = StatusBogus
		res.Errors = append(res.Errors, domainNode.Errors...)
	} else {
		res.OverallStatus = StatusInsecure
	}

	// Propagate warnings
	for _, node := range res.Chain {
		res.Warnings = append(res.Warnings, node.Warnings...)
	}

	return res, nil
}

// inspectZone checks DS, DNSKEY, and RRSIG records for a specific zone.
func (v *Validator) inspectZone(ctx context.Context, zone string, parentZone string, now time.Time) *ChainNode {
	node := &ChainNode{
		Zone:            zone,
		Status:          StatusInsecure,
		DSKeyTags:       make([]uint16, 0),
		DSDigests:       make([]string, 0),
		KSKKeyTags:      make([]uint16, 0),
		ZSKKeyTags:      make([]uint16, 0),
		Algorithms:      make([]string, 0),
		Errors:          make([]string, 0),
		Warnings:        make([]string, 0),
		SignaturesValid: false,
	}

	resolverServer := "1.1.1.1:53"

	// Fetch DNSKEY for this zone
	opts := resolver.DefaultOptions()
	opts.DNSSECOk = true
	opts.RecursionDesired = true

	keyResp, err := v.client.Exchange(ctx, resolverServer, zone, dns.TypeDNSKEY, &opts)
	if err != nil || keyResp == nil || keyResp.Msg == nil {
		node.Errors = append(node.Errors, fmt.Sprintf("failed to fetch DNSKEY for %s: %v", zone, err))
		node.Status = StatusIndeterminate
		return node
	}

	var dnskeys []*dns.DNSKEY
	var dnskeyRRSIG *dns.RRSIG

	for _, rr := range keyResp.Msg.Answer {
		switch r := rr.(type) {
		case *dns.DNSKEY:
			dnskeys = append(dnskeys, r)
			algStr := AlgorithmToString(r.Algorithm)
			node.Algorithms = append(node.Algorithms, algStr)
			if r.Flags == 257 {
				node.KSKKeyTags = append(node.KSKKeyTags, r.KeyTag())
			} else {
				node.ZSKKeyTags = append(node.ZSKKeyTags, r.KeyTag())
			}
		case *dns.RRSIG:
			if r.TypeCovered == dns.TypeDNSKEY {
				dnskeyRRSIG = r
			}
		}
	}

	if len(dnskeys) == 0 {
		// Zone has no DNSKEY records, it is unsigned
		node.Status = StatusInsecure
		return node
	}

	node.HasDNSKEY = true

	// Check RRSIG on DNSKEY
	if dnskeyRRSIG != nil {
		node.HasRRSIG = true
		validTime, inc, exp, timeErr := CheckSignatureValidity(dnskeyRRSIG, now)
		node.Inception = &inc
		node.Expiration = &exp
		node.IsExpired = !validTime

		if timeErr != nil {
			node.Errors = append(node.Errors, timeErr.Error())
			node.Status = StatusBogus
			return node
		}

		// Verify cryptographic signature against DNSKEY set
		var rrset []dns.RR
		for _, k := range dnskeys {
			rrset = append(rrset, k)
		}

		// Find signing KSK
		var signingKey *dns.DNSKEY
		for _, k := range dnskeys {
			if k.KeyTag() == dnskeyRRSIG.KeyTag {
				signingKey = k
				break
			}
		}

		if signingKey != nil {
			if err := VerifyRRSIG(signingKey, dnskeyRRSIG, rrset); err != nil {
				node.Errors = append(node.Errors, fmt.Sprintf("DNSKEY RRSIG invalid: %v", err))
				node.Status = StatusBogus
				return node
			}
			node.SignaturesValid = true
		} else {
			node.Warnings = append(node.Warnings, fmt.Sprintf("DNSKEY signing key tag %d not found in RRset", dnskeyRRSIG.KeyTag))
		}
	}

	// If root zone, it is self-signed trust anchor
	if zone == "." {
		if node.SignaturesValid {
			node.Status = StatusSecure
		} else {
			node.Status = StatusBogus
		}
		return node
	}

	// For non-root zones, query parent DS record
	dsResp, err := v.client.Exchange(ctx, resolverServer, zone, dns.TypeDS, &opts)
	if err != nil || dsResp == nil || dsResp.Msg == nil {
		node.Errors = append(node.Errors, fmt.Sprintf("failed to fetch DS for %s: %v", zone, err))
		node.Status = StatusIndeterminate
		return node
	}

	var dsRecords []*dns.DS
	for _, rr := range dsResp.Msg.Answer {
		if dsRec, ok := rr.(*dns.DS); ok {
			dsRecords = append(dsRecords, dsRec)
			node.DSKeyTags = append(node.DSKeyTags, dsRec.KeyTag)
			node.DSDigests = append(node.DSDigests, dsRec.Digest)
		}
	}

	if len(dsRecords) == 0 {
		// No DS at parent: zone is not delegated securely
		node.Status = StatusInsecure
		return node
	}

	node.HasDS = true

	// Verify DS digest matches child DNSKEY
	matched, _, dsWarnings, dsErr := VerifyDSMatchesDNSKEY(dsRecords, dnskeys)
	node.Warnings = append(node.Warnings, dsWarnings...)
	if dsErr != nil || !matched {
		node.Errors = append(node.Errors, fmt.Sprintf("DS verification failed: %v", dsErr))
		node.Status = StatusBogus
		return node
	}

	node.DigestMatched = true
	if node.SignaturesValid && node.DigestMatched {
		node.Status = StatusSecure
	} else {
		node.Status = StatusBogus
	}

	return node
}
