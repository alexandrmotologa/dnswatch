package trace

import (
	"fmt"
	"strings"
	"time"

	"github.com/alexandrmotologa/dnswatch/pkg/enrich"
	"github.com/alexandrmotologa/dnswatch/pkg/resolver"
	"github.com/miekg/dns"
)

// RecordInfo represents a human-readable DNS resource record.
type RecordInfo struct {
	Name   string         `json:"name"`
	Type   string         `json:"type"`
	TTL    uint32         `json:"ttl"`
	Class  string         `json:"class"`
	Data   string         `json:"data"`
	Raw    string         `json:"raw"`
	IPInfo *enrich.IPInfo `json:"ip_info,omitempty"`
}

// ParseRR converts a miekg/dns.RR into a structured RecordInfo.
func ParseRR(rr dns.RR) RecordInfo {
	if rr == nil {
		return RecordInfo{}
	}
	header := rr.Header()
	typeName := dns.TypeToString[header.Rrtype]
	if typeName == "" {
		typeName = fmt.Sprintf("TYPE%d", header.Rrtype)
	}

	var data string
	switch r := rr.(type) {
	case *dns.A:
		data = r.A.String()
	case *dns.AAAA:
		data = r.AAAA.String()
	case *dns.CNAME:
		data = r.Target
	case *dns.NS:
		data = r.Ns
	case *dns.MX:
		data = fmt.Sprintf("%d %s", r.Preference, r.Mx)
	case *dns.TXT:
		data = strings.Join(r.Txt, " ")
	case *dns.SOA:
		data = fmt.Sprintf("%s %s (%d %d %d %d %d)", r.Ns, r.Mbox, r.Serial, r.Refresh, r.Retry, r.Expire, r.Minttl)
	case *dns.PTR:
		data = r.Ptr
	case *dns.SRV:
		data = fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, r.Target)
	case *dns.CAA:
		data = fmt.Sprintf("%d %s \"%s\"", r.Flag, r.Tag, r.Value)
	case *dns.DNSKEY:
		data = fmt.Sprintf("Flags:%d Proto:%d Alg:%d KeyTag:%d", r.Flags, r.Protocol, r.Algorithm, r.KeyTag())
	case *dns.DS:
		data = fmt.Sprintf("KeyTag:%d Alg:%d DigestType:%d Digest:%s", r.KeyTag, r.Algorithm, r.DigestType, r.Digest)
	case *dns.RRSIG:
		data = fmt.Sprintf("TypeCovered:%s Alg:%d Labels:%d OrigTTL:%d Signer:%s",
			dns.TypeToString[r.TypeCovered], r.Algorithm, r.Labels, r.OrigTtl, r.SignerName)
	default:
		// Fallback to string representation omitting name, ttl, class, type
		raw := rr.String()
		parts := strings.Fields(raw)
		if len(parts) >= 5 {
			data = strings.Join(parts[4:], " ")
		} else {
			data = raw
		}
	}

	return RecordInfo{
		Name:  header.Name,
		Type:  typeName,
		TTL:   header.Ttl,
		Class: dns.ClassToString[header.Class],
		Data:  data,
		Raw:   rr.String(),
	}
}

// ParseRRs converts a slice of dns.RR into structured RecordInfo items.
func ParseRRs(rrs []dns.RR) []RecordInfo {
	res := make([]RecordInfo, 0, len(rrs))
	for _, rr := range rrs {
		res = append(res, ParseRR(rr))
	}
	return res
}

// TraceHop represents a single resolution step in the delegation hierarchy.
type TraceHop struct {
	Step          int                  `json:"step"`
	Zone          string               `json:"zone"`
	ServerName    string               `json:"server_name"`
	ServerIP      string               `json:"server_ip"`
	ServerInfo    *enrich.IPInfo       `json:"server_info,omitempty"`
	RTT           time.Duration        `json:"rtt"`
	Flags        resolver.HeaderFlags `json:"flags"`
	Rcode        int                  `json:"rcode"`
	RcodeStr     string               `json:"rcode_str"`
	Authoritative bool                `json:"authoritative"`
	Delegation   []string             `json:"delegation"`   // Referred NS names
	Glue         []string             `json:"glue"`         // Known IPs for referral
	Answers      []RecordInfo         `json:"answers"`
	Authority    []RecordInfo         `json:"authority"`
	Additional   []RecordInfo         `json:"additional"`
	HasDNSSEC    bool                 `json:"has_dnssec"`
	RRSIGCount   int                  `json:"rrsig_count"`
	Error        string               `json:"error,omitempty"`
}

// TraceResult holds the complete root-to-leaf trace.
type TraceResult struct {
	Domain       string        `json:"domain"`
	QueryType    string        `json:"query_type"`
	Hops         []*TraceHop   `json:"hops"`
	FinalAnswers []RecordInfo  `json:"final_answers"`
	TotalRTT     time.Duration `json:"total_rtt"`
	Success      bool          `json:"success"`
	CNAMEChain   []string      `json:"cname_chain,omitempty"`
	Error        string        `json:"error,omitempty"`
}
