package diff

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alexandrmotologa/dnswatch/pkg/resolver"
	"github.com/miekg/dns"
)

// RecordDiff details differences for a specific record type.
type RecordDiff struct {
	Type      string   `json:"type"`
	Target1   []string `json:"target1"`
	Target2   []string `json:"target2"`
	Identical bool     `json:"identical"`
	OnlyIn1   []string `json:"only_in_1,omitempty"`
	OnlyIn2   []string `json:"only_in_2,omitempty"`
}

// DiffReport aggregates comparison results across all record types.
type DiffReport struct {
	Target1    string       `json:"target1"`
	Target2    string       `json:"target2"`
	Mode       string       `json:"mode"` // "domains" or "servers"
	TotalTypes int          `json:"total_types"`
	MatchCount int          `json:"match_count"`
	DiffCount  int          `json:"diff_count"`
	ParityRate float64      `json:"parity_rate"`
	Diffs      []RecordDiff `json:"diffs"`
	CheckedAt  time.Time    `json:"checked_at"`
}

// Differ compares DNS records across domains or resolvers.
type Differ struct {
	client *resolver.Client
}

// NewDiffer creates a DNS comparison engine.
func NewDiffer(timeout time.Duration) *Differ {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	opts := resolver.DefaultOptions()
	opts.Timeout = timeout
	opts.RecursionDesired = true
	return &Differ{
		client: resolver.NewClient(opts),
	}
}

// Standard record types evaluated in diff
var compareTypes = []uint16{
	dns.TypeA,
	dns.TypeAAAA,
	dns.TypeCNAME,
	dns.TypeMX,
	dns.TypeTXT,
	dns.TypeNS,
	dns.TypeSOA,
	dns.TypeCAA,
}

// CompareDomains compares DNS records between two domain names using a common resolver.
func (d *Differ) CompareDomains(ctx context.Context, domain1, domain2, resolverServer string) (*DiffReport, error) {
	if resolverServer == "" {
		resolverServer = "1.1.1.1:53"
	}
	return d.executeComparison(ctx, domain1, domain2, resolverServer, resolverServer, "domains")
}

// CompareServers compares the same domain queried against two distinct nameservers.
func (d *Differ) CompareServers(ctx context.Context, domain, server1, server2 string) (*DiffReport, error) {
	return d.executeComparison(ctx, domain, domain, server1, server2, "servers")
}

func (d *Differ) executeComparison(ctx context.Context, d1, d2, s1, s2, mode string) (*DiffReport, error) {
	d1 = strings.TrimSpace(d1)
	d2 = strings.TrimSpace(d2)

	report := &DiffReport{
		Target1:   fmt.Sprintf("%s @ %s", d1, s1),
		Target2:   fmt.Sprintf("%s @ %s", d2, s2),
		Mode:      mode,
		Diffs:     make([]RecordDiff, len(compareTypes)),
		CheckedAt: time.Now(),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, qtype := range compareTypes {
		wg.Add(1)
		go func(idx int, t uint16) {
			defer wg.Done()
			qtypeStr := dns.TypeToString[t]

			// Query target 1
			r1 := d.queryValues(ctx, s1, d1, t)
			// Query target 2
			r2 := d.queryValues(ctx, s2, d2, t)

			sort.Strings(r1)
			sort.Strings(r2)

			only1 := difference(r1, r2)
			only2 := difference(r2, r1)
			isSame := len(only1) == 0 && len(only2) == 0

			rd := RecordDiff{
				Type:      qtypeStr,
				Target1:   r1,
				Target2:   r2,
				Identical: isSame,
				OnlyIn1:   only1,
				OnlyIn2:   only2,
			}

			mu.Lock()
			report.Diffs[idx] = rd
			if isSame {
				report.MatchCount++
			} else {
				report.DiffCount++
			}
			mu.Unlock()
		}(i, qtype)
	}

	wg.Wait()

	report.TotalTypes = len(compareTypes)
	if report.TotalTypes > 0 {
		report.ParityRate = (float64(report.MatchCount) / float64(report.TotalTypes)) * 100.0
	}

	return report, nil
}

func (d *Differ) queryValues(ctx context.Context, server, domain string, qtype uint16) []string {
	resp, err := d.client.Exchange(ctx, server, domain, qtype, nil)
	if err != nil || resp == nil || resp.Msg == nil {
		return []string{}
	}

	var values []string
	for _, rr := range resp.Msg.Answer {
		if rr.Header().Rrtype == qtype {
			clean := strings.TrimSpace(extractData(rr))
			if clean != "" {
				values = append(values, clean)
			}
		}
	}
	return values
}

func extractData(rr dns.RR) string {
	switch r := rr.(type) {
	case *dns.A:
		return r.A.String()
	case *dns.AAAA:
		return r.AAAA.String()
	case *dns.CNAME:
		return r.Target
	case *dns.MX:
		return fmt.Sprintf("%d %s", r.Preference, r.Mx)
	case *dns.TXT:
		return strings.Join(r.Txt, " ")
	case *dns.NS:
		return r.Ns
	case *dns.SOA:
		return fmt.Sprintf("Serial:%d NS:%s", r.Serial, r.Ns)
	case *dns.CAA:
		return fmt.Sprintf("%s \"%s\"", r.Tag, r.Value)
	default:
		return rr.String()
	}
}

func difference(a, b []string) []string {
	bMap := make(map[string]bool)
	for _, item := range b {
		bMap[item] = true
	}
	var diff []string
	for _, item := range a {
		if !bMap[item] {
			diff = append(diff, item)
		}
	}
	return diff
}
