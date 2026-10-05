package enrich

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alexandrmotologa/dnswatch/pkg/resolver"
	"github.com/miekg/dns"
)

// IPInfo holds Autonomous System Number, organization, and country metadata for an IP.
type IPInfo struct {
	IP      string `json:"ip"`
	ASN     uint32 `json:"asn,omitempty"`
	ASName  string `json:"as_name,omitempty"`
	Country string `json:"country,omitempty"`
	Prefix  string `json:"prefix,omitempty"`
	PTR     string `json:"ptr,omitempty"`
}

// FormattedLabel returns a compact badge string like "[AS13335 CLOUDFLARENET, US]".
func (info *IPInfo) FormattedLabel() string {
	if info == nil || info.ASN == 0 {
		if info != nil && info.PTR != "" {
			return fmt.Sprintf("[%s]", info.PTR)
		}
		return ""
	}

	name := info.ASName
	if name == "" {
		name = fmt.Sprintf("AS%d", info.ASN)
	}

	if info.Country != "" {
		return fmt.Sprintf("[AS%d %s, %s]", info.ASN, name, info.Country)
	}
	return fmt.Sprintf("[AS%d %s]", info.ASN, name)
}

// Enricher resolves ASN and rDNS metadata via standard DNS protocols (Team Cymru).
type Enricher struct {
	client     *resolver.Client
	server     string
	cacheLock  sync.RWMutex
	ipCache    map[string]*IPInfo
	asNameLock sync.RWMutex
	asNameCache map[uint32]string
}

var (
	defaultEnricher *Enricher
	once            sync.Once
)

// GetDefaultEnricher returns a singleton DNS-based ASN enricher.
func GetDefaultEnricher() *Enricher {
	once.Do(func() {
		opts := resolver.DefaultOptions()
		opts.Timeout = 2 * time.Second
		defaultEnricher = NewEnricher(resolver.NewClient(opts), "1.1.1.1:53")
	})
	return defaultEnricher
}

// NewEnricher creates an ASN and rDNS enricher.
func NewEnricher(client *resolver.Client, server string) *Enricher {
	if server == "" {
		server = "1.1.1.1:53"
	}
	return &Enricher{
		client:      client,
		server:      server,
		ipCache:     make(map[string]*IPInfo),
		asNameCache: make(map[uint32]string),
	}
}

// LookupIP queries ASN, BGP prefix, organization, and PTR hostname for an IP.
func (e *Enricher) LookupIP(ctx context.Context, ipStr string) *IPInfo {
	ipStr = strings.TrimSpace(ipStr)
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return &IPInfo{IP: ipStr}
	}

	// Skip private and loopback addresses
	if parsedIP.IsLoopback() || parsedIP.IsPrivate() || parsedIP.IsUnspecified() {
		return &IPInfo{IP: ipStr, ASName: "Local/Private"}
	}

	// Check cache
	e.cacheLock.RLock()
	if cached, found := e.ipCache[ipStr]; found {
		e.cacheLock.RUnlock()
		return cached
	}
	e.cacheLock.RUnlock()

	info := &IPInfo{IP: ipStr}

	// 1. Resolve reverse DNS PTR in parallel with ASN lookup
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		info.PTR = e.lookupPTR(ctx, parsedIP)
	}()

	go func() {
		defer wg.Done()
		asn, prefix, country := e.lookupCymruASN(ctx, parsedIP)
		info.ASN = asn
		info.Prefix = prefix
		info.Country = country
		if asn > 0 {
			info.ASName = e.lookupASName(ctx, asn)
		}
	}()

	wg.Wait()

	// Store in cache
	e.cacheLock.Lock()
	e.ipCache[ipStr] = info
	e.cacheLock.Unlock()

	return info
}

// lookupPTR retrieves reverse DNS PTR hostname.
func (e *Enricher) lookupPTR(ctx context.Context, ip net.IP) string {
	arpa, err := dns.ReverseAddr(ip.String())
	if err != nil {
		return ""
	}

	opts := resolver.DefaultOptions()
	opts.Timeout = 1500 * time.Millisecond
	opts.RecursionDesired = true

	resp, err := e.client.Exchange(ctx, e.server, arpa, dns.TypePTR, &opts)
	if err != nil || resp == nil || resp.Msg == nil {
		return ""
	}

	for _, rr := range resp.Msg.Answer {
		if ptrRR, ok := rr.(*dns.PTR); ok {
			return strings.TrimSuffix(ptrRR.Ptr, ".")
		}
	}
	return ""
}

// lookupCymruASN queries Team Cymru DNS origin mapping.
func (e *Enricher) lookupCymruASN(ctx context.Context, ip net.IP) (uint32, string, string) {
	var queryDomain string

	if ipv4 := ip.To4(); ipv4 != nil {
		// IPv4: 4.3.2.1.origin.asn.cymru.com
		parts := strings.Split(ipv4.String(), ".")
		queryDomain = fmt.Sprintf("%s.%s.%s.%s.origin.asn.cymru.com", parts[3], parts[2], parts[1], parts[0])
	} else {
		// IPv6: reversed nibbles .origin6.asn.cymru.com
		arpa, err := dns.ReverseAddr(ip.String())
		if err != nil {
			return 0, "", ""
		}
		// Replace ip6.arpa. with origin6.asn.cymru.com
		queryDomain = strings.TrimSuffix(arpa, "ip6.arpa.") + "origin6.asn.cymru.com"
	}

	opts := resolver.DefaultOptions()
	opts.Timeout = 1500 * time.Millisecond
	opts.RecursionDesired = true

	resp, err := e.client.Exchange(ctx, e.server, queryDomain, dns.TypeTXT, &opts)
	if err != nil || resp == nil || resp.Msg == nil {
		return 0, "", ""
	}

	for _, rr := range resp.Msg.Answer {
		if txtRR, ok := rr.(*dns.TXT); ok && len(txtRR.Txt) > 0 {
			fullTxt := strings.Join(txtRR.Txt, "")
			// Format: "13335 | 1.1.1.0/24 | US | arin | 2018-04-12"
			fields := strings.Split(fullTxt, "|")
			if len(fields) >= 3 {
				asnStr := strings.TrimSpace(fields[0])
				// Some returns multiple ASNs separated by space
				if parts := strings.Fields(asnStr); len(parts) > 0 {
					asnStr = parts[0]
				}
				asnNum, _ := strconv.ParseUint(asnStr, 10, 32)
				prefix := strings.TrimSpace(fields[1])
				country := strings.TrimSpace(fields[2])
				return uint32(asnNum), prefix, country
			}
		}
	}

	return 0, "", ""
}

// lookupASName queries the AS description from Team Cymru (e.g. AS13335.asn.cymru.com).
func (e *Enricher) lookupASName(ctx context.Context, asn uint32) string {
	if asn == 0 {
		return ""
	}

	e.asNameLock.RLock()
	if name, found := e.asNameCache[asn]; found {
		e.asNameLock.RUnlock()
		return name
	}
	e.asNameLock.RUnlock()

	queryDomain := fmt.Sprintf("AS%d.asn.cymru.com", asn)
	opts := resolver.DefaultOptions()
	opts.Timeout = 1500 * time.Millisecond
	opts.RecursionDesired = true

	resp, err := e.client.Exchange(ctx, e.server, queryDomain, dns.TypeTXT, &opts)
	if err != nil || resp == nil || resp.Msg == nil {
		return fmt.Sprintf("AS%d", asn)
	}

	var asName string
	for _, rr := range resp.Msg.Answer {
		if txtRR, ok := rr.(*dns.TXT); ok && len(txtRR.Txt) > 0 {
			fullTxt := strings.Join(txtRR.Txt, "")
			// Format: "13335 | US | arin | 2018-04-12 | CLOUDFLARENET"
			fields := strings.Split(fullTxt, "|")
			if len(fields) >= 5 {
				asName = strings.TrimSpace(fields[4])
				break
			}
		}
	}

	if asName == "" {
		asName = fmt.Sprintf("AS%d", asn)
	}

	e.asNameLock.Lock()
	e.asNameCache[asn] = asName
	e.asNameLock.Unlock()

	return asName
}
