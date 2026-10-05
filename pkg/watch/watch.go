package watch

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/alexandrmotologa/dnswatch/pkg/resolver"
	"github.com/alexandrmotologa/dnswatch/pkg/trace"
	"github.com/miekg/dns"
)

// ChangeEvent records a detected mutation in DNS records.
type ChangeEvent struct {
	Timestamp   time.Time          `json:"timestamp"`
	Previous    []string           `json:"previous"`
	Current     []string           `json:"current"`
	Added       []string           `json:"added"`
	Removed     []string           `json:"removed"`
	TTL         uint32             `json:"ttl"`
	Records     []trace.RecordInfo `json:"records"`
}

// WatchConfig configures the live DNS observer.
type WatchConfig struct {
	Domain   string
	QType    uint16
	Interval time.Duration
	Server   string
}

// DefaultWatchConfig returns standard monitoring options.
func DefaultWatchConfig(domain string, qtype uint16) WatchConfig {
	return WatchConfig{
		Domain:   domain,
		QType:    qtype,
		Interval: 3 * time.Second,
		Server:   "1.1.1.1:53",
	}
}

// Watcher monitors DNS changes in real time.
type Watcher struct {
	cfg     WatchConfig
	client  *resolver.Client
	history []ChangeEvent
	lastSet []string
}

// NewWatcher creates a DNS change observer.
func NewWatcher(cfg WatchConfig) *Watcher {
	opts := resolver.DefaultOptions()
	opts.Timeout = 2 * time.Second
	opts.RecursionDesired = true

	return &Watcher{
		cfg:     cfg,
		client:  resolver.NewClient(opts),
		history: make([]ChangeEvent, 0),
	}
}

// Poll executes one DNS check and returns a ChangeEvent if data changed, or nil.
func (w *Watcher) Poll(ctx context.Context) (*ChangeEvent, []trace.RecordInfo, error) {
	domain := dns.Fqdn(strings.TrimSpace(w.cfg.Domain))
	resp, err := w.client.Exchange(ctx, w.cfg.Server, domain, w.cfg.QType, nil)
	if err != nil || resp == nil || resp.Msg == nil {
		return nil, nil, fmt.Errorf("poll failed: %w", err)
	}

	var currentStrings []string
	var records []trace.RecordInfo
	var minTTL uint32 = 0

	for _, rr := range resp.Msg.Answer {
		if rr.Header().Rrtype == w.cfg.QType {
			parsed := trace.ParseRR(rr)
			records = append(records, parsed)
			currentStrings = append(currentStrings, parsed.Data)
			if minTTL == 0 || rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
	}

	sort.Strings(currentStrings)

	// First run: initialize lastSet
	if w.lastSet == nil {
		w.lastSet = currentStrings
		return nil, records, nil
	}

	// Check if set differs
	if !slicesEqual(w.lastSet, currentStrings) {
		added := difference(currentStrings, w.lastSet)
		removed := difference(w.lastSet, currentStrings)

		event := ChangeEvent{
			Timestamp: time.Now(),
			Previous:  w.lastSet,
			Current:   currentStrings,
			Added:     added,
			Removed:   removed,
			TTL:       minTTL,
			Records:   records,
		}

		w.history = append(w.history, event)
		w.lastSet = currentStrings
		return &event, records, nil
	}

	return nil, records, nil
}

// History returns all recorded change events.
func (w *Watcher) History() []ChangeEvent {
	return w.history
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
