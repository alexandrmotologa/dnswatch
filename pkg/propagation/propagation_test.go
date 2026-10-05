package propagation

import (
	"context"
	"testing"
	"time"

	"github.com/alexandrmotologa/dnswatch/pkg/trace"
	"github.com/miekg/dns"
)

func TestCalculateConsensus(t *testing.T) {
	node1 := &NodeResult{
		Provider: Provider{ID: "p1", Name: "P1"},
		RTT:      20 * time.Millisecond,
		Answers: []trace.RecordInfo{
			{Type: "A", Data: "1.1.1.1"},
		},
	}
	node2 := &NodeResult{
		Provider: Provider{ID: "p2", Name: "P2"},
		RTT:      30 * time.Millisecond,
		Answers: []trace.RecordInfo{
			{Type: "A", Data: "1.1.1.1"},
		},
	}
	node3 := &NodeResult{
		Provider: Provider{ID: "p3", Name: "P3"},
		RTT:      40 * time.Millisecond,
		Answers: []trace.RecordInfo{
			{Type: "A", Data: "1.0.0.1"}, // Different IP (split)
		},
	}
	node4 := &NodeResult{
		Provider: Provider{ID: "p4", Name: "P4"},
		Error:    "timeout",
	}

	results := []*NodeResult{node1, node2, node3, node4}
	summary := CalculateConsensus("example.com", dns.TypeA, results, 50*time.Millisecond)

	if summary.TotalTested != 4 {
		t.Errorf("expected 4 total tested, got %d", summary.TotalTested)
	}
	if summary.SuccessCount != 3 {
		t.Errorf("expected 3 success count, got %d", summary.SuccessCount)
	}
	if summary.FailedCount != 1 {
		t.Errorf("expected 1 failed count, got %d", summary.FailedCount)
	}

	// 2 out of 3 successful matched 1.1.1.1 -> 66.66%
	expectedRate := (2.0 / 3.0) * 100.0
	diff := summary.PropagationRate - expectedRate
	if diff < -0.1 || diff > 0.1 {
		t.Errorf("expected propagation rate ~%.2f, got %.2f", expectedRate, summary.PropagationRate)
	}

	if !node1.MatchedConsensus || !node2.MatchedConsensus {
		t.Errorf("expected node1 and node2 to match consensus")
	}
	if node3.MatchedConsensus {
		t.Errorf("expected node3 not to match consensus")
	}
}

func TestPropagationRunnerLive(t *testing.T) {
	// Test with subset of reliable public providers
	providers := []Provider{
		{ID: "cloudflare", Name: "Cloudflare", URL: "https://cloudflare-dns.com/dns-query"},
		{ID: "google", Name: "Google", URL: "https://dns.google/dns-query"},
		{ID: "quad9", Name: "Quad9", URL: "https://dns.quad9.net/dns-query"},
	}

	runner := NewRunner(DefaultRunnerConfig(), providers)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	summary, err := runner.Check(ctx, "one.one.one.one", dns.TypeA)
	if err != nil {
		t.Skipf("skipping live test due to network: %v", err)
		return
	}

	if summary.SuccessCount == 0 {
		t.Skipf("network did not return results from public providers")
		return
	}

	t.Logf("Checked %d providers in %v, success: %d, consensus rate: %.1f%%",
		summary.TotalTested, summary.TotalDuration, summary.SuccessCount, summary.PropagationRate)

	for _, r := range summary.Results {
		if r.Error == "" {
			t.Logf("[%s] RTT: %v, Answers: %v", r.Provider.Name, r.RTT, r.Answers)
		} else {
			t.Logf("[%s] Error: %s", r.Provider.Name, r.Error)
		}
	}
}
