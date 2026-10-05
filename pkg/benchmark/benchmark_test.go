package benchmark

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestBenchmarkerLive(t *testing.T) {
	// Benchmark top 3 resolvers with 2 rounds
	resolvers := []TargetResolver{
		{Name: "Cloudflare", Server: "1.1.1.1:53"},
		{Name: "Google", Server: "8.8.8.8:53"},
		{Name: "Quad9", Server: "9.9.9.9:53"},
	}

	bm := NewBenchmarker(3*time.Second, resolvers)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	report, err := bm.Run(ctx, "cloudflare.com", dns.TypeA, 2)
	if err != nil {
		t.Skipf("skipping live benchmark test due to network: %v", err)
		return
	}

	t.Logf("Benchmark complete in %v. Fastest: %s", report.TotalTime, report.Fastest)
	for _, r := range report.Resolvers {
		t.Logf("  #%d %-15s Avg: %-8v Min: %-8v Max: %-8v Jitter: %-8v Success: %.0f%%",
			r.Rank, r.Name, r.AvgRTT.Round(time.Millisecond), r.MinRTT.Round(time.Millisecond),
			r.MaxRTT.Round(time.Millisecond), r.Jitter.Round(time.Millisecond), r.SuccessRate)
	}

	if len(report.Resolvers) != 3 {
		t.Errorf("expected 3 resolvers tested, got %d", len(report.Resolvers))
	}
}
