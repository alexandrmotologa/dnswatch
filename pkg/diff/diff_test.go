package diff

import (
	"context"
	"testing"
	"time"
)

func TestCompareIdenticalServers(t *testing.T) {
	differ := NewDiffer(4 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// Compare cloudflare.com between Cloudflare DNS and Google DNS
	report, err := differ.CompareServers(ctx, "cloudflare.com", "1.1.1.1:53", "8.8.8.8:53")
	if err != nil {
		t.Skipf("skipping live test due to network: %v", err)
		return
	}

	t.Logf("Comparison Parity: %.1f%% (%d/%d matches)", report.ParityRate, report.MatchCount, report.TotalTypes)
	for _, d := range report.Diffs {
		t.Logf("  [%s] Identical=%v | Target1: %v | Target2: %v", d.Type, d.Identical, d.Target1, d.Target2)
	}

	if report.TotalTypes != len(compareTypes) {
		t.Errorf("expected %d compared types, got %d", len(compareTypes), report.TotalTypes)
	}
}

func TestDifferenceLogic(t *testing.T) {
	a := []string{"1.1.1.1", "1.0.0.1"}
	b := []string{"1.1.1.1", "8.8.8.8"}

	onlyA := difference(a, b)
	onlyB := difference(b, a)

	if len(onlyA) != 1 || onlyA[0] != "1.0.0.1" {
		t.Errorf("expected onlyA=[1.0.0.1], got %v", onlyA)
	}
	if len(onlyB) != 1 || onlyB[0] != "8.8.8.8" {
		t.Errorf("expected onlyB=[8.8.8.8], got %v", onlyB)
	}
}
