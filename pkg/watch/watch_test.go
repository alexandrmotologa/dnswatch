package watch

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestWatcherInitialPoll(t *testing.T) {
	cfg := DefaultWatchConfig("cloudflare.com", dns.TypeA)
	cfg.Interval = 1 * time.Second
	watcher := NewWatcher(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	event, records, err := watcher.Poll(ctx)
	if err != nil {
		t.Fatalf("unexpected error on initial poll: %v", err)
	}

	if event != nil {
		t.Errorf("expected nil ChangeEvent on initial poll, got %v", event)
	}

	if len(records) == 0 {
		t.Errorf("expected records returned for cloudflare.com")
	}

	// Second poll immediately should have no change
	event2, _, err := watcher.Poll(ctx)
	if err != nil {
		t.Fatalf("unexpected error on second poll: %v", err)
	}
	if event2 != nil {
		t.Errorf("expected no change on consecutive poll, got %v", event2)
	}
}

func TestSlicesEqualAndDifference(t *testing.T) {
	a := []string{"1.1.1.1", "1.0.0.1"}
	b := []string{"1.1.1.1", "1.0.0.1"}
	c := []string{"1.1.1.1", "1.0.0.2"}

	if !slicesEqual(a, b) {
		t.Errorf("expected slices equal")
	}
	if slicesEqual(a, c) {
		t.Errorf("expected slices not equal")
	}

	added := difference(c, a)
	if len(added) != 1 || added[0] != "1.0.0.2" {
		t.Errorf("expected [1.0.0.2], got %v", added)
	}

	removed := difference(a, c)
	if len(removed) != 1 || removed[0] != "1.0.0.1" {
		t.Errorf("expected [1.0.0.1], got %v", removed)
	}
}
