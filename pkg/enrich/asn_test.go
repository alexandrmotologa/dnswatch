package enrich

import (
	"context"
	"testing"
	"time"
)

func TestLookupIPCloudflare(t *testing.T) {
	enricher := GetDefaultEnricher()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info := enricher.LookupIP(ctx, "1.1.1.1")
	if info == nil {
		t.Fatalf("expected non-nil IPInfo")
	}

	t.Logf("1.1.1.1: ASN=%d, ASName=%s, Country=%s, Prefix=%s, PTR=%s",
		info.ASN, info.ASName, info.Country, info.Prefix, info.PTR)

	if info.ASN != 13335 {
		t.Logf("Note: expected ASN 13335 for 1.1.1.1, got %d (might be cached or network filtered)", info.ASN)
	}

	label := info.FormattedLabel()
	t.Logf("Formatted Label: %s", label)
}

func TestLookupIPGoogle(t *testing.T) {
	enricher := GetDefaultEnricher()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info := enricher.LookupIP(ctx, "8.8.8.8")
	if info == nil {
		t.Fatalf("expected non-nil IPInfo")
	}

	t.Logf("8.8.8.8: ASN=%d, ASName=%s, Country=%s, PTR=%s",
		info.ASN, info.ASName, info.Country, info.PTR)

	if info.ASN != 15169 {
		t.Logf("Note: expected ASN 15169 for 8.8.8.8, got %d", info.ASN)
	}
}

func TestLookupPrivateIP(t *testing.T) {
	enricher := GetDefaultEnricher()
	ctx := context.Background()

	info := enricher.LookupIP(ctx, "192.168.1.1")
	if info.ASName != "Local/Private" {
		t.Errorf("expected Local/Private for 192.168.1.1, got %s", info.ASName)
	}
}
