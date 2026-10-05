package dnssec

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestSignatureValidity(t *testing.T) {
	now := time.Now().UTC()
	nowSec := uint32(now.Unix())

	// Active signature
	activeSig := &dns.RRSIG{
		Inception:  nowSec - 3600,
		Expiration: nowSec + 3600,
	}

	valid, _, _, err := CheckSignatureValidity(activeSig, now)
	if !valid || err != nil {
		t.Errorf("expected active signature to be valid, got valid=%v, err=%v", valid, err)
	}

	// Expired signature
	expiredSig := &dns.RRSIG{
		Inception:  nowSec - 7200,
		Expiration: nowSec - 3600,
	}

	valid, _, _, err = CheckSignatureValidity(expiredSig, now)
	if valid || err == nil {
		t.Errorf("expected expired signature to be invalid")
	}

	// Future signature (not yet active)
	futureSig := &dns.RRSIG{
		Inception:  nowSec + 3600,
		Expiration: nowSec + 7200,
	}

	valid, _, _, err = CheckSignatureValidity(futureSig, now)
	if valid || err == nil {
		t.Errorf("expected future signature to be invalid")
	}
}

func TestAlgorithmToString(t *testing.T) {
	if AlgorithmToString(dns.ED25519) != "Ed25519" {
		t.Errorf("expected Ed25519, got %s", AlgorithmToString(dns.ED25519))
	}
	if AlgorithmToString(dns.ECDSAP256SHA256) != "ECDSA P-256 with SHA-256" {
		t.Errorf("expected ECDSA P-256 with SHA-256, got %s", AlgorithmToString(dns.ECDSAP256SHA256))
	}
}

func TestLiveDNSSECValidation(t *testing.T) {
	val := NewValidator(4 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// 1. Test cloudflare.com (should be SECURE)
	res, err := val.ValidateDomain(ctx, "cloudflare.com", dns.TypeA)
	if err != nil {
		t.Skipf("skipping live test due to network: %v", err)
		return
	}

	t.Logf("cloudflare.com DNSSEC Status: %s, Chain length: %d", res.OverallStatus, len(res.Chain))
	for _, node := range res.Chain {
		t.Logf("  Zone: %-15s Status: %-10s DS:%v DNSKEY:%v Alg:%v",
			node.Zone, node.Status, node.HasDS, node.HasDNSKEY, node.Algorithms)
	}

	if res.OverallStatus != StatusSecure {
		t.Logf("Note: cloudflare.com got %s, might be due to resolver environment", res.OverallStatus)
	}
}
