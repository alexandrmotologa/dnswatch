package dnssec

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// SignatureInfo details an RRSIG record evaluation.
type SignatureInfo struct {
	SignerName string
	KeyTag     uint16
	Algorithm  uint8
	Inception  time.Time
	Expiration time.Time
	ValidTime  bool
	ValidSig   bool
	Error      string
}

// CheckSignatureValidity checks if the current time falls within the RRSIG validity period.
func CheckSignatureValidity(sig *dns.RRSIG, now time.Time) (valid bool, inception time.Time, expiration time.Time, err error) {
	if sig == nil {
		return false, time.Time{}, time.Time{}, fmt.Errorf("nil signature")
	}

	// dns.RRSIG stores inception and expiration as uint32 Unix epoch seconds
	inception = time.Unix(int64(sig.Inception), 0).UTC()
	expiration = time.Unix(int64(sig.Expiration), 0).UTC()

	nowUTC := now.UTC()
	if nowUTC.Before(inception) {
		return false, inception, expiration, fmt.Errorf("signature not yet active (inception: %s, now: %s)", inception.Format(time.RFC3339), nowUTC.Format(time.RFC3339))
	}
	if nowUTC.After(expiration) {
		return false, inception, expiration, fmt.Errorf("signature expired on %s (now: %s)", expiration.Format(time.RFC3339), nowUTC.Format(time.RFC3339))
	}

	return true, inception, expiration, nil
}

// VerifyRRSIG validates an RRSIG against an RRset using a corresponding DNSKEY.
func VerifyRRSIG(key *dns.DNSKEY, sig *dns.RRSIG, rrset []dns.RR) error {
	if key == nil {
		return fmt.Errorf("nil DNSKEY")
	}
	if sig == nil {
		return fmt.Errorf("nil RRSIG")
	}
	if len(rrset) == 0 {
		return fmt.Errorf("empty RRset for signature verification")
	}

	// Verify cryptographic signature using miekg/dns
	if err := sig.Verify(key, rrset); err != nil {
		return fmt.Errorf("cryptographic verification failed: %w", err)
	}

	return nil
}
