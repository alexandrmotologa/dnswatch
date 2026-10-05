package dnssec

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// AlgorithmToString returns a human-readable name for a DNSSEC algorithm number.
func AlgorithmToString(alg uint8) string {
	switch alg {
	case dns.RSAMD5:
		return "RSAMD5 (Insecure)"
	case dns.DH:
		return "Diffie-Hellman"
	case dns.DSA:
		return "DSA/SHA1 (Deprecated)"
	case dns.RSASHA1:
		return "RSA/SHA1 (Deprecated)"
	case dns.DSANSEC3SHA1:
		return "DSA-NSEC3-SHA1 (Deprecated)"
	case dns.RSASHA1NSEC3SHA1:
		return "RSASHA1-NSEC3-SHA1 (Deprecated)"
	case dns.RSASHA256:
		return "RSA/SHA256"
	case dns.RSASHA512:
		return "RSA/SHA512"
	case dns.ECCGOST:
		return "GOST R 34.10-2001"
	case dns.ECDSAP256SHA256:
		return "ECDSA P-256 with SHA-256"
	case dns.ECDSAP384SHA384:
		return "ECDSA P-384 with SHA-384"
	case dns.ED25519:
		return "Ed25519"
	case dns.ED448:
		return "Ed448"
	default:
		return fmt.Sprintf("Algorithm-%d", alg)
	}
}

// DigestTypeToString returns the digest name for a DS record.
func DigestTypeToString(dt uint8) string {
	switch dt {
	case dns.SHA1:
		return "SHA-1 (Legacy)"
	case dns.SHA256:
		return "SHA-256"
	case dns.GOST94:
		return "GOST R 34.11-94"
	case dns.SHA384:
		return "SHA-384"
	default:
		return fmt.Sprintf("DigestType-%d", dt)
	}
}

// VerifyDSMatchesDNSKEY checks if any of the given DS records match any KSK DNSKEY.
func VerifyDSMatchesDNSKEY(dsRecords []*dns.DS, keys []*dns.DNSKEY) (matched bool, matchedTag uint16, warnings []string, err error) {
	if len(dsRecords) == 0 {
		return false, 0, nil, fmt.Errorf("no DS records provided")
	}
	if len(keys) == 0 {
		return false, 0, nil, fmt.Errorf("no DNSKEY records provided")
	}

	for _, dsRec := range dsRecords {
		if dsRec.DigestType == dns.SHA1 {
			warnings = append(warnings, fmt.Sprintf("DS record tag %d uses deprecated SHA-1 digest", dsRec.KeyTag))
		}
		for _, key := range keys {
			// Check if key is a Key Signing Key (flag 257) or zone key with matching tag
			if key.KeyTag() != dsRec.KeyTag {
				continue
			}

			computedDS := key.ToDS(dsRec.DigestType)
			if computedDS == nil {
				continue
			}

			if strings.EqualFold(computedDS.Digest, dsRec.Digest) {
				return true, dsRec.KeyTag, warnings, nil
			}
		}
	}

	return false, 0, warnings, fmt.Errorf("no DS record digest matched available DNSKEYs")
}
