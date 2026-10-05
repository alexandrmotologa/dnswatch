package dnssec

import (
	"time"
)

// TrustStatus represents the cryptographic state of a zone or record.
type TrustStatus string

const (
	StatusSecure        TrustStatus = "SECURE"        // Valid cryptographic chain of trust
	StatusInsecure      TrustStatus = "INSECURE"      // Zone has no DNSSEC (unsigned)
	StatusBogus         TrustStatus = "BOGUS"         // Signatures present but invalid or expired
	StatusIndeterminate TrustStatus = "INDETERMINATE" // Cannot verify due to network or server issues
)

// ChainNode represents a link in the DNSSEC chain of trust (Root, TLD, Domain).
type ChainNode struct {
	Zone            string      `json:"zone"`
	Status          TrustStatus `json:"status"`
	HasDS           bool        `json:"has_ds"`
	DSKeyTags       []uint16    `json:"ds_key_tags"`
	DSDigests       []string    `json:"ds_digests"`
	HasDNSKEY       bool        `json:"has_dnskey"`
	KSKKeyTags      []uint16    `json:"ksk_key_tags"`
	ZSKKeyTags      []uint16    `json:"zsk_key_tags"`
	Algorithms      []string    `json:"algorithms"`
	HasRRSIG        bool        `json:"has_rrsig"`
	Inception       *time.Time  `json:"inception,omitempty"`
	Expiration      *time.Time  `json:"expiration,omitempty"`
	IsExpired       bool        `json:"is_expired"`
	DigestMatched   bool        `json:"digest_matched"`
	SignaturesValid bool        `json:"signatures_valid"`
	Errors          []string    `json:"errors"`
	Warnings        []string    `json:"warnings"`
}

// ValidationResult summarizes the full chain of trust validation.
type ValidationResult struct {
	Domain        string       `json:"domain"`
	QueryType     string       `json:"query_type"`
	OverallStatus TrustStatus  `json:"overall_status"`
	Chain         []*ChainNode `json:"chain"`
	Errors        []string     `json:"errors"`
	Warnings      []string     `json:"warnings"`
	CheckedAt     time.Time    `json:"checked_at"`
}
