package resolver

import (
	"time"

	"github.com/miekg/dns"
)

// QueryOptions defines resolution parameters for DNS exchanges.
type QueryOptions struct {
	Timeout          time.Duration
	RecursionDesired bool
	DNSSECOk         bool
	EDNS0BufSize     uint16
}

// DefaultOptions returns standard resolver options.
func DefaultOptions() QueryOptions {
	return QueryOptions{
		Timeout:          3 * time.Second,
		RecursionDesired: true,
		DNSSECOk:         true,
		EDNS0BufSize:     1232, // RFC 8900 recommended safe buffer size
	}
}

// TraceOptions returns options configured for iterative delegation walking.
func TraceOptions() QueryOptions {
	return QueryOptions{
		Timeout:          3 * time.Second,
		RecursionDesired: false, // Iterative trace disables RD flag
		DNSSECOk:         true,
		EDNS0BufSize:     1232,
	}
}

// Response encapsulates a DNS message with execution metadata.
type Response struct {
	Msg       *dns.Msg
	RTT       time.Duration
	Server    string
	Protocol  string
	Truncated bool
}

// HeaderFlags summarizes key DNS header flags.
type HeaderFlags struct {
	QR bool `json:"qr"` // Query (false) or Response (true)
	AA bool `json:"aa"` // Authoritative Answer
	TC bool `json:"tc"` // Truncated
	RD bool `json:"rd"` // Recursion Desired
	RA bool `json:"ra"` // Recursion Available
	AD bool `json:"ad"` // Authentic Data (DNSSEC)
	CD bool `json:"cd"` // Checking Disabled
}

// ExtractFlags returns flag booleans from a DNS message.
func ExtractFlags(msg *dns.Msg) HeaderFlags {
	if msg == nil {
		return HeaderFlags{}
	}
	return HeaderFlags{
		QR: msg.Response,
		AA: msg.Authoritative,
		TC: msg.Truncated,
		RD: msg.RecursionDesired,
		RA: msg.RecursionAvailable,
		AD: msg.AuthenticatedData,
		CD: msg.CheckingDisabled,
	}
}
