package propagation

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/alexandrmotologa/dnswatch/pkg/trace"
	"github.com/miekg/dns"
)

// NodeResult captures response data from a single edge vantage point.
type NodeResult struct {
	Provider         Provider           `json:"provider"`
	RTT              time.Duration      `json:"rtt"`
	Answers          []trace.RecordInfo `json:"answers"`
	MatchedConsensus bool               `json:"matched_consensus"`
	Rcode            int                `json:"rcode"`
	RcodeStr         string             `json:"rcode_str"`
	Error            string             `json:"error,omitempty"`
	TTL              uint32             `json:"ttl"`
}

// PropagationSummary aggregates global probe results into consensus metrics.
type PropagationSummary struct {
	Domain           string        `json:"domain"`
	QueryType        string        `json:"query_type"`
	ConsensusAnswers []string      `json:"consensus_answers"`
	PropagationRate  float64       `json:"propagation_rate"` // 0.0 - 100.0%
	TotalTested      int           `json:"total_tested"`
	SuccessCount     int           `json:"success_count"`
	FailedCount      int           `json:"failed_count"`
	MinRTT           time.Duration `json:"min_rtt"`
	MaxRTT           time.Duration `json:"max_rtt"`
	AvgRTT           time.Duration `json:"avg_rtt"`
	TotalDuration    time.Duration `json:"total_duration"`
	Results          []*NodeResult `json:"results"`
}

// signature generates a deterministic key representing a set of DNS answer records.
func answerSignature(answers []trace.RecordInfo) string {
	if len(answers) == 0 {
		return "<empty>"
	}
	parts := make([]string, 0, len(answers))
	for _, a := range answers {
		parts = append(parts, fmt.Sprintf("%s:%s", a.Type, strings.TrimSpace(a.Data)))
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

// CalculateConsensus analyzes edge results and computes agreement metrics.
func CalculateConsensus(domain string, qtype uint16, results []*NodeResult, totalDuration time.Duration) *PropagationSummary {
	qtypeStr := dns.TypeToString[qtype]
	if qtypeStr == "" {
		qtypeStr = fmt.Sprintf("TYPE%d", qtype)
	}

	summary := &PropagationSummary{
		Domain:           domain,
		QueryType:        qtypeStr,
		TotalTested:      len(results),
		Results:          results,
		TotalDuration:    totalDuration,
		ConsensusAnswers: make([]string, 0),
	}

	if len(results) == 0 {
		return summary
	}

	var minRTT, maxRTT, sumRTT time.Duration
	var successCount int
	signatureCounts := make(map[string]int)
	signatureToAnswers := make(map[string][]string)

	first := true
	for _, res := range results {
		if res.Error != "" {
			continue
		}
		successCount++
		if first || res.RTT < minRTT {
			minRTT = res.RTT
		}
		if res.RTT > maxRTT {
			maxRTT = res.RTT
		}
		sumRTT += res.RTT
		first = false

		sig := answerSignature(res.Answers)
		signatureCounts[sig]++

		if _, exists := signatureToAnswers[sig]; !exists {
			ansStrs := make([]string, 0, len(res.Answers))
			for _, a := range res.Answers {
				ansStrs = append(ansStrs, a.Data)
			}
			signatureToAnswers[sig] = ansStrs
		}
	}

	summary.SuccessCount = successCount
	summary.FailedCount = len(results) - successCount
	summary.MinRTT = minRTT
	summary.MaxRTT = maxRTT
	if successCount > 0 {
		summary.AvgRTT = sumRTT / time.Duration(successCount)
	}

	// Determine dominant signature (consensus)
	var dominantSig string
	var maxCount int
	for sig, count := range signatureCounts {
		if count > maxCount {
			maxCount = count
			dominantSig = sig
		}
	}

	if dominantSig != "" {
		summary.ConsensusAnswers = signatureToAnswers[dominantSig]
	}

	// Calculate consensus percentage against successful queries
	if successCount > 0 {
		summary.PropagationRate = (float64(maxCount) / float64(successCount)) * 100.0
	}

	// Mark matched consensus on individual nodes
	for _, res := range results {
		if res.Error == "" && answerSignature(res.Answers) == dominantSig {
			res.MatchedConsensus = true
		} else {
			res.MatchedConsensus = false
		}
	}

	return summary
}
