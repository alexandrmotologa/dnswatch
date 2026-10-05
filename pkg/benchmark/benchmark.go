package benchmark

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alexandrmotologa/dnswatch/pkg/resolver"
	"github.com/miekg/dns"
)

// TargetResolver holds configuration for a benchmark target resolver.
type TargetResolver struct {
	Name   string
	Server string
}

// DefaultBenchmarkResolvers includes 10 popular global resolvers.
var DefaultBenchmarkResolvers = []TargetResolver{
	{Name: "Cloudflare", Server: "1.1.1.1:53"},
	{Name: "Google", Server: "8.8.8.8:53"},
	{Name: "Quad9", Server: "9.9.9.9:53"},
	{Name: "OpenDNS / Cisco", Server: "208.67.222.222:53"},
	{Name: "AdGuard", Server: "94.140.14.14:53"},
	{Name: "NextDNS", Server: "45.90.28.0:53"},
	{Name: "Control D", Server: "76.76.2.0:53"},
	{Name: "CleanBrowsing", Server: "185.228.168.9:53"},
	{Name: "Level 3 / Lumen", Server: "4.2.2.1:53"},
	{Name: "Mullvad", Server: "194.242.2.2:53"},
}

// ResolverStats encapsulates performance metrics for a specific resolver.
type ResolverStats struct {
	Name        string        `json:"name"`
	Server      string        `json:"server"`
	Rank        int           `json:"rank"`
	MinRTT      time.Duration `json:"min_rtt"`
	AvgRTT      time.Duration `json:"avg_rtt"`
	MaxRTT      time.Duration `json:"max_rtt"`
	Jitter      time.Duration `json:"jitter"`
	SuccessRate float64       `json:"success_rate"`
	Rounds      int           `json:"rounds"`
	Failed      int           `json:"failed"`
	Answers     []string      `json:"answers"`
}

// BenchmarkReport details results of a multi-resolver speed test.
type BenchmarkReport struct {
	Domain    string          `json:"domain"`
	QueryType string          `json:"query_type"`
	Rounds    int             `json:"rounds"`
	Fastest   string          `json:"fastest"`
	Resolvers []ResolverStats `json:"resolvers"`
	TotalTime time.Duration   `json:"total_time"`
}

// Benchmarker executes multi-round latency benchmarks against resolvers.
type Benchmarker struct {
	client    *resolver.Client
	resolvers []TargetResolver
}

// NewBenchmarker creates a benchmark coordinator.
func NewBenchmarker(timeout time.Duration, resolvers []TargetResolver) *Benchmarker {
	if timeout <= 0 {
		timeout = 2500 * time.Millisecond
	}
	if len(resolvers) == 0 {
		resolvers = DefaultBenchmarkResolvers
	}
	opts := resolver.DefaultOptions()
	opts.Timeout = timeout
	opts.RecursionDesired = true

	return &Benchmarker{
		client:    resolver.NewClient(opts),
		resolvers: resolvers,
	}
}

// Run executes the benchmark suite for a given domain and query type over N rounds.
func (b *Benchmarker) Run(ctx context.Context, domain string, qtype uint16, rounds int) (*BenchmarkReport, error) {
	if rounds <= 0 {
		rounds = 3
	}
	startTotal := time.Now()
	domain = strings.TrimSpace(domain)

	statsList := make([]ResolverStats, len(b.resolvers))
	var wg sync.WaitGroup

	for i, r := range b.resolvers {
		wg.Add(1)
		go func(idx int, target TargetResolver) {
			defer wg.Done()

			var rtts []time.Duration
			var failed int
			var answersMap = make(map[string]bool)

			for round := 0; round < rounds; round++ {
				select {
				case <-ctx.Done():
					return
				default:
				}

				resp, err := b.client.Exchange(ctx, target.Server, domain, qtype, nil)
				if err != nil || resp == nil || resp.Msg == nil {
					failed++
					continue
				}

				rtts = append(rtts, resp.RTT)
				for _, rr := range resp.Msg.Answer {
					if rr.Header().Rrtype == qtype {
						answersMap[rr.String()] = true
					}
				}

				// Small backoff between rounds
				time.Sleep(20 * time.Millisecond)
			}

			stat := ResolverStats{
				Name:    target.Name,
				Server:  target.Server,
				Rounds:  rounds,
				Failed:  failed,
				Answers: make([]string, 0, len(answersMap)),
			}

			for ans := range answersMap {
				stat.Answers = append(stat.Answers, ans)
			}
			sort.Strings(stat.Answers)

			if len(rtts) > 0 {
				stat.SuccessRate = (float64(len(rtts)) / float64(rounds)) * 100.0

				var sum time.Duration
				minR := rtts[0]
				maxR := rtts[0]

				for _, rtt := range rtts {
					sum += rtt
					if rtt < minR {
						minR = rtt
					}
					if rtt > maxR {
						maxR = rtt
					}
				}

				avg := sum / time.Duration(len(rtts))
				stat.MinRTT = minR
				stat.AvgRTT = avg
				stat.MaxRTT = maxR

				// Calculate Jitter (standard deviation)
				var sumSqDiff float64
				for _, rtt := range rtts {
					diff := float64(rtt - avg)
					sumSqDiff += diff * diff
				}
				variance := sumSqDiff / float64(len(rtts))
				stat.Jitter = time.Duration(math.Sqrt(variance))
			} else {
				stat.SuccessRate = 0.0
			}

			statsList[idx] = stat
		}(i, r)
	}

	wg.Wait()

	// Sort resolvers by AvgRTT (successful ones first)
	sort.Slice(statsList, func(i, j int) bool {
		if statsList[i].SuccessRate == 0 && statsList[j].SuccessRate > 0 {
			return false
		}
		if statsList[i].SuccessRate > 0 && statsList[j].SuccessRate == 0 {
			return true
		}
		return statsList[i].AvgRTT < statsList[j].AvgRTT
	})

	for i := range statsList {
		statsList[i].Rank = i + 1
	}

	fastestName := "None"
	if len(statsList) > 0 && statsList[0].SuccessRate > 0 {
		fastestName = fmt.Sprintf("%s (%v)", statsList[0].Name, statsList[0].AvgRTT.Round(time.Millisecond))
	}

	return &BenchmarkReport{
		Domain:    domain,
		QueryType: dns.TypeToString[qtype],
		Rounds:    rounds,
		Fastest:   fastestName,
		Resolvers: statsList,
		TotalTime: time.Since(startTotal),
	}, nil
}
