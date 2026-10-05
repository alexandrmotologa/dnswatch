package propagation

import (
	"context"
	"sync"
	"time"

	"github.com/alexandrmotologa/dnswatch/pkg/resolver"
	"github.com/alexandrmotologa/dnswatch/pkg/trace"
	"github.com/miekg/dns"
)

// RunnerConfig sets execution parameters for propagation checks.
type RunnerConfig struct {
	Timeout     time.Duration
	Concurrency int
}

// DefaultRunnerConfig returns balanced defaults.
func DefaultRunnerConfig() RunnerConfig {
	return RunnerConfig{
		Timeout:     3500 * time.Millisecond,
		Concurrency: 20,
	}
}

// Runner dispatches parallel DoH queries worldwide.
type Runner struct {
	cfg       RunnerConfig
	dohClient *resolver.DoHClient
	providers []Provider
}

// NewRunner creates a propagation runner with the given config and providers.
func NewRunner(cfg RunnerConfig, providers []Provider) *Runner {
	if len(providers) == 0 {
		providers = GetProviders()
	}
	return &Runner{
		cfg:       cfg,
		dohClient: resolver.NewDoHClient(cfg.Timeout),
		providers: providers,
	}
}

// Check queries all vantage points concurrently for the given domain and record type.
func (r *Runner) Check(ctx context.Context, domain string, qtype uint16) (*PropagationSummary, error) {
	start := time.Now()
	domain = dns.Fqdn(domain)

	results := make([]*NodeResult, len(r.providers))
	var wg sync.WaitGroup

	// Worker pool semaphore
	semaphore := make(chan struct{}, r.cfg.Concurrency)

	for i, p := range r.providers {
		wg.Add(1)
		go func(idx int, prov Provider) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			queryCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
			defer cancel()

			opts := resolver.DefaultOptions()
			opts.Timeout = r.cfg.Timeout

			resp, err := r.dohClient.Exchange(queryCtx, prov.URL, domain, qtype, opts)
			if err != nil {
				results[idx] = &NodeResult{
					Provider: prov,
					Error:    err.Error(),
				}
				return
			}

			// Parse answers and lowest TTL
			var parsedAnswers []trace.RecordInfo
			var minTTL uint32 = 0
			var hasTTL bool
			for _, rr := range resp.Msg.Answer {
				if rr.Header().Rrtype == qtype {
					parsedAnswers = append(parsedAnswers, trace.ParseRR(rr))
					if !hasTTL || rr.Header().Ttl < minTTL {
						minTTL = rr.Header().Ttl
						hasTTL = true
					}
				}
			}

			// If no direct matching qtype record was found but answer contains other records (like CNAME), include them
			if len(parsedAnswers) == 0 && len(resp.Msg.Answer) > 0 {
				for _, rr := range resp.Msg.Answer {
					parsedAnswers = append(parsedAnswers, trace.ParseRR(rr))
					if !hasTTL || rr.Header().Ttl < minTTL {
						minTTL = rr.Header().Ttl
						hasTTL = true
					}
				}
			}

			results[idx] = &NodeResult{
				Provider: prov,
				RTT:      resp.RTT,
				Answers:  parsedAnswers,
				Rcode:    resp.Msg.Rcode,
				RcodeStr: dns.RcodeToString[resp.Msg.Rcode],
				TTL:      minTTL,
			}
		}(i, p)
	}

	wg.Wait()
	summary := CalculateConsensus(domain, qtype, results, time.Since(start))
	return summary, nil
}
