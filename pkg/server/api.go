package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alexandrmotologa/dnswatch/pkg/audit"
	"github.com/alexandrmotologa/dnswatch/pkg/benchmark"
	"github.com/alexandrmotologa/dnswatch/pkg/diff"
	"github.com/alexandrmotologa/dnswatch/pkg/dnssec"
	"github.com/alexandrmotologa/dnswatch/pkg/propagation"
	"github.com/alexandrmotologa/dnswatch/pkg/trace"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/miekg/dns"
)

// Server coordinates the HTTP REST API and static asset delivery.
type Server struct {
	router      *chi.Mux
	walker      *trace.Walker
	propRunner  *propagation.Runner
	dnssecVal   *dnssec.Validator
	auditor     *audit.Auditor
	differ      *diff.Differ
	benchmarker *benchmark.Benchmarker
}

// NewServer creates a new API server instance.
func NewServer() *Server {
	s := &Server{
		router:      chi.NewRouter(),
		walker:      trace.NewWalker(trace.DefaultWalkerConfig()),
		propRunner:  propagation.NewRunner(propagation.DefaultRunnerConfig(), nil),
		dnssecVal:   dnssec.NewValidator(4 * time.Second),
		auditor:     audit.NewAuditor(4 * time.Second),
		differ:      diff.NewDiffer(4 * time.Second),
		benchmarker: benchmark.NewBenchmarker(3*time.Second, nil),
	}

	s.setupRoutes()
	return s
}

// Router returns the underlying Chi mux.
func (s *Server) Router() *chi.Mux {
	return s.router
}

func (s *Server) setupRoutes() {
	r := s.router

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// CORS configuration
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	r.Route("/api", func(r chi.Router) {
		r.Get("/health", s.handleHealth)
		r.Get("/trace", s.handleTrace)
		r.Get("/propagate", s.handlePropagate)
		r.Get("/dnssec", s.handleDNSSEC)
		r.Get("/audit", s.handleAudit)
		r.Get("/summary", s.handleSummary)
		r.Get("/diff", s.handleDiff)
		r.Get("/bench", s.handleBench)
	})
}

func parseQType(qtypeStr string) uint16 {
	qtypeStr = strings.ToUpper(strings.TrimSpace(qtypeStr))
	if qtypeStr == "" {
		return dns.TypeA
	}
	if t, ok := dns.StringToType[qtypeStr]; ok {
		return t
	}
	return dns.TypeA
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "healthy",
		"service": "dnswatch",
		"time":    time.Now().UTC(),
	})
}

func (s *Server) handleTrace(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "missing domain query parameter", http.StatusBadRequest)
		return
	}
	qtype := parseQType(r.URL.Query().Get("type"))

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	res, err := s.walker.Trace(ctx, domain, qtype)
	if err != nil && res == nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handlePropagate(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "missing domain query parameter", http.StatusBadRequest)
		return
	}
	qtype := parseQType(r.URL.Query().Get("type"))

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	res, err := s.propRunner.Check(ctx, domain, qtype)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDNSSEC(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "missing domain query parameter", http.StatusBadRequest)
		return
	}
	qtype := parseQType(r.URL.Query().Get("type"))

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	res, err := s.dnssecVal.ValidateDomain(ctx, domain, qtype)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "missing domain query parameter", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	res, err := s.auditor.Run(ctx, domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, res)
}

// SummaryResult encapsulates full diagnostics in one response.
type SummaryResult struct {
	Domain      string                          `json:"domain"`
	QueryType   string                          `json:"query_type"`
	Trace       *trace.TraceResult              `json:"trace"`
	Propagation *propagation.PropagationSummary `json:"propagation"`
	DNSSEC      *dnssec.ValidationResult        `json:"dnssec"`
	Audit       *audit.AuditReport              `json:"audit"`
	Duration    time.Duration                   `json:"duration"`
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "missing domain query parameter", http.StatusBadRequest)
		return
	}
	qtype := parseQType(r.URL.Query().Get("type"))

	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	summary := &SummaryResult{
		Domain:    domain,
		QueryType: dns.TypeToString[qtype],
	}

	var wg sync.WaitGroup
	wg.Add(4)

	go func() {
		defer wg.Done()
		res, _ := s.walker.Trace(ctx, domain, qtype)
		summary.Trace = res
	}()

	go func() {
		defer wg.Done()
		res, _ := s.propRunner.Check(ctx, domain, qtype)
		summary.Propagation = res
	}()

	go func() {
		defer wg.Done()
		res, _ := s.dnssecVal.ValidateDomain(ctx, domain, qtype)
		summary.DNSSEC = res
	}()

	go func() {
		defer wg.Done()
		res, _ := s.auditor.Run(ctx, domain)
		summary.Audit = res
	}()

	wg.Wait()
	summary.Duration = time.Since(start)

	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	domain1 := r.URL.Query().Get("domain1")
	domain2 := r.URL.Query().Get("domain2")
	ns1 := r.URL.Query().Get("ns1")
	ns2 := r.URL.Query().Get("ns2")

	if domain1 != "" && domain2 != "" {
		res, err := s.differ.CompareDomains(ctx, domain1, domain2, "1.1.1.1:53")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain != "" && ns1 != "" && ns2 != "" {
		res, err := s.differ.CompareServers(ctx, domain, ns1, ns2)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	http.Error(w, "provide either (domain1 and domain2) or (domain, ns1 and ns2)", http.StatusBadRequest)
}

func (s *Server) handleBench(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "missing domain parameter", http.StatusBadRequest)
		return
	}
	qtype := parseQType(r.URL.Query().Get("type"))
	rounds := 3
	if rStr := r.URL.Query().Get("rounds"); rStr != "" {
		if val, err := strconv.Atoi(rStr); err == nil && val > 0 && val <= 10 {
			rounds = val
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()

	report, err := s.benchmarker.Run(ctx, domain, qtype, rounds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, report)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

