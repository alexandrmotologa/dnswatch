package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alexandrmotologa/dnswatch/pkg/audit"
	"github.com/alexandrmotologa/dnswatch/pkg/dnssec"
	"github.com/alexandrmotologa/dnswatch/pkg/propagation"
	"github.com/alexandrmotologa/dnswatch/pkg/server"
	"github.com/alexandrmotologa/dnswatch/pkg/trace"
	"github.com/alexandrmotologa/dnswatch/pkg/tui"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var (
	version = "1.0.0"
	commit  = "main"
	date    = "2026-10-05"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "dnswatch [domain]",
	Short: "⚡ DNSWatch: Recursive DNS Tracing, DNSSEC Validation & Global Edge Propagation",
	Long: `DNSWatch is a modern DNS diagnostic studio combining recursive root traversal,
cryptographic DNSSEC verification, global DoH edge propagation testing, and
automated security audits into a single zero-dependency binary.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := "example.com"
		if len(args) > 0 {
			domain = args[0]
		}

		// Launch Bubble Tea interactive TUI
		m := tui.NewModel(domain)
		p := tea.NewProgram(m, tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			return fmt.Errorf("tui runtime error: %w", err)
		}
		return nil
	},
}

func parseRecordType(qtypeStr string) uint16 {
	qtypeStr = strings.ToUpper(strings.TrimSpace(qtypeStr))
	if qtypeStr == "" {
		return dns.TypeA
	}
	if t, ok := dns.StringToType[qtypeStr]; ok {
		return t
	}
	return dns.TypeA
}

// 1. Trace command
var (
	traceType string
	traceJSON bool
)

var traceCmd = &cobra.Command{
	Use:   "trace <domain>",
	Short: "Iteratively trace DNS delegation from IANA root hints to authoritative servers",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]
		qtype := parseRecordType(traceType)

		walker := trace.NewWalker(trace.DefaultWalkerConfig())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		res, err := walker.Trace(ctx, domain, qtype)
		if err != nil && res == nil {
			return err
		}

		if traceJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(res)
		}

		fmt.Printf("⚡ DNSWatch Recursive Trace: %s (Type: %s)\n", res.Domain, res.QueryType)
		fmt.Printf("Total Latency: %v | Hops: %d | Status: %v\n\n", res.TotalRTT, len(res.Hops), res.Success)

		for _, hop := range res.Hops {
			fmt.Printf("Hop %d [%s] ➔ %s (%s)  RTT: %v\n", hop.Step, hop.Zone, hop.ServerName, hop.ServerIP, hop.RTT)
			if len(hop.Delegation) > 0 {
				fmt.Printf("  Referral: %s\n", strings.Join(hop.Delegation, ", "))
			}
			if len(hop.Glue) > 0 {
				fmt.Printf("  Glue: %s\n", strings.Join(hop.Glue, ", "))
			}
			if hop.HasDNSSEC {
				fmt.Printf("  DNSSEC: %d RRSIGs present\n", hop.RRSIGCount)
			}
			if hop.Error != "" {
				fmt.Printf("  Error: %s\n", hop.Error)
			}
			fmt.Println()
		}

		if len(res.CNAMEChain) > 0 {
			fmt.Println("CNAME Redirection Chain:")
			for _, c := range res.CNAMEChain {
				fmt.Printf("  ↳ %s\n", c)
			}
			fmt.Println()
		}

		if len(res.FinalAnswers) > 0 {
			fmt.Println("✔ Authoritative Answer(s):")
			for _, a := range res.FinalAnswers {
				fmt.Printf("  • %-5s TTL:%-5d %s\n", a.Type, a.TTL, a.Data)
			}
		} else if res.Success {
			fmt.Println("✔ Authoritative NODATA (no records of requested type)")
		}

		return nil
	},
}

// 2. Propagate command
var (
	propType string
	propJSON bool
)

var propCmd = &cobra.Command{
	Use:   "propagate <domain>",
	Short: "Test worldwide edge propagation across 25+ global DoH vantage points",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]
		qtype := parseRecordType(propType)

		runner := propagation.NewRunner(propagation.DefaultRunnerConfig(), nil)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		summary, err := runner.Check(ctx, domain, qtype)
		if err != nil {
			return err
		}

		if propJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(summary)
		}

		fmt.Printf("⚡ DNSWatch Global Propagation: %s (%s)\n", summary.Domain, summary.QueryType)
		fmt.Printf("Consensus Rate: %.1f%% (%d/%d nodes) | Avg RTT: %v | Range: %v - %v\n",
			summary.PropagationRate, summary.SuccessCount, summary.TotalTested,
			summary.AvgRTT, summary.MinRTT, summary.MaxRTT)
		if len(summary.ConsensusAnswers) > 0 {
			fmt.Printf("Consensus Values: %s\n", strings.Join(summary.ConsensusAnswers, ", "))
		}
		fmt.Println()

		fmt.Printf("%-14s %-16s %-22s %-10s %-8s %s\n", "REGION", "LOCATION", "PROVIDER", "STATUS", "RTT", "ANSWERS")
		fmt.Println(strings.Repeat("─", 80))

		for _, node := range summary.Results {
			status := "MATCH"
			if node.Error != "" {
				status = "TIMEOUT"
			} else if !node.MatchedConsensus {
				status = "DIVERGENT"
			}

			var ansStrs []string
			for _, a := range node.Answers {
				ansStrs = append(ansStrs, a.Data)
			}
			ansJoined := strings.Join(ansStrs, ", ")
			if len(ansJoined) > 28 {
				ansJoined = ansJoined[:25] + "..."
			}

			fmt.Printf("%-14s %-16s %-22s %-10s %-8v %s\n",
				node.Provider.Region, node.Provider.City, node.Provider.Name,
				status, node.RTT.Round(time.Millisecond), ansJoined)
		}

		return nil
	},
}

// 3. DNSSEC command
var (
	dnssecType string
	dnssecJSON bool
	failOnBogus bool
)

var dnssecCmd = &cobra.Command{
	Use:   "dnssec <domain>",
	Short: "Inspect cryptographic DNSSEC chain of trust and verify RRSIG signatures",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]
		qtype := parseRecordType(dnssecType)

		validator := dnssec.NewValidator(5 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		res, err := validator.ValidateDomain(ctx, domain, qtype)
		if err != nil {
			return err
		}

		if dnssecJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(res)
		}

		fmt.Printf("⚡ DNSWatch DNSSEC Chain Validation: %s\n", res.Domain)
		fmt.Printf("Overall Status: %s\n\n", res.OverallStatus)

		for i, node := range res.Chain {
			fmt.Printf("[%d] Zone: %-16s Status: %s\n", i+1, node.Zone, node.Status)
			if len(node.Algorithms) > 0 {
				fmt.Printf("    Algorithms: %s\n", strings.Join(node.Algorithms, ", "))
			}
			if len(node.KSKKeyTags) > 0 || len(node.ZSKKeyTags) > 0 {
				fmt.Printf("    Key Tags: KSK=%v ZSK=%v\n", node.KSKKeyTags, node.ZSKKeyTags)
			}
			if node.HasDS {
				fmt.Printf("    Parent DS: Verified (Tags: %v)\n", node.DSKeyTags)
			}
			if node.HasRRSIG {
				fmt.Printf("    RRSIG: Signatures Valid=%v\n", node.SignaturesValid)
			}
			for _, e := range node.Errors {
				fmt.Printf("    ✖ Error: %s\n", e)
			}
			for _, w := range node.Warnings {
				fmt.Printf("    ▲ Warning: %s\n", w)
			}
			fmt.Println()
		}

		if failOnBogus && res.OverallStatus == dnssec.StatusBogus {
			os.Exit(1)
		}

		return nil
	},
}

// 4. Audit command
var (
	auditJSON        bool
	auditFailOnError bool
)

var auditCmd = &cobra.Command{
	Use:   "audit <domain>",
	Short: "Audit email hygiene (SPF/DMARC/MX), subdomain takeover risks, and nameserver consistency",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]
		auditor := audit.NewAuditor(5 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()

		report, err := auditor.Run(ctx, domain)
		if err != nil {
			return err
		}

		if auditJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		}

		fmt.Printf("⚡ DNSWatch Domain Security & Hygiene Audit: %s\n", report.Domain)
		fmt.Printf("Health Score: %d/100 | Grade: %s\n", report.Score, report.Grade)
		fmt.Printf("SPF: %s | DMARC: %s | MX: %s | Takeover Risk: %v | NS Parity: %v\n\n",
			report.SPFStatus, report.DMARCStatus, report.MXStatus, report.TakeoverRisk, report.NSConsistency)

		fmt.Println("Findings & Recommendations:")
		fmt.Println(strings.Repeat("─", 80))

		for _, f := range report.Findings {
			fmt.Printf("[%s] %s (%s)\n", f.Severity, f.Title, f.Category)
			fmt.Printf("  %s\n", f.Description)
			if f.Record != "" {
				fmt.Printf("  Record: %s\n", f.Record)
			}
			if f.Recommendation != "" {
				fmt.Printf("  Recommendation: %s\n", f.Recommendation)
			}
			fmt.Println()
		}

		if auditFailOnError && (report.Grade == "D" || report.Grade == "F" || report.TakeoverRisk) {
			os.Exit(1)
		}

		return nil
	},
}

// 5. Serve command
var (
	servePort int
	serveHost string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start embedded web studio and REST API server",
	RunE: func(cmd *cobra.Command, args []string) error {
		s := server.NewServer()
		s.RegisterStaticRoutes()

		addr := fmt.Sprintf("%s:%d", serveHost, servePort)
		fmt.Printf("⚡ DNSWatch Web Studio active at http://%s\n", addr)
		fmt.Printf("  • REST API: http://%s/api/summary?domain=example.com\n", addr)
		fmt.Printf("  • Press Ctrl+C to terminate\n\n")

		srv := &http.Server{
			Addr:         addr,
			Handler:      s.Router(),
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 30 * time.Second,
		}

		return srv.ListenAndServe()
	},
}

// 6. Version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print DNSWatch version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("DNSWatch v%s (commit: %s, built: %s)\n", version, commit, date)
	},
}

func init() {
	// Trace flags
	traceCmd.Flags().StringVarP(&traceType, "type", "t", "A", "DNS record type (A, AAAA, CNAME, MX, TXT, NS, SOA, CAA)")
	traceCmd.Flags().BoolVar(&traceJSON, "json", false, "Output results in JSON format")

	// Propagate flags
	propCmd.Flags().StringVarP(&propType, "type", "t", "A", "DNS record type")
	propCmd.Flags().BoolVar(&propJSON, "json", false, "Output results in JSON format")

	// DNSSEC flags
	dnssecCmd.Flags().StringVarP(&dnssecType, "type", "t", "A", "DNS record type")
	dnssecCmd.Flags().BoolVar(&dnssecJSON, "json", false, "Output results in JSON format")
	dnssecCmd.Flags().BoolVar(&failOnBogus, "fail-on-bogus", false, "Exit with code 1 if DNSSEC validation is BOGUS")

	// Audit flags
	auditCmd.Flags().BoolVar(&auditJSON, "json", false, "Output audit results in JSON format")
	auditCmd.Flags().BoolVar(&auditFailOnError, "fail-on-errors", false, "Exit with code 1 on poor grade (D/F) or takeover risk")

	// Serve flags
	serveCmd.Flags().IntVarP(&servePort, "port", "p", 50080, "HTTP port for web studio")
	serveCmd.Flags().StringVar(&serveHost, "host", "127.0.0.1", "Host binding address")

	// Register subcommands
	rootCmd.AddCommand(traceCmd)
	rootCmd.AddCommand(propCmd)
	rootCmd.AddCommand(dnssecCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(versionCmd)
}
