# Engineering Specification & Implementation Blueprint: DNSWatch
> Interactive Terminal TUI & Web Studio for Recursive DNS Tracing, DNSSEC Validation & Global Edge Propagation (Reimagining dig +trace, ogham/dog & whatsmydns)

---

## 1. Executive Summary & Market Opportunity

### 1.1 The Market Vacuum
The industry axiom *"It's always DNS"* exists for a reason. DNS misconfigurations, slow TTL cache propagation, broken DNSSEC key chains, and dangling CNAME records are responsible for millions of dollars in unexpected web application downtime every year.

Yet, DNS debugging tools have barely evolved in thirty years:
* **`dig +trace` & `nslookup`:** Output dense, unformatted walls of text with cryptic flag abbreviations (`qr aa rd ra cd`). Tracing where a delegation stalled or why an authoritative nameserver failed requires tedious manual parsing.
* **`ogham/dog` (10,000+ GitHub stars):** A popular command-line DNS client written in Rust that gained massive traction for pretty output, but has been **completely abandoned and unmaintained since 2020**. It lacks recursive root-to-leaf tracing, has no DNSSEC trust chain visualization, and has no global propagation testing.
* **Global Propagation Checkers (e.g. `whatsmydns.net`):** Developers are forced to visit third-party websites littered with ad banners, cookie consent popups, and artificial rate limits just to check if their new `A` or `CNAME` records have propagated globally.
* **DNSSEC Inscrutability:** Validating cryptographic trust chains (`DS` ➔ `DNSKEY` ➔ `RRSIG`) is notoriously difficult, leading to silent outages when zone keys roll over or expire.

### 1.2 The Solution: DNSWatch
**DNSWatch** is a lightning-fast, modern DNS analysis studio and interactive TUI built in **Go 1.23+**. It unites full recursive root-to-leaf resolution, cryptographic DNSSEC chain verification, ad-free global propagation matrix testing, and automated security auditing into a single zero-dependency binary.

* **Visual Recursive Delegation Tree:** Interactively traces every resolution step: Root servers (`.`) ➔ TLD nameservers (e.g. `.com`) ➔ Authoritative nameservers, displaying exact round-trip times (RTT), server IP addresses, authority flags, and delegation glue records.
* **Ad-Free Global Edge Propagation Matrix:** Concurrently queries 25+ worldwide DNS-over-HTTPS (DoH) edge vantage points across North America, Europe, Asia-Pacific, Latin America, and Africa (Cloudflare, Google, Quad9, OpenDNS, and regional edge resolvers) to display live global propagation status in under 500ms.
* **Visual DNSSEC Cryptographic Trust Chain Validator:** Validates parent `DS` hashes against child `DNSKEY` (Key Signing Key / Zone Signing Key) and verifies `RRSIG` signatures with a color-coded cryptographic diagram highlighting expired signatures or mismatched algorithms.
* **Live TTL Countdown & Cache Expiry Tracker:** Displays live countdown bars showing exact remaining seconds before DNS cache expires across resolvers.
* **Automated Domain Health & Security Audit:** Checks for missing or invalid email security records (SPF, DKIM, DMARC), detects dangling CNAME records vulnerable to **subdomain takeover**, and validates nameserver consistency across all authoritative servers.
* **Dual Interface (Bubbletea TUI + Web Dashboard):** Instant visual TUI in the terminal and a local web studio via `go:embed`.

---

## 2. Core Architecture & Tech Stack

```
┌────────────────────────────────────────────────────────────────────────┐
│                          DNSWatch Architecture                         │
└────────────────────────────────────────────────────────────────────────┘

[ Interactive Terminal TUI (Bubbletea) ] OR [ Web Studio ] (http://localhost:50080)
                             │
                             ▼
[ DNSWatch Single Binary ] (Go 1.23+ Engine)
   ├── Protocol & Query Dispatcher
   │     ├── Standard UDP / TCP Client (miekg/dns - RFC 1035)
   │     ├── DNS-over-HTTPS (DoH) Client (RFC 8484 over HTTP/2)
   │     └── DNS-over-TLS (DoT) Client (RFC 7858)
   ├── Recursive Trace Engine
   │     ├── Hardcoded Root Hints (13 Root Server clusters a-m.root-servers.net)
   │     ├── Iterative Query Walker with Glue Record Resolution
   │     └── RTT Latency Benchmarker per Delegation Hop
   ├── Global Edge Propagation Engine
   │     ├── Concurrent DoH Worker Pool (25+ worldwide endpoints)
   │     └── Matrix Convergence Detector (Consensus IP calculation)
   ├── DNSSEC Cryptographic Validator
   │     ├── DS ➔ DNSKEY Hash Digest Validator (SHA-1, SHA-256, SHA-384)
   │     ├── RRSIG Signature Verification (RSA, ECDSA P-256, Ed25519)
   │     └── Inception / Expiration Time-Window Verifier
   └── Health & Security Auditor
         ├── Subdomain Takeover Scanner (Dangling CNAME signatures)
         ├── Email Security Analyzer (SPF syntax, DMARC policy, MX consistency)
         └── Authoritative Zone Lame Delegation Detector
```

### 2.1 Backend Technology
* **Language:** Go 1.23+
* **DNS Core Protocol:** `github.com/miekg/dns` (the industry-standard Go DNS library powering CoreDNS).
* **HTTP/2 DoH Client:** Standard library `net/http` configured with optimized connection pooling.
* **TUI Framework:** `github.com/charmbracelet/bubbletea` + `github.com/charmbracelet/lipgloss` + `github.com/charmbracelet/bubbles` (24-bit TrueColor terminal UI).
* **HTTP Router:** `github.com/go-chi/chi/v5` for embedded web studio mode.
* **CLI Framework:** `github.com/spf13/cobra`.

### 2.2 Frontend Technology (Web Mode)
* **Core:** Vite + React 19 + TypeScript.
* **Styling:** Tailwind CSS + dark glassmorphic UI tokens.
* **Visualizations:** Interactive SVG delegation trees and world map propagation pins.

---

## 3. Key Feature Specifications

### 3.1 Visual Recursive Delegation Tree (`Trace Mode`)
* Traces any record type (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `SRV`, `CAA`).
* Renders an interactive tree:
  ```
  example.com (Type: A)
  ├── [1] Root Servers (a.root-servers.net - 198.41.0.4) ➔ RTT: 12ms
  │   └── Delegation: Referral to .com TLD (13 gTLD nameservers)
  ├── [2] TLD Nameservers (a.gtld-servers.net - 192.5.6.30) ➔ RTT: 24ms
  │   └── Delegation: Referral to ns1.example.com (Glue: 173.245.58.51)
  └── [3] Authoritative (ns1.example.com - 173.245.58.51) ➔ RTT: 9ms [Flags: AA, RD]
      └── Answer: 93.184.216.34 (TTL: 3600s)
  ```
* Flags non-responsive nameservers, referral loops, and lame delegations.

### 3.2 Worldwide Edge Propagation Matrix
* Dispatches concurrent queries to 25+ global DNS-over-HTTPS (DoH) providers:
  * **Global Public:** Cloudflare (`1.1.1.1`), Google (`8.8.8.8`), Quad9 (`9.9.9.9`), OpenDNS (`208.67.222.222`), AdGuard.
  * **North America:** US East (Virginia), US West (California), Canada (Montreal).
  * **Europe:** UK (London), Germany (Frankfurt), France (Paris), Sweden (Stockholm).
  * **Asia-Pacific:** Japan (Tokyo), Singapore, Australia (Sydney), India (Mumbai).
  * **Latin America:** Brazil (São Paulo), Chile (Santiago).
  * **Africa:** South Africa (Johannesburg).
* Renders real-time status matrix:
  * Resolved values, consensus percentage (e.g. `96% propagated`), and min/max/average latency.

### 3.3 Cryptographic DNSSEC Chain Validator
* Visualizes the complete chain of trust:
  * **Root Zone (`.`):** Validates Root KSK trust anchor.
  * **TLD Zone (e.g. `.org`):** Validates `DS` record hash against Root `DNSKEY`.
  * **Child Zone (e.g. `example.org`):** Validates child `DS` record against child `DNSKEY`.
  * **Resource Records:** Validates `RRSIG` signature on target record set.
* Highlights exact points of failure:
  * 🔴 Expired signature (`RRSIG validity window expired on 2026-09-20`).
  * 🔴 Hash digest mismatch between parent `DS` and child `DNSKEY`.
  * 🟡 Weak cryptographic algorithm (e.g. RSASHA1 deprecation warning).

### 3.4 Domain Health & Security Auditor
* **Email Hygiene Audit:**
  * Validates SPF record syntax, catches multi-SPF record errors, and checks for `+all` dangerous permits.
  * Evaluates DMARC policy (`p=none`, `p=quarantine`, `p=reject`) and reporting addresses (`rua`).
  * Inspects MX servers for reachable port 25 and STARTTLS support.
* **Subdomain Takeover Detector:**
  * Analyzes CNAME records pointing to unclaimed third-party services (GitHub Pages, AWS S3, Heroku, Vercel, Azure Traffic Manager) that allow attackers to hijack the domain.

---

## 4. CLI Command-Line Specification

```bash
# Launch interactive Bubbletea TUI for domain inspection
dnswatch example.com

# Trace complete recursive delegation path from Root to Authoritative
dnswatch trace example.com --type A

# Check global propagation across 25+ worldwide edge nodes
dnswatch propagate example.com --type A

# Validate complete DNSSEC cryptographic chain of trust
dnswatch dnssec example.org

# Run complete domain health and security audit (SPF, DMARC, Takeover risks)
dnswatch audit example.com

# Launch local web studio (http://localhost:50080)
dnswatch serve --port 50080

# Headless CI mode (exit code 1 on DNSSEC failure or health error)
dnswatch audit example.com --fail-on-errors --format json
```

---

## 5. Complete Project Directory Layout

```
dnswatch/
├── cmd/
│   └── dnswatch/
│       └── main.go                         # Cobra CLI entrypoint
├── pkg/
│   ├── resolver/
│   │   ├── client.go                       # Standard UDP/TCP DNS client
│   │   ├── doh.go                          # DNS-over-HTTPS (RFC 8484) client
│   │   ├── dot.go                          # DNS-over-TLS (RFC 7858) client
│   │   └── types.go                        # Query, Answer, Header flags, RR types
│   ├── trace/
│   │   ├── root_hints.go                   # Hardcoded IANA root nameservers
│   │   ├── walker.go                       # Recursive delegation stepper
│   │   └── tree.go                         # Hierarchical trace node data structure
│   ├── propagation/
│   │   ├── providers.go                    # 25+ Global DoH resolver registry
│   │   ├── runner.go                       # Concurrent worker pool dispatcher
│   │   └── matrix.go                       # Consensus and propagation calculator
│   ├── dnssec/
│   │   ├── validator.go                    # Chain of trust validator
│   │   ├── ds.go                           # DS record digest verification
│   │   ├── rrsig.go                        # RRSIG signature verifier
│   │   └── types.go                        # ChainNode, TrustStatus, CryptoError
│   ├── audit/
│   │   ├── email.go                        # SPF, DMARC, DKIM, MX security auditor
│   │   ├── takeover.go                     # Dangling CNAME takeover signatures
│   │   └── health.go                       # Nameserver parity & lame delegation check
│   ├── tui/
│   │   ├── app.go                          # Bubbletea root model
│   │   ├── view_trace.go                   # Visual recursive tree view
│   │   ├── view_propagation.go             # Global edge matrix view
│   │   ├── view_dnssec.go                  # Cryptographic trust chain view
│   │   └── view_audit.go                   # Domain security audit report
│   └── server/
│       ├── api.go                          # REST API for web studio
│       └── static.go                       # go:embed static production web assets
├── ui/
│   ├── index.html                          # Web studio entrypoint
│   ├── package.json                        # Vite, React 19, Tailwind
│   ├── tsconfig.json                       # TypeScript config
│   ├── src/
│   │   ├── components/
│   │   │   ├── TraceTree.tsx               # Interactive SVG delegation tree
│   │   │   ├── PropagationMap.tsx          # World map with latency pins
│   │   │   ├── DnssecChain.tsx             # Cryptographic trust visualizer
│   │   │   └── AuditReport.tsx             # Security findings with severity badges
│   │   ├── App.tsx                         # Root web application
│   │   └── main.tsx                        # React 19 mount point
├── Makefile                                # Build and release targets
├── go.mod                                  # Go dependencies
├── go.sum                                  # Checksums
└── README.md                               # Project documentation
```

---

## 6. Implementation Roadmap

### Phase 1: Go Module Setup & Core DNS Protocol Client
- [ ] 1.1 Initialize Go module `github.com/alexandrmotologa/dnswatch` and configure dependencies (`miekg/dns`, `charmbracelet/bubbletea`, `cobra`, `chi`).
- [ ] 1.2 Implement `pkg/resolver/client.go` supporting UDP, TCP, and DoH (DNS-over-HTTPS) resolution.
- [ ] 1.3 Implement `pkg/trace/root_hints.go` embedding IANA root server IP addresses (`a.root-servers.net` to `m.root-servers.net`).
- [ ] 1.4 Implement `pkg/trace/walker.go` performing step-by-step recursive delegation walking from Root to Authoritative.
- [ ] 1.5 Write automated tests verifying recursive resolution against well-known public domains.

### Phase 2: Global Propagation Engine
- [ ] 2.1 Implement `pkg/propagation/providers.go` registering 25+ global DoH endpoints with geographic metadata.
- [ ] 2.2 Implement concurrent worker pool in `runner.go` querying all providers simultaneously with strict timeouts.
- [ ] 2.3 Implement `matrix.go` computing consensus IP distribution and propagation percentage.
- [ ] 2.4 Write unit tests simulating partial propagation scenarios and verifying consensus math.

### Phase 3: DNSSEC Cryptographic Trust Chain Validator
- [ ] 3.1 Implement Root trust anchor verification (`.` zone).
- [ ] 3.2 Implement `pkg/dnssec/ds.go` verifying parent `DS` hashes against child `DNSKEY` records (SHA-1, SHA-256).
- [ ] 3.3 Implement `pkg/dnssec/rrsig.go` validating `RRSIG` signatures and checking inception/expiration validity windows.
- [ ] 3.4 Build structured `ChainNode` graph output representing the complete cryptographic ladder.
- [ ] 3.5 Write tests against known DNSSEC-enabled domains (`cloudflare.com`, `internic.net`) and known broken domains (`dnssec-failed.org`).

### Phase 4: Domain Health & Security Auditor
- [ ] 4.1 Implement `pkg/audit/email.go` parsing and validating SPF records (syntax, mechanism count, `+all` warnings).
- [ ] 4.2 Implement DMARC policy evaluator inspecting `p=reject`, `p=quarantine`, and reporting tags.
- [ ] 4.3 Implement `pkg/audit/takeover.go` with fingerprint database for unclaimed cloud provider CNAMEs.
- [ ] 4.4 Implement authoritative nameserver consistency checker verifying that all listed NS servers return identical serials.

### Phase 5: Terminal TUI (Bubbletea + Lipgloss)
- [ ] 5.1 Implement Bubbletea application shell with 4 tabs: `Trace`, `Propagation`, `DNSSEC`, `Audit`.
- [ ] 5.2 Build `view_trace.go` rendering clean ASCII tree hierarchy with color-coded latency indicators.
- [ ] 5.3 Build `view_propagation.go` rendering global geographic table with live status checkmarks.
- [ ] 5.4 Build `view_dnssec.go` rendering verified trust badges.
- [ ] 5.5 Support keyboard navigation (`Tab` for switching views, `q` for quit, `/` for search).

### Phase 6: Embedded Web Studio & Single-Binary Delivery
- [ ] 6.1 Scaffold Vite + React 19 + TypeScript in `ui/`.
- [ ] 6.2 Build interactive SVG Trace Tree component and Global Propagation Map.
- [ ] 6.3 Implement REST API in `pkg/server/` exposing all resolution, propagation, and DNSSEC endpoints.
- [ ] 6.4 Embed frontend static bundle into the Go binary using `go:embed`.
- [ ] 6.5 Package single-binary release with zero external runtime requirements across macOS, Linux, and Windows.

---

## 7. Verification & Acceptance Criteria
1. **Recursive Trace Accuracy:** Must trace any valid domain from the Root servers to the final answer without infinite referral loops.
2. **Propagation Speed:** Must query 25+ global DoH edge nodes concurrently and display results in <600ms total.
3. **DNSSEC Detection:** Must accurately validate `cloudflare.com` as secure and `dnssec-failed.org` as invalid/tampered.
4. **Subdomain Takeover:** Must flag dangling CNAME pointers to unclaimed cloud targets.
5. **Zero External Dependencies:** Single compiled binary (<20MB) with zero external runtime requirements.

---

## 8. Kick-Off Prompt for Subagent

```markdown
Please read [DNSWATCH_SPEC_AND_ROADMAP.md](file:///B:/workgit/dnswatch/DNSWATCH_SPEC_AND_ROADMAP.md) in full and execute Phase 1: scaffold the Go 1.23+ project in `B:\workgit\dnswatch`, configure core dependencies (`miekg/dns`, `charmbracelet/bubbletea`, `spf13/cobra`, `go-chi/chi/v5`), implement the DNS client with UDP, TCP, and DoH support, build the recursive delegation walker from root hints, and write automated tests verifying resolution against public domains.
```
