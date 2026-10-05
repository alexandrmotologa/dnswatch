# DNSWatch

DNSWatch is an interactive terminal TUI and local web studio for recursive DNS tracing, DNSSEC validation, and global edge propagation. It compiles into a single Go binary with an embedded React web interface.

## Highlights

- Recursive delegation trace: Walks the DNS hierarchy step by step from root hints to authoritative nameservers, measuring round-trip times and displaying referral glue records.
- IP enrichment: Resolves Autonomous System Number (ASN), BGP organization name, country code, and reverse DNS (PTR) directly via DNS protocol lookups without external API tokens.
- Worldwide edge propagation: Queries 25+ DNS-over-HTTPS (DoH) edge resolvers concurrently across North America, Europe, Asia-Pacific, Latin America, and Africa.
- Interactive World Map: Visualizes edge vantage points across continents on an SVG projection canvas with response consensus indicators and latency rings.
- Live mutation monitoring: Tracks real-time DNS changes during infrastructure migrations and domain cutovers (`dnswatch watch`).
- Domain and resolver diff: Compares DNS record sets side by side between two domains or authoritative servers (`dnswatch diff`).
- Latency and jitter benchmarking: Measures query latency, jitter, and packet reliability against 10 public global resolvers (`dnswatch bench`).
- DNSSEC trust chain validation: Inspects DS records, validates DNSKEY records, checks RRSIG signatures, and verifies validity windows and cryptographic algorithms.
- Domain hygiene and security checks: Scans SPF syntax, checks DMARC policies, identifies misconfigured nameservers, and flags dangling CNAME pointers that risk subdomain takeovers.
- Dual interface: Run as an interactive terminal interface (Bubble Tea) with Vim navigation and multiple color palettes, or start a local web studio (React 19, Tailwind CSS) with HTML/JSON report export.

## Installation

### From Source (Go 1.22+)

```bash
git clone https://github.com/alexandrmotologa/dnswatch.git
cd dnswatch
go build -o bin/dnswatch ./cmd/dnswatch
```

### Docker

Run DNSWatch in a container (<15MB minimal image):

```bash
docker run -p 8080:8080 ghcr.io/alexandrmotologa/dnswatch:latest
```

### GitHub Actions

Integrate DNSWatch directly into CI/CD pipelines to enforce domain hygiene and valid DNSSEC:

```yaml
- name: Audit Domain Health
  uses: alexandrmotologa/dnswatch@main
  with:
    command: audit
    domain: example.com
    fail_on_error: true
```

## Quick Start

### Interactive Terminal TUI

Launch the full-screen terminal interface:

```bash
dnswatch example.com
```

Keybindings in TUI:
- Tab / Shift+Tab: Switch between Trace, Propagation, DNSSEC, and Audit views
- 1, 2, 3, 4: Direct view selection
- j / k, Down / Up: Scroll line by line (Vim style)
- d / u: Scroll half page down / up
- g / G: Jump to top / bottom
- y / c: Copy current rendered view to clipboard
- m / M: Cycle visual themes (Electric Cyan, Tokyo Night, Catppuccin, Nord)
- /: Focus domain search input
- t: Change query record type (A, AAAA, CNAME, MX, TXT, NS, SOA)
- r: Refresh current query
- ?: Toggle help dialog
- q / Ctrl+C: Quit

### Command Line Mode

Run specific diagnostics directly in your terminal:

```bash
# Recursive root delegation trace with ASN enrichment
dnswatch trace example.com --type A

# Worldwide edge propagation check across 25+ resolvers
dnswatch propagate example.com --type A

# DNSSEC trust chain verification
dnswatch dnssec example.com

# Domain security and health audit
dnswatch audit example.com

# Live migration monitor (polls every 3s by default)
dnswatch watch example.com --interval 2s

# Compare records between domains or nameservers
dnswatch diff example.com staging.example.com

# Benchmark resolver speed and jitter across 10 global public resolvers
dnswatch bench example.com --rounds 3

# JSON output for automation and CI/CD pipelines
dnswatch audit example.com --format json
```

### Local Web Studio

Start the embedded web application:

```bash
dnswatch serve --port 50080
```

Open http://localhost:50080 in your browser to inspect interactive SVG delegation trees, global propagation charts with world map pins, DNSSEC trust diagrams, and download portable HTML/JSON reports.

## Architecture

```
[ Terminal TUI (Bubble Tea) ]       [ Web Studio (React 19 + SVG) ]
               \                              /
                v                            v
          [ CLI / REST API Router (Chi / Cobra) ]
                           │
            [ DNSWatch Core Engine in Go ]
            ├── Protocol Resolver (UDP, TCP, DoH RFC 8484)
            ├── Recursive Trace Walker (Root Hints to Authoritative)
            ├── ASN & BGP Route Enricher (Team Cymru DNS + rDNS PTR)
            ├── Edge Propagation Worker Pool (25+ Geo-Distributed DoH)
            ├── DNSSEC Cryptographic Verifier (DS, DNSKEY, RRSIG)
            ├── Mutation & Cutover Watcher (Live polling & diffing)
            ├── Zone & Resolver Comparator (Record set differential)
            ├── Public Resolver Benchmarker (Latency & jitter matrix)
            └── Domain Security Auditor (SPF, DMARC, Subdomain Takeover)
```

## Supported Record Types

DNSWatch supports standard and modern DNS record queries:
- A, AAAA (IPv4 and IPv6 addresses)
- CNAME (Canonical names)
- MX (Mail exchange)
- TXT (Verification, SPF, DKIM, DMARC)
- NS (Nameservers)
- SOA (Start of authority)
- PTR (Reverse lookups)
- CAA (Certificate authority authorization)
- SRV (Service records)
- DNSKEY, DS, RRSIG (DNSSEC infrastructure records)

## Documentation

Detailed architecture specifications, protocol notes, and extension guides are in the docs directory:
- [Architecture & Design](docs/architecture.md)
- [DNSSEC Validation Guide](docs/dnssec.md)
- [Edge Propagation Providers](docs/propagation_providers.md)
- [Security Audit Rules](docs/security_audit.md)

## License

MIT License. See [LICENSE](LICENSE) for details.
