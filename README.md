# DNSWatch

DNSWatch is an interactive terminal TUI and local web studio for recursive DNS tracing, DNSSEC validation, and global edge propagation. It runs as a single Go binary with an embedded React web interface.

## Highlights

- Recursive delegation trace: Walks the DNS hierarchy step by step from root hints to authoritative nameservers, measuring round-trip times and displaying referral glue records.
- Worldwide edge propagation: Queries 25+ DNS-over-HTTPS (DoH) edge resolvers concurrently across North America, Europe, Asia-Pacific, Latin America, and Africa.
- DNSSEC trust chain validation: Inspects DS records, validates DNSKEY records, checks RRSIG signatures, and verifies validity windows and cryptographic algorithms.
- Domain hygiene and security checks: Scans SPF syntax, checks DMARC policies, identifies misconfigured nameservers, and flags dangling CNAME pointers that risk subdomain takeovers.
- Dual interface: Run as an interactive terminal interface (Bubble Tea) or start a local web studio (React 19, Tailwind CSS) with SVG visualization tools.

## Installation

### From Source (Go 1.23+)

```bash
git clone https://github.com/alexandrmotologa/dnswatch.git
cd dnswatch
go build -o bin/dnswatch ./cmd/dnswatch
```

### Prebuilt Binaries

Download precompiled binaries for Linux, macOS, and Windows from GitHub Releases.

## Quick Start

### Interactive Terminal TUI

Launch the full-screen terminal interface:

```bash
dnswatch example.com
```

Keybindings in TUI:
- Tab / Shift+Tab: Switch between Trace, Propagation, DNSSEC, and Audit views
- 1, 2, 3, 4: Direct view selection
- /: Focus domain search input
- t: Change query record type (A, AAAA, CNAME, MX, TXT, NS, SOA)
- r: Refresh current query
- q / Ctrl+C: Quit

### Command Line Mode

Run specific diagnostics directly in your terminal:

```bash
# Recursive root delegation trace
dnswatch trace example.com --type A

# Worldwide edge propagation check across 25+ resolvers
dnswatch propagate example.com --type A

# DNSSEC trust chain verification
dnswatch dnssec example.com

# Domain security and health audit
dnswatch audit example.com

# JSON output for automation and CI/CD pipelines
dnswatch audit example.com --format json --fail-on-errors
```

### Local Web Studio

Start the embedded web application:

```bash
dnswatch serve --port 50080
```

Open http://localhost:50080 in your browser to inspect interactive SVG delegation trees, global propagation charts, and DNSSEC trust diagrams.

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
            ├── Edge Propagation Worker Pool (25+ Geo-Distributed DoH)
            ├── DNSSEC Cryptographic Verifier (DS, DNSKEY, RRSIG)
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
