# Architecture Overview

DNSWatch combines an iterative DNS resolution engine with multiple client frontends. The core engine runs purely in Go without requiring C bindings or system resolver dependencies.

## Key Components

### 1. Protocol Layer (`pkg/resolver`)
The protocol layer handles direct communication with nameservers.
- Standard DNS queries use UDP port 53 with fallback to TCP port 53 when responses are truncated (TC flag set).
- EDNS0 (RFC 6891) is enabled by default with a 1232-byte UDP buffer size to prevent fragmentation and truncation issues.
- DNS-over-HTTPS (DoH, RFC 8484) uses HTTP/2 with binary wire format (`application/dns-message`) over TLS for secure edge propagation queries.
- DNS-over-TLS (DoT, RFC 7858) is supported over port 853.

### 2. Recursive Trace Engine (`pkg/trace`)
Unlike standard stub resolvers that query a local caching resolver, the recursive trace engine simulates full resolution from the Internet root zone:
1. Queries one of the 13 root server clusters (`a.root-servers.net` through `m.root-servers.net`).
2. Follows delegation NS records and glue A/AAAA records down to the Top-Level Domain (TLD) authoritative nameservers.
3. Queries TLD nameservers to obtain delegation to the domain authoritative nameservers.
4. Queries domain authoritative nameservers to retrieve the final answer, CNAME chain, or negative response (NXDOMAIN / NODATA).
5. For each step, it records:
   - Responding server hostname and IP address
   - Round-trip time (RTT) in milliseconds
   - Response header flags (AA, TC, RD, RA, AD, CD)
   - Returned RR sets (Question, Answer, Authority, Additional)

### 3. Edge Propagation Engine (`pkg/propagation`)
To verify how quickly DNS records propagate worldwide, the propagation engine maintains a registry of 25+ geographically distributed DoH endpoints.
- Queries are executed concurrently using a worker pool with a configurable timeout (default 3 seconds).
- Results are aggregated into a consensus matrix that groups identical responses and calculates global agreement percentages.
- Metrics track minimum, maximum, and median response latencies across regions.

### 4. DNSSEC Validation Engine (`pkg/dnssec`)
DNSSEC provides cryptographic authentication of DNS data. The validation engine performs:
- Verification of Delegation Signer (DS) digests against child DNSKEY records.
- Validation of Resource Record Signatures (RRSIG) across record sets using public keys from the DNSKEY RRset.
- Signature window verification ensuring current time falls between inception and expiration timestamps.
- Detection of algorithm deprecations and weak key sizes.

### 5. Domain Security Auditor (`pkg/audit`)
The auditor checks domain configuration against operational best practices:
- SPF syntax checks (multiple SPF records, `+all` policy, excessive DNS lookups exceeding RFC 7208 limits).
- DMARC policy validation (`p=reject`, `p=quarantine`, `p=none`), percentage enforcement (`pct`), and reporting mailboxes (`rua`/`ruf`).
- MX server reachability and STARTTLS support.
- Subdomain takeover detection by inspecting dangling CNAME records pointing to decommissioned cloud buckets, hosting services, and CDNs.
- Authoritative nameserver consistency (SOA serial parity across all declared nameservers).

### 6. User Interfaces (`pkg/tui` & `ui`)
- Terminal UI: Built with Bubble Tea and Lipgloss. Provides an interactive multi-tab dashboard with responsive layout adjustments.
- Web Studio: Built with React 19, TypeScript, and Tailwind CSS. Embedded directly into the Go executable using `go:embed`. Serves a REST API for automated tooling and browser access.
