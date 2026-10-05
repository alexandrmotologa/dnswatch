# Domain Security & Hygiene Audit

DNSWatch includes automated rules to inspect domain records for common misconfigurations and security risks.

## Audit Categories

### 1. Email Security (SPF, DMARC, DKIM, MX)
- **SPF Verification:**
  - Validates syntax according to RFC 7208.
  - Flags duplicate SPF records (violates RFC 7208 section 3.2 and leads to PermError).
  - Flags permissive mechanisms like `+all` or `?all` which allow spoofing.
  - Warns on lookup mechanisms (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`) that exceed the 10-lookup limit.
- **DMARC Policy:**
  - Verifies presence of `_dmarc.<domain>` TXT record.
  - Validates `v=DMARC1` tag presence and position.
  - Evaluates enforcement policy:
    - `p=none`: Monitoring only, no mail rejected (flagged as informational/warning).
    - `p=quarantine`: Suspicious mail sent to spam.
    - `p=reject`: Maximum spoofing protection.
  - Checks presence of reporting addresses (`rua` and `ruf`).
  - Evaluates alignment tags (`aspf`, `adkim`) and percentage tag (`pct`).
- **MX Records:**
  - Ensures at least one MX record is present.
  - Verifies MX hostnames are not CNAME records (violates RFC 2181 section 10.3).
  - Validates port 25 availability and STARTTLS support on primary mail exchanges.

### 2. Subdomain Takeover Vulnerabilities
Subdomain takeover occurs when a domain or subdomain points via CNAME or NS delegation to a third-party service provider, but the resource is no longer provisioned by the legitimate owner. An attacker can register the resource on the provider and claim control over the domain.

DNSWatch checks CNAME targets against known signatures:
- GitHub Pages (`*.github.io`)
- Amazon AWS S3 Buckets (`*.s3.amazonaws.com`, `*.s3-website-*.amazonaws.com`)
- Heroku (`*.herokuapp.com`)
- Vercel (`*.vercel-dns.com`, `cname.vercel-dns.com`)
- Netlify (`*.netlify.app`)
- Shopify (`shops.myshopify.com`)
- Azure Traffic Manager & App Services (`*.azurewebsites.net`, `*.trafficmanager.net`)
- Fastly CDN (`*.fastly.net`)
- Ghost (`*.ghost.io`)
- Bitbucket (`*.bitbucket.io`)
- Zendesk (`*.zendesk.com`)

### 3. Nameserver Consistency & Zone Hygiene
- **SOA Serial Consistency:** Queries all authoritative nameservers listed in the zone NS set and compares SOA serial numbers. Mismatches indicate replication delays or split-brain configurations.
- **Lame Delegation:** Checks whether every delegated nameserver responds authoritatively (AA flag set) for the zone.
- **Open DNS Recursion:** Tests authoritative nameservers to confirm they do not provide open recursive resolution to the public Internet.
