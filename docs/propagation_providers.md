# Global Propagation Providers

DNSWatch queries 25+ geographically distributed DNS-over-HTTPS (DoH) vantage points. These endpoints run on anycast networks or regional edge clusters.

## Global Anycast Networks

- Cloudflare (`1.1.1.1`): `https://cloudflare-dns.com/dns-query`
- Google Public DNS (`8.8.8.8`): `https://dns.google/dns-query`
- Quad9 (`9.9.9.9`): `https://dns.quad9.net/dns-query`
- OpenDNS / Cisco Umbrella: `https://doh.opendns.com/dns-query`
- AdGuard DNS: `https://dns.adguard-dns.com/dns-query`
- NextDNS: `https://dns.nextdns.io/dns-query`
- CleanBrowsing: `https://doh.cleanbrowsing.org/doh/adult-filter/`
- Mullvad DNS: `https://doh.mullvad.net/dns-query`
- Control D: `https://freedns.controld.com/p0`

## Regional Vantage Points

### North America
- US East (Virginia): Cloudflare Ashburn node / NextDNS US-East
- US Central (Chicago): Quad9 ORD cluster
- US West (San Jose / Los Angeles): Google SJC cluster / Cloudflare LAX
- Canada (Montreal / Toronto): CIRA Canadian Shield (`https://private.canadianshield.cira.ca/dns-query`)

### Europe
- United Kingdom (London): Cloudflare LHR / Quad9 London
- Germany (Frankfurt): Digitalcourage (`https://dns.digitalcourage.de/dns-query`) / DNS.SB Frankfurt
- France (Paris): Quad9 CDG cluster
- Netherlands (Amsterdam): Foundation for Applied Privacy (`https://doh.applied-privacy.net/query`)
- Switzerland (Zurich): Switch DNS (`https://dns.switch.ch/dns-query`)
- Sweden (Stockholm): Quad9 ARN cluster

### Asia-Pacific
- Japan (Tokyo): IIJ Public DNS (`https://public.dns.iij.jp/dns-query`) / Cloudflare NRT
- Singapore: Cloudflare SIN / Google SIN
- Australia (Sydney): Cloudflare SYD / NextDNS Sydney
- India (Mumbai): Cloudflare BOM / Google BOM
- Taiwan (Taipei): TWNIC Quad101 (`https://dns.twnic.tw/dns-query`)

### Latin America
- Brazil (São Paulo): NIC.br DNS / Cloudflare GRU
- Chile (Santiago): Cloudflare SCL

### Africa
- South Africa (Johannesburg): Cloudflare JNB / Quad9 JNB

## Consensus Calculation

1. All providers are queried concurrently with binary wire-format DNS requests.
2. Answers are parsed and sorted into distinct response sets.
3. The response set with the highest count is designated the consensus answer.
4. Propagation percentage is computed as:
   `propagation_rate = (count_matching_consensus / total_successful_responses) * 100`
5. Outliers are flagged for rapid troubleshooting.
