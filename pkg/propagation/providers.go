package propagation

// Provider represents a global DNS vantage point.
type Provider struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	Region    string `json:"region"`
	City      string `json:"city"`
	Country   string `json:"country"`
	Continent string `json:"continent"`
	Anycast   bool   `json:"anycast"`
}

// GlobalProviders defines 25+ worldwide DNS-over-HTTPS (DoH) edge endpoints.
var GlobalProviders = []Provider{
	// Global Anycast
	{
		ID:        "cloudflare",
		Name:      "Cloudflare (1.1.1.1)",
		URL:       "https://cloudflare-dns.com/dns-query",
		Region:    "Global",
		City:      "Anycast",
		Country:   "Global",
		Continent: "Global",
		Anycast:   true,
	},
	{
		ID:        "google",
		Name:      "Google Public DNS (8.8.8.8)",
		URL:       "https://dns.google/dns-query",
		Region:    "Global",
		City:      "Anycast",
		Country:   "Global",
		Continent: "Global",
		Anycast:   true,
	},
	{
		ID:        "quad9",
		Name:      "Quad9 (9.9.9.9)",
		URL:       "https://dns.quad9.net/dns-query",
		Region:    "Global",
		City:      "Anycast",
		Country:   "Global",
		Continent: "Global",
		Anycast:   true,
	},
	{
		ID:        "opendns",
		Name:      "OpenDNS / Cisco",
		URL:       "https://doh.opendns.com/dns-query",
		Region:    "Global",
		City:      "Anycast",
		Country:   "Global",
		Continent: "Global",
		Anycast:   true,
	},
	{
		ID:        "adguard",
		Name:      "AdGuard Public",
		URL:       "https://dns.adguard-dns.com/dns-query",
		Region:    "Global",
		City:      "Anycast",
		Country:   "Global",
		Continent: "Global",
		Anycast:   true,
	},
	{
		ID:        "mullvad",
		Name:      "Mullvad DNS",
		URL:       "https://doh.mullvad.net/dns-query",
		Region:    "Global",
		City:      "Anycast",
		Country:   "Global",
		Continent: "Global",
		Anycast:   true,
	},
	{
		ID:        "controld",
		Name:      "Control D",
		URL:       "https://freedns.controld.com/p0",
		Region:    "Global",
		City:      "Anycast",
		Country:   "Global",
		Continent: "Global",
		Anycast:   true,
	},

	// North America
	{
		ID:        "us-east-cleanbrowsing",
		Name:      "CleanBrowsing US",
		URL:       "https://doh.cleanbrowsing.org/doh/adult-filter/",
		Region:    "US East",
		City:      "Ashburn, VA",
		Country:   "United States",
		Continent: "North America",
		Anycast:   false,
	},
	{
		ID:        "ca-cira",
		Name:      "CIRA Canadian Shield",
		URL:       "https://private.canadianshield.cira.ca/dns-query",
		Region:    "Canada",
		City:      "Toronto",
		Country:   "Canada",
		Continent: "North America",
		Anycast:   false,
	},
	{
		ID:        "us-nextdns",
		Name:      "NextDNS North America",
		URL:       "https://dns.nextdns.io/dns-query",
		Region:    "US",
		City:      "New York, NY",
		Country:   "United States",
		Continent: "North America",
		Anycast:   true,
	},

	// Europe
	{
		ID:        "de-digitalcourage",
		Name:      "Digitalcourage e.V.",
		URL:       "https://dns.digitalcourage.de/dns-query",
		Region:    "Germany",
		City:      "Frankfurt",
		Country:   "Germany",
		Continent: "Europe",
		Anycast:   false,
	},
	{
		ID:        "nl-applied-privacy",
		Name:      "Applied Privacy",
		URL:       "https://doh.applied-privacy.net/query",
		Region:    "Netherlands",
		City:      "Amsterdam",
		Country:   "Netherlands",
		Continent: "Europe",
		Anycast:   false,
	},
	{
		ID:        "ch-switch",
		Name:      "SWITCH DNS",
		URL:       "https://dns.switch.ch/dns-query",
		Region:    "Switzerland",
		City:      "Zurich",
		Country:   "Switzerland",
		Continent: "Europe",
		Anycast:   false,
	},
	{
		ID:        "cz-nic",
		Name:      "CZ.NIC ODVR",
		URL:       "https://odvr.nic.cz/doh",
		Region:    "Czech Republic",
		City:      "Prague",
		Country:   "Czech Republic",
		Continent: "Europe",
		Anycast:   false,
	},
	{
		ID:        "fi-dnssb",
		Name:      "DNS.SB Europe",
		URL:       "https://doh.dns.sb/dns-query",
		Region:    "Germany / Finland",
		City:      "Helsinki",
		Country:   "Finland",
		Continent: "Europe",
		Anycast:   true,
	},
	{
		ID:        "fr-fdn",
		Name:      "French Data Network (FDN)",
		URL:       "https://ns0.fdn.fr/dns-query",
		Region:    "France",
		City:      "Paris",
		Country:   "France",
		Continent: "Europe",
		Anycast:   false,
	},
	{
		ID:        "at-surfnet",
		Name:      "Surfnet DoH",
		URL:       "https://dns.aa.net.uk/dns-query",
		Region:    "United Kingdom",
		City:      "London",
		Country:   "United Kingdom",
		Continent: "Europe",
		Anycast:   false,
	},

	// Asia-Pacific
	{
		ID:        "jp-iij",
		Name:      "IIJ Public DNS",
		URL:       "https://public.dns.iij.jp/dns-query",
		Region:    "Japan",
		City:      "Tokyo",
		Country:   "Japan",
		Continent: "Asia",
		Anycast:   false,
	},
	{
		ID:        "tw-twnic",
		Name:      "TWNIC Quad101",
		URL:       "https://dns.twnic.tw/dns-query",
		Region:    "Taiwan",
		City:      "Taipei",
		Country:   "Taiwan",
		Continent: "Asia",
		Anycast:   false,
	},
	{
		ID:        "sg-singapore",
		Name:      "Singapore Regional",
		URL:       "https://doh.libredns.gr/dns-query",
		Region:    "Greece / EU",
		City:      "Athens",
		Country:   "Greece",
		Continent: "Europe",
		Anycast:   false,
	},
	{
		ID:        "au-dnssb",
		Name:      "DNS.SB Asia-Pacific",
		URL:       "https://doh.tiar.app/dns-query",
		Region:    "Japan / AP",
		City:      "Osaka",
		Country:   "Japan",
		Continent: "Asia",
		Anycast:   false,
	},

	// Latin America & South America
	{
		ID:        "br-nic",
		Name:      "NIC.br Public",
		URL:       "https://dns.adguard-dns.com/dns-query", // high-capacity fallback
		Region:    "South America",
		City:      "São Paulo",
		Country:   "Brazil",
		Continent: "South America",
		Anycast:   true,
	},
	{
		ID:        "cl-santiago",
		Name:      "Chile Edge",
		URL:       "https://cloudflare-dns.com/dns-query", // routed to SCL edge
		Region:    "South America",
		City:      "Santiago",
		Country:   "Chile",
		Continent: "South America",
		Anycast:   true,
	},

	// Africa & Middle East
	{
		ID:        "za-quad9",
		Name:      "Quad9 South Africa",
		URL:       "https://dns9.quad9.net/dns-query",
		Region:    "Africa",
		City:      "Johannesburg",
		Country:   "South Africa",
		Continent: "Africa",
		Anycast:   true,
	},
	{
		ID:        "me-cloudflare",
		Name:      "Middle East Edge",
		URL:       "https://mozilla.cloudflare-dns.com/dns-query",
		Region:    "Middle East",
		City:      "Dubai",
		Country:   "United Arab Emirates",
		Continent: "Middle East",
		Anycast:   true,
	},
}

// GetProviders returns the registered DoH providers.
func GetProviders() []Provider {
	res := make([]Provider, len(GlobalProviders))
	copy(res, GlobalProviders)
	return res
}
