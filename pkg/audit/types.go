package audit

import (
	"time"
)

// Severity indicates finding criticality.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
	SeverityGood     Severity = "GOOD"
)

// Finding represents an individual security or configuration issue.
type Finding struct {
	Category       string   `json:"category"` // Email, SubdomainTakeover, Nameserver, Hygiene
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Severity       Severity `json:"severity"`
	Recommendation string   `json:"recommendation"`
	Record         string   `json:"record,omitempty"`
}

// AuditReport aggregates all security and hygiene findings for a domain.
type AuditReport struct {
	Domain        string     `json:"domain"`
	Score         int        `json:"score"` // 0 to 100 Health Score
	Grade         string     `json:"grade"` // A+, A, B, C, D, F
	Findings      []Finding  `json:"findings"`
	SPFStatus     string     `json:"spf_status"`
	DMARCStatus   string     `json:"dmarc_status"`
	MXStatus      string     `json:"mx_status"`
	TakeoverRisk  bool       `json:"takeover_risk"`
	NSConsistency bool       `json:"ns_consistency"`
	CheckedAt     time.Time  `json:"checked_at"`
}
