package audit

import (
	"context"
	"testing"
	"time"
)

func TestCalculateScoreAndGrade(t *testing.T) {
	tests := []struct {
		name          string
		findings      []Finding
		expectedScore int
		expectedGrade string
	}{
		{
			name:          "Clean domain",
			findings:      []Finding{{Severity: SeverityGood}},
			expectedScore: 100,
			expectedGrade: "A+",
		},
		{
			name: "Low finding",
			findings: []Finding{
				{Severity: SeverityLow},
			},
			expectedScore: 95,
			expectedGrade: "A+",
		},
		{
			name: "Medium finding",
			findings: []Finding{
				{Severity: SeverityMedium},
			},
			expectedScore: 90,
			expectedGrade: "A",
		},
		{
			name: "High finding",
			findings: []Finding{
				{Severity: SeverityHigh},
			},
			expectedScore: 80,
			expectedGrade: "B",
		},
		{
			name: "Critical finding",
			findings: []Finding{
				{Severity: SeverityCritical},
			},
			expectedScore: 65,
			expectedGrade: "D",
		},
		{
			name: "Multiple severe findings clamp to zero",
			findings: []Finding{
				{Severity: SeverityCritical},
				{Severity: SeverityCritical},
				{Severity: SeverityCritical},
				{Severity: SeverityCritical},
			},
			expectedScore: 0,
			expectedGrade: "F",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, grade := calculateScoreAndGrade(tt.findings)
			if score != tt.expectedScore {
				t.Errorf("expected score %d, got %d", tt.expectedScore, score)
			}
			if grade != tt.expectedGrade {
				t.Errorf("expected grade %s, got %s", tt.expectedGrade, grade)
			}
		})
	}
}

func TestFingerprintMatching(t *testing.T) {
	auditor := NewTakeoverAuditor(nil, "1.1.1.1:53")

	matched := auditor.matchFingerprint("user.github.io")
	if matched == nil || matched.Service != "GitHub Pages" {
		t.Errorf("expected GitHub Pages match, got %v", matched)
	}

	matchedS3 := auditor.matchFingerprint("my-bucket.s3.amazonaws.com")
	if matchedS3 == nil || matchedS3.Service != "Amazon S3" {
		t.Errorf("expected Amazon S3 match, got %v", matchedS3)
	}

	matchedNone := auditor.matchFingerprint("custom-server.internal.net")
	if matchedNone != nil {
		t.Errorf("expected no match, got %v", matchedNone)
	}
}

func TestLiveDomainAudit(t *testing.T) {
	auditor := NewAuditor(4 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	report, err := auditor.Run(ctx, "cloudflare.com")
	if err != nil {
		t.Skipf("skipping live test due to network: %v", err)
		return
	}

	t.Logf("Audit domain: %s, Score: %d, Grade: %s, SPF: %s, DMARC: %s, MX: %s",
		report.Domain, report.Score, report.Grade, report.SPFStatus, report.DMARCStatus, report.MXStatus)

	if len(report.Findings) == 0 {
		t.Errorf("expected at least some findings/evaluations for cloudflare.com")
	}

	for _, f := range report.Findings {
		t.Logf("  [%s] %s (%s)", f.Severity, f.Title, f.Category)
	}
}
