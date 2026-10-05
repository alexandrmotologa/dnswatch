package tui

import (
	"fmt"
	"strings"

	"github.com/alexandrmotologa/dnswatch/pkg/audit"
	"github.com/charmbracelet/lipgloss"
)

var (
	gradeStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#4F46E5")).
			Padding(0, 1)

	findingCard = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(lipgloss.Color("#334155")).
			Padding(0, 0, 1, 0)
)

func renderGradeBadge(grade string) string {
	var bg lipgloss.Color
	switch grade {
	case "A+", "A":
		bg = lipgloss.Color("#059669")
	case "B":
		bg = lipgloss.Color("#0D9488")
	case "C":
		bg = lipgloss.Color("#D97706")
	case "D":
		bg = lipgloss.Color("#EA580C")
	default:
		bg = lipgloss.Color("#DC2626")
	}

	return lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(bg).
		Padding(0, 1).
		Render(fmt.Sprintf("GRADE %s", grade))
}

func renderSeverityBadge(sev audit.Severity) string {
	switch sev {
	case audit.SeverityCritical:
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#DC2626")).Padding(0, 1).Render("CRITICAL")
	case audit.SeverityHigh:
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#EA580C")).Padding(0, 1).Render("HIGH")
	case audit.SeverityMedium:
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#D97706")).Padding(0, 1).Render("MEDIUM")
	case audit.SeverityLow:
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#38BDF8")).Render("[LOW]")
	case audit.SeverityGood:
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#10B981")).Render("[PASS]")
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#94A3B8")).Render("[INFO]")
	}
}

func (m Model) renderAuditView() string {
	if m.auditResult == nil {
		if m.loading {
			return "  Scanning domain health, email authentication, and takeover risks..."
		}
		return "  No security audit data available. Press 'r' to execute audit."
	}

	res := m.auditResult
	var b strings.Builder

	b.WriteString(fmt.Sprintf("  Domain Security & Health Audit: %s\n", res.Domain))

	// Score and Grade summary
	b.WriteString(fmt.Sprintf("  Score: %s %d/100  %s\n\n",
		renderProgressBar(float64(res.Score), 20),
		res.Score,
		renderGradeBadge(res.Grade),
	))

	// Quick status overview
	b.WriteString(fmt.Sprintf("  SPF: %-12s DMARC: %-12s MX: %-12s Takeover: %-14s NS Parity: %v\n\n",
		res.SPFStatus,
		res.DMARCStatus,
		res.MXStatus,
		formatTakeoverStatus(res.TakeoverRisk),
		res.NSConsistency,
	))

	b.WriteString("  Findings & Recommendations:\n")
	b.WriteString("  ─────────────────────────────────────────────────────────────────────────────\n")

	for _, f := range res.Findings {
		b.WriteString(fmt.Sprintf("  %s %s  (%s)\n",
			renderSeverityBadge(f.Severity),
			lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F8FAFC")).Render(f.Title),
			lipgloss.NewStyle().Foreground(lipgloss.Color("#64748B")).Render(f.Category),
		))
		b.WriteString(fmt.Sprintf("    %s\n", f.Description))
		if f.Record != "" {
			b.WriteString(fmt.Sprintf("    Record: %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#94A3B8")).Render(f.Record)))
		}
		if f.Recommendation != "" {
			b.WriteString(fmt.Sprintf("    Fix: %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#38BDF8")).Render(f.Recommendation)))
		}
		b.WriteString("\n")
	}

	return b.String()
}

func formatTakeoverStatus(risk bool) string {
	if risk {
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#EF4444")).Render("VULNERABLE")
	}
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#10B981")).Render("SECURE")
}
