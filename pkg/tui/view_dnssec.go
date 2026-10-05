package tui

import (
	"fmt"
	"strings"

	"github.com/alexandrmotologa/dnswatch/pkg/dnssec"
	"github.com/charmbracelet/lipgloss"
)

var (
	secureBanner = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#059669")).
			Padding(0, 1)

	bogusBanner = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#DC2626")).
			Padding(0, 1)

	insecureBanner = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#D97706")).
			Padding(0, 1)

	chainCard = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#4338CA")).
			Padding(0, 1)
)

func (m Model) renderDNSSECView() string {
	if m.dnssecResult == nil {
		if m.loading {
			return "  Validating DNSSEC chain of trust from Root anchor..."
		}
		return "  No DNSSEC validation data available. Press 'r' to validate."
	}

	res := m.dnssecResult
	var b strings.Builder

	b.WriteString(fmt.Sprintf("  DNSSEC Trust Chain Validation: %s\n", res.Domain))

	// Overall status banner
	var banner string
	switch res.OverallStatus {
	case dnssec.StatusSecure:
		banner = secureBanner.Render("✔ SECURE — Complete Cryptographic Chain of Trust Verified")
	case dnssec.StatusBogus:
		banner = bogusBanner.Render("✖ BOGUS — Signature Verification or Digest Mismatch Detected")
	case dnssec.StatusInsecure:
		banner = insecureBanner.Render("▲ INSECURE — Zone or Parent Delegation is Unsigned")
	default:
		banner = insecureBanner.Render(fmt.Sprintf("? %s", res.OverallStatus))
	}

	b.WriteString("  " + banner + "\n\n")

	// Render chain nodes
	for i, node := range res.Chain {
		isLast := i == len(res.Chain)-1
		prefix := "├──"
		if isLast {
			prefix = "└──"
		}

		var nodeStatus string
		switch node.Status {
		case dnssec.StatusSecure:
			nodeStatus = successBadge.Render("[SECURE]")
		case dnssec.StatusBogus:
			nodeStatus = errorBadge.Render("[BOGUS]")
		case dnssec.StatusInsecure:
			nodeStatus = warningBadge.Render("[INSECURE]")
		default:
			nodeStatus = warningBadge.Render(string(node.Status))
		}

		b.WriteString(fmt.Sprintf("  %s Zone: %s %s\n",
			prefix,
			lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#38BDF8")).Render(node.Zone),
			nodeStatus,
		))

		subPrefix := "│  "
		if isLast {
			subPrefix = "   "
		}

		// Node details
		if len(node.Algorithms) > 0 {
			b.WriteString(fmt.Sprintf("  %s   Algorithms: %s\n", subPrefix, strings.Join(node.Algorithms, ", ")))
		}

		if len(node.KSKKeyTags) > 0 || len(node.ZSKKeyTags) > 0 {
			b.WriteString(fmt.Sprintf("  %s   Key Tags: KSK=%v | ZSK=%v\n", subPrefix, node.KSKKeyTags, node.ZSKKeyTags))
		}

		if node.HasDS {
			digestStatus := "✔ Matched Parent"
			if !node.DigestMatched {
				digestStatus = "✖ Digest Mismatch"
			}
			b.WriteString(fmt.Sprintf("  %s   DS Record: Tags=%v (%s)\n", subPrefix, node.DSKeyTags, digestStatus))
		}

		if node.HasRRSIG {
			sigStatus := "✔ Signatures Verified"
			if !node.SignaturesValid {
				sigStatus = "✖ Invalid Signatures"
			}
			expStr := ""
			if node.Expiration != nil {
				expStr = fmt.Sprintf(" | Expires: %s", node.Expiration.Format("2006-01-02 15:04 MST"))
			}
			b.WriteString(fmt.Sprintf("  %s   RRSIG: %s%s\n", subPrefix, sigStatus, expStr))
		}

		if len(node.Errors) > 0 {
			for _, e := range node.Errors {
				b.WriteString(fmt.Sprintf("  %s   %s: %s\n", subPrefix, errorBadge.Render("ERROR"), e))
			}
		}

		if len(node.Warnings) > 0 {
			for _, w := range node.Warnings {
				b.WriteString(fmt.Sprintf("  %s   %s: %s\n", subPrefix, warningBadge.Render("WARNING"), w))
			}
		}

		b.WriteString(fmt.Sprintf("  %s\n", subPrefix))
	}

	// Overall Errors / Warnings
	if len(res.Errors) > 0 {
		b.WriteString("  " + errorBadge.Render("Validation Errors:") + "\n")
		for _, e := range res.Errors {
			b.WriteString(fmt.Sprintf("    • %s\n", e))
		}
		b.WriteString("\n")
	}

	if len(res.Warnings) > 0 {
		b.WriteString("  " + warningBadge.Render("Cryptographic Warnings:") + "\n")
		for _, w := range res.Warnings {
			b.WriteString(fmt.Sprintf("    • %s\n", w))
		}
		b.WriteString("\n")
	}

	return b.String()
}
