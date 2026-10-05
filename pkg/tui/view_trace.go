package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

var (
	hopHeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#E0E7FF")).
			Background(lipgloss.Color("#3730A3")).
			Padding(0, 1)

	zoneStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#38BDF8"))

	serverStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F1F5F9"))

	glueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#94A3B8"))

	answerCardStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#10B981")).
			Padding(0, 1)

	rttFast = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#10B981"))

	rttMedium = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F59E0B"))

	rttSlow = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#EF4444"))
)

func formatRTT(rtt time.Duration) string {
	ms := rtt.Milliseconds()
	str := fmt.Sprintf("%dms", ms)
	if ms < 40 {
		return rttFast.Render(str)
	} else if ms < 120 {
		return rttMedium.Render(str)
	}
	return rttSlow.Render(str)
}

func (m Model) renderTraceView() string {
	if m.traceResult == nil {
		if m.loading {
			return "  Tracing recursive delegation path from Root servers..."
		}
		return "  No trace result available. Press 'r' to execute trace."
	}

	res := m.traceResult
	var b strings.Builder

	b.WriteString(fmt.Sprintf("  Recursive Trace: %s (Type: %s)\n", res.Domain, res.QueryType))
	b.WriteString(fmt.Sprintf("  Total Resolution Time: %v | Hops: %d\n\n", res.TotalRTT, len(res.Hops)))

	for i, hop := range res.Hops {
		isLast := i == len(res.Hops)-1
		prefix := "├──"
		subPrefix := "│  "
		if isLast {
			prefix = "└──"
			subPrefix = "   "
		}

		stepLabel := fmt.Sprintf("[%d] Zone: %s", hop.Step, hop.Zone)
		asnLabel := ""
		if hop.ServerInfo != nil && hop.ServerInfo.FormattedLabel() != "" {
			asnLabel = " " + lipgloss.NewStyle().Foreground(lipgloss.Color("#A78BFA")).Render(hop.ServerInfo.FormattedLabel())
		}

		b.WriteString(fmt.Sprintf("  %s %s ➔ %s (%s)%s  RTT: %s\n",
			prefix,
			hopHeaderStyle.Render(stepLabel),
			serverStyle.Render(hop.ServerName),
			hop.ServerIP,
			asnLabel,
			formatRTT(hop.RTT),
		))

		// Flags
		var flagList []string
		if hop.Authoritative {
			flagList = append(flagList, "AA (Authoritative)")
		}
		if hop.Flags.RD {
			flagList = append(flagList, "RD")
		}
		if hop.Flags.RA {
			flagList = append(flagList, "RA")
		}
		if hop.HasDNSSEC {
			flagList = append(flagList, fmt.Sprintf("DNSSEC (%d RRSIGs)", hop.RRSIGCount))
		}
		if len(flagList) > 0 {
			b.WriteString(fmt.Sprintf("  %s   Flags: [%s]\n", subPrefix, strings.Join(flagList, ", ")))
		}

		// Referrals
		if len(hop.Delegation) > 0 {
			b.WriteString(fmt.Sprintf("  %s   Referral: %s\n", subPrefix, strings.Join(hop.Delegation, ", ")))
		}

		// Glue records
		if len(hop.Glue) > 0 {
			for _, glue := range hop.Glue {
				b.WriteString(fmt.Sprintf("  %s   Glue: %s\n", subPrefix, glueStyle.Render(glue)))
			}
		}

		if hop.Error != "" {
			b.WriteString(fmt.Sprintf("  %s   Error: %s\n", subPrefix, errorBadge.Render(hop.Error)))
		}

		b.WriteString(fmt.Sprintf("  %s\n", subPrefix))
	}

	// CNAME chain
	if len(res.CNAMEChain) > 0 {
		b.WriteString("  CNAME Redirection Chain:\n")
		for _, cname := range res.CNAMEChain {
			b.WriteString(fmt.Sprintf("    ↳ %s\n", cname))
		}
		b.WriteString("\n")
	}

	// Final Answers
	if len(res.FinalAnswers) > 0 {
		var ansLines []string
		ansLines = append(ansLines, lipgloss.NewStyle().Bold(true).Render("✔ Authoritative Answer(s):"))
		for _, ans := range res.FinalAnswers {
			ansASN := ""
			if ans.IPInfo != nil && ans.IPInfo.FormattedLabel() != "" {
				ansASN = " " + lipgloss.NewStyle().Foreground(lipgloss.Color("#A78BFA")).Render(ans.IPInfo.FormattedLabel())
			}
			ansLines = append(ansLines, fmt.Sprintf("  • %-5s TTL:%-5d %s%s", ans.Type, ans.TTL, ans.Data, ansASN))
		}
		b.WriteString("  " + answerCardStyle.Render(strings.Join(ansLines, "\n")))
		b.WriteString("\n")
	} else if res.Success {
		b.WriteString("  " + warningBadge.Render("✔ Resolution Complete: Authoritative NODATA (no records of requested type)") + "\n")
	} else if res.Error != "" {
		b.WriteString("  " + errorBadge.Render("✖ Trace Failed: "+res.Error) + "\n")
	}

	return b.String()
}
