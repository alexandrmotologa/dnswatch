package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func renderProgressBar(percent float64, width int) string {
	fillWidth := int((percent / 100.0) * float64(width))
	if fillWidth > width {
		fillWidth = width
	}
	emptyWidth := width - fillWidth
	if emptyWidth < 0 {
		emptyWidth = 0
	}

	filled := strings.Repeat("█", fillWidth)
	empty := strings.Repeat("░", emptyWidth)

	var color lipgloss.Color
	if percent >= 90 {
		color = lipgloss.Color("#10B981")
	} else if percent >= 60 {
		color = lipgloss.Color("#F59E0B")
	} else {
		color = lipgloss.Color("#EF4444")
	}

	barStyle := lipgloss.NewStyle().Foreground(color)
	return fmt.Sprintf("[%s%s]", barStyle.Render(filled), lipgloss.NewStyle().Foreground(lipgloss.Color("#374151")).Render(empty))
}

func (m Model) renderPropagationView() string {
	if m.propResult == nil {
		if m.loading {
			return "  Querying 25+ worldwide DNS-over-HTTPS vantage points..."
		}
		return "  No propagation data available. Press 'r' to execute propagation check."
	}

	res := m.propResult
	var b strings.Builder

	b.WriteString(fmt.Sprintf("  Worldwide Edge Propagation: %s (%s)\n", res.Domain, res.QueryType))
	b.WriteString(fmt.Sprintf("  Consensus Rate: %s %.1f%% (%d/%d Nodes) | Avg RTT: %v | Span: %v - %v\n",
		renderProgressBar(res.PropagationRate, 24),
		res.PropagationRate,
		res.SuccessCount,
		res.TotalTested,
		res.AvgRTT,
		res.MinRTT,
		res.MaxRTT,
	))

	if len(res.ConsensusAnswers) > 0 {
		b.WriteString(fmt.Sprintf("  Consensus Value(s): %s\n\n",
			lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#38BDF8")).Render(strings.Join(res.ConsensusAnswers, ", ")),
		))
	} else {
		b.WriteString("\n")
	}

	// Table header
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#94A3B8")).
		Border(lipgloss.NormalBorder(), false, false, true, false).
		BorderForeground(lipgloss.Color("#334155"))

	header := fmt.Sprintf("  %-16s %-18s %-24s %-10s %-8s %-6s %s",
		"REGION", "LOCATION", "PROVIDER", "STATUS", "RTT", "TTL", "RESOLVED ANSWER")
	b.WriteString(headerStyle.Render(header))
	b.WriteString("\n")

	for _, node := range res.Results {
		var statusStr string
		var answerStr string
		var ttlStr string

		if node.Error != "" {
			statusStr = errorBadge.Render("✖ TIMEOUT")
			answerStr = lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280")).Render(node.Error)
			ttlStr = "-"
		} else if node.MatchedConsensus {
			statusStr = successBadge.Render("✔ MATCH")
			var ansList []string
			for _, a := range node.Answers {
				ansList = append(ansList, a.Data)
			}
			answerStr = strings.Join(ansList, ", ")
			ttlStr = fmt.Sprintf("%ds", node.TTL)
		} else {
			statusStr = warningBadge.Render("▲ DIVERGENT")
			var ansList []string
			for _, a := range node.Answers {
				ansList = append(ansList, a.Data)
			}
			answerStr = strings.Join(ansList, ", ")
			ttlStr = fmt.Sprintf("%ds", node.TTL)
		}

		if len(answerStr) > 35 {
			answerStr = answerStr[:32] + "..."
		}

		line := fmt.Sprintf("  %-16s %-18s %-24s %-10s %-8s %-6s %s",
			node.Provider.Region,
			node.Provider.City,
			node.Provider.Name,
			statusStr,
			formatRTT(node.RTT),
			ttlStr,
			answerStr,
		)
		b.WriteString(line + "\n")
	}

	return b.String()
}
