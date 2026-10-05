package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/alexandrmotologa/dnswatch/pkg/audit"
	"github.com/alexandrmotologa/dnswatch/pkg/dnssec"
	"github.com/alexandrmotologa/dnswatch/pkg/propagation"
	"github.com/alexandrmotologa/dnswatch/pkg/trace"
	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/miekg/dns"
)

// Tab represents active dashboard view.
type Tab int

const (
	TabTrace Tab = iota
	TabPropagation
	TabDNSSEC
	TabAudit
)

// Supported record types
var queryTypes = []uint16{
	dns.TypeA,
	dns.TypeAAAA,
	dns.TypeCNAME,
	dns.TypeMX,
	dns.TypeTXT,
	dns.TypeNS,
	dns.TypeSOA,
	dns.TypeCAA,
	dns.TypePTR,
}

// Model is the Bubble Tea root state.
type Model struct {
	domain         string
	qtypeIdx       int
	activeTab      Tab
	input          textinput.Model
	isEditingInput bool
	spinner        spinner.Model
	loading        bool
	statusMsg      string
	viewport       viewport.Model
	width          int
	height         int
	showHelp       bool
	themeIdx       int

	// Engine instances
	walker         *trace.Walker
	propRunner     *propagation.Runner
	dnssecVal      *dnssec.Validator
	auditor        *audit.Auditor

	// Engine results
	traceResult    *trace.TraceResult
	propResult     *propagation.PropagationSummary
	dnssecResult   *dnssec.ValidationResult
	auditResult    *audit.AuditReport
}

// Msg types
type traceDoneMsg struct{ res *trace.TraceResult }
type propDoneMsg struct{ res *propagation.PropagationSummary }
type dnssecDoneMsg struct{ res *dnssec.ValidationResult }
type auditDoneMsg struct{ res *audit.AuditReport }
type errMsg struct{ err error }

// NewModel creates an initialized TUI model.
func NewModel(initialDomain string) Model {
	if initialDomain == "" {
		initialDomain = "example.com"
	}
	initialDomain = strings.TrimSuffix(initialDomain, ".")

	ti := textinput.New()
	ti.Placeholder = "Enter domain (e.g. cloudflare.com)..."
	ti.SetValue(initialDomain)
	ti.CharLimit = 255
	ti.Width = 35

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#00d2ff"))

	vp := viewport.New(80, 20)

	cfg := trace.DefaultWalkerConfig()
	cfg.Timeout = 3 * time.Second

	return Model{
		domain:         initialDomain,
		qtypeIdx:       0, // TypeA
		activeTab:      TabTrace,
		input:          ti,
		isEditingInput: false,
		spinner:        s,
		loading:        false,
		viewport:       vp,
		walker:         trace.NewWalker(cfg),
		propRunner:     propagation.NewRunner(propagation.DefaultRunnerConfig(), nil),
		dnssecVal:      dnssec.NewValidator(4 * time.Second),
		auditor:        audit.NewAuditor(4 * time.Second),
	}
}

// Init triggers initial data loading.
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		m.fetchCurrentTab(),
	)
}

// CurrentQType returns active DNS RR type.
func (m Model) CurrentQType() uint16 {
	return queryTypes[m.qtypeIdx]
}

// CurrentQTypeStr returns string name of active RR type.
func (m Model) CurrentQTypeStr() string {
	return dns.TypeToString[m.CurrentQType()]
}

// Theme returns active color theme.
func (m Model) Theme() Theme {
	if len(Themes) == 0 {
		return Theme{
			Name:       "Default",
			Primary:    lipgloss.Color("#4F46E5"),
			Secondary:  lipgloss.Color("#00F5FF"),
			Accent:     lipgloss.Color("#38BDF8"),
			Background: lipgloss.Color("#0B0F19"),
			Text:       lipgloss.Color("#F8FAFC"),
			Muted:      lipgloss.Color("#64748B"),
			Success:    lipgloss.Color("#10B981"),
			Warning:    lipgloss.Color("#F59E0B"),
			Error:      lipgloss.Color("#EF4444"),
		}
	}
	return Themes[m.themeIdx%len(Themes)]
}

// fetchCurrentTab dispatches query for the active tab.
func (m Model) fetchCurrentTab() tea.Cmd {
	m.loading = true
	domain := m.domain
	qtype := m.CurrentQType()

	switch m.activeTab {
	case TabTrace:
		return func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			res, err := m.walker.Trace(ctx, domain, qtype)
			if err != nil && res == nil {
				return errMsg{err}
			}
			return traceDoneMsg{res}
		}
	case TabPropagation:
		return func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			res, err := m.propRunner.Check(ctx, domain, qtype)
			if err != nil {
				return errMsg{err}
			}
			return propDoneMsg{res}
		}
	case TabDNSSEC:
		return func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			res, err := m.dnssecVal.ValidateDomain(ctx, domain, qtype)
			if err != nil {
				return errMsg{err}
			}
			return dnssecDoneMsg{res}
		}
	case TabAudit:
		return func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			res, err := m.auditor.Run(ctx, domain)
			if err != nil {
				return errMsg{err}
			}
			return auditDoneMsg{res}
		}
	}
	return nil
}

// Update handles events and state transitions.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.isEditingInput {
			switch msg.Type {
			case tea.KeyEnter:
				m.isEditingInput = false
				m.input.Blur()
				newDomain := strings.TrimSpace(m.input.Value())
				if newDomain != "" {
					m.domain = newDomain
					m.loading = true
					m.traceResult = nil
					m.propResult = nil
					m.dnssecResult = nil
					m.auditResult = nil
					return m, m.fetchCurrentTab()
				}
			case tea.KeyEsc:
				m.isEditingInput = false
				m.input.Blur()
				m.input.SetValue(m.domain)
			default:
				var cmd tea.Cmd
				m.input, cmd = m.input.Update(msg)
				return m, cmd
			}
			return m, nil
		}

		// Global navigation keys
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "/":
			m.isEditingInput = true
			m.input.Focus()
			return m, textinput.Blink
		case "j", "down":
			m.viewport.LineDown(1)
			return m, nil
		case "k", "up":
			m.viewport.LineUp(1)
			return m, nil
		case "d", "ctrl+d":
			m.viewport.HalfViewDown()
			return m, nil
		case "u", "ctrl+u":
			m.viewport.HalfViewUp()
			return m, nil
		case "g":
			m.viewport.GotoTop()
			return m, nil
		case "G":
			m.viewport.GotoBottom()
			return m, nil
		case "m", "M":
			m.themeIdx = (m.themeIdx + 1) % len(Themes)
			m.statusMsg = fmt.Sprintf("Theme: %s", m.Theme().Name)
			m.updateViewportContent()
			return m, nil
		case "y", "c":
			content := m.viewport.View()
			if err := clipboard.WriteAll(content); err != nil {
				m.statusMsg = fmt.Sprintf("Clipboard error: %v", err)
			} else {
				m.statusMsg = "✓ Copied view to clipboard!"
			}
			return m, nil
		case "tab":
			m.activeTab = (m.activeTab + 1) % 4
			m.viewport.SetYOffset(0)
			m.statusMsg = ""
			if m.shouldRefreshTab() {
				return m, m.fetchCurrentTab()
			}
			m.updateViewportContent()
			return m, nil
		case "shift+tab":
			m.activeTab = (m.activeTab + 3) % 4
			m.viewport.SetYOffset(0)
			m.statusMsg = ""
			if m.shouldRefreshTab() {
				return m, m.fetchCurrentTab()
			}
			m.updateViewportContent()
			return m, nil
		case "1":
			m.activeTab = TabTrace
			m.viewport.SetYOffset(0)
			m.statusMsg = ""
			if m.traceResult == nil {
				return m, m.fetchCurrentTab()
			}
			m.updateViewportContent()
			return m, nil
		case "2":
			m.activeTab = TabPropagation
			m.viewport.SetYOffset(0)
			m.statusMsg = ""
			if m.propResult == nil {
				return m, m.fetchCurrentTab()
			}
			m.updateViewportContent()
			return m, nil
		case "3":
			m.activeTab = TabDNSSEC
			m.viewport.SetYOffset(0)
			m.statusMsg = ""
			if m.dnssecResult == nil {
				return m, m.fetchCurrentTab()
			}
			m.updateViewportContent()
			return m, nil
		case "4":
			m.activeTab = TabAudit
			m.viewport.SetYOffset(0)
			m.statusMsg = ""
			if m.auditResult == nil {
				return m, m.fetchCurrentTab()
			}
			m.updateViewportContent()
			return m, nil
		case "t", "T":
			m.qtypeIdx = (m.qtypeIdx + 1) % len(queryTypes)
			m.loading = true
			m.statusMsg = ""
			m.traceResult = nil
			m.propResult = nil
			m.dnssecResult = nil
			return m, m.fetchCurrentTab()
		case "r", "R":
			m.loading = true
			m.statusMsg = ""
			return m, m.fetchCurrentTab()
		case "?":
			m.showHelp = !m.showHelp
			return m, nil
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		headerHeight := 6
		footerHeight := 3
		m.viewport.Width = msg.Width - 4
		m.viewport.Height = msg.Height - headerHeight - footerHeight
		m.updateViewportContent()

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case traceDoneMsg:
		m.loading = false
		m.traceResult = msg.res
		m.updateViewportContent()

	case propDoneMsg:
		m.loading = false
		m.propResult = msg.res
		m.updateViewportContent()

	case dnssecDoneMsg:
		m.loading = false
		m.dnssecResult = msg.res
		m.updateViewportContent()

	case auditDoneMsg:
		m.loading = false
		m.auditResult = msg.res
		m.updateViewportContent()

	case errMsg:
		m.loading = false
		m.statusMsg = fmt.Sprintf("Error: %v", msg.err)
		m.updateViewportContent()
	}

	// Update viewport scrolling
	var vpCmd tea.Cmd
	m.viewport, vpCmd = m.viewport.Update(msg)
	cmds = append(cmds, vpCmd)

	return m, tea.Batch(cmds...)
}

func (m Model) shouldRefreshTab() bool {
	switch m.activeTab {
	case TabTrace:
		return m.traceResult == nil
	case TabPropagation:
		return m.propResult == nil
	case TabDNSSEC:
		return m.dnssecResult == nil
	case TabAudit:
		return m.auditResult == nil
	}
	return false
}

// updateViewportContent refreshes rendered text inside viewport.
func (m *Model) updateViewportContent() {
	var content string
	switch m.activeTab {
	case TabTrace:
		content = m.renderTraceView()
	case TabPropagation:
		content = m.renderPropagationView()
	case TabDNSSEC:
		content = m.renderDNSSECView()
	case TabAudit:
		content = m.renderAuditView()
	}
	m.viewport.SetContent(content)
}

// View compiles UI output.
func (m Model) View() string {
	if m.width == 0 {
		return "Initializing DNSWatch..."
	}

	var b strings.Builder
	b.WriteString(m.renderHeader())
	b.WriteString("\n")

	if m.loading {
		loadingBar := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00d2ff")).
			Padding(1, 2).
			Render(fmt.Sprintf("%s Querying %s (%s)...", m.spinner.View(), m.domain, m.CurrentQTypeStr()))
		b.WriteString(loadingBar)
		b.WriteString("\n")
	}

	b.WriteString(m.viewport.View())
	b.WriteString("\n")
	b.WriteString(m.renderFooter())

	if m.showHelp {
		return m.renderHelpModal(b.String())
	}

	return b.String()
}

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#4F46E5")).
			Padding(0, 1)

	activeTabStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00F5FF")).
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(lipgloss.Color("#00F5FF")).
			Padding(0, 1)

	inactiveTabStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#888888")).
				Padding(0, 1)

	domainStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#38BDF8"))

	typeBadgeStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F59E0B")).
			Background(lipgloss.Color("#1E293B")).
			Padding(0, 1)

	footerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6B7280")).
			Padding(0, 1)

	successBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#10B981"))

	warningBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F59E0B"))

	errorBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#EF4444"))
)

func (m Model) renderHeader() string {
	th := m.Theme()
	tabs := []string{"[1] Trace", "[2] Propagation", "[3] DNSSEC", "[4] Security Audit"}
	var renderedTabs []string

	curActiveTabStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(th.Secondary).
		Border(lipgloss.NormalBorder(), false, false, true, false).
		BorderForeground(th.Secondary).
		Padding(0, 1)

	curInactiveTabStyle := lipgloss.NewStyle().
		Foreground(th.Muted).
		Padding(0, 1)

	for i, t := range tabs {
		if Tab(i) == m.activeTab {
			renderedTabs = append(renderedTabs, curActiveTabStyle.Render(t))
		} else {
			renderedTabs = append(renderedTabs, curInactiveTabStyle.Render(t))
		}
	}

	curTitleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(th.Primary).
		Padding(0, 1)

	curDomainStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(th.Accent)

	themeBadge := lipgloss.NewStyle().
		Foreground(th.Muted).
		Render(fmt.Sprintf("[%s]", th.Name))

	topBar := lipgloss.JoinHorizontal(
		lipgloss.Center,
		curTitleStyle.Render("⚡ DNSWatch"),
		"  ",
		curDomainStyle.Render(m.domain),
		" ",
		typeBadgeStyle.Render(m.CurrentQTypeStr()),
		"  ",
		themeBadge,
	)

	navBar := strings.Join(renderedTabs, " ")

	return lipgloss.JoinVertical(lipgloss.Left, topBar, navBar)
}

func (m Model) renderFooter() string {
	th := m.Theme()

	if m.isEditingInput {
		return lipgloss.JoinHorizontal(
			lipgloss.Center,
			"Target: ",
			m.input.View(),
			" (Enter to query, Esc to cancel)",
		)
	}

	shortcuts := "[/] Domain  [t] Type  [1-4/Tab] Tabs  [j/k] Scroll  [y] Copy  [m] Theme  [r] Refresh  [?] Help  [q] Quit"

	if m.statusMsg != "" {
		statusBadge := lipgloss.NewStyle().
			Bold(true).
			Foreground(th.Success).
			Render(m.statusMsg)
		return lipgloss.JoinHorizontal(
			lipgloss.Left,
			statusBadge,
			"  │  ",
			footerStyle.Render(shortcuts),
		)
	}

	return footerStyle.Render(shortcuts)
}

func (m Model) renderHelpModal(background string) string {
	th := m.Theme()
	helpText := fmt.Sprintf(`
  ⚡ DNSWatch Keybindings (Theme: %s)
  ─────────────────────────────────────────────────────────────
  /              : Edit domain name
  t / T          : Cycle query type (A, AAAA, CNAME, MX, TXT, NS, SOA, CAA)
  1, 2, 3, 4     : Direct tab jump (Trace, Propagation, DNSSEC, Audit)
  Tab / Shift+Tab: Next / Previous tab
  j / k, ↑ / ↓   : Scroll viewport 1 line (Vim style)
  d / u          : Scroll viewport half-page down / up
  g / G          : Jump to top / bottom of current view
  y / c          : Copy rendered text to system clipboard
  m / M          : Cycle visual theme (Electric, Tokyo Night, Catppuccin, Nord)
  r / R          : Refresh active tab query
  ?              : Toggle this help dialog
  q / Ctrl+C     : Exit DNSWatch
`, th.Name)

	modal := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(th.Primary).
		Background(lipgloss.Color("#0F172A")).
		Padding(1, 2).
		Render(helpText)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal)
}
