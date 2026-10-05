package tui

import "github.com/charmbracelet/lipgloss"

// Theme defines color palette for TUI interface.
type Theme struct {
	Name       string
	Primary    lipgloss.Color
	Secondary  lipgloss.Color
	Accent     lipgloss.Color
	Background lipgloss.Color
	Text       lipgloss.Color
	Muted      lipgloss.Color
	Success    lipgloss.Color
	Warning    lipgloss.Color
	Error      lipgloss.Color
}

// Available themes
var Themes = []Theme{
	{
		Name:       "Electric Cyan",
		Primary:    lipgloss.Color("#4F46E5"),
		Secondary:  lipgloss.Color("#00F5FF"),
		Accent:     lipgloss.Color("#38BDF8"),
		Background: lipgloss.Color("#0B0F19"),
		Text:       lipgloss.Color("#F8FAFC"),
		Muted:      lipgloss.Color("#64748B"),
		Success:    lipgloss.Color("#10B981"),
		Warning:    lipgloss.Color("#F59E0B"),
		Error:      lipgloss.Color("#EF4444"),
	},
	{
		Name:       "Tokyo Night",
		Primary:    lipgloss.Color("#7AA2F7"),
		Secondary:  lipgloss.Color("#BB9AF7"),
		Accent:     lipgloss.Color("#7DCFFF"),
		Background: lipgloss.Color("#1A1B26"),
		Text:       lipgloss.Color("#C0CAF5"),
		Muted:      lipgloss.Color("#565F89"),
		Success:    lipgloss.Color("#9ECE6A"),
		Warning:    lipgloss.Color("#E0AF68"),
		Error:      lipgloss.Color("#F7768E"),
	},
	{
		Name:       "Catppuccin Mocha",
		Primary:    lipgloss.Color("#CBA6F7"),
		Secondary:  lipgloss.Color("#89B4FA"),
		Accent:     lipgloss.Color("#F5C2E7"),
		Background: lipgloss.Color("#1E1E2E"),
		Text:       lipgloss.Color("#CDD6F4"),
		Muted:      lipgloss.Color("#6C7086"),
		Success:    lipgloss.Color("#A6E3A1"),
		Warning:    lipgloss.Color("#F9E2AF"),
		Error:      lipgloss.Color("#F38BA8"),
	},
	{
		Name:       "Nord",
		Primary:    lipgloss.Color("#88C0D0"),
		Secondary:  lipgloss.Color("#81A1C1"),
		Accent:     lipgloss.Color("#5E81AC"),
		Background: lipgloss.Color("#2E3440"),
		Text:       lipgloss.Color("#ECEFF4"),
		Muted:      lipgloss.Color("#7B88A1"),
		Success:    lipgloss.Color("#A3BE8C"),
		Warning:    lipgloss.Color("#EBCB8B"),
		Error:      lipgloss.Color("#BF616A"),
	},
}
