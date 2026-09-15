package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Xsamsx/SBOMber/internal/verify"
)

// Styles - using ANSI 256 colors for better light/dark terminal compatibility
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("33")). // Blue
			MarginBottom(1)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("243")). // Medium gray
			Italic(true)

	selectedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("40")) // Green

	unselectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("250")) // Light gray (visible on dark bg)

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")) // Medium-light gray

	accentStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("39")) // Cyan

	successStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("40")) // Green

	bannerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("39")). // Cyan
			MarginLeft(2)

	inputStyle = lipgloss.NewStyle().
			Bold(true)
)

// View states
type viewState int

const (
	viewMenu viewState = iota
	viewFormat
	viewVulnScan
	viewPathInput
	viewScanning
	viewDone
	viewGitHubToken
	viewGitHubURLs
	viewGitHubFormat
	viewGitHubHealth
	viewGitHubVulns
	viewGitHubStatus
)

// Menu item
type menuItem struct {
	label string
	desc  string
}

// TUI model
type model struct {
	state         viewState
	cursor        int
	items         []menuItem
	formats       []menuItem
	vulnOptions   []menuItem
	healthOptions []menuItem
	selected      string
	scanPath      string
	scanFormat    string
	includeVulns  bool
	pathInput     string
	quitting      bool
	githubToken   string
	githubURLs    string
	includeHealth bool
	tokenSaved    bool
}

func newModel() model {
	return model{
		state: viewMenu,
		items: []menuItem{
			{label: "Scan current folder", desc: "Scan repos in the current directory"},
			{label: "Scan custom folder", desc: "Choose a folder to scan"},
			{label: "Scan GitHub repos", desc: "Scan remote GitHub repositories"},
			{label: "GitHub API status", desc: "Check rate limits and token"},
			{label: "Open reports folder", desc: "Open ~/.sbomber/reports"},
			{label: "Version", desc: "Show SBOMber version"},
			{label: "Help", desc: "Show usage information"},
			{label: "Exit", desc: "Quit SBOMber"},
		},
		formats: []menuItem{
			{label: "CycloneDX", desc: "recommended"},
			{label: "SPDX", desc: "alternative standard"},
			{label: "Both", desc: "generate both formats"},
		},
		vulnOptions: []menuItem{
			{label: "Yes", desc: "scan for CVEs using Grype"},
			{label: "No", desc: "skip vulnerability scanning"},
		},
		healthOptions: []menuItem{
			{label: "Yes", desc: "check dependency health metrics"},
			{label: "No", desc: "skip health analysis"},
		},
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch m.state {
		case viewMenu:
			return m.updateMenu(msg)
		case viewFormat:
			return m.updateFormat(msg)
		case viewVulnScan:
			return m.updateVulnScan(msg)
		case viewPathInput:
			return m.updatePathInput(msg)
		case viewScanning, viewDone:
			return m.updatePost(msg)
		case viewGitHubToken:
			return m.updateGitHubToken(msg)
		case viewGitHubURLs:
			return m.updateGitHubURLs(msg)
		case viewGitHubFormat:
			return m.updateGitHubFormat(msg)
		case viewGitHubHealth:
			return m.updateGitHubHealth(msg)
		case viewGitHubVulns:
			return m.updateGitHubVulns(msg)
		case viewGitHubStatus:
			return m.updateGitHubStatus(msg)
		}
	}
	return m, nil
}

func (m model) updateMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.items)-1 {
			m.cursor++
		}
	case "enter":
		switch m.cursor {
		case 0: // Scan current folder
			m.scanPath = "."
			m.state = viewFormat
			m.cursor = 0
		case 1: // Scan custom folder
			m.state = viewPathInput
			m.pathInput = ""
		case 2: // Scan GitHub repos
			m.githubToken = getGitHubToken()
			if m.githubToken == "" {
				m.state = viewGitHubToken
			} else {
				m.tokenSaved = true
				m.state = viewGitHubURLs
			}
			m.githubURLs = ""
		case 3: // GitHub API status
			m.state = viewGitHubStatus
			m.cursor = 0
		case 4: // Open reports folder
			m.selected = "open-reports"
			m.state = viewDone
		case 5: // Version
			m.selected = "version"
			m.state = viewDone
		case 6: // Help
			m.selected = "help"
			m.state = viewDone
		case 7: // Exit
			m.quitting = true
			return m, tea.Quit
		}
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) updateFormat(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.formats)-1 {
			m.cursor++
		}
	case "enter":
		switch m.cursor {
		case 0:
			m.scanFormat = formatCycloneDX
		case 1:
			m.scanFormat = formatSPDX
		case 2:
			m.scanFormat = formatBoth
		}
		m.state = viewVulnScan
		m.cursor = 0
	case "esc":
		m.state = viewMenu
		m.cursor = 0
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) updateVulnScan(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.vulnOptions)-1 {
			m.cursor++
		}
	case "enter":
		m.includeVulns = m.cursor == 0
		m.selected = "scan"
		m.state = viewScanning
		return m, tea.Quit
	case "esc":
		m.state = viewFormat
		m.cursor = 0
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) updatePathInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		if m.pathInput == "" {
			m.pathInput = "."
		}
		m.scanPath = m.pathInput
		m.state = viewFormat
		m.cursor = 0
	case tea.KeyBackspace:
		if len(m.pathInput) > 0 {
			m.pathInput = m.pathInput[:len(m.pathInput)-1]
		}
	case tea.KeyEsc:
		m.state = viewMenu
		m.cursor = 0
	case tea.KeyCtrlC:
		m.quitting = true
		return m, tea.Quit
	case tea.KeyTab:
		m.pathInput = expandPathWithTab(m.pathInput)
	case tea.KeySpace:
		m.pathInput += " "
	case tea.KeyRunes:
		m.pathInput += string(msg.Runes)
	}
	return m, nil
}

func (m model) updateGitHubToken(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		if m.githubToken != "" {
			if err := saveGitHubToken(m.githubToken); err != nil {
				m.tokenSaved = false
				m.state = viewGitHubURLs
				return m, nil
			}
			m.tokenSaved = true
			m.state = viewGitHubURLs
		}
	case tea.KeyBackspace:
		if len(m.githubToken) > 0 {
			m.githubToken = m.githubToken[:len(m.githubToken)-1]
		}
	case tea.KeyEsc:
		m.state = viewMenu
		m.cursor = 2
	case tea.KeyCtrlC:
		m.quitting = true
		return m, tea.Quit
	case tea.KeyRunes:
		m.githubToken += string(msg.Runes)
	}
	return m, nil
}

func (m model) updateGitHubURLs(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		if m.githubURLs != "" {
			m.state = viewGitHubFormat
			m.cursor = 0
		}
	case tea.KeyBackspace:
		if len(m.githubURLs) > 0 {
			m.githubURLs = m.githubURLs[:len(m.githubURLs)-1]
		}
	case tea.KeyEsc:
		m.state = viewMenu
		m.cursor = 2
	case tea.KeyCtrlC:
		m.quitting = true
		return m, tea.Quit
	case tea.KeySpace:
		m.githubURLs += " "
	case tea.KeyRunes:
		m.githubURLs += string(msg.Runes)
	}
	return m, nil
}

func (m model) updateGitHubFormat(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.formats)-1 {
			m.cursor++
		}
	case "enter":
		switch m.cursor {
		case 0:
			m.scanFormat = formatCycloneDX
		case 1:
			m.scanFormat = formatSPDX
		case 2:
			m.scanFormat = formatBoth
		}
		m.state = viewGitHubHealth
		m.cursor = 0
	case "esc":
		m.state = viewGitHubURLs
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) updateGitHubHealth(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.healthOptions)-1 {
			m.cursor++
		}
	case "enter":
		m.includeHealth = m.cursor == 0
		m.state = viewGitHubVulns
		m.cursor = 0
	case "esc":
		m.state = viewGitHubFormat
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) updateGitHubVulns(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.vulnOptions)-1 {
			m.cursor++
		}
	case "enter":
		m.includeVulns = m.cursor == 0
		m.selected = "github"
		m.state = viewScanning
		return m, tea.Quit
	case "esc":
		m.state = viewGitHubHealth
		m.cursor = 0
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) updatePost(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter", "esc", "q", "ctrl+c":
		if m.selected == "version" || m.selected == "help" {
			m.state = viewMenu
			m.cursor = 0
			m.selected = ""
			return m, nil
		}
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(renderBanner())
	b.WriteString("\n")

	switch m.state {
	case viewMenu:
		b.WriteString(m.renderMenu())
	case viewFormat:
		b.WriteString(m.renderFormatSelect())
	case viewVulnScan:
		b.WriteString(m.renderVulnScan())
	case viewPathInput:
		b.WriteString(m.renderPathInput())
	case viewDone:
		b.WriteString(m.renderDone())
	case viewGitHubToken:
		b.WriteString(m.renderGitHubToken())
	case viewGitHubURLs:
		b.WriteString(m.renderGitHubURLs())
	case viewGitHubFormat:
		b.WriteString(m.renderGitHubFormat())
	case viewGitHubHealth:
		b.WriteString(m.renderGitHubHealth())
	case viewGitHubVulns:
		b.WriteString(m.renderGitHubVulns())
	case viewGitHubStatus:
		b.WriteString(m.renderGitHubStatusView())
	}

	return b.String()
}

func renderBanner() string {
	banner := `  ____  ____   ___  __  __ ____
 / ___|| __ ) / _ \|  \/  | __ )  ___ _ __
 \___ \|  _ \| | | | |\/| |  _ \ / _ \ '__|
  ___) | |_) | |_| | |  | | |_) |  __/ |
 |____/|____/ \___/|_|  |_|____/ \___|_|`

	// Show small gamification state: scans completed and badge
	st := loadUIState()
	scansText := fmt.Sprintf("Scans completed: %d", st.Scans)
	badge := badgeForScans(st.Scans)

	return bannerStyle.Render(banner) + "\n" +
		lipgloss.NewStyle().MarginLeft(2).Foreground(lipgloss.Color("#666666")).Render("  v"+version) + "\n\n" +
		lipgloss.NewStyle().MarginLeft(2).Foreground(lipgloss.Color("#888888")).Render("  A lightweight CLI for scanning local repositories and generating SBOMs.") + "\n\n" +
		lipgloss.NewStyle().MarginLeft(2).Foreground(lipgloss.Color("39")).Bold(true).Render("  "+badge+" ") + lipgloss.NewStyle().MarginLeft(0).Foreground(lipgloss.Color("245")).Render(" "+scansText) + "\n\n"
}

// uiState holds persistent interactive UI metadata
type uiState struct {
	Scans    int    `json:"scans"`
	LastScan string `json:"last_scan,omitempty"`
}

func stateFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	dir := filepath.Join(home, ".sbomber")
	_ = os.MkdirAll(dir, 0755)
	return filepath.Join(dir, "state.json")
}

func loadUIState() uiState {
	path := stateFilePath()
	if path == "" {
		return uiState{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return uiState{}
	}
	var s uiState
	if err := json.Unmarshal(data, &s); err != nil {
		return uiState{}
	}
	return s
}

func saveUIState(s uiState) {
	path := stateFilePath()
	if path == "" {
		return
	}
	data, _ := json.MarshalIndent(s, "", "  ")
	_ = os.WriteFile(path, data, 0644)
}

func incrementScanCount() {
	s := loadUIState()
	s.Scans++
	s.LastScan = time.Now().Format(time.RFC3339)
	saveUIState(s)
}

func badgeForScans(n int) string {
	switch {
	case n >= 100:
		return "🏆 Legend"
	case n >= 50:
		return "🥇 Veteran"
	case n >= 10:
		return "🎖️ Explorer"
	case n >= 1:
		return "✨ Rookie"
	default:
		return "🌱 Newbie"
	}
}

func (m model) renderMenu() string {
	var b strings.Builder

	header := titleStyle.MarginLeft(2).Render("  SELECT AN OPTION")
	b.WriteString(header + "\n\n")

	for i, item := range m.items {
		cursor := "  "
		label := unselectedStyle.Render(item.label)
		desc := dimStyle.Render(item.desc)
		bullet := dimStyle.Render("○")

		if m.cursor == i {
			cursor = selectedStyle.Render("▸ ")
			label = selectedStyle.Render(item.label)
			bullet = successStyle.Render("●")
			desc = subtitleStyle.Render(item.desc)
		}

		line := fmt.Sprintf("  %s %s %s  %s", cursor, bullet, label, desc)
		b.WriteString(line + "\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  ↑/↓ navigate  enter select  q quit") + "\n")

	return b.String()
}

func (m model) renderFormatSelect() string {
	var b strings.Builder

	header := titleStyle.MarginLeft(2).Render("  SBOM EXPORT FORMAT")
	b.WriteString(header + "\n\n")

	scanLabel := accentStyle.Render(m.scanPath)
	b.WriteString(dimStyle.MarginLeft(2).Render("  Scanning: ") + scanLabel + "\n\n")

	for i, item := range m.formats {
		cursor := "  "
		label := unselectedStyle.Render(item.label)
		desc := dimStyle.Render(item.desc)
		bullet := dimStyle.Render("○")

		if m.cursor == i {
			cursor = selectedStyle.Render("▸ ")
			label = selectedStyle.Render(item.label)
			bullet = successStyle.Render("●")
			desc = subtitleStyle.Render(item.desc)
		}

		line := fmt.Sprintf("  %s %s %s  %s", cursor, bullet, label, desc)
		b.WriteString(line + "\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  ↑/↓ navigate  enter select  esc back") + "\n")

	return b.String()
}

func (m model) renderVulnScan() string {
	var b strings.Builder

	header := titleStyle.MarginLeft(2).Render("  VULNERABILITY SCANNING")
	b.WriteString(header + "\n\n")

	scanLabel := accentStyle.Render(m.scanPath)
	formatLabel := accentStyle.Render(m.scanFormat)
	b.WriteString(dimStyle.MarginLeft(2).Render("  Scanning: ") + scanLabel + "\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  Format: ") + formatLabel + "\n\n")

	b.WriteString(dimStyle.MarginLeft(2).Render("  Include vulnerability scan with Grype?") + "\n\n")

	for i, item := range m.vulnOptions {
		cursor := "  "
		label := unselectedStyle.Render(item.label)
		desc := dimStyle.Render(item.desc)
		bullet := dimStyle.Render("○")

		if m.cursor == i {
			cursor = selectedStyle.Render("▸ ")
			label = selectedStyle.Render(item.label)
			bullet = successStyle.Render("●")
			desc = subtitleStyle.Render(item.desc)
		}

		line := fmt.Sprintf("  %s %s %s  %s", cursor, bullet, label, desc)
		b.WriteString(line + "\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  ↑/↓ navigate  enter select  esc back") + "\n")

	return b.String()
}

func (m model) renderPathInput() string {
	var b strings.Builder

	header := titleStyle.MarginLeft(2).Render("  ENTER FOLDER PATH")
	b.WriteString(header + "\n\n")

	prompt := inputStyle.Render("  Path: ")
	cursor := accentStyle.Render("█")
	input := accentStyle.Render(m.pathInput)

	b.WriteString("  " + prompt + input + cursor + "\n\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  enter confirm  esc back") + "\n")

	return b.String()
}

func (m model) renderDone() string {
	var b strings.Builder

	switch m.selected {
	case "version":
		ver := accentStyle.Render("SBOMber") + " " + dimStyle.Render("v"+version)
		b.WriteString("  " + ver + "\n\n")
		b.WriteString(dimStyle.MarginLeft(2).Render("  Press Enter to return to menu") + "\n")
	case "help":
		b.WriteString(renderHelp())
		b.WriteString("\n")
		b.WriteString(dimStyle.MarginLeft(2).Render("  Press Enter to return to menu") + "\n")
	case "github-status":
		b.WriteString(renderGitHubStatus())
		b.WriteString("\n")
		b.WriteString(dimStyle.MarginLeft(2).Render("  Press Enter to return to menu") + "\n")
	case "open-reports":
		b.WriteString(titleStyle.MarginLeft(2).Render("  OPENING REPORTS FOLDER") + "\n\n")
		reportsDir := filepath.Join(os.Getenv("HOME"), ".sbomber", "reports")
		b.WriteString(dimStyle.MarginLeft(2).Render("  "+reportsDir) + "\n\n")
		openFolder(reportsDir)
		b.WriteString(dimStyle.MarginLeft(2).Render("  Press Enter to return to menu") + "\n")
	}

	return b.String()
}

func renderHelp() string {
	var b strings.Builder

	b.WriteString(titleStyle.MarginLeft(2).Render("  USAGE") + "\n\n")
	_, _ = fmt.Fprintf(&b, "  %s                                     %s\n", accentStyle.Render("  sbomber"), dimStyle.Render("Interactive mode"))
	_, _ = fmt.Fprintf(&b, "  %s [path] [flags]                 %s\n", accentStyle.Render("  sbomber scan"), dimStyle.Render("Scan repositories"))
	_, _ = fmt.Fprintf(&b, "  %s <url> [flags]              %s\n", accentStyle.Render("  sbomber github"), dimStyle.Render("Scan GitHub repos"))
	_, _ = fmt.Fprintf(&b, "  %s                             %s\n\n", accentStyle.Render("  sbomber version"), dimStyle.Render("Show version"))

	b.WriteString(titleStyle.MarginLeft(2).Render("  FLAGS") + "\n\n")
	_, _ = fmt.Fprintf(&b, "  %s   cyclonedx | spdx | both          %s\n", accentStyle.Render("  --format"), dimStyle.Render("(default: cyclonedx)"))
	_, _ = fmt.Fprintf(&b, "  %s             %s\n", accentStyle.Render("  --include-vulnerabilities"), dimStyle.Render("scan vulnerabilities with Grype"))
	_, _ = fmt.Fprintf(&b, "  %s                          %s\n\n", accentStyle.Render("  --health"), dimStyle.Render("include supply chain health metrics"))

	b.WriteString(titleStyle.MarginLeft(2).Render("  VULNERABILITY SCANNING") + "\n\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  SBOMber uses Grype when vulnerability scanning is enabled.") + "\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  Install Grype from https://github.com/anchore/grype.") + "\n")

	return b.String()
}

func renderGitHubStatus() string {
	var b strings.Builder

	b.WriteString(titleStyle.MarginLeft(2).Render("  GITHUB API STATUS") + "\n\n")

	token := getGitHubToken()
	if token == "" {
		b.WriteString(dimStyle.MarginLeft(2).Render("  Token: ") + lipgloss.NewStyle().Foreground(lipgloss.Color("#f85149")).Render("Not configured") + "\n")
		b.WriteString(dimStyle.MarginLeft(2).Render("  Rate limit: 60 requests/hour (unauthenticated)") + "\n\n")
		b.WriteString(dimStyle.MarginLeft(2).Render("  Set up a token via 'Scan GitHub repos' menu option") + "\n")
		b.WriteString(dimStyle.MarginLeft(2).Render("  or set GITHUB_TOKEN environment variable.") + "\n")
		return b.String()
	}

	b.WriteString(dimStyle.MarginLeft(2).Render("  Token: ") + successStyle.Render("Configured ✓") + "\n\n")

	// Fetch actual rate limit from GitHub API
	status := fetchGitHubRateLimit(token)
	b.WriteString(status)

	return b.String()
}

func fetchGitHubRateLimit(token string) string {
	var b strings.Builder

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", "https://api.github.com/rate_limit", nil)
	if err != nil {
		b.WriteString(dimStyle.MarginLeft(2).Render("  Error fetching rate limit") + "\n")
		return b.String()
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "SBOMber")

	resp, err := client.Do(req)
	if err != nil {
		b.WriteString(dimStyle.MarginLeft(2).Render("  Error connecting to GitHub API") + "\n")
		return b.String()
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		Resources struct {
			Core struct {
				Limit     int   `json:"limit"`
				Remaining int   `json:"remaining"`
				Reset     int64 `json:"reset"`
			} `json:"core"`
		} `json:"resources"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		b.WriteString(dimStyle.MarginLeft(2).Render("  Error parsing response") + "\n")
		return b.String()
	}

	core := result.Resources.Core
	resetTime := time.Unix(core.Reset, 0)
	timeUntilReset := time.Until(resetTime).Round(time.Minute)

	// Color based on remaining
	remainingStyle := successStyle
	if core.Remaining < 1000 {
		remainingStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#d29922"))
	}
	if core.Remaining < 100 {
		remainingStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#f85149"))
	}

	b.WriteString(dimStyle.MarginLeft(2).Render("  Rate Limit:") + "\n")
	_, _ = fmt.Fprintf(&b, "    Remaining: %s / %d\n", remainingStyle.Render(fmt.Sprintf("%d", core.Remaining)), core.Limit)
	_, _ = fmt.Fprintf(&b, "    Resets in: %s\n", dimStyle.Render(timeUntilReset.String()))
	_, _ = fmt.Fprintf(&b, "    Reset at:  %s\n\n", dimStyle.Render(resetTime.Format("15:04:05")))

	// Estimate repos that can be scanned
	// ~10 requests per repo (tree + manifests + health checks)
	estimatedRepos := core.Remaining / 15
	b.WriteString(dimStyle.MarginLeft(2).Render(fmt.Sprintf("  Estimated repos scannable: ~%d (with health metrics)", estimatedRepos)) + "\n")
	b.WriteString(dimStyle.MarginLeft(2).Render(fmt.Sprintf("  Without health metrics: ~%d repos", core.Remaining/3)) + "\n")

	return b.String()
}

func (m model) renderGitHubToken() string {
	var b strings.Builder

	header := titleStyle.MarginLeft(2).Render("  GITHUB API TOKEN")
	b.WriteString(header + "\n\n")

	b.WriteString(dimStyle.MarginLeft(2).Render("  A GitHub token is required for scanning remote repositories.") + "\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  Without a token: 60 requests/hour. With token: 5000/hour.") + "\n\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  Create one at: github.com/settings/tokens") + "\n\n")

	prompt := inputStyle.Render("  Token: ")
	cursor := accentStyle.Render("█")
	masked := strings.Repeat("•", len(m.githubToken))
	input := accentStyle.Render(masked)

	b.WriteString("  " + prompt + input + cursor + "\n\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  Token will be saved to ~/.sbomber/config.json") + "\n\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  enter continue  esc back") + "\n")

	return b.String()
}

func (m model) updateGitHubStatus(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	token := getGitHubToken()
	maxItems := 2 // "Set up token", "Back"
	if token != "" {
		maxItems = 3 // "Remove token", "Replace token", "Back"
	}

	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < maxItems-1 {
			m.cursor++
		}
	case "enter":
		if token != "" {
			switch m.cursor {
			case 0: // Remove token
				removeGitHubToken()
				m.githubToken = ""
				m.tokenSaved = false
				m.cursor = 0
			case 1: // Replace token
				m.githubToken = ""
				m.tokenSaved = false
				m.state = viewGitHubToken
				m.cursor = 0
			case 2: // Back
				m.state = viewMenu
				m.cursor = 3
			}
		} else {
			switch m.cursor {
			case 0: // Set up token
				m.githubToken = ""
				m.state = viewGitHubToken
				m.cursor = 0
			case 1: // Back
				m.state = viewMenu
				m.cursor = 3
			}
		}
	case "esc":
		m.state = viewMenu
		m.cursor = 3
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) renderGitHubStatusView() string {
	var b strings.Builder

	b.WriteString(titleStyle.MarginLeft(2).Render("  GITHUB API STATUS") + "\n\n")

	token := getGitHubToken()

	if token == "" {
		b.WriteString(dimStyle.MarginLeft(2).Render("  Token: ") +
			lipgloss.NewStyle().Foreground(lipgloss.Color("#f85149")).Render("Not configured") + "\n")
		b.WriteString(dimStyle.MarginLeft(2).Render("  Rate limit: 60 requests/hour (unauthenticated)") + "\n\n")

		actions := []string{"Set up token", "Back"}
		for i, action := range actions {
			if m.cursor == i {
				b.WriteString(selectedStyle.Render("  ▸ "+action) + "\n")
			} else {
				b.WriteString(unselectedStyle.Render("    "+action) + "\n")
			}
		}
	} else {
		b.WriteString(dimStyle.MarginLeft(2).Render("  Token: ") + successStyle.Render("Configured ✓") + "\n\n")

		status := fetchGitHubRateLimit(token)
		b.WriteString(status)
		b.WriteString("\n")

		actions := []string{"Remove token", "Replace token", "Back"}
		for i, action := range actions {
			if m.cursor == i {
				label := selectedStyle.Render("  ▸ " + action)
				if action == "Remove token" {
					label = lipgloss.NewStyle().Foreground(lipgloss.Color("#f85149")).Bold(true).Render("  ▸ " + action)
				}
				b.WriteString(label + "\n")
			} else {
				b.WriteString(unselectedStyle.Render("    "+action) + "\n")
			}
		}
	}

	b.WriteString("\n" + dimStyle.MarginLeft(2).Render("  ↑↓ navigate  enter select  esc back") + "\n")

	return b.String()
}

// removeGitHubToken clears the saved token from both the config file and env.
func removeGitHubToken() {
	_ = os.Setenv("GITHUB_TOKEN", "")
	_ = saveGitHubToken("")
}

func (m model) renderGitHubURLs() string {
	var b strings.Builder

	header := titleStyle.MarginLeft(2).Render("  GITHUB REPOSITORY URLS")
	b.WriteString(header + "\n\n")

	if m.tokenSaved {
		b.WriteString(successStyle.MarginLeft(2).Render("  ✓ GitHub token configured") + "\n\n")
	}

	b.WriteString(dimStyle.MarginLeft(2).Render("  Enter GitHub URLs separated by spaces or commas.") + "\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  Example: https://github.com/expressjs/express") + "\n\n")

	prompt := inputStyle.Render("  URLs: ")
	cursor := accentStyle.Render("█")
	input := accentStyle.Render(m.githubURLs)

	b.WriteString("  " + prompt + input + cursor + "\n\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  enter continue  esc back") + "\n")

	return b.String()
}

func (m model) renderGitHubFormat() string {
	var b strings.Builder

	header := titleStyle.MarginLeft(2).Render("  SBOM EXPORT FORMAT")
	b.WriteString(header + "\n\n")

	for i, item := range m.formats {
		cursor := "  "
		label := unselectedStyle.Render(item.label)
		desc := dimStyle.Render(item.desc)
		bullet := dimStyle.Render("○")

		if m.cursor == i {
			cursor = selectedStyle.Render("▸ ")
			label = selectedStyle.Render(item.label)
			bullet = successStyle.Render("●")
			desc = subtitleStyle.Render(item.desc)
		}

		line := fmt.Sprintf("  %s %s %s  %s", cursor, bullet, label, desc)
		b.WriteString(line + "\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  ↑/↓ navigate  enter select  esc back") + "\n")

	return b.String()
}

func (m model) renderGitHubHealth() string {
	var b strings.Builder

	header := titleStyle.MarginLeft(2).Render("  INCLUDE HEALTH METRICS?")
	b.WriteString(header + "\n\n")

	b.WriteString(dimStyle.MarginLeft(2).Render("  Health metrics show dependency risk: activity, contributors, stars.") + "\n\n")

	for i, item := range m.healthOptions {
		cursor := "  "
		label := unselectedStyle.Render(item.label)
		desc := dimStyle.Render(item.desc)
		bullet := dimStyle.Render("○")

		if m.cursor == i {
			cursor = selectedStyle.Render("▸ ")
			label = selectedStyle.Render(item.label)
			bullet = successStyle.Render("●")
			desc = subtitleStyle.Render(item.desc)
		}

		line := fmt.Sprintf("  %s %s %s  %s", cursor, bullet, label, desc)
		b.WriteString(line + "\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  ↑/↓ navigate  enter select  esc back") + "\n")

	return b.String()
}

func (m model) renderGitHubVulns() string {
	var b strings.Builder

	header := titleStyle.MarginLeft(2).Render("  INCLUDE VULNERABILITY SCANNING?")
	b.WriteString(header + "\n\n")

	b.WriteString(dimStyle.MarginLeft(2).Render("  Scans the generated SBOM for CVEs using Grype.") + "\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  Requires Grype to be installed.") + "\n\n")

	for i, item := range m.vulnOptions {
		cursor := "  "
		label := unselectedStyle.Render(item.label)
		desc := dimStyle.Render(item.desc)
		bullet := dimStyle.Render("○")

		if m.cursor == i {
			cursor = selectedStyle.Render("▸ ")
			label = selectedStyle.Render(item.label)
			bullet = successStyle.Render("●")
			desc = subtitleStyle.Render(item.desc)
		}

		line := fmt.Sprintf("  %s %s %s  %s", cursor, bullet, label, desc)
		b.WriteString(line + "\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  ↑/↓ navigate  enter select  esc back") + "\n")

	return b.String()
}

// TUIResult holds all results from the TUI interaction
type TUIResult struct {
	Action        string
	ScanPath      string
	ScanFormat    string
	IncludeVulns  bool
	GitHubURLs    string
	GitHubToken   string
	IncludeHealth bool
}

// runTUIFull launches the TUI and returns all results including GitHub options
func runTUIFull() TUIResult {
	m := newModel()

	p := tea.NewProgram(m, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		return TUIResult{Action: "exit"}
	}

	final := finalModel.(model)
	if final.quitting && final.selected == "" {
		return TUIResult{Action: "exit"}
	}

	// Clear screen after TUI exits for clean transition
	fmt.Print("\033[H\033[2J")

	return TUIResult{
		Action:        final.selected,
		ScanPath:      final.scanPath,
		ScanFormat:    final.scanFormat,
		IncludeVulns:  final.includeVulns,
		GitHubURLs:    final.githubURLs,
		GitHubToken:   final.githubToken,
		IncludeHealth: final.includeHealth,
	}
}

// getGitHubToken retrieves token from env or config
func getGitHubToken() string {
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		return token
	}

	configPath := filepath.Join(os.Getenv("HOME"), ".sbomber", "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}

	var cfg struct {
		GitHubToken string `json:"github_token"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return ""
	}

	return cfg.GitHubToken
}

// saveGitHubToken saves token to config file
func saveGitHubToken(token string) error {
	configDir := filepath.Join(os.Getenv("HOME"), ".sbomber")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return err
	}

	cfg := struct {
		GitHubToken string `json:"github_token"`
	}{
		GitHubToken: token,
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(configDir, "config.json"), data, 0600)
}

// resultsModel for showing scan results with actions
// Ground-truth accuracy check sub-states within the results screen.
const (
	gtStateMenu = iota
	gtStatePathInput
	gtStateReport
)

type resultsModel struct {
	content    string
	outputPath string
	cursor     int
	actions    []string
	quitting   bool

	// Ground-truth accuracy check. groundTruthSBOM is the single
	// generated SBOM to compare against, derived from content via
	// extractSingleScanSBOM; the action is only offered (see actions
	// above) when that derivation succeeds, i.e. exactly one repo was
	// scanned. See docs/design/canonical-scan.md for why a comparison
	// needs exactly one generated SBOM to be meaningful.
	groundTruthSBOM string
	gtState         int
	gtPathInput     string
	gtReport        string
	gtErr           string
}

func newResultsModel(content, outputPath string) resultsModel {
	actions := []string{"Back to menu", "Open output folder", "Quit"}
	sbomPath := extractSingleScanSBOM(content)
	if sbomPath != "" {
		actions = append(actions, "Check ground-truth accuracy")
	}
	return resultsModel{
		content:         content,
		outputPath:      outputPath,
		cursor:          0,
		actions:         actions,
		groundTruthSBOM: sbomPath,
	}
}

func (m resultsModel) Init() tea.Cmd {
	return nil
}

func (m resultsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.gtState {
	case gtStatePathInput:
		return m.updateGroundTruthPathInput(msg)
	case gtStateReport:
		return m.updateGroundTruthReport(msg)
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.actions)-1 {
				m.cursor++
			}
		case "enter":
			switch m.actions[m.cursor] {
			case "Back to menu":
				m.quitting = true
				return m, tea.Quit
			case "Open output folder":
				if m.outputPath != "" {
					openFolder(m.outputPath)
				}
				return m, nil // Stay on results screen
			case "Quit":
				m.quitting = true
				m.cursor = 2 // Mark as quit
				return m, tea.Quit
			case "Check ground-truth accuracy":
				m.gtState = gtStatePathInput
				m.gtPathInput = ""
				m.gtErr = ""
			}
		case "q", "ctrl+c", "esc":
			m.quitting = true
			return m, tea.Quit
		}
	}
	return m, nil
}

// updateGroundTruthPathInput handles free-text entry of the ground-truth
// SBOM path, mirroring model.updatePathInput's key handling.
func (m resultsModel) updateGroundTruthPathInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	switch keyMsg.Type {
	case tea.KeyEnter:
		path := strings.TrimSpace(m.gtPathInput)
		if path == "" {
			m.gtErr = "enter a path to a ground-truth SBOM"
			return m, nil
		}
		result, err := verify.VerifyFiles(path, m.groundTruthSBOM)
		if err != nil {
			m.gtErr = err.Error()
			return m, nil
		}
		m.gtReport = result.PrintReport()
		m.gtErr = ""
		m.gtState = gtStateReport
	case tea.KeyBackspace:
		if len(m.gtPathInput) > 0 {
			m.gtPathInput = m.gtPathInput[:len(m.gtPathInput)-1]
		}
	case tea.KeyEsc:
		m.gtState = gtStateMenu
		m.gtErr = ""
	case tea.KeyCtrlC:
		m.quitting = true
		return m, tea.Quit
	case tea.KeyTab:
		m.gtPathInput = expandPathWithTab(m.gtPathInput)
	case tea.KeySpace:
		m.gtPathInput += " "
	case tea.KeyRunes:
		m.gtPathInput += string(keyMsg.Runes)
	}
	return m, nil
}

// updateGroundTruthReport handles the report screen shown after a
// successful ground-truth comparison: any key other than quit returns to
// the results menu.
func (m resultsModel) updateGroundTruthReport(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	switch keyMsg.String() {
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	default:
		m.gtState = gtStateMenu
	}
	return m, nil
}

func (m resultsModel) View() string {
	if m.quitting {
		return ""
	}
	switch m.gtState {
	case gtStatePathInput:
		return m.viewGroundTruthPathInput()
	case gtStateReport:
		return m.viewGroundTruthReport()
	}

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(renderBanner())

	// Results header
	headerBox := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00FF88")).
		MarginLeft(4).
		MarginBottom(1)
	b.WriteString(headerBox.Render("SCAN COMPLETE") + "\n\n")

	// Content - no color styling so it works on light and dark terminals
	// Render each line with just margin
	for _, line := range strings.Split(m.content, "\n") {
		b.WriteString("    " + line + "\n")
	}
	b.WriteString("\n")

	// Output location
	if m.outputPath != "" {
		pathStyle := lipgloss.NewStyle().
			MarginLeft(4).
			Foreground(lipgloss.Color("#888888"))
		pathValue := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00D4FF"))
		b.WriteString(pathStyle.Render("Output: ") + pathValue.Render(m.outputPath) + "\n\n")
	}

	// Divider
	divider := lipgloss.NewStyle().
		MarginLeft(4).
		Foreground(lipgloss.Color("#444444"))
	b.WriteString(divider.Render("─────────────────────────────────────────") + "\n\n")

	// Actions
	actionHeader := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00D4FF")).
		MarginLeft(4)
	b.WriteString(actionHeader.Render("WHAT'S NEXT?") + "\n\n")

	for i, action := range m.actions {
		cursor := "  "
		label := unselectedStyle.Render(action)
		bullet := dimStyle.Render("○")

		if m.cursor == i {
			cursor = selectedStyle.Render("▸ ")
			label = selectedStyle.Render(action)
			bullet = successStyle.Render("●")
		}

		line := fmt.Sprintf("  %s %s %s", cursor, bullet, label)
		b.WriteString(lipgloss.NewStyle().MarginLeft(2).Render(line) + "\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.MarginLeft(4).Render("↑/↓ navigate  enter select") + "\n")

	return b.String()
}

func (m resultsModel) viewGroundTruthPathInput() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(renderBanner())

	header := titleStyle.MarginLeft(4).Render("  GROUND-TRUTH ACCURACY CHECK")
	b.WriteString(header + "\n\n")
	b.WriteString(dimStyle.MarginLeft(4).Render("  Compares the SBOM just generated against a ground-truth") + "\n")
	b.WriteString(dimStyle.MarginLeft(4).Render("  SBOM you provide — see docs/design/canonical-scan.md.") + "\n\n")

	prompt := inputStyle.Render("  Ground-truth SBOM path: ")
	cursor := accentStyle.Render("█")
	input := accentStyle.Render(m.gtPathInput)
	b.WriteString("  " + prompt + input + cursor + "\n\n")

	if m.gtErr != "" {
		errStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#f85149")).MarginLeft(4)
		b.WriteString(errStyle.Render("Error: "+m.gtErr) + "\n\n")
	}

	b.WriteString(dimStyle.MarginLeft(4).Render("  enter check  esc back") + "\n")
	return b.String()
}

func (m resultsModel) viewGroundTruthReport() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(renderBanner())

	header := titleStyle.MarginLeft(4).Render("  GROUND-TRUTH ACCURACY CHECK")
	b.WriteString(header + "\n\n")

	for _, line := range strings.Split(m.gtReport, "\n") {
		b.WriteString("    " + line + "\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.MarginLeft(4).Render("  any key back  q quit") + "\n")
	return b.String()
}

// showResultsScreen displays scan results in a styled TUI view
func showResultsScreen(content, outputPath string) bool {
	m := newResultsModel(content, outputPath)
	p := tea.NewProgram(m, tea.WithAltScreen())
	finalModel, _ := p.Run()
	final := finalModel.(resultsModel)

	// Return true if user wants to quit entirely (cursor == 2)
	return final.cursor == 2
}

// openFolder opens the folder in the system file manager
func openFolder(path string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "linux":
		cmd = exec.Command("xdg-open", path)
	case "windows":
		cmd = exec.Command("explorer", path)
	}
	if cmd != nil {
		_ = cmd.Start()
	}
}

// expandPathWithTab provides basic tab completion for paths
func expandPathWithTab(input string) string {
	if input == "" {
		return input
	}

	// Expand ~ to home directory
	path := input
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, strings.TrimPrefix(path, "~"))
		}
	}

	// Get directory and prefix
	dir := filepath.Dir(path)
	prefix := filepath.Base(path)

	// If path ends with /, list contents of that directory
	if strings.HasSuffix(input, "/") || strings.HasSuffix(input, string(filepath.Separator)) {
		dir = path
		prefix = ""
	}

	// Read directory
	entries, err := os.ReadDir(dir)
	if err != nil {
		return input
	}

	// Find matching entries
	var matches []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
			fullPath := filepath.Join(dir, name)
			if entry.IsDir() {
				fullPath += string(filepath.Separator)
			}
			matches = append(matches, fullPath)
		}
	}

	// Return first match or original input
	if len(matches) == 1 {
		// Convert back to use ~ if it was used
		if strings.HasPrefix(input, "~") {
			home, _ := os.UserHomeDir()
			if strings.HasPrefix(matches[0], home) {
				return "~" + strings.TrimPrefix(matches[0], home)
			}
		}
		return matches[0]
	}

	// Find common prefix among matches
	if len(matches) > 1 {
		common := matches[0]
		for _, m := range matches[1:] {
			for i := 0; i < len(common) && i < len(m); i++ {
				if common[i] != m[i] {
					common = common[:i]
					break
				}
			}
			if len(m) < len(common) {
				common = common[:len(m)]
			}
		}
		if len(common) > len(path) {
			if strings.HasPrefix(input, "~") {
				home, _ := os.UserHomeDir()
				if strings.HasPrefix(common, home) {
					return "~" + strings.TrimPrefix(common, home)
				}
			}
			return common
		}
	}

	return input
}
