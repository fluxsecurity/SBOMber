package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Xsamsx/SBOMber/internal/reachability"
	"github.com/Xsamsx/SBOMber/internal/vulnerability"
)

// lookupExploitIntel is swapped out in tests so they make no network calls.
var lookupExploitIntel = vulnerability.LookupExploitIntel

type reachabilityReport struct {
	Path            string                            `json:"path"`
	OverallPercent  int                               `json:"overallPercent"`
	OverallBand     reachability.RiskBand             `json:"overallBand"`
	CalledFunctions []reachability.CalledFunctionRisk `json:"calledFunctions"`
	Unresolved      []reachability.Finding            `json:"unresolved"`
}

func runReachability(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("reachability", flag.ContinueOnError)
	fs.SetOutput(stderr)
	outputJSON := fs.Bool("json", false, "output results as JSON")
	dbURL := fs.String("db", "", "vulnerability database URL (default: https://vuln.go.dev)")
	noColor := fs.Bool("no-color", false, "disable ANSI color output")

	if err := fs.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if *noColor || *outputJSON {
		setColorOutput(false)
	}

	root := "."
	if fs.NArg() > 1 {
		_, _ = fmt.Fprintln(stderr, "Error: expected at most one module path (place flags before the path)")
		return 2
	}
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	if !reachability.IsGovulncheckAvailable() {
		_, _ = fmt.Fprintf(stderr, "ERROR: govulncheck is not installed\n")
		_, _ = fmt.Fprintf(stderr, "Install it with: go install golang.org/x/vuln/cmd/govulncheck@latest\n")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if !*outputJSON {
		_, _ = fmt.Fprintf(stderr, "Building call graph with govulncheck...\n")
	}
	findings, err := reachability.AnalyzeWithDB(ctx, absRoot, *dbURL)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	var cves []string
	var unresolved []reachability.Finding
	for _, f := range findings {
		if f.Reachable {
			cves = append(cves, f.CVEs...)
		} else {
			unresolved = append(unresolved, f)
		}
	}
	sort.Slice(unresolved, func(i, j int) bool { return unresolved[i].OSV < unresolved[j].OSV })

	progress := func(done, total int) {
		if !*outputJSON {
			_, _ = fmt.Fprintf(stderr, "\rLooking up CVSS scores on NVD... %d/%d", done, total)
			if done == total {
				_, _ = fmt.Fprintln(stderr)
			}
		}
	}
	intel := make(map[string]reachability.ExploitIntel)
	for cve, in := range lookupExploitIntel(ctx, cves, progress) {
		intel[cve] = reachability.ExploitIntel{CVSS: in.CVSS, EPSS: in.EPSS, InKEV: in.InCISAKEV, EPSSKnown: in.EPSSKnown, KEVKnown: in.KEVKnown}
	}

	if ctx.Err() != nil {
		_, _ = fmt.Fprintf(stderr, "Error: reachability analysis deadline exceeded: %v\n", ctx.Err())
		return 2
	}
	called := reachability.ScoreCalledFunctions(findings, intel)
	percent, band := reachability.OverallRisk(called)
	report := reachabilityReport{
		Path:            absRoot,
		OverallPercent:  percent,
		OverallBand:     band,
		CalledFunctions: called,
		Unresolved:      unresolved,
	}
	if report.Unresolved == nil {
		report.Unresolved = []reachability.Finding{}
	}

	if *outputJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return 2
		}
		return 0
	}

	printReachabilityReport(stdout, report)
	return 0
}

func bandColor(band reachability.RiskBand) string {
	switch band {
	case reachability.BandHigh:
		return colorRed
	case reachability.BandMedium:
		return colorYellow
	case reachability.BandLow:
		return colorCyan
	default:
		return colorGreen
	}
}

func printReachabilityReport(w io.Writer, r reachabilityReport) {
	_, _ = fmt.Fprintf(w, "\n%sReachability Risk%s  %s\n", colorBold, colorReset, r.Path)
	_, _ = fmt.Fprintf(w, "%sScores are prioritisation points out of 100, not exploit probabilities. Only findings with a resolved call path are scored; unresolved findings do not establish absence of usage.%s\n\n", colorDim, colorReset)

	if len(r.CalledFunctions) == 0 {
		_, _ = fmt.Fprintln(w, "  No call paths resolved; overall risk is undetermined.")
	}
	_, _ = fmt.Fprintf(w, "  Highest resolved-call priority: %s%s%d%% %s%s\n", colorBold, bandColor(r.OverallBand), r.OverallPercent, r.OverallBand, colorReset)
	_, _ = fmt.Fprintf(w, "  %d vulnerability finding(s) with a resolved call path, %d finding(s) with no resolved call path (not scored)\n\n",
		len(r.CalledFunctions), len(r.Unresolved))

	for i, c := range r.CalledFunctions {
		color := bandColor(c.Band)
		_, _ = fmt.Fprintf(w, "  %s%2d. %3d%% %-11s%s  %s  %s\n", color, i+1, c.Percent, c.Band, colorReset, c.OSV, c.Symbol)
		if c.Summary != "" {
			_, _ = fmt.Fprintf(w, "      %s\n", c.Summary)
		}

		cveText := "no CVE"
		if len(c.CVEs) > 0 {
			cveText = strings.Join(c.CVEs, ", ")
		}
		cvssText := fmt.Sprintf("CVSS %.1f", c.CVSS)
		if c.SeverityAssumed {
			cvssText = "CVSS n/a (assumed 5.0)"
		}
		kevText := "CISA KEV status unavailable"
		if c.KEVKnown {
			kevText = "not listed in CISA KEV"
		}
		if c.InKEV {
			kevText = "IN CISA KEV"
		}
		epssText := "EPSS not reported"
		if c.EPSSKnown {
			epssText = fmt.Sprintf("EPSS %.2f%%", c.EPSS*100)
		}
		_, _ = fmt.Fprintf(w, "      %s · %s · %s · %s\n", cveText, cvssText, epssText, kevText)

		_, _ = fmt.Fprintf(w, "      Call path:\n")
		for j, frame := range c.CallPath {
			marker := "  "
			if j > 0 {
				marker = "→ "
			}
			who := "dependency"
			switch {
			case frame.InApp:
				who = "your code"
			case j == len(c.CallPath)-1:
				who = "VULNERABLE"
			case frame.Module == "stdlib":
				who = "stdlib"
			}
			loc := frame.Location()
			if loc != "" {
				loc = "  " + colorDim + loc + colorReset
			}
			_, _ = fmt.Fprintf(w, "        %s%-10s %s%s\n", marker, who, frame.Name(), loc)
		}

		b := c.Breakdown
		_, _ = fmt.Fprintf(w, "      Score: severity %.1f + exploit %.1f + KEV %.0f + call %.0f = %d%%\n",
			b.Severity, b.ExploitChance, b.KnownExploited, b.CallProximity, c.Percent)
		if c.FixedVersion != "" {
			_, _ = fmt.Fprintf(w, "      Fix: upgrade to %s\n", c.FixedVersion)
		}
		_, _ = fmt.Fprintln(w)
	}

	if len(r.Unresolved) > 0 {
		ids := make([]string, 0, len(r.Unresolved))
		for _, f := range r.Unresolved {
			ids = append(ids, f.OSV)
		}
		_, _ = fmt.Fprintf(w, "  %sNo resolved call path (not scored): %s%s\n\n", colorDim, strings.Join(ids, ", "), colorReset)
	}

	_, _ = fmt.Fprintf(w, "  %sScoring chart (max 100%%)%s\n", colorBold, colorReset)
	_, _ = fmt.Fprintf(w, "    Severity         CVSS / 10 × %.0f                       up to %.0f\n", reachability.MaxSeverityPoints, reachability.MaxSeverityPoints)
	_, _ = fmt.Fprintf(w, "    Exploit chance   EPSS × %.0f                            up to %.0f\n", reachability.MaxExploitPoints, reachability.MaxExploitPoints)
	_, _ = fmt.Fprintf(w, "    Known exploited  in CISA KEV                          +%.0f\n", reachability.KnownExploitedPoints)
	_, _ = fmt.Fprintf(w, "    Call proximity   your code calls it +%.0f, via a dependency +%.0f\n", reachability.DirectCallPoints, reachability.IndirectCallPoints)
	_, _ = fmt.Fprintf(w, "    %s0-20%% Minimal priority%s · %s21-39%% Low%s · %s40-69%% Medium%s · %s70-100%% High%s\n",
		colorGreen, colorReset, colorCyan, colorReset, colorYellow, colorReset, colorRed, colorReset)
}
