package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Xsamsx/SBOMber/internal/report"
)

const reportUsage = "Usage: sbomber report --decision-results <decision-results.json> [--usage-graph <usage-graph.json>] [--format html|text] [--out <file>|-]\n"

// defaultHTMLReport is where the HTML report goes when --out is not given.
const defaultHTMLReport = "remediation-report.html"

// runReport is S5-09's (#120) grouped remediation report: it reads
// decision-results.json (and, optionally, the usage-graph.json the
// decisions rest on) and writes the report as HTML or text.
//
// Without --usage-graph the report still renders, and says in its own text
// that coverage was not provided; a warning is also printed here.
//
// Exit codes: 0 when the report was written; 2 for bad input, including a
// usage graph from a different scan than the decisions.
func runReport(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	drPath := fs.String("decision-results", "", "decision-results.json (Component 4, required)")
	ugPath := fs.String("usage-graph", "", "usage-graph.json the decisions rest on (shows analysis coverage)")
	format := fs.String("format", "html", "output format: html or text")
	out := fs.String("out", "", "file to write, or - for stdout (default: "+defaultHTMLReport+" for html, stdout for text)")

	if err := fs.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if *drPath == "" || fs.NArg() != 0 {
		_, _ = fmt.Fprint(stderr, reportUsage)
		return 2
	}
	if *format != "html" && *format != "text" {
		_, _ = fmt.Fprintf(stderr, "Error: --format must be html or text, not %q\n", *format)
		return 2
	}

	dr, err := report.LoadDecisionResults(*drPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: read decision results: %v\n", err)
		return 2
	}
	r := report.BuildReport(dr)

	if *ugPath != "" {
		cov, err := report.LoadCoverage(*ugPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: read usage graph: %v\n", err)
			return 2
		}
		if err := cov.MatchesScan(dr.ScanID); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return 2
		}
		r.Coverage = cov
	} else {
		_, _ = fmt.Fprintf(stderr, "Warning: no --usage-graph; the report states that analysis coverage was not provided\n")
	}

	var body string
	if *format == "html" {
		body, err = report.RenderHTML(r)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: render report: %v\n", err)
			return 2
		}
	} else {
		body = report.RenderText(r)
	}

	dest := *out
	if dest == "" {
		dest = "-"
		if *format == "html" {
			dest = defaultHTMLReport
		}
	}
	if dest == "-" {
		_, _ = fmt.Fprint(stdout, body)
		return 0
	}
	if err := os.WriteFile(dest, []byte(body), 0o644); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: write %s: %v\n", dest, err)
		return 2
	}

	var parts []string
	for _, c := range r.FindingCounts() {
		parts = append(parts, fmt.Sprintf("%d %s", c.Findings, c.Section))
	}
	_, _ = fmt.Fprintf(stdout, "Wrote %s for %s: %s\n", dest, dr.ScanID, strings.Join(parts, "; "))
	return 0
}
