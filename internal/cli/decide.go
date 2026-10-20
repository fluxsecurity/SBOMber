package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/Xsamsx/SBOMber/internal/decision"
)

const decideUsage = "Usage: sbomber decide --canonical-scan <canonical-scan.json> --usage-graph <usage-graph.json> --localisation <localisation.json> [--out decision-results.json]\n"

// runDecide is Component 4's join (S5-08, #119): it reads the three
// upstream contract files and writes decision-results.json, giving every
// finding a state, a confidence category with criteria, a risk priority, a
// justification and the coverage the verdict rests on.
func runDecide(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("decide", flag.ContinueOnError)
	fs.SetOutput(stderr)
	scanPath := fs.String("canonical-scan", "", "canonical-scan.json (Component 1, required)")
	usagePath := fs.String("usage-graph", "", "usage-graph.json (Component 2, required)")
	locPath := fs.String("localisation", "", "localisation.json (Component 3, required)")
	out := fs.String("out", "decision-results.json", "decision-results.json to write")

	if err := fs.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if *scanPath == "" || *usagePath == "" || *locPath == "" {
		_, _ = fmt.Fprint(stderr, decideUsage)
		return 2
	}

	scan, err := decision.LoadCanonicalScan(*scanPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: read canonical scan: %v\n", err)
		return 2
	}
	if scan.Scan.ScanID == "" {
		_, _ = fmt.Fprintf(stderr, "Error: %s has no scan.scanId\n", *scanPath)
		return 2
	}
	graph, err := decision.LoadUsageGraph(*usagePath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: read usage graph: %v\n", err)
		return 2
	}
	loc, err := decision.LoadLocalisationReport(*locPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: read localisation: %v\n", err)
		return 2
	}

	res, err := decision.BuildResults(scan, graph, loc)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	_, _ = fmt.Fprintf(stdout, "Decided %d finding(s) for %s\n", len(res.Decisions), res.ScanID)
	for _, d := range res.Decisions {
		_, _ = fmt.Fprintf(stdout, "  %-10s %-18s %-48s %-6s %s\n",
			d.FindingID, d.VulnerabilityID, d.State.Display(), d.AnalysisConfidence, d.RiskPriority.Band)
	}
	dist := res.Distribution
	_, _ = fmt.Fprintf(stdout, "Distribution: %d usage detected, %d no usage evidence within the analysed scope, %d unknown, %d unsupported\n",
		dist.UsageDetected, dist.NoUsageDetected, dist.Unknown, dist.Unsupported)

	if err := writeJSONFile(*out, res); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	_, _ = fmt.Fprintf(stdout, "Wrote %s\n", *out)
	return 0
}
