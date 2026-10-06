package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Coverage is the subset of usage-graph.json (Component 2) the report needs
// to make incomplete analysis visible (S5-09, #120; coverage presentation
// decision, 13 September 2026). The decision-results file only carries a
// per-finding summary, so the report reads the graph's own counts directly.
type Coverage struct {
	ScanID        string                 `json:"scanId"`
	Analysis      CoverageAnalysis       `json:"analysis"`
	Counts        CoverageCounts         `json:"coverage"`
	Unanalysed    []UnanalysedOccurrence `json:"unanalysedOccurrences"`
	ParseFailures []ParseFailure         `json:"parseFailures"`
}

// CoverageAnalysis is usage-graph.json's "analysis" object.
type CoverageAnalysis struct {
	Status     string `json:"status"`
	Ecosystem  string `json:"ecosystem"`
	AnalyzerID string `json:"analyzerId"`
	ReasonCode string `json:"reasonCode"`
}

// CoverageCounts is usage-graph.json's "coverage" object. FilesParsed is
// files parsed with no error nodes; FilesDiscovered is the sum of the four
// file counts. Pruned directory trees are not in any of them.
type CoverageCounts struct {
	FilesDiscovered               int      `json:"filesDiscovered"`
	FilesParsed                   int      `json:"filesParsed"`
	FilesParsedWithErrors         int      `json:"filesParsedWithErrors"`
	FilesFailed                   int      `json:"filesFailed"`
	FilesSkipped                  int      `json:"filesSkipped"`
	ThirdPartyImportsResolved     int      `json:"thirdPartyImportsResolved"`
	ThirdPartyImportsTypeOnly     int      `json:"thirdPartyImportsTypeOnly"`
	ThirdPartyImportsUnresolved   int      `json:"thirdPartyImportsUnresolved"`
	ThirdPartyCallSitesResolved   int      `json:"thirdPartyCallSitesResolved"`
	ThirdPartyCallSitesUnresolved int      `json:"thirdPartyCallSitesUnresolved"`
	EntryPointsDetected           int      `json:"entryPointsDetected"`
	CallPathsResolved             int      `json:"callPathsResolved"`
	CallPathsUnresolved           int      `json:"callPathsUnresolved"`
	LimitsHit                     []string `json:"limitsHit"`
}

// UnanalysedOccurrence is one usage-graph.json unanalysedOccurrences[] entry.
type UnanalysedOccurrence struct {
	OccurrenceID string `json:"occurrenceId"`
	PURL         string `json:"purl"`
	Reason       string `json:"reason"`
}

// ParseFailure is one usage-graph.json parseFailures[] entry.
type ParseFailure struct {
	RepositoryID string `json:"repositoryId"`
	File         string `json:"file"`
	Reason       string `json:"reason"`
}

// LoadCoverage reads the coverage parts of a usage-graph.json file.
func LoadCoverage(path string) (*Coverage, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Coverage
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Analysis.Status == "" {
		return nil, fmt.Errorf("%s has no analysis.status; is it a usage-graph.json?", path)
	}
	return &c, nil
}

// MatchesScan refuses coverage from a different scan than the decisions:
// pairing a report with another scan's coverage would misstate what was
// analysed.
func (c *Coverage) MatchesScan(scanID string) error {
	if c.ScanID != "" && scanID != "" && c.ScanID != scanID {
		return fmt.Errorf("usage graph is for scan %q but the decisions are for scan %q", c.ScanID, scanID)
	}
	return nil
}

// Incomplete reports whether the analysis behind this report was not a
// complete analysis: any status other than complete, any limit hit, or any
// file that was parsed with errors, failed or was skipped.
func (c *Coverage) Incomplete() bool {
	if c == nil {
		return true
	}
	n := c.Counts
	return c.Analysis.Status != "complete" || len(n.LimitsHit) > 0 ||
		n.FilesParsedWithErrors > 0 || n.FilesFailed > 0 || n.FilesSkipped > 0
}

// excludedTreesNote explains pruned directories. Component 2 prunes
// dependency, build-output and version-control trees before parsing and
// does not publish which paths it pruned, so the report states the rule
// rather than a list it cannot see.
const excludedTreesNote = "Directory trees the source analyser excludes (dependency, build-output and version-control directories such as node_modules, build, dist and .git) are outside the declared analysis scope. They were not analysed and are not counted in the file totals above; they are not successfully analysed files."

// coverageMissingNote is shown when the report was built without a
// usage-graph.json: the gap is stated, never hidden.
const coverageMissingNote = "Analysis coverage was not provided to this report (no usage-graph.json), so files analysed, import and call resolution, and limits hit cannot be shown. Treat every verdict in this report as resting on coverage you have not seen."

// coverageLines renders the coverage block as plain lines, shared by the
// text and HTML renderers.
func coverageLines(c *Coverage) []string {
	if c == nil {
		return []string{coverageMissingNote}
	}
	a, n := c.Analysis, c.Counts

	status := fmt.Sprintf("Analysis status: %s", a.Status)
	var detail []string
	if a.Ecosystem != "" {
		detail = append(detail, a.Ecosystem)
	}
	if a.AnalyzerID != "" {
		detail = append(detail, "analyser "+a.AnalyzerID)
	}
	if a.ReasonCode != "" {
		detail = append(detail, "reason "+a.ReasonCode)
	}
	if len(detail) > 0 {
		status += " (" + strings.Join(detail, ", ") + ")"
	}

	lines := []string{
		status,
		fmt.Sprintf("Files: %d discovered, %d parsed without errors, %d parsed with errors, %d failed, %d skipped",
			n.FilesDiscovered, n.FilesParsed, n.FilesParsedWithErrors, n.FilesFailed, n.FilesSkipped),
		fmt.Sprintf("Third-party imports: %d resolved, %d type-only, %d unresolved",
			n.ThirdPartyImportsResolved, n.ThirdPartyImportsTypeOnly, n.ThirdPartyImportsUnresolved),
		fmt.Sprintf("Third-party call sites: %d resolved, %d unresolved",
			n.ThirdPartyCallSitesResolved, n.ThirdPartyCallSitesUnresolved),
		fmt.Sprintf("Call paths from %d detected entry point(s): %d resolved, %d unresolved",
			n.EntryPointsDetected, n.CallPathsResolved, n.CallPathsUnresolved),
	}
	if len(n.LimitsHit) > 0 {
		lines = append(lines, "Limits hit: "+strings.Join(n.LimitsHit, ", ")+" (the analysis is incomplete by policy)")
	} else {
		lines = append(lines, "Limits hit: none")
	}
	if len(c.Unanalysed) > 0 {
		lines = append(lines, "Package occurrences not analysed: "+reasonCounts(c.Unanalysed))
	}
	if len(c.ParseFailures) > 0 {
		var files []string
		for _, f := range c.ParseFailures {
			files = append(files, f.File)
		}
		lines = append(lines, "Files that failed to parse: "+strings.Join(files, ", "))
	}
	lines = append(lines, excludedTreesNote)
	return lines
}

func reasonCounts(us []UnanalysedOccurrence) string {
	counts := map[string]int{}
	for _, u := range us {
		counts[u.Reason]++
	}
	reasons := make([]string, 0, len(counts))
	for r := range counts {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	parts := make([]string, 0, len(reasons))
	for _, r := range reasons {
		parts = append(parts, fmt.Sprintf("%d %s", counts[r], r))
	}
	return strings.Join(parts, ", ")
}

// partialWarning is shown beside usage evidence found during an analysis
// that did not complete: the evidence is kept, and so is the caveat.
func partialWarning(scanStatus string) string {
	return fmt.Sprintf("Partial analysis: this usage evidence was found, but the analysis was %s, so other usage may not have been seen.", scanStatus)
}

// needsPartialWarning reports whether a finding's usage evidence comes from
// an analysis that did not complete.
func needsPartialWarning(f PackageFinding) bool {
	return f.State == StateUsageDetected && (f.ScanStatus == "partial" || f.ScanStatus == "failed")
}
