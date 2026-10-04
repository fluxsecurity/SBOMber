package report

import (
	"strings"
	"testing"
)

const fixtureUsageGraph = "../../contracts/fixtures/usage-graph.sample.json"

func TestLoadCoverage_SampleUsageGraph(t *testing.T) {
	c, err := LoadCoverage(fixtureUsageGraph)
	if err != nil {
		t.Fatal(err)
	}
	if c.Analysis.Status != "complete" || c.Counts.FilesDiscovered != 142 {
		t.Fatalf("unexpected coverage: %+v", c)
	}
	if c.Incomplete() {
		t.Error("a complete analysis with no limits, errors, failures or skips was reported as incomplete")
	}
	out := strings.Join(coverageLines(c), "\n")
	for _, want := range []string{
		"Analysis status: complete (npm, analyser component2-js-ts-tree-sitter)",
		"Files: 142 discovered, 142 parsed without errors, 0 parsed with errors, 0 failed, 0 skipped",
		"Third-party imports: 5 resolved, 1 type-only, 1 unresolved",
		"Third-party call sites: 5 resolved, 1 unresolved",
		"Call paths from 2 detected entry point(s): 1 resolved, 4 unresolved",
		"Limits hit: none",
		"Package occurrences not analysed: 2 nested_under_dependency, 1 not_imported_by_analysed_source",
		excludedTreesNote,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("coverage block missing %q in:\n%s", want, out)
		}
	}
}

func TestLoadCoverage_RejectsOtherDocuments(t *testing.T) {
	if _, err := LoadCoverage(fixtureDecisionResults); err == nil {
		t.Fatal("a decision-results file was accepted as usage-graph coverage")
	}
}

func TestCoverage_IncompleteWhenPartialOrLimited(t *testing.T) {
	cases := map[string]Coverage{
		"partial": {Analysis: CoverageAnalysis{Status: "partial"}},
		"limits":  {Analysis: CoverageAnalysis{Status: "complete"}, Counts: CoverageCounts{LimitsHit: []string{"max_files"}}},
		"errors":  {Analysis: CoverageAnalysis{Status: "complete"}, Counts: CoverageCounts{FilesParsedWithErrors: 1}},
		"skipped": {Analysis: CoverageAnalysis{Status: "complete"}, Counts: CoverageCounts{FilesSkipped: 2}},
	}
	for name, c := range cases {
		if !c.Incomplete() {
			t.Errorf("%s: not reported as incomplete", name)
		}
	}
	var missing *Coverage
	if !missing.Incomplete() {
		t.Error("missing coverage must count as incomplete")
	}
}

// Without usage-graph.json the report says so, at the top and in the
// insufficient-information section; it never renders as if coverage were
// complete.
func TestRenderText_MissingCoverageIsStated(t *testing.T) {
	out := RenderText(loadSampleReport(t))
	if !strings.Contains(out, coverageMissingNote) {
		t.Error("missing-coverage note not rendered")
	}
	if !strings.Contains(out, incompleteBanner(nil)) {
		t.Error("missing-coverage banner not rendered")
	}
}

func TestRenderText_CoverageBlockInInsufficientSection(t *testing.T) {
	c, err := LoadCoverage(fixtureUsageGraph)
	if err != nil {
		t.Fatal(err)
	}
	r := loadSampleReport(t)
	r.Coverage = c
	out := RenderText(r)
	i := strings.Index(out, "== "+string(SectionInsufficientInfo)+" ==")
	j := strings.Index(out, "Files: 142 discovered")
	k := strings.Index(out, "== "+string(SectionNoDirectUsage)+" ==")
	if i < 0 || j < i || k < j {
		t.Fatalf("coverage block must sit inside the insufficient-information section:\n%s", out)
	}
	if strings.Contains(out, coverageMissingNote) {
		t.Error("missing-coverage note rendered although coverage was provided")
	}
}

// Both mandatory sections are rendered even when they hold no findings.
func TestRenderText_MandatorySectionsAlwaysPresent(t *testing.T) {
	dr := DecisionResults{
		ScanID: "scan-only-usage",
		Decisions: []Decision{{FindingID: "a", PURL: "pkg:npm/x@1.0.0", State: StateUsageDetected,
			RiskPriority: RiskPriority{Band: BandActNow}}},
		RemediationGroups: []RemediationGroup{{PURL: "pkg:npm/x@1.0.0", FindingIDs: []string{"a"}}},
	}
	out := RenderText(BuildReport(dr))
	for _, s := range []Section{SectionInsufficientInfo, SectionNoDirectUsage} {
		if !strings.Contains(out, "== "+string(s)+" ==") {
			t.Errorf("section %q missing from a report with no findings in it", s)
		}
	}
	if strings.Count(out, "No findings in this section.") != 2 {
		t.Errorf("both empty mandatory sections should say so:\n%s", out)
	}
}

// Usage evidence from a partial analysis is kept, with the warning beside it.
func TestRenderText_PartialAnalysisWarningBesideUsage(t *testing.T) {
	dr := DecisionResults{
		ScanID: "scan-partial",
		Decisions: []Decision{
			{FindingID: "p", PURL: "pkg:npm/x@1.0.0", State: StateUsageDetected,
				RiskPriority: RiskPriority{Band: BandActNow}},
			{FindingID: "c", PURL: "pkg:npm/y@1.0.0", State: StateUsageDetected,
				RiskPriority: RiskPriority{Band: BandActNow}},
		},
		RemediationGroups: []RemediationGroup{
			{PURL: "pkg:npm/x@1.0.0", FindingIDs: []string{"p"}},
			{PURL: "pkg:npm/y@1.0.0", FindingIDs: []string{"c"}},
		},
	}
	dr.Decisions[0].BasedOn.CoverageSummary.ScanStatus = "partial"
	dr.Decisions[1].BasedOn.CoverageSummary.ScanStatus = "complete"
	r := BuildReport(dr)
	if _, ok := entriesFor(r, "pkg:npm/x@1.0.0")[SectionUpdateFirst]; !ok {
		t.Fatal("usage evidence from a partial analysis must stay under Update first")
	}
	out := RenderText(r)
	if strings.Count(out, partialWarning("partial")) != 1 {
		t.Errorf("want exactly one partial-analysis warning (finding p), got:\n%s", out)
	}
}

func TestRenderText_CoverageWordingGuard(t *testing.T) {
	c, err := LoadCoverage(fixtureUsageGraph)
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{"safe", "clean", "unaffected", "not affected", "false positive",
		"not reachable", "low urgency", "informational", "no risk"}
	for name, cov := range map[string]*Coverage{"provided": c, "missing": nil} {
		r := withoutJustifications(loadSampleReport(t))
		r.Coverage = cov
		out := strings.ToLower(RenderText(r))
		for _, p := range banned {
			if strings.Contains(out, p) {
				t.Errorf("%s: rendered report contains %q", name, p)
			}
		}
	}
}

func TestCoverage_MatchesScan(t *testing.T) {
	c, err := LoadCoverage(fixtureUsageGraph)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.MatchesScan("scan-2026-08-12-0001"); err != nil {
		t.Errorf("same scan rejected: %v", err)
	}
	if err := c.MatchesScan("scan-other"); err == nil {
		t.Error("coverage from a different scan was accepted")
	}
}

func TestLoadDecisionResults_RejectsOtherDocuments(t *testing.T) {
	if _, err := LoadDecisionResults(fixtureUsageGraph); err == nil {
		t.Fatal("a usage-graph file was accepted as decision-results")
	}
}

func TestReport_FindingCounts(t *testing.T) {
	got := BuildReport(mixedResults()).FindingCounts()
	want := map[Section]int{SectionUpdateFirst: 2, SectionInsufficientInfo: 0, SectionNoDirectUsage: 3}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for _, c := range got {
		if want[c.Section] != c.Findings {
			t.Errorf("%s: %d findings, want %d", c.Section, c.Findings, want[c.Section])
		}
	}
}
