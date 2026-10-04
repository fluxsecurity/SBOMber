package report

import (
	"html"
	"regexp"
	"strings"
	"testing"
)

func renderHTML(t *testing.T, r Report) string {
	t.Helper()
	out, err := RenderHTML(r)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	return out
}

func sampleWithCoverage(t *testing.T) Report {
	t.Helper()
	r := loadSampleReport(t)
	c, err := LoadCoverage(fixtureUsageGraph)
	if err != nil {
		t.Fatal(err)
	}
	r.Coverage = c
	return r
}

// The exact D1 heading and the distinct insufficient-information heading are
// both present as section headings, in section order.
func TestRenderHTML_SectionsAndExactHeadings(t *testing.T) {
	out := renderHTML(t, sampleWithCoverage(t))
	var last int
	for _, s := range []Section{SectionUpdateFirst, SectionInsufficientInfo, SectionNoDirectUsage} {
		h := "<h2>" + string(s) + "</h2>"
		i := strings.Index(out, h)
		if i < 0 {
			t.Fatalf("missing heading %q", h)
		}
		if i < last {
			t.Errorf("heading %q out of order", h)
		}
		last = i
	}
	if strings.Count(out, "<h2>"+string(SectionNoDirectUsage)+"</h2>") != 1 {
		t.Error("D1 heading should appear exactly once")
	}
	if !strings.Contains(out, html.EscapeString(noDirectUsageNote)) {
		t.Error("D1 note missing")
	}
}

// Every finding is rendered exactly once, mixed package included.
func TestRenderHTML_EveryFindingOnce(t *testing.T) {
	dr := mixedResults()
	out := renderHTML(t, BuildReport(dr))
	for _, d := range dr.Decisions {
		attr := `data-finding-id="` + d.FindingID + `"`
		if n := strings.Count(out, attr); n != 1 {
			t.Errorf("finding %s rendered %d times, want 1", d.FindingID, n)
		}
	}
	if !strings.Contains(out, `href="#no-direct-usage"`) {
		t.Error("cross-reference link to the D1 section is missing")
	}
}

// Coverage sits inside the insufficient-information section; when missing
// it is stated, with the banner at the top.
func TestRenderHTML_Coverage(t *testing.T) {
	out := renderHTML(t, sampleWithCoverage(t))
	i := strings.Index(out, `id="insufficient-information"`)
	j := strings.Index(out, "Files: 142 discovered")
	k := strings.Index(out, `id="no-direct-usage"`)
	if i < 0 || j < i || k < j {
		t.Fatal("coverage block must sit inside the insufficient-information section")
	}
	if strings.Contains(out, `class="banner"`) {
		t.Error("banner shown although coverage is complete")
	}

	missing := renderHTML(t, loadSampleReport(t))
	if !strings.Contains(missing, html.EscapeString(coverageMissingNote)) {
		t.Error("missing-coverage note not rendered")
	}
	if !strings.Contains(missing, `class="banner"`) {
		t.Error("missing-coverage banner not rendered")
	}
}

// Input text is escaped, never interpreted as markup.
func TestRenderHTML_EscapesInput(t *testing.T) {
	dr := mixedResults()
	dr.Decisions[0].Justification = `<script>alert(1)</script>`
	dr.Decisions[0].VulnerabilityID = `<img src=x onerror=alert(1)>`
	out := renderHTML(t, BuildReport(dr))
	if strings.Contains(out, "<script>") || strings.Contains(out, "<img") {
		t.Fatal("decision text was rendered as markup")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("escaped justification not found")
	}
}

// Self-contained: no scripts, no external resources.
func TestRenderHTML_SelfContained(t *testing.T) {
	out := renderHTML(t, sampleWithCoverage(t))
	if strings.Contains(out, "<script") {
		t.Error("report contains a script element")
	}
	if regexp.MustCompile(`(?i)(src|href)\s*=\s*"(https?:)?//`).MatchString(out) {
		t.Error("report references an external resource")
	}
}

// Partial-analysis warning beside usage evidence, as in the text format.
func TestRenderHTML_PartialWarning(t *testing.T) {
	dr := DecisionResults{
		ScanID: "scan-partial",
		Decisions: []Decision{{FindingID: "p", PURL: "pkg:npm/x@1.0.0", State: StateUsageDetected,
			RiskPriority: RiskPriority{Band: BandActNow}}},
		RemediationGroups: []RemediationGroup{{PURL: "pkg:npm/x@1.0.0", FindingIDs: []string{"p"}}},
	}
	dr.Decisions[0].BasedOn.CoverageSummary.ScanStatus = "partial"
	out := renderHTML(t, BuildReport(dr))
	if !strings.Contains(out, html.EscapeString(partialWarning("partial"))) {
		t.Error("partial-analysis warning missing")
	}
}

// #120 wording guard over everything the report itself writes, styling
// included.
func TestRenderHTML_NoReassuringWording(t *testing.T) {
	banned := []string{"safe", "clean", "unaffected", "not affected", "false positive",
		"not reachable", "low urgency", "informational", "no risk"}
	for name, cov := range map[string]*Coverage{"provided": sampleWithCoverage(t).Coverage, "missing": nil} {
		for rname, r := range map[string]Report{"sample": loadSampleReport(t), "mixed": BuildReport(mixedResults())} {
			r = withoutJustifications(r)
			r.Coverage = cov
			out := strings.ToLower(renderHTML(t, r))
			for _, p := range banned {
				if strings.Contains(out, p) {
					t.Errorf("%s/%s: HTML report contains %q", rname, name, p)
				}
			}
		}
	}
}

// An omitted EPSS score is shown as not reported, never as a score of zero.
func TestRender_MissingEPSSIsNotReported(t *testing.T) {
	r := BuildReport(mixedResults())
	text := RenderText(r)
	if strings.Contains(text, "EPSS 0.0000") {
		t.Error("an omitted EPSS score was rendered as 0.0000")
	}
	if !strings.Contains(text, "EPSS not reported") || !strings.Contains(text, "EPSS 0.5000") {
		t.Errorf("want both a reported and a not-reported EPSS tag in:\n%s", text)
	}
}
