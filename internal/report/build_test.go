package report

import (
	"strings"
	"testing"
)

// Fixture path assumes the standard layout: internal/report/*_test.go
// running two directories below repo root, with contracts/fixtures/ at
// root/contracts/fixtures/ — same convention as internal/decision's tests.
const fixtureDecisionResults = "../../contracts/fixtures/decision-results.sample.json"

func loadSampleReport(t *testing.T) Report {
	t.Helper()
	dr, err := LoadDecisionResults(fixtureDecisionResults)
	if err != nil {
		t.Fatalf("LoadDecisionResults: %v", err)
	}
	return BuildReport(dr)
}

func findGroup(t *testing.T, r Report, purl string) (PackageGroup, Section) {
	t.Helper()
	for _, sg := range r.Sections {
		for _, pg := range sg.Groups {
			if pg.PURL == purl {
				return pg, sg.Section
			}
		}
	}
	t.Fatalf("package %s not found in any section", purl)
	return PackageGroup{}, ""
}

// TestBuildReport_SuccessPath is S4-13's clean positive case: find-001
// (lodash@4.17.20) is usage_detected with riskPriority.band act_now in the
// sample fixture. It must be grouped under its package (not a flat CVE
// list) and filed under "Update first".
func TestBuildReport_SuccessPath(t *testing.T) {
	r := loadSampleReport(t)

	pg, section := findGroup(t, r, "pkg:npm/lodash@4.17.20")
	if section != SectionUpdateFirst {
		t.Fatalf("lodash@4.17.20: got section %q, want %q", section, SectionUpdateFirst)
	}
	if pg.InstalledVersion != "4.17.20" {
		t.Errorf("installed version = %q, want 4.17.20", pg.InstalledVersion)
	}
	if pg.ReportedFixedVersion != "4.17.21" {
		t.Errorf("reported fixed version = %q, want 4.17.21", pg.ReportedFixedVersion)
	}
	if len(pg.Findings) != 1 || pg.Findings[0].FindingID != "find-001" {
		t.Fatalf("findings = %+v, want exactly [find-001]", pg.Findings)
	}
	if pg.Findings[0].State != StateUsageDetected {
		t.Errorf("find-001 state = %q, want %q", pg.Findings[0].State, StateUsageDetected)
	}
}

// TestBuildReport_UnknownPath is the failure/unknown-path case: find-003
// (minimist@1.2.5) and find-004 (lodash@3.10.1) are both "unknown" with
// band insufficient_information in the sample fixture, because Component 3
// could not localise (find-003) or the occurrence is nested under a
// dependency Component 2 never analysed (find-004). Neither may be filed
// under a reassuring section, and both must land under
// SectionInsufficientInfo, distinct from SectionNoDirectUsage.
func TestBuildReport_UnknownPath(t *testing.T) {
	r := loadSampleReport(t)

	for _, purl := range []string{"pkg:npm/minimist@1.2.5", "pkg:npm/lodash@3.10.1"} {
		pg, section := findGroup(t, r, purl)
		if section != SectionInsufficientInfo {
			t.Errorf("%s: got section %q, want %q", purl, section, SectionInsufficientInfo)
		}
		for _, f := range pg.Findings {
			if f.State != StateUnknown {
				t.Errorf("%s: finding %s state = %q, want %q", purl, f.FindingID, f.State, StateUnknown)
			}
		}
	}

	// D1: the no-direct-usage section and the insufficient-information
	// section must be genuinely distinct sections, not the same heading
	// used twice.
	if SectionNoDirectUsage == SectionInsufficientInfo {
		t.Fatal("SectionNoDirectUsage and SectionInsufficientInfo must be distinct section names")
	}
}

// TestBuildReport_NoDirectUsageSection checks the D1 acceptance criterion
// directly: find-002 (axios@0.21.0) is no_usage_detected with band
// lower_priority in the sample fixture -- a package where analysis
// completed and found nothing, not one where analysis was incomplete. It
// must be filed under the exact D1 section name, not folded into
// "Insufficient information" or "Lower priority".
func TestBuildReport_NoDirectUsageSection(t *testing.T) {
	r := loadSampleReport(t)

	pg, section := findGroup(t, r, "pkg:npm/axios@0.21.0")
	wantSection := Section("No direct usage evidence found within the analysed scope")
	if section != wantSection {
		t.Fatalf("axios@0.21.0: got section %q, want %q", section, wantSection)
	}
	if len(pg.Findings) != 1 || pg.Findings[0].State != StateNoUsageDetected {
		t.Fatalf("axios@0.21.0 findings = %+v, want exactly one no_usage_detected finding", pg.Findings)
	}

	rendered := RenderText(r)
	if !strings.Contains(rendered, "No direct usage evidence found within the analysed scope") {
		t.Error("rendered report is missing the exact D1 section heading")
	}
	if strings.Count(rendered, "== No direct usage evidence found within the analysed scope ==") != 1 {
		t.Error("D1 section heading should appear exactly once in the rendered report")
	}
}

// TestBuildReport_UntrustedBandValue is the boundary/untrusted-input case:
// a remediation group referencing a finding ID that decisions.json does not
// contain (a broken upstream join), plus a decision carrying a band value
// this package has never seen. Neither may be silently treated as
// reassuring (lower_priority or no-direct-usage) -- both must land in
// SectionInsufficientInfo, mirroring internal/decision's rule that an
// unrecognised reason code blocks a negative verdict rather than
// permitting one.
func TestBuildReport_UntrustedBandValue(t *testing.T) {
	dr := DecisionResults{
		ScanID: "scan-boundary-test",
		Decisions: []Decision{
			{
				FindingID: "find-999",
				PURL:      "pkg:npm/mystery-pkg@1.0.0",
				State:     StateNoUsageDetected,
				RiskPriority: RiskPriority{
					Band: "urgent_now", // typo/unrecognised value, not a real band
				},
				Justification: "no usage evidence found within the analysed scope",
			},
		},
		RemediationGroups: []RemediationGroup{
			{
				PURL:             "pkg:npm/mystery-pkg@1.0.0",
				InstalledVersion: "1.0.0",
				FindingIDs:       []string{"find-999", "find-missing"}, // find-missing is not in Decisions
			},
		},
	}

	r := BuildReport(dr)
	pg, section := findGroup(t, r, "pkg:npm/mystery-pkg@1.0.0")
	if section != SectionInsufficientInfo {
		t.Fatalf("package with an unrecognised band and a missing joined finding: got section %q, want %q", section, SectionInsufficientInfo)
	}

	var sawMissing bool
	for _, f := range pg.Findings {
		if f.FindingID == "find-missing" {
			sawMissing = true
			if !f.Untrusted {
				t.Error("find-missing: expected Untrusted = true for a finding absent from decisions")
			}
			if f.State != StateUnknown {
				t.Errorf("find-missing: state = %q, want %q (never dropped, never guessed)", f.State, StateUnknown)
			}
		}
	}
	if !sawMissing {
		t.Fatal("find-missing was dropped from the group instead of being recorded as untrusted")
	}
}

// ---- S5-09 (#120) ----------------------------------------------------------

func mixedResults() DecisionResults {
	return DecisionResults{
		ScanID: "scan-s509",
		Decisions: []Decision{
			{FindingID: "f-use", VulnerabilityID: "CVE-1", PURL: "pkg:npm/lodash@4.17.4", State: StateUsageDetected,
				RiskPriority: RiskPriority{Band: BandActNow, EPSSScore: 0.5, CVSSScore: 9.1},
				Remediation:  Remediation{ReportedFixedVersion: "4.17.11"}},
			{FindingID: "f-none-1", VulnerabilityID: "CVE-2", PURL: "pkg:npm/lodash@4.17.4", State: StateNoUsageDetected,
				RiskPriority: RiskPriority{Band: BandLowerPriority},
				Remediation:  Remediation{ReportedFixedVersion: "4.17.21"}},
			{FindingID: "f-none-2", VulnerabilityID: "CVE-3", PURL: "pkg:npm/lodash@4.17.4", State: StateNoUsageDetected,
				RiskPriority: RiskPriority{Band: BandLowerPriority}},
			{FindingID: "f-kev", VulnerabilityID: "CVE-4", PURL: "pkg:npm/kevpkg@1.0.0", State: StateNoUsageDetected,
				RiskPriority: RiskPriority{Band: BandActNow, CISAKev: true}},
			{FindingID: "f-orphan", VulnerabilityID: "CVE-5", State: StateUsageDetected,
				RiskPriority: RiskPriority{Band: BandActNow}},
		},
		RemediationGroups: []RemediationGroup{
			{PURL: "pkg:npm/kevpkg@1.0.0", InstalledVersion: "1.0.0", FindingIDs: []string{"f-kev"}, HighestBand: BandActNow},
			{PURL: "pkg:npm/lodash@4.17.4", InstalledVersion: "4.17.4", ReportedFixedVersion: "4.17.21",
				FindingIDs: []string{"f-use", "f-none-1", "f-none-2"}, HighestBand: BandActNow},
		},
	}
}

func entriesFor(r Report, purl string) map[Section]PackageGroup {
	out := map[Section]PackageGroup{}
	for _, sg := range r.Sections {
		for _, pg := range sg.Groups {
			if pg.PURL == purl {
				out[sg.Section] = pg
			}
		}
	}
	return out
}

// Every decision is listed exactly once across all sections.
func TestBuildReport_EveryFindingListedExactlyOnce(t *testing.T) {
	for name, dr := range map[string]DecisionResults{"mixed": mixedResults()} {
		r := BuildReport(dr)
		seen := map[string]int{}
		for _, sg := range r.Sections {
			for _, pg := range sg.Groups {
				for _, f := range pg.Findings {
					seen[f.FindingID]++
				}
			}
		}
		for _, d := range dr.Decisions {
			if seen[d.FindingID] != 1 {
				t.Errorf("%s: finding %s listed %d times, want 1", name, d.FindingID, seen[d.FindingID])
			}
		}
	}
	sample := loadSampleReport(t)
	dr, _ := LoadDecisionResults(fixtureDecisionResults)
	seen := map[string]int{}
	for _, sg := range sample.Sections {
		for _, pg := range sg.Groups {
			for _, f := range pg.Findings {
				seen[f.FindingID]++
			}
		}
	}
	for _, d := range dr.Decisions {
		if seen[d.FindingID] != 1 {
			t.Errorf("sample: finding %s listed %d times, want 1", d.FindingID, seen[d.FindingID])
		}
	}
}

// D1: a package with both usage and no-usage findings gets one entry per
// section, each pointing at the other; the upgrade counts all findings.
func TestBuildReport_MixedPackageSplitsAndCrossReferences(t *testing.T) {
	e := entriesFor(BuildReport(mixedResults()), "pkg:npm/lodash@4.17.4")
	main, ok := e[SectionUpdateFirst]
	if !ok {
		t.Fatalf("lodash has no %q entry: %+v", SectionUpdateFirst, e)
	}
	d1, ok := e[SectionNoDirectUsage]
	if !ok {
		t.Fatalf("lodash has no %q entry: %+v", SectionNoDirectUsage, e)
	}
	if len(main.Findings) != 1 || main.Findings[0].FindingID != "f-use" {
		t.Errorf("update-first entry findings = %+v, want [f-use]", main.Findings)
	}
	if len(d1.Findings) != 2 {
		t.Errorf("no-direct-usage entry findings = %+v, want f-none-1 and f-none-2", d1.Findings)
	}
	if main.ListedElsewhere != 2 || main.ElsewhereSection != SectionNoDirectUsage {
		t.Errorf("update-first cross-reference = %d under %q", main.ListedElsewhere, main.ElsewhereSection)
	}
	if d1.ListedElsewhere != 1 || d1.ElsewhereSection != SectionUpdateFirst {
		t.Errorf("no-direct-usage cross-reference = %d under %q", d1.ListedElsewhere, d1.ElsewhereSection)
	}
	if main.TotalFindings != 3 || main.ResolvedByUpgrade != 2 {
		t.Errorf("upgrade covers %d of %d, want 2 of 3 (f-none-2 has no reported fix)", main.ResolvedByUpgrade, main.TotalFindings)
	}
	if d1.Why != "" {
		t.Errorf("no-direct-usage entry must carry no urgency statement, got Why %q", d1.Why)
	}
	if !strings.Contains(main.Why, "usage detected") || !strings.Contains(main.Why, "EPSS 0.5000") {
		t.Errorf("update-first Why = %q, want the usage and EPSS signals", main.Why)
	}
}

// A KEV-listed no_usage_detected finding is listed under D1, but its
// package still appears under "Update first" so the urgency is not lost.
func TestBuildReport_KEVNoUsageKeepsPackageInUpdateFirst(t *testing.T) {
	e := entriesFor(BuildReport(mixedResults()), "pkg:npm/kevpkg@1.0.0")
	main, ok := e[SectionUpdateFirst]
	if !ok {
		t.Fatalf("kevpkg has no %q entry: %+v", SectionUpdateFirst, e)
	}
	if len(main.Findings) != 0 || main.ListedElsewhere != 1 {
		t.Errorf("update-first entry should list no findings and point at 1 elsewhere, got %+v", main)
	}
	if !strings.Contains(main.Why, "CISA KEV") {
		t.Errorf("Why = %q, want the KEV signal", main.Why)
	}
	d1, ok := e[SectionNoDirectUsage]
	if !ok || len(d1.Findings) != 1 || d1.Findings[0].FindingID != "f-kev" {
		t.Fatalf("f-kev must be listed under %q, got %+v", SectionNoDirectUsage, e)
	}
}

// A decision no remediation group references is listed, never dropped.
func TestBuildReport_UngroupedDecisionIsListed(t *testing.T) {
	e := entriesFor(BuildReport(mixedResults()), UngroupedPURL)
	pg, ok := e[SectionUpdateFirst]
	if !ok || len(pg.Findings) != 1 || pg.Findings[0].FindingID != "f-orphan" {
		t.Fatalf("f-orphan must be listed under %q as %q, got %+v", SectionUpdateFirst, UngroupedPURL, e)
	}
}

// withoutJustifications blanks the per-finding justifications, which are
// Component 4's decision text (linted by internal/decision), so a test can
// check only the wording this package writes.
func withoutJustifications(r Report) Report {
	out := r
	out.Sections = nil
	for _, sg := range r.Sections {
		nsg := sg
		nsg.Groups = nil
		for _, pg := range sg.Groups {
			fs := append([]PackageFinding(nil), pg.Findings...)
			for i := range fs {
				fs[i].Justification = ""
			}
			pg.Findings = fs
			nsg.Groups = append(nsg.Groups, pg)
		}
		out.Sections = append(out.Sections, nsg)
	}
	return out
}

// #120 wording: nothing the report itself writes implies safety, and the D1
// section is never labelled low urgency or informational.
func TestRenderText_NoReassuringWording(t *testing.T) {
	banned := []string{"safe", "clean", "unaffected", "not affected", "false positive",
		"not reachable", "low urgency", "informational", "no risk"}
	for name, r := range map[string]Report{"mixed": BuildReport(mixedResults()), "sample": loadSampleReport(t)} {
		out := strings.ToLower(RenderText(withoutJustifications(r)))
		for _, p := range banned {
			if strings.Contains(out, p) {
				t.Errorf("%s: rendered report contains %q", name, p)
			}
		}
	}
	out := RenderText(BuildReport(mixedResults()))
	if !strings.Contains(out, noDirectUsageNote) {
		t.Error("D1 section is missing its explanatory note")
	}
	if !strings.Contains(out, `2 further findings on this package listed under "No direct usage evidence found within the analysed scope".`) {
		t.Errorf("missing cross-reference line in:\n%s", out)
	}
}
