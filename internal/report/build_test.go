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
