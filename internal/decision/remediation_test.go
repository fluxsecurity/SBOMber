package decision

import (
	"reflect"
	"testing"
)

func fptr(f float64) *float64 { return &f }
func bptr(b bool) *bool       { return &b }

func rd(id, purl string, band RiskBand) ResultDecision {
	return ResultDecision{FindingID: id, PURL: purl, RiskPriority: RiskPriority{Band: band}}
}

func TestVersionFromPURL(t *testing.T) {
	cases := map[string]string{
		"pkg:npm/lodash@4.17.4":           "4.17.4",
		"pkg:npm/%40babel/core@7.0.0":     "7.0.0",
		"pkg:npm/%40babel/core@7.0.0?x=1": "7.0.0",
		"pkg:npm/lodash":                  "",
		"pkg:npm/lodash@":                 "",
		"lodash@4.17.4":                   "",
	}
	for in, want := range cases {
		if got := versionFromPURL(in); got != want {
			t.Errorf("versionFromPURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"4.17.21", "4.17.5", 1},
		{"4.17.5", "4.17.11", -1},
		{"1.2", "1.2.0", 0},
		{"v2.0.0", "1.9.9", 1},
		{"1.0.0-beta.1", "1.0.0", -1},
		{"1.0.0-beta.2", "1.0.0-beta.10", -1},
		{"1.0.0-alpha", "1.0.0-1", 1},
		{"1.0.0+build.5", "1.0.0", 0},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	for _, bad := range []string{"", "^4.17.0", "latest", "1.x", "1.0.0-"} {
		if _, ok := parseVersion(bad); ok {
			t.Errorf("parseVersion(%q) accepted an unorderable version", bad)
		}
	}
}

func TestBuildRemediationGroups_OneGroupPerPackageHighestReportedFix(t *testing.T) {
	const lodash = "pkg:npm/lodash@4.17.4"
	decisions := []ResultDecision{
		rd("f-3", lodash, BandLowerPriority),
		rd("f-1", lodash, BandActNow),
		rd("f-2", lodash, BandInsufficientInformation),
	}
	findings := []ScanFinding{
		{FindingID: "f-1", PURL: lodash, FixedVersion: "4.17.5"},
		{FindingID: "f-2", PURL: lodash, FixedVersion: "4.17.21"},
		{FindingID: "f-3", PURL: lodash, FixedVersion: "4.17.11"},
	}
	got := BuildRemediationGroups(decisions, findings)
	want := []RemediationGroup{{
		PURL:                 lodash,
		InstalledVersion:     "4.17.4",
		ReportedFixedVersion: "4.17.21",
		FindingIDs:           []string{"f-1", "f-2", "f-3"},
		HighestBand:          BandActNow,
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestBuildRemediationGroups_UnorderableFixLeavesTargetEmpty(t *testing.T) {
	const p = "pkg:npm/x@1.0.0"
	got := BuildRemediationGroups(
		[]ResultDecision{rd("a", p, BandActNow), rd("b", p, BandActNow)},
		[]ScanFinding{{FindingID: "a", FixedVersion: "1.2.0"}, {FindingID: "b", FixedVersion: "1.x"}},
	)
	if len(got) != 1 || got[0].ReportedFixedVersion != "" {
		t.Fatalf("an unorderable reported fix must leave the group target empty, got %+v", got)
	}
}

func TestBuildRemediationGroups_NoReportedFixLeavesTargetEmpty(t *testing.T) {
	const p = "pkg:npm/node-serialize@0.0.4"
	got := BuildRemediationGroups([]ResultDecision{rd("a", p, BandActNow)}, []ScanFinding{{FindingID: "a"}})
	if len(got) != 1 || got[0].ReportedFixedVersion != "" {
		t.Fatalf("got %+v", got)
	}
}

func TestBuildRemediationGroups_UpdateFirstOrder(t *testing.T) {
	decisions := []ResultDecision{
		rd("lower", "pkg:npm/lower@1.0.0", BandLowerPriority),
		rd("insuff", "pkg:npm/insuff@1.0.0", BandInsufficientInformation),
		{FindingID: "act-epss", PURL: "pkg:npm/act-epss@1.0.0", RiskPriority: RiskPriority{Band: BandActNow, EPSSScore: fptr(0.9)}},
		{FindingID: "act-kev", PURL: "pkg:npm/act-kev@1.0.0", RiskPriority: RiskPriority{Band: BandActNow, CISAKev: bptr(true), EPSSScore: fptr(0.1)}},
		{FindingID: "act-cvss", PURL: "pkg:npm/act-cvss@1.0.0", RiskPriority: RiskPriority{Band: BandActNow, EPSSScore: fptr(0.9), CVSSScore: fptr(9.8)}},
	}
	var got []string
	for _, g := range BuildRemediationGroups(decisions, nil) {
		got = append(got, g.FindingIDs[0])
	}
	want := []string{"act-kev", "act-cvss", "act-epss", "insuff", "lower"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
}

func TestBuildRemediationGroups_EveryDecisionWithPURLAppearsExactlyOnce(t *testing.T) {
	decisions := []ResultDecision{
		rd("a", "pkg:npm/a@1.0.0", BandActNow),
		rd("b", "pkg:npm/a@1.0.0", BandLowerPriority),
		rd("c", "pkg:npm/a@2.0.0", BandLowerPriority),
		rd("d", "", BandActNow),
	}
	seen := map[string]int{}
	for _, g := range BuildRemediationGroups(decisions, nil) {
		for _, id := range g.FindingIDs {
			seen[id]++
		}
	}
	want := map[string]int{"a": 1, "b": 1, "c": 1}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("finding counts %v, want %v (a decision without a purl is not grouped)", seen, want)
	}
}

func TestBuildRemediationGroups_DirectWinsOverTransitive(t *testing.T) {
	const p = "pkg:npm/qs@6.7.0"
	decisions := []ResultDecision{
		{FindingID: "a", PURL: p, RiskPriority: RiskPriority{Band: BandActNow, Relationship: "transitive"}},
		{FindingID: "b", PURL: p, RiskPriority: RiskPriority{Band: BandActNow, Relationship: "direct"}},
	}
	got := BuildRemediationGroups(decisions, nil)
	if len(got) != 1 || got[0].Relationship != "direct" {
		t.Fatalf("got %+v", got)
	}
}

func TestBuildResults_SampleContractsEmitGroupsCoveringEveryDecision(t *testing.T) {
	scan, err := LoadCanonicalScan(fixtureCanonicalScan)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := LoadUsageGraph(fixtureUsageGraph)
	if err != nil {
		t.Fatal(err)
	}
	loc, err := LoadLocalisationReport(fixtureLocalisation)
	if err != nil {
		t.Fatal(err)
	}
	res, err := BuildResults(scan, graph, loc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RemediationGroups) == 0 {
		t.Fatal("BuildResults emitted no remediationGroups")
	}
	grouped := map[string]bool{}
	for _, g := range res.RemediationGroups {
		if g.PURL == "" || len(g.FindingIDs) == 0 {
			t.Errorf("group missing purl or findingIds: %+v", g)
		}
		for _, id := range g.FindingIDs {
			grouped[id] = true
		}
	}
	for _, d := range res.Decisions {
		if d.PURL != "" && !grouped[d.FindingID] {
			t.Errorf("decision %s (%s) is in no remediation group", d.FindingID, d.PURL)
		}
	}
}

func TestBuildRemediationGroups_FixNotAboveInstalledLeavesTargetEmpty(t *testing.T) {
	const p = "pkg:npm/semver@7.5.1"
	got := BuildRemediationGroups(
		[]ResultDecision{rd("a", p, BandActNow)},
		[]ScanFinding{{FindingID: "a", FixedVersion: "5.7.2"}},
	)
	if len(got) != 1 || got[0].ReportedFixedVersion != "" {
		t.Fatalf("a reported fix below the installed version must not be the target, got %+v", got)
	}
}

// A lower-priority finding's EPSS must not lift a package above one whose
// act-now findings score higher.
func TestBuildRemediationGroups_OrderUsesHighestBandSignalsOnly(t *testing.T) {
	decisions := []ResultDecision{
		{FindingID: "a1", PURL: "pkg:npm/a@1.0.0", RiskPriority: RiskPriority{Band: BandActNow, EPSSScore: fptr(0.01)}},
		{FindingID: "a2", PURL: "pkg:npm/a@1.0.0", RiskPriority: RiskPriority{Band: BandLowerPriority, EPSSScore: fptr(0.9)}},
		{FindingID: "b1", PURL: "pkg:npm/b@1.0.0", RiskPriority: RiskPriority{Band: BandActNow, EPSSScore: fptr(0.5)}},
	}
	var got []string
	for _, g := range BuildRemediationGroups(decisions, nil) {
		got = append(got, g.PURL)
	}
	want := []string{"pkg:npm/b@1.0.0", "pkg:npm/a@1.0.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
}
