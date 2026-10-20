package reachability

import "testing"

func TestBandForBoundaries(t *testing.T) {
	cases := []struct {
		percent int
		want    RiskBand
	}{
		{0, BandMinimal},
		{20, BandMinimal},
		{21, BandLow},
		{39, BandLow},
		{40, BandMedium},
		{69, BandMedium},
		{70, BandHigh},
		{100, BandHigh},
	}
	for _, c := range cases {
		if got := BandFor(c.percent); got != c.want {
			t.Errorf("BandFor(%d) = %q, want %q", c.percent, got, c.want)
		}
	}
}

func TestScoreCalledFunctionsUsesChart(t *testing.T) {
	findings := []Finding{
		// Log4Shell-like: critical CVSS, very likely exploited, in KEV,
		// called directly by app code: 40 + 24.25 + 20 + 15 = 99.25.
		{OSV: "GO-A", Tier: TierCritical, Reachable: true, CVEs: []string{"CVE-A"}},
		// CVSS 7.5, negligible EPSS, called via a dependency: 30 + 0.025 + 8.
		{OSV: "GO-B", Tier: TierHigh, Reachable: true, CVEs: []string{"CVE-B"}},
		// Low CVSS, called via a dependency: 8 + 0 + 8 = 16.
		{OSV: "GO-C", Tier: TierHigh, Reachable: true, CVEs: []string{"CVE-C"}},
		// CVSS 7.5 called directly: 30 + 0 + 15 = 45.
		{OSV: "GO-D", Tier: TierCritical, Reachable: true, CVEs: []string{"CVE-D"}},
	}
	intel := map[string]ExploitIntel{
		"CVE-A": {CVSS: 10, EPSS: 0.97, InKEV: true},
		"CVE-B": {CVSS: 7.5, EPSS: 0.001},
		"CVE-C": {CVSS: 2.0},
		"CVE-D": {CVSS: 7.5},
	}

	got := ScoreCalledFunctions(findings, intel)
	want := []struct {
		osv     string
		percent int
		band    RiskBand
	}{
		{"GO-A", 99, BandHigh},
		{"GO-D", 45, BandMedium},
		{"GO-B", 38, BandLow},
		{"GO-C", 16, BandMinimal},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d results, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].OSV != w.osv || got[i].Percent != w.percent || got[i].Band != w.band {
			t.Errorf("result %d = %s %d%% %s, want %s %d%% %s",
				i, got[i].OSV, got[i].Percent, got[i].Band, w.osv, w.percent, w.band)
		}
	}
	if b := got[0].Breakdown; b.KnownExploited != KnownExploitedPoints || b.CallProximity != DirectCallPoints {
		t.Errorf("unexpected breakdown for GO-A: %+v", b)
	}
}

// Vulnerable code that is with no resolved call path must not be scored.
func TestScoreCalledFunctionsSkipsUncalled(t *testing.T) {
	findings := []Finding{
		{OSV: "GO-LOW", Tier: TierLow, Reachable: false, CVEs: []string{"CVE-X"}},
		{OSV: "GO-MED", Tier: TierMedium, Reachable: false, CVEs: []string{"CVE-X"}},
	}
	intel := map[string]ExploitIntel{"CVE-X": {CVSS: 10, EPSS: 1, InKEV: true}}

	got := ScoreCalledFunctions(findings, intel)
	if len(got) != 0 {
		t.Fatalf("expected no scored results, got %+v", got)
	}
	if percent, band := OverallRisk(got); percent != 0 || band != BandUndetermined {
		t.Errorf("OverallRisk of nothing called = %d%% %s, want 0 points UNDETERMINED", percent, band)
	}
}

// With no CVSS anywhere, severity falls back to 5.0 rather than zero, so an
// unrated vulnerability is not reported as harmless.
func TestScoreCalledFunctionsAssumesSeverityWhenMissing(t *testing.T) {
	findings := []Finding{{OSV: "GO-N", Tier: TierCritical, Reachable: true, CVEs: []string{"CVE-UNKNOWN"}}}

	got := ScoreCalledFunctions(findings, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if !got[0].SeverityAssumed {
		t.Error("expected SeverityAssumed to be true")
	}
	// 5.0/10*40 + 0 + 0 + 15 = 35
	if got[0].Percent != 35 || got[0].Band != BandLow {
		t.Errorf("got %d%% %s, want 35%% LOW RISK", got[0].Percent, got[0].Band)
	}
}

// A vulnerability with several CVE aliases takes the worst of each signal.
func TestScoreCalledFunctionsMergesAliases(t *testing.T) {
	findings := []Finding{{OSV: "GO-M", Tier: TierHigh, Reachable: true, CVEs: []string{"CVE-1", "CVE-2"}}}
	intel := map[string]ExploitIntel{
		"CVE-1": {CVSS: 9.0, EPSS: 0.1},
		"CVE-2": {CVSS: 4.0, EPSS: 0.5, InKEV: true},
	}

	got := ScoreCalledFunctions(findings, intel)
	r := got[0]
	if r.CVSS != 9.0 || r.EPSS != 0.5 || !r.InKEV {
		t.Errorf("merged intel = CVSS %.1f EPSS %.2f KEV %v, want 9.0 0.50 true", r.CVSS, r.EPSS, r.InKEV)
	}
	// 36 + 12.5 + 20 + 8 = 76.5 -> 77
	if r.Percent != 77 || r.Band != BandHigh {
		t.Errorf("got %d%% %s, want 77%% HIGH RISK", r.Percent, r.Band)
	}
}
