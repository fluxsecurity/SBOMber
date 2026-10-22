package decision

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

// S6-15 (#156): reachable-only method agreement, the call path in the
// justification, and severity/EPSS ordering that never touches state or
// confidence.

// lodashCallWithReachability is lodashCall("merge") with the call site's
// level-3 result replaced, path fields included only when given.
func lodashCallWithReachability(reach, entry string, path []CallPathStep) UsageObservation {
	o := lodashCall("merge")
	o.CallSites[0].Reachability = reach
	o.CallSites[0].EntryPointID = entry
	o.CallSites[0].CallPath = path
	return o
}

func mergeCase(obs UsageObservation) joinCase {
	c := baseCase()
	c.candidates = []CandidateSymbol{publicCandidate("merge")}
	c.observations = []UsageObservation{obs}
	return c
}

// Success: a resolved path counts as agreement, lifts confidence to high,
// and the justification names the entry point and the path.
func TestS615_ReachablePathAgreesAndIsJustified(t *testing.T) {
	path := []CallPathStep{
		{Function: "postMerge", File: "src/routes/merge.js", Line: 12},
		{Function: "mergeConfig", File: "src/config.js", Line: 30},
	}
	in, dec, rd := mergeCase(lodashCallWithReachability("reachable", "ep-007", path)).decide(t)

	wantState(t, dec, StateUsageDetected)
	if !in.Confidence.DeterministicMethodsAgree {
		t.Fatal("reachable call site with a resolved path should count as agreement")
	}
	if dec.Confidence != ConfidenceHigh {
		t.Errorf("confidence = %q, want high: %v", dec.Confidence, dec.Criteria)
	}
	for _, want := range []string{
		"resolved call path",
		"entry point ep-007",
		"postMerge (src/routes/merge.js:12) -> mergeConfig (src/config.js:30)",
		"the call to merge at src/app.js:10",
	} {
		if !strings.Contains(rd.Justification, want) {
			t.Errorf("justification missing %q: %q", want, rd.Justification)
		}
	}
}

// Failure/unknown path: reachability "unknown" (and "not_analysed") is not
// agreement. The state is still usage_detected from the symbol match, but
// confidence cannot reach high and no call path is claimed.
func TestS615_UnknownReachabilityIsNotAgreement(t *testing.T) {
	for _, reach := range []string{"unknown", "not_analysed"} {
		t.Run(reach, func(t *testing.T) {
			in, dec, rd := mergeCase(lodashCallWithReachability(reach, "", nil)).decide(t)

			wantState(t, dec, StateUsageDetected)
			if in.Confidence.DeterministicMethodsAgree {
				t.Errorf("reachability %q counted as agreement", reach)
			}
			if dec.Confidence == ConfidenceHigh {
				t.Errorf("reachability %q rated high: %v", reach, dec.Criteria)
			}
			if !strings.Contains(strings.Join(dec.Criteria, "|"), "no second deterministic method") {
				t.Errorf("criteria do not say corroboration is missing: %v", dec.Criteria)
			}
			if strings.Contains(rd.Justification, "call path") {
				t.Errorf("justification claims a call path that does not exist: %q", rd.Justification)
			}
		})
	}
}

// Boundary/untrusted input: "reachable" without the entry point or path the
// schema requires is not accepted as a resolved path.
func TestS615_ReachableWithoutPathIsNotAgreement(t *testing.T) {
	cases := map[string]UsageObservation{
		"no path":        lodashCallWithReachability("reachable", "ep-001", nil),
		"empty path":     lodashCallWithReachability("reachable", "ep-001", []CallPathStep{}),
		"no entry point": lodashCallWithReachability("reachable", "", []CallPathStep{{Function: "f", File: "a.js", Line: 1}}),
		"wrong case":     lodashCallWithReachability("REACHABLE", "ep-001", []CallPathStep{{Function: "f", File: "a.js", Line: 1}}),
	}
	for name, obs := range cases {
		t.Run(name, func(t *testing.T) {
			in, dec, rd := mergeCase(obs).decide(t)
			if in.Confidence.DeterministicMethodsAgree {
				t.Error("malformed reachable call site counted as agreement")
			}
			if dec.Confidence == ConfidenceHigh {
				t.Errorf("malformed reachable call site rated high: %v", dec.Criteria)
			}
			if strings.Contains(rd.Justification, "call path") {
				t.Errorf("justification claims a call path: %q", rd.Justification)
			}
		})
	}
}

// Boundary: a very long untrusted path is shortened in the justification,
// keeping its first and last steps, and stays lint-clean.
func TestS615_LongPathIsElided(t *testing.T) {
	var path []CallPathStep
	for i := 1; i <= 20; i++ {
		path = append(path, CallPathStep{Function: "f" + string(rune('a'+i)), File: "src/x.js", Line: i})
	}
	_, _, rd := mergeCase(lodashCallWithReachability("reachable", "ep-001", path)).decide(t)
	if !strings.Contains(rd.Justification, "(14 more)") {
		t.Errorf("long path not elided: %q", rd.Justification)
	}
	if !strings.Contains(rd.Justification, "fb (src/x.js:1)") || !strings.Contains(rd.Justification, "fu (src/x.js:20)") {
		t.Errorf("elided path lost its first or last step: %q", rd.Justification)
	}
	if hits := Lint(rd.Justification); len(hits) > 0 {
		t.Errorf("banned language %v", hits)
	}
}

// When several call sites resolve, the shortest path is the one cited, so
// the justification is the same on every run.
func TestS615_ShortestPathIsCited(t *testing.T) {
	obs := lodashCall("merge", "merge")
	obs.CallSites[0].CallPath = []CallPathStep{
		{Function: "a", File: "src/a.js", Line: 1},
		{Function: "b", File: "src/b.js", Line: 2},
	}
	obs.CallSites[1].CallPath = []CallPathStep{{Function: "short", File: "src/s.js", Line: 3}}
	_, _, rd := mergeCase(obs).decide(t)
	if !strings.Contains(rd.Justification, "short (src/s.js:3)") || strings.Contains(rd.Justification, "a (src/a.js:1)") {
		t.Errorf("did not cite the shortest path: %q", rd.Justification)
	}
}

// ---- ordering ----------------------------------------------------------------

func prio(id string, band RiskBand, sev string, epss *float64) ResultDecision {
	return ResultDecision{FindingID: id, RiskPriority: RiskPriority{Band: band, Severity: sev, EPSSScore: epss}}
}

func ids(ds []ResultDecision) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.FindingID
	}
	return out
}

// Success: band first, then severity, then EPSS (reported before not
// reported), then findingId.
func TestSortDecisions_Rule(t *testing.T) {
	ds := []ResultDecision{
		prio("low-band-critical", BandLowerPriority, "critical", fptr(0.99)),
		prio("insuff-high", BandInsufficientInformation, "high", nil),
		prio("act-high-noepss", BandActNow, "high", nil),
		prio("act-high-epss-low", BandActNow, "High", fptr(0.02)),
		prio("act-high-epss-hi", BandActNow, "HIGH", fptr(0.70)),
		prio("act-critical", BandActNow, "critical", fptr(0.01)),
		prio("act-medium", BandActNow, "moderate", fptr(0.95)),
		prio("act-high-epss-hi-b", BandActNow, "high", fptr(0.70)),
	}
	SortDecisions(ds)
	want := []string{
		"act-critical",       // severity beats EPSS
		"act-high-epss-hi",   // then EPSS, highest first
		"act-high-epss-hi-b", // tie broken by findingId
		"act-high-epss-low",
		"act-high-noepss", // not reported sorts after every reported score
		"act-medium",      // "moderate" is medium
		"insuff-high",     // insufficient_information above lower_priority
		"low-band-critical",
	}
	if got := ids(ds); !reflect.DeepEqual(got, want) {
		t.Errorf("order\n got %v\nwant %v", got, want)
	}
}

// Boundary/untrusted input: an invalid EPSS (NaN, negative, above 1) or an
// unrecognised severity never jumps the queue, and the sort stays total.
func TestSortDecisions_UntrustedValues(t *testing.T) {
	ds := []ResultDecision{
		prio("nan", BandActNow, "high", fptr(math.NaN())),
		prio("above-one", BandActNow, "high", fptr(7)),
		prio("negative", BandActNow, "high", fptr(-0.5)),
		prio("valid", BandActNow, "high", fptr(0.001)),
		prio("weird-severity", BandActNow, "SUPER-CRITICAL", fptr(1)),
		prio("empty-severity", BandActNow, "", fptr(1)),
	}
	SortDecisions(ds)
	want := []string{"valid", "above-one", "nan", "negative", "empty-severity", "weird-severity"}
	if got := ids(ds); !reflect.DeepEqual(got, want) {
		t.Errorf("order\n got %v\nwant %v", got, want)
	}
}

// EPSS changes the order but never a state, a band or a confidence rating.
// Two findings identical except for EPSS are run through the real
// BuildResults; swapping their scores swaps their order and nothing else.
func TestPriority_EPSSOrdersOnly(t *testing.T) {
	run := func(epssA, epssB float64) Results {
		t.Helper()
		c := mergeCase(lodashCall("merge"))
		scan, graph, loc := c.docs()
		base := scan.Findings[0]
		a, b := base, base
		a.FindingID, a.VulnerabilityID = "find-a", "CVE-A"
		b.FindingID, b.VulnerabilityID = "find-b", "CVE-B"
		a.EPSS = &struct {
			Score *float64 `json:"score"`
		}{Score: fptr(epssA)}
		b.EPSS = &struct {
			Score *float64 `json:"score"`
		}{Score: fptr(epssB)}
		scan.Findings = []ScanFinding{a, b}
		la, lb := loc.Results[0], loc.Results[0]
		la.FindingID, lb.FindingID = "find-a", "find-b"
		loc.Results = []LocalisationResult{la, lb}
		res, err := BuildResults(scan, graph, loc)
		if err != nil {
			t.Fatalf("BuildResults: %v", err)
		}
		return res
	}

	low, high := run(0.01, 0.90), run(0.90, 0.01)

	if got := ids(low.Decisions); !reflect.DeepEqual(got, []string{"find-b", "find-a"}) {
		t.Errorf("higher EPSS should come first, got %v", got)
	}
	if got := ids(high.Decisions); !reflect.DeepEqual(got, []string{"find-a", "find-b"}) {
		t.Errorf("swapping EPSS should swap the order, got %v", got)
	}

	byID := func(r Results) map[string]ResultDecision {
		m := map[string]ResultDecision{}
		for _, d := range r.Decisions {
			m[d.FindingID] = d
		}
		return m
	}
	l, h := byID(low), byID(high)
	for _, id := range []string{"find-a", "find-b"} {
		if l[id].State != h[id].State ||
			l[id].AnalysisConfidence != h[id].AnalysisConfidence ||
			!reflect.DeepEqual(l[id].ConfidenceCriteria, h[id].ConfidenceCriteria) ||
			l[id].RiskPriority.Band != h[id].RiskPriority.Band ||
			l[id].Justification != h[id].Justification {
			t.Errorf("%s: EPSS changed more than the order:\n low  %+v\n high %+v", id, l[id], h[id])
		}
	}
	if l["find-a"].State != l["find-b"].State || l["find-a"].AnalysisConfidence != l["find-b"].AnalysisConfidence {
		t.Error("findings identical except EPSS got different states or confidence")
	}
	if !reflect.DeepEqual(low.Distribution, high.Distribution) {
		t.Errorf("distribution changed with EPSS: %+v vs %+v", low.Distribution, high.Distribution)
	}
}
