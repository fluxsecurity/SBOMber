package decision

import (
	"strings"
	"testing"
)

// Fixture paths assume the standard layout: internal/decision/*_test.go
// running two directories below repo root, with contracts/fixtures/ at
// root/contracts/fixtures/. Adjust if your module root differs.
const (
	fixtureCanonicalScan = "../../contracts/fixtures/canonical-scan.sample.json"
	fixtureUsageGraph    = "../../contracts/fixtures/usage-graph.sample.json"
	fixtureLocalisation  = "../../contracts/fixtures/localisation.sample.json"
)

func loadSampleInputs(t *testing.T) map[string]FindingInputs {
	t.Helper()
	scan, err := LoadCanonicalScan(fixtureCanonicalScan)
	if err != nil {
		t.Fatalf("LoadCanonicalScan: %v", err)
	}
	graph, err := LoadUsageGraph(fixtureUsageGraph)
	if err != nil {
		t.Fatalf("LoadUsageGraph: %v", err)
	}
	loc, err := LoadLocalisationReport(fixtureLocalisation)
	if err != nil {
		t.Fatalf("LoadLocalisationReport: %v", err)
	}

	inputs := BuildFindingInputs(scan, graph, loc)
	byID := make(map[string]FindingInputs, len(inputs))
	for _, in := range inputs {
		byID[in.FindingID] = in
	}
	return byID
}

// TestFindingInputs_SuccessPath: find-001 (lodash@4.17.20) has a resolved
// call site (`template`, reachability "reachable") matching localisation's
// candidate symbol, named via advisory_metadata (the highest-quality
// method) with high localisation confidence. This should produce
// usage_detected at high confidence -- the clean positive case.
func TestFindingInputs_SuccessPath(t *testing.T) {
	inputs := loadSampleInputs(t)
	in, ok := inputs["find-001"]
	if !ok {
		t.Fatal("find-001 missing from joined inputs")
	}

	verdict := DetermineState(in.State)
	if verdict.State != StateUsageDetected {
		t.Fatalf("find-001: got state %q, want %q (reasons: %v)", verdict.State, StateUsageDetected, verdict.Reasons)
	}

	rating := Rate(in.Confidence)
	if rating.Confidence != ConfidenceHigh {
		t.Fatalf("find-001: got confidence %q, want %q (criteria: %v)", rating.Confidence, ConfidenceHigh, rating.Criteria)
	}
}

// TestFindingInputs_SampleNegativeIsNowUnknown: find-002 (axios@0.21.0) was
// fully analysed and neither resolved call site matches a candidate. Before
// S5-08 this was no_usage_detected. Under the handoff rules it is unknown:
// obs-005 is an unresolved computed member access on axios, which could be
// a candidate (#119 rule 4), and localisation 1.0.0 cannot close the set
// (#139 rule 5). The relative computed import obs-006 must NOT be listed:
// it loads application code, not a package (#119 rule 5).
func TestFindingInputs_SampleNegativeIsNowUnknown(t *testing.T) {
	inputs := loadSampleInputs(t)
	in, ok := inputs["find-002"]
	if !ok {
		t.Fatal("find-002 missing from joined inputs")
	}
	if in.State.HasResolvedUsageEvidence {
		t.Fatal("find-002: HasResolvedUsageEvidence should be false -- neither candidate symbol was called")
	}

	verdict := DetermineState(in.State)
	if verdict.State != StateUnknown {
		t.Fatalf("find-002: got state %q, want %q (reasons: %v)", verdict.State, StateUnknown, verdict.Reasons)
	}
	assertReasonContains(t, verdict, "computed_member_access")
	assertReasonContains(t, verdict, OpenSetCriterion)
	for _, r := range verdict.Reasons {
		if strings.Contains(r, "plugins") {
			t.Errorf("relative computed import was treated as relevant: %q", r)
		}
	}
}

func assertReasonContains(t *testing.T, v Verdict, want string) {
	t.Helper()
	for _, r := range v.Reasons {
		if strings.Contains(r, want) {
			return
		}
	}
	t.Errorf("no reason mentions %q; reasons: %v", want, v.Reasons)
}

// TestFindingInputs_BoundaryUnanalysedOccurrenceBlocksNegative: find-004
// (lodash@3.10.1) has HIGH-confidence localisation via patch_reference --
// the strongest method -- naming a specific function (defaultsDeep). But
// its only occurrence (occ-002) is in unanalysedOccurrences with reason
// nested_under_dependency. This is the boundary case: strong evidence on
// one axis (localisation) sitting on top of zero evidence on the other
// (usage analysis never reached the occurrence at all). Proves the DoD's
// "incomplete evidence cannot produce a negative finding" -- if the join
// or DetermineState collapsed "no matching call site" and "never analysed"
// into the same signal, this would wrongly resolve to no_usage_detected
// despite the high localisation confidence appearing to support it.
func TestFindingInputs_BoundaryUnanalysedOccurrenceBlocksNegative(t *testing.T) {
	inputs := loadSampleInputs(t)
	in, ok := inputs["find-004"]
	if !ok {
		t.Fatal("find-004 missing from joined inputs")
	}

	if in.Confidence.LocalisationConfidence != LocalisationConfidenceHigh {
		t.Fatalf("test setup assumption broken: find-004 localisation confidence is %q, want %q -- fixture may have changed",
			in.Confidence.LocalisationConfidence, LocalisationConfidenceHigh)
	}
	if len(in.State.UnanalysedReasons) == 0 {
		t.Fatal("test setup assumption broken: find-004 should carry an unanalysed reason (nested_under_dependency) -- fixture may have changed")
	}

	verdict := DetermineState(in.State)
	if verdict.State == StateNoUsageDetected {
		t.Fatalf("find-004: incomplete evidence produced a negative finding -- got %q despite unanalysed occurrence reasons %v",
			verdict.State, in.State.UnanalysedReasons)
	}
	if verdict.State != StateUnknown {
		t.Fatalf("find-004: got state %q, want %q (reasons: %v)", verdict.State, StateUnknown, verdict.Reasons)
	}
}
