package decision

import "testing"

// TestEngine_ConsumesAllThreeFixturesAndEmitsJustifiedDecisions is the
// direct DoD check for S4-12's first line: "Engine consumes all three
// sample fixtures and emits states with human-readable justifications."
// It runs the real Decide() (not DetermineState/Rate in isolation) across
// every finding the loader produces, and checks each Decision actually has
// non-empty, lint-clean justification text -- not just a bare state.
func TestEngine_ConsumesAllThreeFixturesAndEmitsJustifiedDecisions(t *testing.T) {
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
	if len(inputs) != 4 {
		t.Fatalf("got %d findings from the fixtures, want 4 (find-001..find-004)", len(inputs))
	}

	wantStates := map[string]State{
		"find-001": StateUsageDetected,
		"find-002": StateNoUsageDetected,
		"find-003": StateUnknown,
		"find-004": StateUnknown,
	}

	decisions := make([]Decision, 0, len(inputs))
	for _, in := range inputs {
		dec := Decide(in.FindingID, in.State, in.Confidence)
		decisions = append(decisions, dec)

		if dec.Justification == "" {
			t.Errorf("%s: empty justification -- DoD requires human-readable justification for every state", in.FindingID)
		}
		if hits := Lint(dec.Justification); len(hits) != 0 {
			t.Errorf("%s: justification contains banned language %v: %q", in.FindingID, hits, dec.Justification)
		}
		if want, ok := wantStates[in.FindingID]; ok && dec.State != want {
			t.Errorf("%s: state = %q, want %q", in.FindingID, dec.State, want)
		}
	}

	dist := Tally(decisions)
	if dist.TotalFindings != 4 || dist.UsageDetected != 1 || dist.NoUsageDetected != 1 || dist.Unknown != 2 {
		t.Errorf("unexpected distribution: %+v", dist)
	}
}
