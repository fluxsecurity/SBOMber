package decision

import (
	"strings"
	"testing"
)

func TestIssue172AbsentImportCannotSupportNegative(t *testing.T) {
	in := StateInputs{
		AnalysisStatus: AnalysisComplete, LocalisationMethod: LocalisationPatchReference,
		FilesDiscovered: 1, CandidateSetClosed: true,
		UnanalysedReasons: []UnanalysedReason{ReasonNotImportedByAnalysedSource},
	}
	got := DetermineState(in)
	if got.State != StateUnknown || !strings.Contains(strings.Join(got.Reasons, " "), "dependency-internal usage was not analysed") {
		t.Fatalf("absence of application imports supported a negative: %+v", got)
	}
	// Even repeated upstream reasons must produce one policy explanation.
	in.UnanalysedReasons = append(in.UnanalysedReasons, ReasonNotImportedByAnalysedSource)
	if repeated := DetermineState(in); len(repeated.Reasons) != len(got.Reasons) {
		t.Fatalf("duplicate reason changed explanation: %+v", repeated)
	}
	// A positive call for a matched occurrence is retained even when another
	// occurrence for the finding has no application import.
	in.HasResolvedUsageEvidence = true
	in.MatchedSymbols = []string{"merge"}
	if positive := DetermineState(in); positive.State != StateUsageDetected {
		t.Fatalf("matched positive evidence lost: %+v", positive)
	}
}
