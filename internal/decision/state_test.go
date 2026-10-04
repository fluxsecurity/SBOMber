package decision

import (
	"sort"
	"testing"
)

// TestDetermineState_Success_UsageDetected mirrors find-001 in
// contracts/fixtures/decision-results.sample.json: lodash 4.17.20, advisory
// names template, and a resolved call site at email.js:47 reachable from
// the postWelcome route handler. Expected outcome per the fixture:
// usage_detected.
func TestDetermineState_Success_UsageDetected(t *testing.T) {
	got := DetermineState(StateInputs{
		AnalysisStatus:           AnalysisComplete,
		LocalisationMethod:       LocalisationAdvisoryMetadata,
		HasResolvedUsageEvidence: true,
	})

	if got.State != StateUsageDetected {
		t.Fatalf("state = %q, want %q", got.State, StateUsageDetected)
	}
	if len(got.Reasons) == 0 {
		t.Fatal("expected at least one reason to justify usage_detected")
	}
}

// TestDetermineState_FailureOrUnknownPath_NestedUnderDependency mirrors
// find-004, described in contracts/README.md as "the case that matters":
// lodash 3.10.1 is nested under legacy-reporter, localisation identified
// defaultsDeep with HIGH confidence via patch_reference, but Component 2
// reports the occurrence unanalysed with reason nested_under_dependency.
// High-quality localisation must NOT be enough to produce a verdict here —
// the fixture's point is exactly that this must be unknown, not
// no_usage_detected and not usage_detected.
func TestDetermineState_FailureOrUnknownPath_NestedUnderDependency(t *testing.T) {
	got := DetermineState(StateInputs{
		AnalysisStatus:           AnalysisComplete,
		LocalisationMethod:       LocalisationPatchReference,
		HasResolvedUsageEvidence: false,
		UnanalysedReasons:        []UnanalysedReason{ReasonNestedUnderDependency},
	})

	if got.State != StateUnknown {
		t.Fatalf("state = %q, want %q (nested_under_dependency must block any verdict)", got.State, StateUnknown)
	}
}

// TestDetermineState_FailureOrUnknownPath_LocalisationUnknown mirrors
// find-003: minimist prototype pollution with no single implicated symbol,
// localisation honestly returns unknown. Expected: unknown, low confidence
// (confidence is tested separately in confidence_test.go).
func TestDetermineState_FailureOrUnknownPath_LocalisationUnknown(t *testing.T) {
	got := DetermineState(StateInputs{
		AnalysisStatus:           AnalysisComplete,
		LocalisationMethod:       LocalisationUnknown,
		HasResolvedUsageEvidence: false,
	})

	if got.State != StateUnknown {
		t.Fatalf("state = %q, want %q", got.State, StateUnknown)
	}
}

// TestDetermineState_Success_NoUsageDetected mirrors find-002: axios 0.21.0,
// analysis completed, no unanalysed occurrences, and no resolved evidence
// matching the candidates. This is the ONLY combination of inputs that may
// legally produce no_usage_detected.
func TestDetermineState_Success_NoUsageDetected(t *testing.T) {
	got := DetermineState(StateInputs{
		AnalysisStatus:           AnalysisComplete,
		LocalisationMethod:       LocalisationVersionDiff,
		HasResolvedUsageEvidence: false,
	})

	if got.State != StateNoUsageDetected {
		t.Fatalf("state = %q, want %q", got.State, StateNoUsageDetected)
	}
}

// TestDetermineState_BoundaryUntrustedInput_PartialScanCannotBeNegative is
// the core S4-11 acceptance criterion, exercised directly: an untrusted or
// merely incomplete upstream analysis (partial or failed) must never be
// able to produce no_usage_detected, however confidently the rest of the
// input looks like a clean negative. This is the guard the whole state
// model exists to enforce.
func TestDetermineState_BoundaryUntrustedInput_PartialScanCannotBeNegative(t *testing.T) {
	for _, status := range []AnalysisStatus{AnalysisPartial, AnalysisFailed} {
		got := DetermineState(StateInputs{
			AnalysisStatus:           status,
			LocalisationMethod:       LocalisationAdvisoryMetadata,
			HasResolvedUsageEvidence: false,
		})
		if got.State == StateNoUsageDetected {
			t.Fatalf("AnalysisStatus=%q produced no_usage_detected; incomplete analysis must never assert a negative", status)
		}
		if got.State != StateUnknown {
			t.Fatalf("AnalysisStatus=%q produced %q, want %q", status, got.State, StateUnknown)
		}
	}
}

// TestDetermineState_BoundaryUntrustedInput_UnsupportedWins checks that
// AnalysisUnsupported takes precedence even when paired with a combination
// of other fields that would otherwise look like strong positive evidence —
// an adversarial or simply buggy upstream producer should not be able to
// smuggle a usage_detected verdict past an unsupported analysis by also
// setting HasResolvedUsageEvidence.
func TestDetermineState_BoundaryUntrustedInput_UnsupportedWins(t *testing.T) {
	got := DetermineState(StateInputs{
		AnalysisStatus:           AnalysisUnsupported,
		LocalisationMethod:       LocalisationAdvisoryMetadata,
		HasResolvedUsageEvidence: true, // contradictory / adversarial input
	})

	if got.State != StateUnsupported {
		t.Fatalf("state = %q, want %q even with contradictory HasResolvedUsageEvidence=true", got.State, StateUnsupported)
	}
}

// TestDetermineState_BoundaryUntrustedInput_UnrecognisedReasonCodeBlocks
// feeds an UnanalysedReason value that does not appear anywhere in
// usage-graph.schema.json's enum — simulating a future schema addition, a
// version skew between components, or a malformed upstream file. The guard
// must fail closed (treat it as blocking) rather than fail open (silently
// permit a negative verdict because the reason wasn't recognised).
func TestDetermineState_BoundaryUntrustedInput_UnrecognisedReasonCodeBlocks(t *testing.T) {
	got := DetermineState(StateInputs{
		AnalysisStatus:           AnalysisComplete,
		LocalisationMethod:       LocalisationAdvisoryMetadata,
		HasResolvedUsageEvidence: false,
		UnanalysedReasons:        []UnanalysedReason{"some_future_reason_code"},
	})

	if got.State != StateUnknown {
		t.Fatalf("state = %q, want %q for an unrecognised reason code (must fail closed)", got.State, StateUnknown)
	}
}

// TestBlockingReasons_DeduplicatesAndSorts checks the helper in isolation:
// repeated and mixed blocking/non-blocking reasons should collapse to a
// stable, deduplicated, sorted set so report output and tests do not depend
// on slice ordering from upstream.
func TestBlockingReasons_DeduplicatesAndSorts(t *testing.T) {
	got := blockingReasons([]UnanalysedReason{
		ReasonNestedUnderDependency,
		ReasonNotImportedByAnalysedSource, // must NOT appear in output
		ReasonNestedUnderDependency,       // duplicate
		ReasonEcosystemUnsupported,
	})

	if len(got) != 2 {
		t.Fatalf("got %d reasons, want 2 (deduplicated, excluding not_imported_by_analysed_source): %v", len(got), got)
	}
	if !sort.StringsAreSorted(got) {
		t.Fatalf("expected sorted output, got %v", got)
	}
}
