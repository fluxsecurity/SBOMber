package decision

import (
	"math"
	"strings"
	"testing"
)

// TestRate_Success_High mirrors find-001's confidenceCriteria in
// contracts/fixtures/decision-results.sample.json: advisory_metadata
// localisation, 97.2 percent parse coverage, no unresolved imports for the
// package, and a direct call site. Expected: high, with criteria that name
// every input actually met.
func TestRate_Success_High(t *testing.T) {
	got := Rate(ConfidenceInputs{
		LocalisationMethod:            LocalisationAdvisoryMetadata,
		LocalisationConfidence:        LocalisationConfidenceHigh,
		ParseCoveragePercent:          97.2,
		UnresolvedImportsForPackage:   0,
		UnresolvedCallSitesForPackage: 0,
		DeterministicMethodsAgree:     true,
	})

	if got.Confidence != ConfidenceHigh {
		t.Fatalf("confidence = %q, want %q", got.Confidence, ConfidenceHigh)
	}
	if len(got.Criteria) == 0 {
		t.Fatal("high confidence must be displayed with the evidence that produced it (S4-11), got no criteria")
	}
	joined := strings.Join(got.Criteria, " | ")
	if !strings.Contains(joined, "advisory_metadata") {
		t.Errorf("criteria should name the localisation method used, got: %s", joined)
	}
}

// TestRate_FailureOrUnknownPath_Medium mirrors find-002 (axios): version_diff
// localisation with two candidates, 95.8 percent parse coverage, and one
// unresolved computed member access. The fixture's own analysisConfidence
// for this finding is "medium" — not high, because of that one unresolved
// call site.
func TestRate_FailureOrUnknownPath_Medium(t *testing.T) {
	got := Rate(ConfidenceInputs{
		LocalisationMethod:            LocalisationVersionDiff,
		LocalisationConfidence:        LocalisationConfidenceMedium,
		ParseCoveragePercent:          95.8,
		UnresolvedImportsForPackage:   0,
		UnresolvedCallSitesForPackage: 1,
		DeterministicMethodsAgree:     false,
	})

	if got.Confidence != ConfidenceMedium {
		t.Fatalf("confidence = %q, want %q", got.Confidence, ConfidenceMedium)
	}
}

// TestRate_FailureOrUnknownPath_LowOnUnknownLocalisation mirrors find-003
// (minimist): localisation returned unknown, no implicated symbol at all.
// The fixture's analysisConfidence is "low" — confidence has a floor, it is
// never allowed to report "none" (that value is reserved for
// localisationConfidence in the upstream contract, not analysisConfidence).
func TestRate_FailureOrUnknownPath_LowOnUnknownLocalisation(t *testing.T) {
	got := Rate(ConfidenceInputs{
		LocalisationMethod:     LocalisationUnknown,
		LocalisationConfidence: LocalisationConfidenceNone,
		ParseCoveragePercent:   95.8,
	})

	if got.Confidence != ConfidenceLow {
		t.Fatalf("confidence = %q, want %q", got.Confidence, ConfidenceLow)
	}
}

// TestRate_BoundaryUntrustedCoverage feeds coverage figures that should
// never occur from a correctly-computed upstream percentage — negative,
// above 100, and NaN (the classic result of an upstream 0/0 division) — and
// checks the function degrades safely instead of panicking or propagating
// nonsense into a client-facing report.
func TestRate_BoundaryUntrustedCoverage(t *testing.T) {
	cases := []float64{-15.0, 143.0, math.NaN(), math.Inf(1), math.Inf(-1)}

	for _, coverage := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Rate panicked on coverage=%v: %v", coverage, r)
				}
			}()
			got := Rate(ConfidenceInputs{
				LocalisationMethod:          LocalisationAdvisoryMetadata,
				LocalisationConfidence:      LocalisationConfidenceHigh,
				ParseCoveragePercent:        coverage,
				UnresolvedImportsForPackage: 0,
			})
			if got.Confidence != ConfidenceHigh && got.Confidence != ConfidenceMedium && got.Confidence != ConfidenceLow {
				t.Fatalf("coverage=%v produced invalid Confidence %q", coverage, got.Confidence)
			}
		}()
	}
}

// TestRate_LLMSuggestedNeverExceedsLow checks that an uncorroborated
// LLM-suggested localisation cannot reach high or medium confidence even
// when every other input looks ideal — matching
// localisation.schema.json's rule that "an uncorroborated LLM result cannot
// claim high or medium confidence."
func TestRate_LLMSuggestedNeverExceedsLow(t *testing.T) {
	got := Rate(ConfidenceInputs{
		LocalisationMethod:            LocalisationLLMSuggested,
		LocalisationConfidence:        LocalisationConfidenceHigh, // adversarial: upstream over-claims
		ParseCoveragePercent:          100,
		UnresolvedImportsForPackage:   0,
		UnresolvedCallSitesForPackage: 0,
		DeterministicMethodsAgree:     false, // uncorroborated
	})

	if got.Confidence == ConfidenceHigh {
		t.Fatalf("uncorroborated llm_suggested localisation produced high confidence; want low or medium at most")
	}
}

func TestClampPercent(t *testing.T) {
	cases := map[float64]float64{
		-10:          0,
		0:            0,
		50:           50,
		100:          100,
		150:          100,
		math.NaN():   0,
		math.Inf(1):  100,
		math.Inf(-1): 0,
	}
	for in, want := range cases {
		if got := clampPercent(in); got != want {
			t.Errorf("clampPercent(%v) = %v, want %v", in, got, want)
		}
	}
}
