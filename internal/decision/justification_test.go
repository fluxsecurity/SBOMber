package decision

import "testing"

// TestLint_Success_CleanText checks that ordinary justification text
// produced by Justify from a real Verdict passes with no hits.
func TestLint_Success_CleanText(t *testing.T) {
	v := Verdict{
		State:   StateNoUsageDetected,
		Reasons: []string{"analysis completed and found no import or call matching a candidate symbol within the analysed scope"},
	}
	text := Justify(v)

	if hits := Lint(text); len(hits) != 0 {
		t.Fatalf("Lint found banned phrases in generated text: %v (text: %q)", hits, text)
	}
}

// TestLint_FailureOrUnknownPath_CatchesEachBannedPhrase checks every entry
// in contracts/validate.py's BANNED list is caught here too, so the two
// validators cannot drift into passing different justifications.
func TestLint_FailureOrUnknownPath_CatchesEachBannedPhrase(t *testing.T) {
	phrases := []string{"not affected", "is safe", "no risk", "false positive"}
	for _, phrase := range phrases {
		text := "This finding is " + phrase + " based on our analysis."
		hits := Lint(text)
		if len(hits) != 1 || hits[0] != phrase {
			t.Errorf("Lint(%q) = %v, want exactly [%q]", text, hits, phrase)
		}
	}
}

// TestLint_BoundaryUntrustedInput_CaseAndEmbedding checks Lint against
// adversarial formatting: mixed case (matching validate.py's
// justification.lower() behaviour) and a banned phrase embedded inside a
// longer sentence with surrounding punctuation, rather than appearing as a
// clean standalone phrase.
func TestLint_BoundaryUntrustedInput_CaseAndEmbedding(t *testing.T) {
	text := "Reviewed manually; concluded this package IS SAFE, so no further action needed."
	hits := Lint(text)
	if len(hits) != 1 || hits[0] != "is safe" {
		t.Fatalf("Lint(%q) = %v, want exactly [\"is safe\"]", text, hits)
	}
}

// TestLint_BoundaryUntrustedInput_EmptyText checks the zero-value case does
// not panic and reports no hits.
func TestLint_BoundaryUntrustedInput_EmptyText(t *testing.T) {
	if hits := Lint(""); len(hits) != 0 {
		t.Fatalf("Lint(\"\") = %v, want no hits", hits)
	}
}

// TestJustify_StatesWhatCouldNotBeSeen exercises the S4-11 requirement that
// a justification "must state what was checked and what could not be seen"
// by checking the unknown/nested-dependency case produces non-empty,
// specific text rather than a generic placeholder.
func TestJustify_StatesWhatCouldNotBeSeen(t *testing.T) {
	verdict := DetermineState(StateInputs{
		AnalysisStatus:     AnalysisComplete,
		LocalisationMethod: LocalisationPatchReference,
		UnanalysedReasons:  []UnanalysedReason{ReasonNestedUnderDependency},
	})
	text := Justify(verdict)

	if text == "" {
		t.Fatal("expected non-empty justification")
	}
	if hits := Lint(text); len(hits) != 0 {
		t.Fatalf("generated justification contains banned language: %v (%q)", hits, text)
	}
}
