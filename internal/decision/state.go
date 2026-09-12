package decision

import "sort"

// StateInputs is everything the state guard needs for one finding. Every
// field traces to a specific upstream contract field so the mapping from
// "what Component 2 and Component 3 reported" to "what we are allowed to
// conclude" stays auditable.
type StateInputs struct {
	// AnalysisStatus is usage-graph.json's analysis.status for the
	// ecosystem this finding's package belongs to.
	AnalysisStatus AnalysisStatus

	// LocalisationMethod is localisation.json's results[].method for this
	// finding.
	LocalisationMethod LocalisationMethod

	// HasResolvedUsageEvidence is true when at least one usage observation
	// tied to this finding has a resolved call site implicating one of the
	// candidate symbols (evidenceLevel 2 or 3 in usage-graph.json terms).
	// This is the ONLY input that can produce a positive (usage_detected)
	// verdict.
	HasResolvedUsageEvidence bool

	// UnanalysedReasons lists the reasons (usage-graph.json
	// "unanalysedOccurrences[].reason") for every package occurrence tied
	// to this finding that Component 2 did not examine. Empty when every
	// occurrence for this finding has a usage observation.
	UnanalysedReasons []UnanalysedReason
}

// Verdict is the result of running the state guard: a state plus the
// specific reasons it was chosen, so a justification can be built from real
// inputs instead of a template (see justification.go).
//
// NOTE (S4-11 -> S4-12 handoff): validate.py additionally requires that
// when a decision's state is no_usage_detected, its
// basedOn.coverageSummary.scanStatus field equals "complete" exactly —
// coverageSummary lives only in decision-results.schema.json (it is NOT
// part of usage-graph.json), and scanStatus is optional in that schema, so
// a missing value fails validate.py even though it satisfies the schema.
// DetermineState does not build coverageSummary; whatever assembles the
// final decision JSON (S4-12+) MUST set scanStatus to "complete" exactly
// when Verdict.State == StateNoUsageDetected, or the output will fail
// validate.py despite State being correct.
type Verdict struct {
	State   State
	Reasons []string
}

// DetermineState is the single function permitted to decide a finding's
// State. It is written so that no combination of inputs — however
// malformed, adversarial, or simply incomplete — can produce
// StateNoUsageDetected without a completed analysis that positively found
// nothing. This is the S4-11 acceptance criterion: "Model states the
// evidence required per state and forbids incomplete analysis producing a
// negative finding."
//
// The precedence order below mirrors contracts/validate.py's
// validate_decisions checks exactly, so a Go caller and the Python validator
// reach the same verdict from the same fixture:
//
//  1. Component 2 analysis-level unsupported -> unsupported, unconditionally.
//  2. Component 3 localisation unknown -> unknown (nothing to compare
//     usage against).
//  3. Any unanalysed occurrence for this finding with a blocking reason
//     (anything except not_imported_by_analysed_source) -> unknown.
//  4. Resolved usage evidence exists -> usage_detected, regardless of
//     analysis status. Positive evidence is trusted even from a partial
//     scan; it is only the ABSENCE of evidence that a partial or failed
//     scan is not allowed to turn into a negative verdict.
//  5. Analysis completed with no blocking occurrences and no evidence ->
//     no_usage_detected. This is the only path to this state.
//  6. Anything else (partial or failed analysis, no evidence found) ->
//     unknown, not no_usage_detected.
func DetermineState(in StateInputs) Verdict {
	if in.AnalysisStatus == AnalysisUnsupported {
		return Verdict{
			State:   StateUnsupported,
			Reasons: []string{"Component 2 analysis status is unsupported for this ecosystem"},
		}
	}

	if in.LocalisationMethod == LocalisationUnknown {
		return Verdict{
			State:   StateUnknown,
			Reasons: []string{"localisation could not name a candidate function to compare against usage evidence"},
		}
	}

	if blocked := blockingReasons(in.UnanalysedReasons); len(blocked) > 0 {
		return Verdict{
			State:   StateUnknown,
			Reasons: blocked,
		}
	}

	if in.HasResolvedUsageEvidence {
		return Verdict{
			State:   StateUsageDetected,
			Reasons: []string{"a resolved call site matches a candidate symbol named by localisation"},
		}
	}

	if in.AnalysisStatus == AnalysisComplete {
		return Verdict{
			State:   StateNoUsageDetected,
			Reasons: []string{"analysis completed and found no import or call matching a candidate symbol within the analysed scope"},
		}
	}

	// AnalysisStatus is partial or failed and no evidence was found. The
	// guard: incomplete analysis is never allowed to stand in for a
	// completed one, so this cannot become no_usage_detected no matter what
	// upstream data claims.
	return Verdict{
		State:   StateUnknown,
		Reasons: []string{"Component 2 analysis was " + string(in.AnalysisStatus) + ", so absence of evidence is not evidence of absence"},
	}
}

// blockingReasons returns a human-readable reason string per unanalysed
// occurrence reason that forbids a negative verdict, deduplicated and
// sorted for stable output (tests and reports should not depend on map or
// slice ordering).
func blockingReasons(reasons []UnanalysedReason) []string {
	seen := make(map[UnanalysedReason]bool, len(reasons))
	var out []string
	for _, r := range reasons {
		if !r.blocksNegativeVerdict() || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, blockingReasonText(r))
	}
	sort.Strings(out)
	return out
}

func blockingReasonText(r UnanalysedReason) string {
	switch r {
	case ReasonNestedUnderDependency:
		return "a package occurrence for this finding is nested under a dependency, whose internals are not parsed"
	case ReasonEcosystemUnsupported:
		return "a package occurrence for this finding is outside the analysed ecosystems"
	case ReasonImportSiteParseFailed:
		return "a package occurrence for this finding could not be parsed at its import site"
	case ReasonExcludedByLimits:
		return "a package occurrence for this finding was excluded by scan limits"
	default:
		// Untrusted or future input: treat any unrecognised reason as
		// blocking rather than silently permitting a negative verdict.
		// Boundary case exercised by TestDetermineState_UnknownReasonCode.
		return "a package occurrence for this finding was reported unanalysed for reason \"" + string(r) + "\""
	}
}
