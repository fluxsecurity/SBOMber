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

	// MatchedSymbols are the join keys that matched a resolved call site
	// (only meaningful when HasResolvedUsageEvidence is true). Used for the
	// justification, never for the decision itself.
	MatchedSymbols []string

	// MatchFromAdvisoryTextOnly is true when every matched join key came
	// from advisory prose rather than the package's own code (#139:
	// prose-derived keys are positive-only and cap confidence at medium).
	MatchFromAdvisoryTextOnly bool

	// FilesDiscovered is usage-graph.json's coverage.filesDiscovered. A
	// negative verdict needs at least one discovered source file (#119
	// rule 3; contracts/validate.py "negative needs discovered source").
	FilesDiscovered int

	// RelevantUnresolved describes every unresolved import or call that
	// could refer to this finding's package (#119 rule 4). Any entry
	// blocks a negative verdict. Unresolved observations about OTHER
	// packages are not listed here, so they cannot make this finding
	// unknown (#119 rule 5).
	RelevantUnresolved []string

	// CandidateSetClosed is true only when every localisation candidate is
	// public, or internal with an exhaustive, code-derived exposedVia
	// (#139 rules 3-4). The zero value is false: an open set, which can
	// never support a negative.
	CandidateSetClosed bool

	// CandidateSetOpenDetail says why the set is open, for the
	// justification. Ignored when CandidateSetClosed is true.
	CandidateSetOpenDetail string
}

// OpenSetCriterion is the criterion text agreed in #139 for a finding whose
// localisation candidate set is open. Kept verbatim so the report, the
// justification and the Sprint 6 audit all search for the same phrase.
const OpenSetCriterion = "localised to an internal function with no resolved public entry point"

// Verdict is the result of running the state guard: a state plus the
// specific reasons it was chosen, so a justification can be built from real
// inputs instead of a template (see justification.go).
//
// validate.py additionally requires basedOn.coverageSummary.scanStatus ==
// "complete" and unresolvedImportsInScope == 0 on every no_usage_detected
// decision. BuildResults (results.go) fills both from the same evidence
// the guard below used, so they cannot disagree.
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
//     scan is not allowed to turn into a negative verdict (#119 rule 1).
//  5. Without positive evidence, every one of these must hold for a
//     negative, otherwise the verdict is unknown and the reasons list
//     every precondition that failed:
//     a. Component 2 status is complete (#119 rules 2-3);
//     b. at least one source file was discovered (#119 rule 3);
//     c. no unresolved import or call could refer to this package
//     (#119 rule 4);
//     d. the localisation candidate set is closed (#139 rule 4, the S5-08
//     implementation of #119 rule 6).
//  6. All of 5 hold -> no_usage_detected. This is the only path to it.
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
		return Verdict{State: StateUsageDetected, Reasons: usageReasons(in)}
	}

	// From here on there is no positive evidence. Collect every failed
	// negative precondition rather than stopping at the first, so the
	// justification states everything that could not be seen.
	var missing []string
	if in.AnalysisStatus != AnalysisComplete {
		// Partial, failed, or an unrecognised status from untrusted input.
		missing = append(missing, "Component 2 analysis was "+statusText(in.AnalysisStatus)+", so absence of evidence is not evidence of absence")
	}
	if in.FilesDiscovered <= 0 {
		missing = append(missing, "Component 2 discovered no application source files, so there was nothing to search for usage")
	}
	missing = append(missing, in.RelevantUnresolved...)
	if !in.CandidateSetClosed {
		detail := in.CandidateSetOpenDetail
		if detail == "" {
			detail = "the candidate set is not known to be complete"
		}
		missing = append(missing, OpenSetCriterion+" ("+detail+")")
	}
	if len(missing) > 0 {
		return Verdict{State: StateUnknown, Reasons: missing}
	}

	return Verdict{
		State:   StateNoUsageDetected,
		Reasons: []string{NoUsageDisplay + ": analysis completed and no application call reached any public entry point of the localised functions"},
	}
}

// NoUsageDisplay is how no_usage_detected is shown to people (R3
// acceptance criterion; #119 "Done when"). It is never "safe" or "not
// affected".
const NoUsageDisplay = "no usage evidence found within the analysed scope"

// Display returns the human-facing label for a state.
func (s State) Display() string {
	switch s {
	case StateUsageDetected:
		return "usage detected"
	case StateNoUsageDetected:
		return NoUsageDisplay
	case StateUnsupported:
		return "not analysed by SBOMber"
	default:
		return "insufficient information"
	}
}

func usageReasons(in StateInputs) []string {
	reason := "a resolved call site in application source matches a candidate symbol named by localisation"
	if len(in.MatchedSymbols) > 0 {
		reason = "the application calls " + joinQuoted(in.MatchedSymbols) + ", which localisation names as a candidate or a public entry point to one"
	}
	out := []string{reason}
	if in.MatchFromAdvisoryTextOnly {
		out = append(out, "the matched name came from the advisory text, not from the package's own code, so confidence is capped at medium")
	}
	if in.AnalysisStatus != AnalysisComplete {
		out = append(out, "Component 2 analysis was "+statusText(in.AnalysisStatus)+"; this evidence is real but other call sites may not have been seen")
	}
	return out
}

func statusText(s AnalysisStatus) string {
	if s == "" {
		return "not reported"
	}
	return string(s)
}

func joinQuoted(names []string) string {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	out := ""
	for i, n := range sorted {
		switch {
		case i == 0:
		case i == len(sorted)-1:
			out += " and "
		default:
			out += ", "
		}
		out += n
	}
	return out
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
	case ReasonAmbiguousOccurrence:
		return "an import matched more than one installed occurrence of this package and could not be assigned safely"
	case ReasonComputedSpecifier:
		return "a dynamic import with a computed module name could load this package"
	default:
		// Untrusted or future input: treat any unrecognised reason as
		// blocking rather than silently permitting a negative verdict.
		// Boundary case exercised by TestDetermineState_UnknownReasonCode.
		return "a package occurrence for this finding was reported unanalysed for reason \"" + string(r) + "\""
	}
}
