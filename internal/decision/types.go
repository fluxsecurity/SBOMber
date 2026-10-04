// Package decision implements Component 4 of SBOMber: the state model and
// categorical confidence rating described in S4-11 (issue #93).
//
// Vocabulary and invariants here are not this package's invention. They are
// fixed by three JSON contracts under /contracts, and cross-checked by
// contracts/validate.py against the sample fixtures in
// contracts/fixtures/*.sample.json:
//
//   - decision-results.schema.json (this component's own output)
//   - usage-graph.schema.json      (Component 2's usage/reachability evidence)
//   - localisation.schema.json     (Component 3's candidate-symbol evidence)
//
// Any change to the string values below is a schema change and requires
// contracts/validate.py to keep passing against the fixtures, per
// contracts/README.md's "Changing a schema" section.
package decision

// State is SBOMber's four-state verdict, per Requirements v8 R3 and
// decision-results.schema.json's "decisions[].state".
//
// This supersedes the Semester 1 three-signal model. The write-up of that
// supersession as a research finding is tracked separately (S4-11 "Done
// when": "Supersession of the Semester 1 three-signal model written up as a
// research finding") and lives in docs/design, not in this package.
type State string

const (
	// StateUsageDetected means the vulnerable function was both localised
	// and observed as called from application source, per the evidence
	// levels recorded in usage-graph.json.
	StateUsageDetected State = "usage_detected"

	// StateNoUsageDetected means no evidence of use was found WITHIN THE
	// ANALYSED SCOPE. This is never "safe" and must never be displayed,
	// logged, or worded as "not affected", "is safe", "no risk" or "false
	// positive" (contracts/validate.py's BANNED list, enforced in this
	// package by Lint in justification.go).
	StateNoUsageDetected State = "no_usage_detected"

	// StateUnknown means the analysis could not determine usage one way or
	// the other: localisation failed, the occurrence sits behind
	// unanalysed dependency code, or the underlying scan was partial or
	// failed. Nothing about "unknown" implies the vulnerability is present
	// OR absent.
	StateUnknown State = "unknown"

	// StateUnsupported means SBOMber did not analyse this case at all
	// (unsupported ecosystem, analysis-level failure upstream). It is
	// deliberately not called "not applicable" — the vulnerability may well
	// apply; SBOMber simply did not look.
	StateUnsupported State = "unsupported"
)

// Confidence is the categorical rating attached to every state. It is never
// a raw percentage and never a single numeric score — see the package doc
// on Rate in confidence.go for why.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// AnalysisStatus mirrors usage-graph.json's "analysis.status", Component 2's
// own report of whether it actually completed. This is the field that
// prevents an empty unsupported, failed or partial analysis from being
// mistaken for a completed analysis that simply found no usage.
type AnalysisStatus string

const (
	AnalysisComplete    AnalysisStatus = "complete"
	AnalysisPartial     AnalysisStatus = "partial"
	AnalysisUnsupported AnalysisStatus = "unsupported"
	AnalysisFailed      AnalysisStatus = "failed"
)

// LocalisationMethod mirrors localisation.json's "results[].method": the
// technique Component 3 used to name candidate vulnerable functions, in
// cheapest-and-most-reliable-first fallback order. LocalisationUnknown is an
// honest outcome, not an error — the finding falls back to package-level
// treatment.
type LocalisationMethod string

const (
	LocalisationAdvisoryMetadata LocalisationMethod = "advisory_metadata"
	LocalisationPatchReference   LocalisationMethod = "patch_reference"
	LocalisationAdvisoryText     LocalisationMethod = "advisory_text"
	LocalisationVersionDiff      LocalisationMethod = "version_diff"
	LocalisationLLMSuggested     LocalisationMethod = "llm_suggested"
	LocalisationUnknown          LocalisationMethod = "unknown"
)

// LocalisationConfidence mirrors localisation.json's "results[].confidence".
// "none" only ever accompanies LocalisationUnknown.
type LocalisationConfidence string

const (
	LocalisationConfidenceHigh   LocalisationConfidence = "high"
	LocalisationConfidenceMedium LocalisationConfidence = "medium"
	LocalisationConfidenceLow    LocalisationConfidence = "low"
	LocalisationConfidenceNone   LocalisationConfidence = "none"
)

// UnanalysedReason mirrors usage-graph.json's "unanalysedOccurrences[].reason".
// This is, in the contract README's own words, "THE SAFETY-CRITICAL ARRAY":
// without it, "analysed and found no usage" and "never analysed" would both
// look like an occurrence with no observations.
type UnanalysedReason string

const (
	// ReasonNotImportedByAnalysedSource is the ONLY reason that may support
	// a no_usage_detected verdict: the analysis completed and genuinely
	// found no import.
	ReasonNotImportedByAnalysedSource UnanalysedReason = "not_imported_by_analysed_source"

	// ReasonNestedUnderDependency: reachable only from inside another
	// package whose source is not parsed. Resolves to unknown, never
	// no_usage_detected.
	ReasonNestedUnderDependency UnanalysedReason = "nested_under_dependency"

	ReasonEcosystemUnsupported  UnanalysedReason = "ecosystem_unsupported"
	ReasonImportSiteParseFailed UnanalysedReason = "import_site_parse_failed"
	ReasonExcludedByLimits      UnanalysedReason = "excluded_by_limits"
)

// blocksNegativeVerdict reports whether an unanalysed occurrence carrying
// this reason forbids a no_usage_detected verdict for the finding it belongs
// to. Every reason except ReasonNotImportedByAnalysedSource blocks it.
func (r UnanalysedReason) blocksNegativeVerdict() bool {
	return r != ReasonNotImportedByAnalysedSource
}
