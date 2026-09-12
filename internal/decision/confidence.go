package decision

import "fmt"

// ConfidenceInputs are the five measured inputs S4-11 names as the basis for
// a categorical confidence rating: "localisation method quality, parse
// coverage, import-resolution rate, unresolved call count, agreement between
// deterministic methods." Nothing about exploitability, severity, EPSS, or
// KEV appears here — risk priority is computed independently, and this
// package never reads it, so a frightening CVE can never inflate trust in
// SBOMber's own analysis.
type ConfidenceInputs struct {
	// LocalisationMethod is the technique that named the candidate symbol.
	LocalisationMethod LocalisationMethod

	// LocalisationConfidence is Component 3's own categorical confidence in
	// that localisation (localisation.json's results[].confidence).
	LocalisationConfidence LocalisationConfidence

	// ParseCoveragePercent is the share of files in scope that parsed
	// cleanly, taken from usage-graph.json's coverage object. Range 0-100.
	// Values outside that range are treated as untrusted input — see
	// clampPercent — rather than trusted at face value.
	ParseCoveragePercent float64

	// UnresolvedImportsForPackage is the count of this package's own
	// import observations with resolution "unresolved" (usage-graph.json).
	// Zero means every import of the package resolved to a known binding.
	UnresolvedImportsForPackage int

	// UnresolvedCallSitesForPackage is the count of call sites on this
	// package's resolved imports that themselves could not be resolved
	// (e.g. computed member access). Zero is the strongest signal.
	UnresolvedCallSitesForPackage int

	// DeterministicMethodsAgree is true when more than one
	// non-LLM-derived signal agrees on the outcome — for example,
	// localisation's candidate symbol matches a resolved call site AND
	// that call site's reachability result is not "not_analysed". A
	// single deterministic method with no second method to check it
	// against should leave this false rather than assumed true.
	DeterministicMethodsAgree bool
}

// Rating is a confidence rating together with the published criteria that
// produced it. Per S4-11: "Every category is displayed with the evidence
// that produced it. Never the category alone." Criteria is intended to be
// rendered directly next to Confidence in the report and in
// decision-results.json's confidenceCriteria array — never collapsed into a
// single percentage, and never implying certainty even when every criterion
// for High is met, because analysis is never proven complete. That is why
// there is no ConfidenceCertain or numeric 100 anywhere in this package.
type Rating struct {
	Confidence Confidence
	Criteria   []string
}

// Rate computes a categorical confidence rating from measured inputs. It is
// a decision table, not a formula: S4-11 is explicit that confidence is
// "categorical... Not a numeric formula," so this function never sums or
// averages its inputs into a score. Each branch names the specific
// criteria that were or were not met.
func Rate(in ConfidenceInputs) Rating {
	coverage := clampPercent(in.ParseCoveragePercent)

	methodQuality := localisationMethodQuality(in.LocalisationMethod)

	switch {
	case methodQuality == qualityHigh &&
		coverage >= 90 &&
		in.UnresolvedImportsForPackage == 0 &&
		in.UnresolvedCallSitesForPackage == 0 &&
		in.DeterministicMethodsAgree:
		return Rating{
			Confidence: ConfidenceHigh,
			Criteria: []string{
				fmt.Sprintf("localisation method %s", in.LocalisationMethod),
				fmt.Sprintf("parse coverage %.1f percent", coverage),
				"no unresolved imports for this package",
				"no unresolved call sites for this package",
				"agreement between independent deterministic methods",
			},
		}

	case methodQuality != qualityNone &&
		coverage >= 70 &&
		in.UnresolvedImportsForPackage <= 1 &&
		in.UnresolvedCallSitesForPackage <= 2:
		return Rating{
			Confidence: ConfidenceMedium,
			Criteria:   mediumCriteria(in, coverage, methodQuality),
		}

	default:
		return Rating{
			Confidence: ConfidenceLow,
			Criteria:   lowCriteria(in, coverage, methodQuality),
		}
	}
}

type methodQuality int

const (
	qualityNone methodQuality = iota
	qualityLow
	qualityMedium
	qualityHigh
)

// localisationMethodQuality ranks methods by the reliability order
// documented in localisation.schema.json: "Fallback order, cheapest and
// most reliable first."
func localisationMethodQuality(m LocalisationMethod) methodQuality {
	switch m {
	case LocalisationAdvisoryMetadata, LocalisationPatchReference:
		return qualityHigh
	case LocalisationVersionDiff, LocalisationAdvisoryText:
		return qualityMedium
	case LocalisationLLMSuggested:
		// An LLM-suggested candidate is never, by itself, more than low
		// quality here — localisation.schema.json requires it to be
		// corroborated before it can support anything stronger, and
		// corroboration is what DeterministicMethodsAgree is for.
		return qualityLow
	default: // LocalisationUnknown, or an untrusted/unrecognised value
		return qualityNone
	}
}

func mediumCriteria(in ConfidenceInputs, coverage float64, q methodQuality) []string {
	criteria := []string{
		fmt.Sprintf("localisation method %s", in.LocalisationMethod),
		fmt.Sprintf("parse coverage %.1f percent", coverage),
	}
	if in.UnresolvedImportsForPackage > 0 {
		criteria = append(criteria, fmt.Sprintf("%d unresolved import(s) for this package", in.UnresolvedImportsForPackage))
	}
	if in.UnresolvedCallSitesForPackage > 0 {
		criteria = append(criteria, fmt.Sprintf("%d unresolved call site(s) for this package", in.UnresolvedCallSitesForPackage))
	}
	if !in.DeterministicMethodsAgree {
		criteria = append(criteria, "no second deterministic method available to corroborate")
	}
	if q == qualityLow {
		criteria = append(criteria, "localisation method quality is low")
	}
	return criteria
}

func lowCriteria(in ConfidenceInputs, coverage float64, q methodQuality) []string {
	if q == qualityNone {
		return []string{
			fmt.Sprintf("localisation method %s", in.LocalisationMethod),
			"no reliable candidate symbol to evaluate",
		}
	}
	criteria := []string{
		fmt.Sprintf("localisation method %s", in.LocalisationMethod),
		fmt.Sprintf("parse coverage %.1f percent", coverage),
	}
	if coverage < 70 {
		criteria = append(criteria, "parse coverage below the medium-confidence threshold")
	}
	if in.UnresolvedImportsForPackage > 1 {
		criteria = append(criteria, fmt.Sprintf("%d unresolved imports for this package", in.UnresolvedImportsForPackage))
	}
	if in.UnresolvedCallSitesForPackage > 2 {
		criteria = append(criteria, fmt.Sprintf("%d unresolved call sites for this package", in.UnresolvedCallSitesForPackage))
	}
	return criteria
}

// clampPercent guards against untrusted or malformed upstream input (a
// negative coverage figure, a value above 100, or NaN from a bad division
// upstream) rather than propagating it into a report a client reads.
// Boundary case exercised by TestRate_BoundaryUntrustedCoverage.
func clampPercent(p float64) float64 {
	if p != p { // NaN never equals itself
		return 0
	}
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}
