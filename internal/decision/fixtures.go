package decision

import (
	"encoding/json"
	"os"
)

// ---- Fixture-shaped types -------------------------------------------------
//
// These are intentionally a SUBSET of the full JSON contracts — only the
// fields Component 4's loader actually reads. They are not a substitute for
// contracts/*.schema.json and make no claim to validate anything; that is
// what contracts/validate.py is for. If a contract adds a field this
// package doesn't use, these structs simply ignore it (encoding/json does
// this by default), which is deliberate: the loader should not break every
// time Components 1-3 add an unrelated field.

type CanonicalScan struct {
	Findings []ScanFinding `json:"findings"`
}

type ScanFinding struct {
	FindingID     string   `json:"findingId"`
	PURL          string   `json:"purl"`
	OccurrenceIDs []string `json:"occurrenceIds"`
}

type UsageGraph struct {
	Analysis     UsageAnalysis          `json:"analysis"`
	Coverage     UsageCoverage          `json:"coverage"`
	Observations []UsageObservation     `json:"observations"`
	Unanalysed   []UnanalysedOccurrence `json:"unanalysedOccurrences"`
}

type UsageAnalysis struct {
	Status string `json:"status"`
}

type UsageCoverage struct {
	FilesDiscovered int `json:"filesDiscovered"`
	FilesParsed     int `json:"filesParsed"`
}

type UsageObservation struct {
	OccurrenceID string     `json:"occurrenceId"`
	PURL         string     `json:"purl"`
	Resolution   string     `json:"resolution"`
	CallSites    []CallSite `json:"callSites"`
}

type CallSite struct {
	CalledSymbol string `json:"calledSymbol"`
	Resolution   string `json:"resolution"`
	Reachability string `json:"reachability"`
}

type UnanalysedOccurrence struct {
	OccurrenceID string `json:"occurrenceId"`
	Reason       string `json:"reason"`
}

type LocalisationReport struct {
	Results []LocalisationResult `json:"results"`
}

type LocalisationResult struct {
	FindingID        string            `json:"findingId"`
	Method           string            `json:"method"`
	Confidence       string            `json:"confidence"`
	CandidateSymbols []CandidateSymbol `json:"candidateSymbols"`
}

type CandidateSymbol struct {
	Symbol string `json:"symbol"`
}

// ---- Loading ---------------------------------------------------------------
//
// These read from disk. No dependency on another component's running code —
// only on the sample fixtures / real contract-shaped JSON files, satisfying
// S4-12's "No dependency on another component's running code" criterion.

func LoadCanonicalScan(path string) (CanonicalScan, error) {
	var s CanonicalScan
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(b, &s)
	return s, err
}

func LoadUsageGraph(path string) (UsageGraph, error) {
	var g UsageGraph
	b, err := os.ReadFile(path)
	if err != nil {
		return g, err
	}
	err = json.Unmarshal(b, &g)
	return g, err
}

func LoadLocalisationReport(path string) (LocalisationReport, error) {
	var l LocalisationReport
	b, err := os.ReadFile(path)
	if err != nil {
		return l, err
	}
	err = json.Unmarshal(b, &l)
	return l, err
}

// ---- Join --------------------------------------------------------------

// FindingInputs bundles one finding's StateInputs and ConfidenceInputs,
// ready to hand to Decide. Building both from the same join keeps them
// describing the same evidence, per decision.go's comment that confidence
// and justification must never describe a competing verdict from the one
// the state guard produced.
type FindingInputs struct {
	FindingID  string
	State      StateInputs
	Confidence ConfidenceInputs
}

// BuildFindingInputs joins a canonical scan, a usage graph, and a
// localisation report into one FindingInputs per scan finding, keyed on
// findingId -> occurrenceIds -> purl.
//
// Known limitations (documented per S4-12's "any limitation documented when
// discovered" rule, not reconstructed later):
//
//   - AnalysisStatus is read once from the top-level usage-graph.analysis
//     .status and applied to every finding. This is correct for the sample
//     fixtures (single ecosystem, npm) but will need a per-ecosystem lookup
//     once a scan spans more than one ecosystem with different statuses.
//   - HasResolvedUsageEvidence is derived directly from call-site
//     resolution + candidate-symbol match, not from usage-graph's
//     evidenceLevel field. The two should agree on every fixture observed
//     so far, but they are not the same check, and evidenceLevel is not
//     currently cross-validated against the derived boolean.
//   - Matching is by purl, not occurrenceId, for ConfidenceInputs' package-
//     level counters ("this package's own import observations"), per the
//     field's own doc comment. In this fixture set purl already
//     disambiguates by version (lodash@4.17.20 vs lodash@3.10.1), so this
//     does not cross-contaminate the two lodash findings. It would need
//     revisiting if a purl could ever appear at two different occurrences
//     with different usage evidence.
func BuildFindingInputs(scan CanonicalScan, graph UsageGraph, loc LocalisationReport) []FindingInputs {
	locByFinding := make(map[string]LocalisationResult, len(loc.Results))
	for _, r := range loc.Results {
		locByFinding[r.FindingID] = r
	}

	unanalysedByOcc := make(map[string]string, len(graph.Unanalysed))
	for _, u := range graph.Unanalysed {
		unanalysedByOcc[u.OccurrenceID] = u.Reason
	}

	coverage := 0.0
	if graph.Coverage.FilesDiscovered > 0 {
		coverage = float64(graph.Coverage.FilesParsed) / float64(graph.Coverage.FilesDiscovered) * 100
	}

	out := make([]FindingInputs, 0, len(scan.Findings))
	for _, f := range scan.Findings {
		method := LocalisationUnknown
		locConf := LocalisationConfidenceNone
		candidateSymbols := map[string]bool{}

		if r, ok := locByFinding[f.FindingID]; ok {
			method = LocalisationMethod(r.Method)
			locConf = LocalisationConfidence(r.Confidence)
			for _, cs := range r.CandidateSymbols {
				candidateSymbols[cs.Symbol] = true
			}
		}
		// A finding with no localisation result at all (missing from the
		// report entirely, not just "unknown") falls back to
		// LocalisationUnknown above, which DetermineState treats the same
		// as an explicit unknown -- untrusted/incomplete input still can't
		// produce a positive OR negative verdict.

		var reasons []UnanalysedReason
		for _, occID := range f.OccurrenceIDs {
			if reason, blocked := unanalysedByOcc[occID]; blocked {
				reasons = append(reasons, UnanalysedReason(reason))
			}
		}

		hasResolvedUsage := false
		agree := false
		unresolvedImports := 0
		unresolvedCallSites := 0

		for _, obs := range graph.Observations {
			if obs.PURL != f.PURL {
				continue
			}
			if obs.Resolution == "unresolved" {
				unresolvedImports++
			}
			for _, cs := range obs.CallSites {
				if cs.Resolution == "unresolved" {
					unresolvedCallSites++
					continue
				}
				if candidateSymbols[cs.CalledSymbol] {
					hasResolvedUsage = true
					if cs.Reachability != "not_analysed" {
						agree = true
					}
				}
			}
		}

		out = append(out, FindingInputs{
			FindingID: f.FindingID,
			State: StateInputs{
				AnalysisStatus:           AnalysisStatus(graph.Analysis.Status),
				LocalisationMethod:       method,
				HasResolvedUsageEvidence: hasResolvedUsage,
				UnanalysedReasons:        reasons,
			},
			Confidence: ConfidenceInputs{
				LocalisationMethod:            method,
				LocalisationConfidence:        locConf,
				ParseCoveragePercent:          coverage,
				UnresolvedImportsForPackage:   unresolvedImports,
				UnresolvedCallSitesForPackage: unresolvedCallSites,
				DeterministicMethodsAgree:     agree,
			},
		})
	}
	return out
}
