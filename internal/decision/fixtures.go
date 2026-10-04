package decision

import (
	"encoding/json"
	"fmt"
	"os"
)

// ---- Contract-shaped input types -------------------------------------------
//
// These are intentionally a SUBSET of the full JSON contracts — only the
// fields Component 4 actually reads. They are not a substitute for
// contracts/*.schema.json and make no claim to validate anything; that is
// what contracts/validate.py is for. If a contract adds a field this
// package doesn't use, these structs simply ignore it (encoding/json does
// this by default), which is deliberate: the loader should not break every
// time Components 1-3 add an unrelated field.
//
// Field names follow the published contracts, not any producer's Go types
// (internal/canonicalscan uses different names; see the Sprint 5 status
// risk "Component 1's Go types don't match the published contract").

// CanonicalScan is canonical-scan.json (Component 1).
type CanonicalScan struct {
	Scan        ScanMeta         `json:"scan"`
	Occurrences []ScanOccurrence `json:"occurrences"`
	Findings    []ScanFinding    `json:"findings"`
}

// ScanMeta is canonical-scan.json's "scan" object.
type ScanMeta struct {
	ScanID string `json:"scanId"`
}

// ScanOccurrence is one installed package occurrence.
type ScanOccurrence struct {
	OccurrenceID string `json:"occurrenceId"`
	PURL         string `json:"purl"`
	Relationship string `json:"relationship"`
}

// ScanFinding is one vulnerability finding: vulnerability ID + component PURL.
type ScanFinding struct {
	FindingID       string   `json:"findingId"`
	VulnerabilityID string   `json:"vulnerabilityId"`
	PURL            string   `json:"purl"`
	OccurrenceIDs   []string `json:"occurrenceIds"`
	Severity        string   `json:"severity"`
	CVSSScore       *float64 `json:"cvssScore"`
	FixedVersion    string   `json:"fixedVersion"`
	EPSS            *struct {
		Score *float64 `json:"score"`
	} `json:"epss"`
	CISAKev *bool `json:"cisaKev"`
}

// UsageGraph is usage-graph.json (Component 2). Schema 1.2.0 and 1.3.0 are
// both read; 1.3.0 is additive.
type UsageGraph struct {
	SchemaVersion string                 `json:"schemaVersion"`
	Analysis      UsageAnalysis          `json:"analysis"`
	Coverage      UsageCoverage          `json:"coverage"`
	Observations  []UsageObservation     `json:"observations"`
	Unanalysed    []UnanalysedOccurrence `json:"unanalysedOccurrences"`
}

// UsageAnalysis is usage-graph.json's "analysis" object.
type UsageAnalysis struct {
	Status string `json:"status"`
}

// UsageCoverage is usage-graph.json's "coverage" object. Only the counters
// this package reads are listed.
type UsageCoverage struct {
	FilesDiscovered       int      `json:"filesDiscovered"`
	FilesParsed           int      `json:"filesParsed"`
	FilesParsedWithErrors int      `json:"filesParsedWithErrors"`
	FilesFailed           int      `json:"filesFailed"`
	FilesSkipped          int      `json:"filesSkipped"`
	LimitsHit             []string `json:"limitsHit"`
}

// UsageObservation is one third-party import binding.
type UsageObservation struct {
	ObservationID     string        `json:"observationId"`
	OccurrenceID      string        `json:"occurrenceId"`
	PURL              string        `json:"purl"`
	ImportedSpecifier string        `json:"importedSpecifier"`
	ComputedSpecifier bool          `json:"computedSpecifier"`
	ImportKind        string        `json:"importKind"`
	Resolution        string        `json:"resolution"`
	UnresolvedReason  string        `json:"unresolvedReason"`
	Location          UsageLocation `json:"location"`
	EvidenceLevel     int           `json:"evidenceLevel"`
	CallSites         []CallSite    `json:"callSites"`
}

// UsageLocation is where an import statement appears.
type UsageLocation struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// CallSite is one use of an import binding.
type CallSite struct {
	File             string `json:"file"`
	Line             int    `json:"line"`
	CalledSymbol     string `json:"calledSymbol"`
	Resolution       string `json:"resolution"`
	UnresolvedReason string `json:"unresolvedReason"`
	Reachability     string `json:"reachability"`
}

// UnanalysedOccurrence is usage-graph.json's safety-critical array entry.
type UnanalysedOccurrence struct {
	OccurrenceID string `json:"occurrenceId"`
	PURL         string `json:"purl"`
	Reason       string `json:"reason"`
}

// LocalisationReport is localisation.json (Component 3). Schema 1.0.0 is
// read today; the optional 1.1.0 candidate fields agreed in #139 are read
// when present.
type LocalisationReport struct {
	SchemaVersion string               `json:"schemaVersion"`
	Results       []LocalisationResult `json:"results"`
}

// LocalisationResult is one finding's localisation.
type LocalisationResult struct {
	FindingID        string            `json:"findingId"`
	PURL             string            `json:"purl"`
	Method           string            `json:"method"`
	Confidence       string            `json:"confidence"`
	CandidateSymbols []CandidateSymbol `json:"candidateSymbols"`
}

// CandidateSymbol is one candidate vulnerable function. Visibility,
// ExposedVia, ExposedViaSource and ExposedViaComplete are the localisation
// 1.1.0 fields from the #139 join rule (ExposedViaComplete is Component 4's
// sign-off condition 1: a partial caller walk must not close a set). All
// are absent in 1.0.0 documents, which this package reads as an open set.
type CandidateSymbol struct {
	Symbol             string   `json:"symbol"`
	ModulePath         string   `json:"modulePath"`
	Visibility         string   `json:"visibility"`
	ExposedVia         []string `json:"exposedVia"`
	ExposedViaSource   string   `json:"exposedViaSource"`
	ExposedViaComplete bool     `json:"exposedViaComplete"`
}

// ---- Loading ---------------------------------------------------------------

// LoadCanonicalScan reads canonical-scan.json from disk.
func LoadCanonicalScan(path string) (CanonicalScan, error) {
	var s CanonicalScan
	return s, loadJSON(path, &s)
}

// LoadUsageGraph reads usage-graph.json from disk.
func LoadUsageGraph(path string) (UsageGraph, error) {
	var g UsageGraph
	return g, loadJSON(path, &g)
}

// LoadLocalisationReport reads localisation.json from disk.
func LoadLocalisationReport(path string) (LocalisationReport, error) {
	var l LocalisationReport
	return l, loadJSON(path, &l)
}

func loadJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}
