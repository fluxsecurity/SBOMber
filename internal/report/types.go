// Package report implements Component 4's S4-13 grouped remediation report
// wireframe: the question this package answers is the one the client asked
// for directly — which package do I update first, why, and what will that
// upgrade fix?
//
// S4-13 is a wireframe/prototype stage only. It renders package-grouped
// findings from decision-results.json exactly as produced (currently
// contracts/fixtures/decision-results.sample.json, hand-authored against
// decision-results.schema.json's riskPriority / remediation /
// remediationGroups shape). It does not compute risk bands, EPSS,
// confidence, or remediation targets itself — joining real Component 2/3
// evidence into those fields is S5-08/S5-09's job (Sprint Plan v7). This
// package is a consumer and a renderer, not a second decision engine.
package report

import (
	"encoding/json"
	"os"
)

// ---- Fixture-shaped types --------------------------------------------------
//
// Deliberately a SUBSET of decision-results.schema.json — only the fields
// this package's grouping and rendering actually read, following the same
// convention as internal/decision/fixtures.go: encoding/json ignores fields
// it doesn't know about, so this loader does not break every time the
// schema gains an unrelated field.

// DecisionResults is decision-results.json: Component 4's own contract
// output, produced by the (future, S5-08) real join and consumed here.
type DecisionResults struct {
	ScanID            string             `json:"scanId"`
	Distribution      Distribution       `json:"distribution"`
	Decisions         []Decision         `json:"decisions"`
	RemediationGroups []RemediationGroup `json:"remediationGroups"`
}

// Distribution mirrors decision-results.json's "distribution" object.
type Distribution struct {
	TotalFindings   int `json:"totalFindings"`
	UsageDetected   int `json:"usageDetected"`
	NoUsageDetected int `json:"noUsageDetected"`
	Unknown         int `json:"unknown"`
	Unsupported     int `json:"unsupported"`
}

// Decision is one finding's verdict, as decision-results.json's
// "decisions[]" entries. State and RiskPriority.Band are read as opaque
// strings, not Go enums: this package must not silently accept an
// unrecognised value as if it were a known, reassuring one (see
// classifyGroup in build.go), and comparing against known string constants
// makes that discipline visible at the call site.
type Decision struct {
	FindingID          string       `json:"findingId"`
	VulnerabilityID    string       `json:"vulnerabilityId"`
	PURL               string       `json:"purl"`
	State              string       `json:"state"`
	AnalysisConfidence string       `json:"analysisConfidence"`
	RiskPriority       RiskPriority `json:"riskPriority"`
	Justification      string       `json:"justification"`
	Remediation        Remediation  `json:"remediation"`
}

// RiskPriority mirrors decision-results.json's "decisions[].riskPriority".
type RiskPriority struct {
	Band         string  `json:"band"`
	Severity     string  `json:"severity"`
	CVSSScore    float64 `json:"cvssScore"`
	EPSSScore    float64 `json:"epssScore"`
	CISAKev      bool    `json:"cisaKev"`
	Relationship string  `json:"relationship"`
	FixAvailable bool    `json:"fixAvailable"`
}

// Remediation mirrors decision-results.json's "decisions[].remediation".
type Remediation struct {
	ReportedFixedVersion string   `json:"reportedFixedVersion"`
	ResolvesFindingIDs   []string `json:"resolvesFindingIds"`
}

// RemediationGroup mirrors decision-results.json's top-level
// "remediationGroups[]" — already grouped by package and installed version
// upstream. S4-13 groups by package using THIS, not by re-deriving groups
// from decisions itself, per the schema's own framing: "Answers the
// developer's real question: which package do I update first, why, and
// what will that fix?"
type RemediationGroup struct {
	PURL                 string   `json:"purl"`
	InstalledVersion     string   `json:"installedVersion"`
	ReportedFixedVersion string   `json:"reportedFixedVersion"`
	FindingIDs           []string `json:"findingIds"`
	HighestBand          string   `json:"highestBand"`
	Relationship         string   `json:"relationship"`
}

// Known band and state values. Declared as constants so classifyGroup
// compares against named values instead of bare string literals, and so an
// unrecognised value is visibly "the thing that didn't match any of
// these", not a silent typo.
const (
	BandActNow           = "act_now"
	BandLowerPriority    = "lower_priority"
	BandInsufficientInfo = "insufficient_information"
	StateUsageDetected   = "usage_detected"
	StateNoUsageDetected = "no_usage_detected"
	StateUnknown         = "unknown"
	StateUnsupported     = "unsupported"
)

// LoadDecisionResults reads and parses a decision-results.json file (or a
// contract sample fixture in the same shape). No dependency on the decision
// engine's running code — only on the file on disk, matching S4-12's own
// "no dependency on another component's running code" convention.
func LoadDecisionResults(path string) (DecisionResults, error) {
	var dr DecisionResults
	b, err := os.ReadFile(path)
	if err != nil {
		return dr, err
	}
	err = json.Unmarshal(b, &dr)
	return dr, err
}
