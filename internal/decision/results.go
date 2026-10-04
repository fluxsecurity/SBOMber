package decision

import (
	"fmt"
	"sort"
)

// ---- decision-results.json (schema 1.1.0) -----------------------------------
//
// These types mirror contracts/decision-results.schema.json field for field
// (additionalProperties is false there, so nothing extra may be emitted).
// remediationGroups is S5-09's (#120) and is not produced here.

// ResultsSchemaVersion is decision-results.schema.json's const.
const ResultsSchemaVersion = "1.1.0"

// Results is a whole decision-results.json document.
type Results struct {
	SchemaVersion string              `json:"schemaVersion"`
	ScanID        string              `json:"scanId"`
	Distribution  ResultsDistribution `json:"distribution"`
	Decisions     []ResultDecision    `json:"decisions"`
}

// ResultsDistribution is the prioritisation distribution, not noise reduction.
type ResultsDistribution struct {
	TotalFindings   int `json:"totalFindings"`
	UsageDetected   int `json:"usageDetected"`
	NoUsageDetected int `json:"noUsageDetected"`
	Unknown         int `json:"unknown"`
	Unsupported     int `json:"unsupported"`
}

// ResultDecision is one decisions[] entry.
type ResultDecision struct {
	FindingID          string             `json:"findingId"`
	VulnerabilityID    string             `json:"vulnerabilityId,omitempty"`
	PURL               string             `json:"purl,omitempty"`
	State              State              `json:"state"`
	AnalysisConfidence Confidence         `json:"analysisConfidence"`
	ConfidenceCriteria []string           `json:"confidenceCriteria"`
	RiskPriority       RiskPriority       `json:"riskPriority"`
	Justification      string             `json:"justification"`
	BasedOn            BasedOn            `json:"basedOn"`
	Remediation        *ResultRemediation `json:"remediation,omitempty"`
	VEXMapping         *VEXMapping        `json:"vexMapping,omitempty"`
}

// RiskPriority is how urgent a finding is. It is computed separately from
// confidence and never feeds into it.
type RiskPriority struct {
	Band         RiskBand `json:"band"`
	Severity     string   `json:"severity,omitempty"`
	CVSSScore    *float64 `json:"cvssScore,omitempty"`
	EPSSScore    *float64 `json:"epssScore,omitempty"`
	CISAKev      *bool    `json:"cisaKev,omitempty"`
	Relationship string   `json:"relationship,omitempty"`
	FixAvailable bool     `json:"fixAvailable"`
}

// RiskBand is decisions[].riskPriority.band.
type RiskBand string

const (
	BandActNow                  RiskBand = "act_now"
	BandLowerPriority           RiskBand = "lower_priority"
	BandInsufficientInformation RiskBand = "insufficient_information"
)

// BasedOn is the evidence the verdict rests on.
type BasedOn struct {
	UsageObservationIDs    []string               `json:"usageObservationIds"`
	LocalisationMethod     LocalisationMethod     `json:"localisationMethod"`
	LocalisationConfidence LocalisationConfidence `json:"localisationConfidence"`
	MatchedSymbols         []string               `json:"matchedSymbols"`
	EvidenceLevel          int                    `json:"evidenceLevel,omitempty"`
	CoverageSummary        CoverageSummary        `json:"coverageSummary"`
}

// CoverageSummary is basedOn.coverageSummary.
type CoverageSummary struct {
	ParseCoveragePercent     float64 `json:"parseCoveragePercent"`
	UnresolvedImportsInScope int     `json:"unresolvedImportsInScope"`
	ScanStatus               string  `json:"scanStatus,omitempty"`
}

// ResultRemediation is decisions[].remediation.
type ResultRemediation struct {
	ReportedFixedVersion string   `json:"reportedFixedVersion,omitempty"`
	ResolvesFindingIDs   []string `json:"resolvesFindingIds,omitempty"`
}

// VEXMapping is decisions[].vexMapping, consumed by Component 3's exporter.
type VEXMapping struct {
	Statement       string `json:"statement"`
	ActionStatement string `json:"actionStatement,omitempty"`
}

// OpenVEX vocabulary selected by S4-09 (contracts/fixtures/vex-decision.json).
const (
	VEXAffected           = "affected"
	VEXUnderInvestigation = "under_investigation"
	VEXOmit               = "omit"
)

// BuildResults runs the join and the decision for every finding and
// assembles decision-results.json. It returns an error if any
// justification contains banned language, so unsafe wording can never be
// written to disk.
func BuildResults(scan CanonicalScan, graph UsageGraph, loc LocalisationReport) (Results, error) {
	inputs := BuildFindingInputs(scan, graph, loc)

	findings := make(map[string]ScanFinding, len(scan.Findings))
	for _, f := range scan.Findings {
		findings[f.FindingID] = f
	}
	relationship := relationshipByOccurrence(scan)

	res := Results{SchemaVersion: ResultsSchemaVersion, ScanID: scan.Scan.ScanID}
	decisions := make([]Decision, 0, len(inputs))
	for _, in := range inputs {
		f := findings[in.FindingID]
		dec := Decide(in.FindingID, in.State, in.Confidence)
		if hits := Lint(dec.Justification); len(hits) > 0 {
			return Results{}, fmt.Errorf("%s: justification contains banned language %v", in.FindingID, hits)
		}
		decisions = append(decisions, dec)

		rd := ResultDecision{
			FindingID:          in.FindingID,
			VulnerabilityID:    f.VulnerabilityID,
			PURL:               f.PURL,
			State:              dec.State,
			AnalysisConfidence: dec.Confidence,
			ConfidenceCriteria: nonNil(dec.Criteria),
			RiskPriority:       riskPriority(f, dec.State, relationship),
			Justification:      dec.Justification,
			BasedOn:            basedOn(in.Evidence),
			Remediation:        remediation(f, scan.Findings),
			VEXMapping:         vexMapping(f, dec.State, in.Evidence),
		}
		res.Decisions = append(res.Decisions, rd)
	}

	d := Tally(decisions)
	res.Distribution = ResultsDistribution{
		TotalFindings:   d.TotalFindings,
		UsageDetected:   d.UsageDetected,
		NoUsageDetected: d.NoUsageDetected,
		Unknown:         d.Unknown,
		Unsupported:     d.Unsupported,
	}
	if res.Decisions == nil {
		res.Decisions = []ResultDecision{}
	}
	return res, nil
}

// riskPriority assigns the urgency band. It reads the verdict and the
// finding's own severity data; it never reads confidence, and confidence
// never reads it.
//
//   - usage_detected -> act_now.
//   - no_usage_detected -> lower_priority, except a CISA KEV-listed
//     vulnerability, which stays act_now: known exploitation in the wild
//     outweighs an application-source-only absence of evidence.
//   - unknown / unsupported -> insufficient_information. Severity is still
//     carried, so the report can surface a critical with no determination.
func riskPriority(f ScanFinding, s State, rel map[string]string) RiskPriority {
	rp := RiskPriority{
		Severity:     f.Severity,
		CVSSScore:    f.CVSSScore,
		CISAKev:      f.CISAKev,
		Relationship: findingRelationship(f, rel),
		FixAvailable: f.FixedVersion != "",
	}
	if f.EPSS != nil {
		rp.EPSSScore = f.EPSS.Score
	}
	switch s {
	case StateUsageDetected:
		rp.Band = BandActNow
	case StateNoUsageDetected:
		rp.Band = BandLowerPriority
		if f.CISAKev != nil && *f.CISAKev {
			rp.Band = BandActNow
		}
	default:
		rp.Band = BandInsufficientInformation
	}
	return rp
}

func relationshipByOccurrence(scan CanonicalScan) map[string]string {
	m := make(map[string]string, len(scan.Occurrences))
	for _, o := range scan.Occurrences {
		m[o.OccurrenceID] = o.Relationship
	}
	return m
}

// findingRelationship is "direct" if any occurrence is direct, otherwise
// "transitive" if any is transitive, otherwise omitted.
func findingRelationship(f ScanFinding, rel map[string]string) string {
	out := ""
	for _, o := range f.OccurrenceIDs {
		switch rel[o] {
		case "direct":
			return "direct"
		case "transitive":
			out = "transitive"
		}
	}
	return out
}

func basedOn(e Evidence) BasedOn {
	b := BasedOn{
		UsageObservationIDs:    nonNil(e.ObservationIDs),
		LocalisationMethod:     e.LocalisationMethod,
		LocalisationConfidence: e.LocalisationConfidence,
		MatchedSymbols:         nonNil(e.MatchedSymbols),
		CoverageSummary: CoverageSummary{
			ParseCoveragePercent:     e.ParseCoveragePercent,
			UnresolvedImportsInScope: e.UnresolvedImportsInScope,
		},
	}
	if e.EvidenceLevel >= 1 && e.EvidenceLevel <= 3 {
		b.EvidenceLevel = e.EvidenceLevel
	}
	// decision-results.schema.json allows complete, partial and failed only;
	// "unsupported" and unrecognised values are omitted.
	switch e.ScanStatus {
	case AnalysisComplete, AnalysisPartial, AnalysisFailed:
		b.CoverageSummary.ScanStatus = string(e.ScanStatus)
	}
	return b
}

// remediation records the scanner-reported fix and, conservatively, which
// findings the same upgrade resolves: findings on the same purl reporting
// the identical fixed version. Grouping by package is S5-09's job.
func remediation(f ScanFinding, all []ScanFinding) *ResultRemediation {
	if f.FixedVersion == "" {
		return nil
	}
	var ids []string
	for _, o := range all {
		if o.PURL == f.PURL && o.FixedVersion == f.FixedVersion {
			ids = append(ids, o.FindingID)
		}
	}
	sort.Strings(ids)
	return &ResultRemediation{ReportedFixedVersion: f.FixedVersion, ResolvesFindingIDs: ids}
}

// vexMapping maps a verdict to OpenVEX vocabulary for Component 3. It never
// produces not_affected (decision-results.schema.json: application-source-
// only analysis cannot prove it). affected needs all of: a usage verdict,
// matched symbols, and high or medium localisation confidence.
func vexMapping(f ScanFinding, s State, e Evidence) *VEXMapping {
	switch s {
	case StateUnsupported:
		return &VEXMapping{Statement: VEXOmit}
	case StateUsageDetected:
		reliable := e.LocalisationConfidence == LocalisationConfidenceHigh || e.LocalisationConfidence == LocalisationConfidenceMedium
		if reliable && len(e.MatchedSymbols) > 0 {
			action := "No fixed version is reported; review the matched call sites and the advisory."
			if f.FixedVersion != "" {
				action = fmt.Sprintf("Upgrade %s to %s or later.", packageLabel(f.PURL), f.FixedVersion)
			}
			return &VEXMapping{Statement: VEXAffected, ActionStatement: action}
		}
		return &VEXMapping{Statement: VEXUnderInvestigation}
	default:
		return &VEXMapping{Statement: VEXUnderInvestigation}
	}
}

func packageLabel(purl string) string {
	if n := npmPackageFromPURL(purl); n != "" {
		return n
	}
	return purl
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
