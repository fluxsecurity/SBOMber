package audit

import (
	"errors"
	"fmt"
	"sort"

	"github.com/Xsamsx/SBOMber/internal/decision"
)

// ReportSchemaVersion is the version of audit-results.json.
const ReportSchemaVersion = "1.0.0"

// Outcome is how SBOMber's verdict on one finding compares with the label.
//
// The names deliberately avoid the vocabulary contracts/validate.py bans
// ("false positive" and friends): a disagreement is described by what
// happened to the finding, never by a claim about whether the
// vulnerability can be exploited.
type Outcome string

const (
	// OutcomeAgreeUsage: labelled genuine_usage, decided usage_detected.
	OutcomeAgreeUsage Outcome = "agree_usage"

	// OutcomeMissedUsage: labelled genuine_usage, decided
	// no_usage_detected. This is the outcome the whole state model exists
	// to prevent. Any occurrence fails the harness.
	OutcomeMissedUsage Outcome = "missed_usage"

	// OutcomeOverReported: labelled no_genuine_usage, decided
	// usage_detected. Costs attention, not safety.
	OutcomeOverReported Outcome = "over_reported_usage"

	// OutcomeAgreeNoUsage: labelled no_genuine_usage, decided
	// no_usage_detected.
	OutcomeAgreeNoUsage Outcome = "agree_no_usage"

	// OutcomeAbstained: decided unknown or unsupported. Not wrong, but not
	// a determination either; counted separately so it can never inflate
	// agreement.
	OutcomeAbstained Outcome = "abstained"

	// OutcomeUnlabelled: SBOMber made a decision for a finding nobody
	// labelled. The case is incomplete.
	OutcomeUnlabelled Outcome = "unlabelled"

	// OutcomeNoDecision: a label names a finding SBOMber did not decide
	// (absent from canonical-scan.json, or the ID changed). The case is
	// stale.
	OutcomeNoDecision Outcome = "no_decision"

	// OutcomeLabelMismatch: a label's findingId matches a decision, but its
	// vulnerabilityId or purl does not (the scan was regenerated and the
	// IDs moved). Comparing it would score the label against the wrong
	// finding, so the case is stale.
	OutcomeLabelMismatch Outcome = "label_mismatch"
)

// Report is the whole harness output (audit-results.json).
type Report struct {
	SchemaVersion string       `json:"schemaVersion"`
	CasesRoot     string       `json:"casesRoot"`
	Totals        Totals       `json:"totals"`
	Cases         []CaseResult `json:"cases"`
}

// CaseResult is one case's per-finding comparison.
type CaseResult struct {
	CaseID     string     `json:"caseId"`
	Dir        string     `json:"dir"`
	Repository Repository `json:"repository"`
	ScanID     string     `json:"scanId"`
	Coverage   Coverage   `json:"coverage"`
	Totals     Totals     `json:"totals"`
	Rows       []Row      `json:"rows"`
}

// Coverage is what Component 2 reported about how much of the repository it
// actually analysed. A case is only as informative as this.
type Coverage struct {
	AnalysisStatus        string   `json:"analysisStatus"`
	FilesDiscovered       int      `json:"filesDiscovered"`
	FilesParsed           int      `json:"filesParsed"`
	FilesParsedWithErrors int      `json:"filesParsedWithErrors"`
	FilesFailed           int      `json:"filesFailed"`
	FilesSkipped          int      `json:"filesSkipped"`
	LimitsHit             []string `json:"limitsHit"`
}

// Row is one finding: SBOMber's full verdict next to the human label.
// Everything needed to inspect a downgrade is here, so nobody has to rerun
// the pipeline to see why a finding moved.
type Row struct {
	FindingID       string  `json:"findingId"`
	VulnerabilityID string  `json:"vulnerabilityId,omitempty"`
	PURL            string  `json:"purl,omitempty"`
	Outcome         Outcome `json:"outcome"`

	// Downgrade is true when SBOMber moved the finding out of "usage
	// detected" into the no-direct-usage section (no_usage_detected),
	// whatever the label says. Every downgrade must be inspectable.
	Downgrade bool `json:"downgrade"`

	Label             Label    `json:"label,omitempty"`
	LabelVulnID       string   `json:"labelVulnerabilityId,omitempty"`
	LabelPURL         string   `json:"labelPurl,omitempty"`
	LabelReasoning    string   `json:"labelReasoning,omitempty"`
	LabelEvidence     []string `json:"labelEvidence,omitempty"`
	VulnerableSymbols []string `json:"vulnerableSymbols,omitempty"`

	State              decision.State      `json:"state,omitempty"`
	Band               decision.RiskBand   `json:"band,omitempty"`
	AnalysisConfidence decision.Confidence `json:"analysisConfidence,omitempty"`
	ConfidenceCriteria []string            `json:"confidenceCriteria,omitempty"`
	Justification      string              `json:"justification,omitempty"`
	BasedOn            *decision.BasedOn   `json:"basedOn,omitempty"`
}

// Totals counts outcomes. Agreement is reported as counts, never a single
// percentage: three to five repositories cannot support an accuracy rate.
type Totals struct {
	Findings     int `json:"findings"`
	AgreeUsage   int `json:"agreeUsage"`
	MissedUsage  int `json:"missedUsage"`
	OverReported int `json:"overReportedUsage"`
	AgreeNoUsage int `json:"agreeNoUsage"`
	Abstained    int `json:"abstained"`
	Unlabelled   int `json:"unlabelled"`
	NoDecision   int `json:"noDecision"`
	Mismatched   int `json:"labelMismatch"`
	Downgrades   int `json:"downgrades"`
}

// Failed reports whether the harness should fail: any missed usage, or a
// case that no longer lines up with its labels.
func (t Totals) Failed() bool {
	return t.MissedUsage > 0 || t.Unlabelled > 0 || t.NoDecision > 0 || t.Mismatched > 0
}

// Compare lines up one case's decisions with its labels.
func Compare(c Case, res decision.Results) CaseResult {
	cr := CaseResult{
		CaseID:     c.Labels.CaseID,
		Dir:        c.Dir,
		Repository: c.Labels.Repository,
		ScanID:     res.ScanID,
		Coverage: Coverage{
			AnalysisStatus:        c.Graph.Analysis.Status,
			FilesDiscovered:       c.Graph.Coverage.FilesDiscovered,
			FilesParsed:           c.Graph.Coverage.FilesParsed,
			FilesParsedWithErrors: c.Graph.Coverage.FilesParsedWithErrors,
			FilesFailed:           c.Graph.Coverage.FilesFailed,
			FilesSkipped:          c.Graph.Coverage.FilesSkipped,
			LimitsHit:             c.Graph.Coverage.LimitsHit,
		},
	}

	labels := make(map[string]FindingLabel, len(c.Labels.Labels))
	for _, l := range c.Labels.Labels {
		labels[l.FindingID] = l
	}
	decided := make(map[string]bool, len(res.Decisions))

	for _, d := range res.Decisions {
		decided[d.FindingID] = true
		basedOn := d.BasedOn
		row := Row{
			FindingID:          d.FindingID,
			VulnerabilityID:    d.VulnerabilityID,
			PURL:               d.PURL,
			State:              d.State,
			Band:               d.RiskPriority.Band,
			AnalysisConfidence: d.AnalysisConfidence,
			ConfidenceCriteria: d.ConfidenceCriteria,
			Justification:      d.Justification,
			BasedOn:            &basedOn,
			Downgrade:          d.State == decision.StateNoUsageDetected,
		}
		if l, ok := labels[d.FindingID]; ok {
			row.Label = l.Label
			row.LabelVulnID = l.VulnerabilityID
			row.LabelPURL = l.PURL
			row.LabelReasoning = l.Reasoning
			row.LabelEvidence = l.Evidence
			row.VulnerableSymbols = l.VulnerableSymbols
			if l.VulnerabilityID != d.VulnerabilityID || l.PURL != d.PURL {
				row.Outcome = OutcomeLabelMismatch
			} else {
				row.Outcome = outcome(l.Label, d.State)
			}
		} else {
			row.Outcome = OutcomeUnlabelled
		}
		cr.Rows = append(cr.Rows, row)
	}

	for _, l := range c.Labels.Labels {
		if decided[l.FindingID] {
			continue
		}
		cr.Rows = append(cr.Rows, Row{
			FindingID:         l.FindingID,
			VulnerabilityID:   l.VulnerabilityID,
			PURL:              l.PURL,
			Outcome:           OutcomeNoDecision,
			Label:             l.Label,
			LabelVulnID:       l.VulnerabilityID,
			LabelPURL:         l.PURL,
			LabelReasoning:    l.Reasoning,
			LabelEvidence:     l.Evidence,
			VulnerableSymbols: l.VulnerableSymbols,
		})
	}

	sort.SliceStable(cr.Rows, func(i, j int) bool { return cr.Rows[i].FindingID < cr.Rows[j].FindingID })
	cr.Totals = tally(cr.Rows)
	return cr
}

// outcome is the label x state table.
func outcome(l Label, s decision.State) Outcome {
	switch s {
	case decision.StateUsageDetected:
		if l == LabelGenuineUsage {
			return OutcomeAgreeUsage
		}
		return OutcomeOverReported
	case decision.StateNoUsageDetected:
		if l == LabelGenuineUsage {
			return OutcomeMissedUsage
		}
		return OutcomeAgreeNoUsage
	default:
		return OutcomeAbstained
	}
}

func tally(rows []Row) Totals {
	var t Totals
	for _, r := range rows {
		t.Findings++
		if r.Downgrade {
			t.Downgrades++
		}
		switch r.Outcome {
		case OutcomeAgreeUsage:
			t.AgreeUsage++
		case OutcomeMissedUsage:
			t.MissedUsage++
		case OutcomeOverReported:
			t.OverReported++
		case OutcomeAgreeNoUsage:
			t.AgreeNoUsage++
		case OutcomeAbstained:
			t.Abstained++
		case OutcomeUnlabelled:
			t.Unlabelled++
		case OutcomeNoDecision:
			t.NoDecision++
		case OutcomeLabelMismatch:
			t.Mismatched++
		}
	}
	return t
}

func total(cases []CaseResult) Totals {
	var t Totals
	for _, c := range cases {
		t.Findings += c.Totals.Findings
		t.AgreeUsage += c.Totals.AgreeUsage
		t.MissedUsage += c.Totals.MissedUsage
		t.OverReported += c.Totals.OverReported
		t.AgreeNoUsage += c.Totals.AgreeNoUsage
		t.Abstained += c.Totals.Abstained
		t.Unlabelled += c.Totals.Unlabelled
		t.NoDecision += c.Totals.NoDecision
		t.Mismatched += c.Totals.Mismatched
		t.Downgrades += c.Totals.Downgrades
	}
	return t
}

// Run loads, replays and compares every case under root. It returns an
// error if root holds no cases: an audit over nothing must not look like a
// clean audit.
func Run(root string) (Report, error) {
	dirs, err := DiscoverCases(root)
	if err != nil {
		return Report{}, err
	}
	if len(dirs) == 0 {
		return Report{}, errNoCases(root)
	}
	rep := Report{SchemaVersion: ReportSchemaVersion, CasesRoot: root}
	for _, dir := range dirs {
		c, err := LoadCase(dir)
		if err != nil {
			return Report{}, err
		}
		res, err := c.Replay()
		if err != nil {
			return Report{}, err
		}
		rep.Cases = append(rep.Cases, Compare(c, res))
	}
	rep.Totals = total(rep.Cases)
	return rep, nil
}

// ErrNoCases is returned by Run when the cases directory holds no case.
var ErrNoCases = errors.New("no labelled cases found")

func errNoCases(root string) error {
	return fmt.Errorf("%s: %w (each case is a subdirectory containing %s)", root, ErrNoCases, LabelsFile)
}
