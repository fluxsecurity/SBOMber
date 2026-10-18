// Package audit is S5-14's (#124) audit harness: it replays hand-labelled
// end-to-end cases through Component 4's decision pipeline and reports, per
// finding, how SBOMber's verdict compares with a human's label.
//
// The harness exists so the Sprint 6 audit can measure one thing above all
// others: whether any finding a human labelled as genuinely used was moved
// out of "usage detected". Every such move ("downgrade") is reported with
// the evidence the verdict rested on and the human's reasoning side by side,
// so it can be inspected rather than taken on trust.
//
// The labels are a human judgement, not a ground truth produced by SBOMber.
// They are only as good as the reasoning recorded with them, which is why
// that reasoning is a required field.
package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// LabelsSchemaVersion is the version of the labels.json format below.
const LabelsSchemaVersion = "1.0.0"

// Label is the human verdict on one finding.
type Label string

const (
	// LabelGenuineUsage: a person read the application source and found it
	// calls the vulnerable function (or a public entry point that reaches
	// it) in code that ships.
	LabelGenuineUsage Label = "genuine_usage"

	// LabelNoGenuineUsage: a person read the application source and found
	// no such call. This is a statement about what the labeller found, not
	// a claim that the vulnerability cannot be exploited.
	LabelNoGenuineUsage Label = "no_genuine_usage"
)

// Valid reports whether l is one of the two labels.
func (l Label) Valid() bool {
	return l == LabelGenuineUsage || l == LabelNoGenuineUsage
}

// LabelSet is one case's labels.json.
type LabelSet struct {
	SchemaVersion string         `json:"schemaVersion"`
	CaseID        string         `json:"caseId"`
	Repository    Repository     `json:"repository"`
	LabelledBy    string         `json:"labelledBy"`
	LabelledAt    string         `json:"labelledAt"`
	Labels        []FindingLabel `json:"labels"`
}

// Repository pins the real repository a case was built from. Commit must be
// a SHA, never a branch: a moving branch would silently change the case.
type Repository struct {
	URL    string `json:"url"`
	Commit string `json:"commit"`
}

// FindingLabel is the human label for one finding in canonical-scan.json.
type FindingLabel struct {
	FindingID         string   `json:"findingId"`
	VulnerabilityID   string   `json:"vulnerabilityId"`
	PURL              string   `json:"purl"`
	Label             Label    `json:"label"`
	VulnerableSymbols []string `json:"vulnerableSymbols"`
	Reasoning         string   `json:"reasoning"`
	Evidence          []string `json:"evidence"`
}

// LoadLabels reads and validates a labels.json file. Unknown fields are
// rejected: a misspelt key would otherwise drop a label's data silently.
func LoadLabels(path string) (LabelSet, error) {
	var ls LabelSet
	b, err := os.ReadFile(path)
	if err != nil {
		return ls, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ls); err != nil {
		return ls, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := ls.Validate(); err != nil {
		return ls, fmt.Errorf("%s: %w", path, err)
	}
	return ls, nil
}

// Validate enforces the rules that make a label inspectable: every label
// names its finding, carries one of the two labels, and records the
// reasoning behind it. A label without reasoning cannot be audited, so it
// is rejected rather than counted.
func (ls LabelSet) Validate() error {
	var problems []string
	add := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }

	if ls.SchemaVersion != LabelsSchemaVersion {
		add("schemaVersion is %q, want %q", ls.SchemaVersion, LabelsSchemaVersion)
	}
	if strings.TrimSpace(ls.CaseID) == "" {
		add("caseId is empty")
	}
	if strings.TrimSpace(ls.Repository.URL) == "" {
		add("repository.url is empty")
	}
	if !isCommitSHA(ls.Repository.Commit) {
		add("repository.commit %q is not a commit SHA (pin the case to a commit, never a branch)", ls.Repository.Commit)
	}
	if strings.TrimSpace(ls.LabelledBy) == "" {
		add("labelledBy is empty")
	}
	if strings.TrimSpace(ls.LabelledAt) == "" {
		add("labelledAt is empty")
	}
	if len(ls.Labels) == 0 {
		add("labels is empty")
	}

	seen := make(map[string]bool, len(ls.Labels))
	for i, l := range ls.Labels {
		where := fmt.Sprintf("labels[%d]", i)
		if l.FindingID == "" {
			add("%s: findingId is empty", where)
		} else {
			where = fmt.Sprintf("labels[%d] (%s)", i, l.FindingID)
			if seen[l.FindingID] {
				add("%s: duplicate findingId", where)
			}
			seen[l.FindingID] = true
		}
		// findingId alone is not a stable key (find-001 is a position, not an
		// identity), so every label also names what it is about and Compare
		// checks both against the decision.
		if strings.TrimSpace(l.VulnerabilityID) == "" {
			add("%s: vulnerabilityId is empty", where)
		}
		if strings.TrimSpace(l.PURL) == "" {
			add("%s: purl is empty", where)
		}
		if !l.Label.Valid() {
			add("%s: label %q is not %q or %q", where, l.Label, LabelGenuineUsage, LabelNoGenuineUsage)
		}
		if strings.TrimSpace(l.Reasoning) == "" {
			add("%s: reasoning is empty (every label must say why)", where)
		}
		if l.Label == LabelGenuineUsage && len(l.Evidence) == 0 {
			add("%s: genuine_usage needs at least one evidence entry (file:line of the call)", where)
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid labels: %s", strings.Join(problems, "; "))
	}
	return nil
}

// isCommitSHA accepts a 7-40 character hex string.
func isCommitSHA(s string) bool {
	if len(s) < 7 || len(s) > 40 {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}
