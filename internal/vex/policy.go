package vex

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// BannedPhrases mirrors BANNED in contracts/validate.py. None may appear in
// any text field of the document, compared case-insensitively.
var BannedPhrases = []string{"not affected", "is safe", "no risk", "false positive"}

// ErrMixedVocabulary rejects a document whose decisions use the CycloneDX
// investigation token while the selected format is OpenVEX.
var ErrMixedVocabulary = errors.New("mixed VEX vocabulary")

// Mapping is the policy outcome for one decision.
type Mapping struct {
	// Status is the OpenVEX status, or "" when the decision is omitted.
	Status string
	// ActionStatement is set for affected.
	ActionStatement string
	// Reviewer is reserved for possible future manual-review support; Map currently rejects not_affected.
	Reviewer string
}

// Omitted reports whether the decision produces no statement.
func (m Mapping) Omitted() bool { return m.Status == "" }

// Map is the single policy layer from a decision to an OpenVEX status. The
// status is derived from the decision's state; component 4's own
// vexMapping.statement is checked against it and a contradiction is an
// error, never silently resolved either way.
func Map(d Decision) (Mapping, error) {
	stmt := ""
	if d.VEXMapping != nil {
		stmt = d.VEXMapping.Statement
	}
	if stmt == mappingInTriage {
		return Mapping{}, fmt.Errorf("%s: %w: in_triage is the CycloneDX token, OpenVEX uses %s",
			d.FindingID, ErrMixedVocabulary, StatusUnderInvestigation)
	}

	// not_affected is deliberately outside the committed automated exporter.
	// The current decision contract has no field that proves a manual or
	// deterministic not_affected conclusion, and contracts/validate.py rejects
	// it. Keep the exporter conservative until that contract is designed.
	if stmt == StatusNotAffected {
		return Mapping{}, fmt.Errorf(
			"%s: not_affected is not supported by the committed automated exporter; use under_investigation",
			d.FindingID,
		)
	}

	var want string
	switch d.State {
	case StateUsageDetected:
		// Usage evidence alone is not enough for affected. Component 4 must
		// explicitly assert affected after checking affected version, reliable
		// localisation and direct call evidence. Missing mapping therefore
		// remains under_investigation.
		switch stmt {
		case StatusAffected:
			want = StatusAffected
		case "", StatusUnderInvestigation:
			want = StatusUnderInvestigation
		default:
			want = StatusAffected
		}
	case StateNoUsageDetected, StateUnknown:
		want = StatusUnderInvestigation
	case StateUnsupported:
		want = mappingOmit
	default:
		return Mapping{}, fmt.Errorf("%s: unknown decision state %q", d.FindingID, d.State)
	}
	if stmt != "" && stmt != want {
		return Mapping{}, fmt.Errorf("%s: state %s maps to %s but vexMapping.statement is %s",
			d.FindingID, d.State, want, stmt)
	}

	switch want {
	case StatusAffected:
		action := ""
		if d.VEXMapping != nil {
			action = strings.TrimSpace(d.VEXMapping.ActionStatement)
		}
		if action == "" {
			return Mapping{}, fmt.Errorf("%s: affected requires an action statement (vexMapping.actionStatement)", d.FindingID)
		}
		return Mapping{Status: StatusAffected, ActionStatement: action}, nil
	case mappingOmit:
		return Mapping{}, nil
	default:
		return Mapping{Status: want}, nil
	}
}

// checkVocabulary rejects the whole document if any decision uses in_triage,
// naming every offending finding.
func checkVocabulary(decisions []Decision) error {
	var bad []string
	for _, d := range decisions {
		if d.VEXMapping != nil && d.VEXMapping.Statement == mappingInTriage {
			bad = append(bad, d.FindingID)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	sort.Strings(bad)
	return fmt.Errorf("%w: OpenVEX document requires %s, but %s use in_triage",
		ErrMixedVocabulary, StatusUnderInvestigation, strings.Join(bad, ", "))
}

// checkLanguage returns an error if text contains a banned phrase.
func checkLanguage(findingID, field, text string) error {
	lower := strings.ToLower(text)
	for _, p := range BannedPhrases {
		if strings.Contains(lower, p) {
			return fmt.Errorf("%s: %s contains banned phrase %q", findingID, field, p)
		}
	}
	return nil
}
