package audit

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// committedCases is where the real, hand-labelled S5-14 cases live.
var committedCases = filepath.Join("..", "..", "testdata", "audit")

// TestCommittedCases is the regression gate over the real labelled set: on
// every `go test ./...` it replays each committed case and fails if any
// finding a human labelled as genuine usage is moved out of usage detected,
// or if a case's labels no longer line up with its scan.
//
// It skips (loudly) only while no case has been committed yet, so the gate
// can land before the cases do. Once one labels.json exists, it never skips.
func TestCommittedCases(t *testing.T) {
	if _, err := os.Stat(committedCases); errors.Is(err, os.ErrNotExist) {
		t.Skipf("%s does not exist yet", committedCases)
	}
	rep, err := Run(committedCases)
	if errors.Is(err, ErrNoCases) {
		t.Skipf("no labelled case committed under %s yet (S5-14 not done)", committedCases)
	}
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, c := range rep.Cases {
		for _, r := range c.Rows {
			switch r.Outcome {
			case OutcomeMissedUsage:
				t.Errorf("%s/%s (%s): labelled genuine usage, decided %s. Justification: %s",
					c.CaseID, r.FindingID, r.VulnerabilityID, r.State, r.Justification)
			case OutcomeUnlabelled, OutcomeNoDecision:
				t.Errorf("%s/%s: %s; re-label the case", c.CaseID, r.FindingID, r.Outcome)
			}
		}
		t.Logf("%s: %s", c.CaseID, totalsLine(c.Totals))
	}
}
