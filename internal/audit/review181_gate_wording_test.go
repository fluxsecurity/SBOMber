package audit

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/decision"
)

func TestReview181GateWordingMatchesClassifications(t *testing.T) {
	for _, item := range []struct {
		name    string
		state   decision.State
		outcome Outcome
		totals  Totals
		passed  bool
	}{
		{"genuine usage abstained", decision.StateUnknown, OutcomeAbstained, Totals{Findings: 1, Abstained: 1}, true},
		{"genuine usage detected", decision.StateUsageDetected, OutcomeAgreeUsage, Totals{Findings: 1, AgreeUsage: 1}, true},
		{"genuine usage assigned negative", decision.StateNoUsageDetected, OutcomeMissedUsage, Totals{Findings: 1, MissedUsage: 1, Downgrades: 1}, false},
	} {
		t.Run(item.name, func(t *testing.T) {
			row := Row{FindingID: "finding", Label: LabelGenuineUsage, State: item.state, Outcome: item.outcome, Downgrade: !item.passed}
			rep := Report{CasesRoot: "fixture", Totals: item.totals, Cases: []CaseResult{{CaseID: "fixture", Totals: item.totals, Rows: []Row{row}}}}
			var out bytes.Buffer
			if err := RenderText(&out, rep); err != nil {
				t.Fatal(err)
			}
			text := out.String()
			if strings.Contains(text, "moved out of usage detected") {
				t.Fatalf("gate wording overstates retained usage: %s", text)
			}
			if item.passed {
				if !strings.Contains(text, "RESULT: PASS - no finding labelled genuine_usage was classified no_usage_detected.") {
					t.Fatalf("PASS must describe only the negative-verdict gate: %s", text)
				}
				if !strings.Contains(text, "Abstentions are not successful usage detections.") {
					t.Fatalf("abstention limitation missing: %s", text)
				}
			} else if !strings.Contains(text, "RESULT: FAIL") || strings.Contains(text, "RESULT: PASS") || !strings.Contains(text, "were classified no_usage_detected") {
				t.Fatalf("missed usage must still fail the gate: %s", text)
			}
		})
	}
}
