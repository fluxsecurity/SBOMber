package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/decision"
)

const syntheticRoot = "testdata/cases"

// The committed synthetic case runs end to end: discover, load, replay
// through decision.BuildResults, compare. It is hand-built because real
// runs cannot yet produce no_usage_detected (every candidate set is open
// until localisation 1.1.0 ships), and the downgrade path must still be
// exercised.
func TestRun_SyntheticClosedSet(t *testing.T) {
	rep, err := Run(syntheticRoot)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Cases) != 1 {
		t.Fatalf("got %d cases, want 1", len(rep.Cases))
	}
	got := map[string]Row{}
	for _, r := range rep.Cases[0].Rows {
		got[r.FindingID] = r
	}

	if r := got["find-001"]; r.Outcome != OutcomeAgreeUsage || r.State != decision.StateUsageDetected || r.Downgrade {
		t.Errorf("find-001 = %s/%s downgrade=%v, want agree_usage/usage_detected, no downgrade", r.Outcome, r.State, r.Downgrade)
	}
	r := got["find-002"]
	if r.Outcome != OutcomeAgreeNoUsage || r.State != decision.StateNoUsageDetected || !r.Downgrade {
		t.Errorf("find-002 = %s/%s downgrade=%v, want agree_no_usage/no_usage_detected, downgrade", r.Outcome, r.State, r.Downgrade)
	}
	// A downgrade is only inspectable if the evidence travels with it.
	if r.Justification == "" || r.BasedOn == nil || r.LabelReasoning == "" {
		t.Errorf("downgrade row is missing its evidence: %+v", r)
	}

	want := Totals{Findings: 2, AgreeUsage: 1, AgreeNoUsage: 1, Downgrades: 1}
	if rep.Totals != want {
		t.Errorf("totals = %+v, want %+v", rep.Totals, want)
	}
	if rep.Totals.Failed() {
		t.Error("synthetic case should pass")
	}
}

// The outcome the harness exists to catch: a human says the app calls the
// vulnerable function and SBOMber moved it out of usage detected anyway.
func TestCompare_MissedUsageFails(t *testing.T) {
	c := loadSynthetic(t)
	res, err := c.Replay()
	if err != nil {
		t.Fatal(err)
	}
	// Relabel the finding SBOMber decided no_usage_detected as genuine.
	for i := range c.Labels.Labels {
		if c.Labels.Labels[i].FindingID == "find-002" {
			c.Labels.Labels[i].Label = LabelGenuineUsage
			c.Labels.Labels[i].Evidence = []string{"index.js:20 _.template(userInput)"}
		}
	}
	cr := Compare(c, res)
	if cr.Totals.MissedUsage != 1 || !cr.Totals.Failed() {
		t.Fatalf("totals = %+v, want one missed usage and a failure", cr.Totals)
	}

	var buf bytes.Buffer
	rep := Report{CasesRoot: syntheticRoot, Cases: []CaseResult{cr}, Totals: cr.Totals}
	if err := RenderText(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"MISSED USAGE", "RESULT: FAIL", "index.js:20 _.template(userInput)", "justification:"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q:\n%s", want, out)
		}
	}
}

func TestOutcomeTable(t *testing.T) {
	cases := []struct {
		label Label
		state decision.State
		want  Outcome
	}{
		{LabelGenuineUsage, decision.StateUsageDetected, OutcomeAgreeUsage},
		{LabelGenuineUsage, decision.StateNoUsageDetected, OutcomeMissedUsage},
		{LabelGenuineUsage, decision.StateUnknown, OutcomeAbstained},
		{LabelGenuineUsage, decision.StateUnsupported, OutcomeAbstained},
		{LabelNoGenuineUsage, decision.StateUsageDetected, OutcomeOverReported},
		{LabelNoGenuineUsage, decision.StateNoUsageDetected, OutcomeAgreeNoUsage},
		{LabelNoGenuineUsage, decision.StateUnknown, OutcomeAbstained},
	}
	for _, tc := range cases {
		if got := outcome(tc.label, tc.state); got != tc.want {
			t.Errorf("outcome(%s, %s) = %s, want %s", tc.label, tc.state, got, tc.want)
		}
	}
}

// Labels and decisions that do not line up fail the run rather than being
// silently dropped from the counts.
func TestCompare_UnlabelledAndStaleLabels(t *testing.T) {
	c := loadSynthetic(t)
	res, err := c.Replay()
	if err != nil {
		t.Fatal(err)
	}
	c.Labels.Labels = []FindingLabel{
		c.Labels.Labels[0],
		{FindingID: "find-999", Label: LabelNoGenuineUsage, Reasoning: "stale"},
	}
	cr := Compare(c, res)
	if cr.Totals.Unlabelled != 1 || cr.Totals.NoDecision != 1 || !cr.Totals.Failed() {
		t.Errorf("totals = %+v, want 1 unlabelled, 1 without decision, failed", cr.Totals)
	}
}

// A regenerated scan can renumber findings. A label whose findingId now
// points at a different vulnerability must fail the run, not be scored
// against the wrong finding: here the human says template (find-002's
// CVE) is called, and with the IDs swapped a plain findingId join would
// report two agreements and hide the missed usage.
func TestCompare_LabelForDifferentFindingFails(t *testing.T) {
	c := loadSynthetic(t)
	res, err := c.Replay()
	if err != nil {
		t.Fatal(err)
	}
	l := c.Labels.Labels
	l[0].Label, l[0].Evidence = LabelNoGenuineUsage, nil
	l[1].Label, l[1].Evidence = LabelGenuineUsage, []string{"index.js:20 _.template(userInput)"}
	l[0].FindingID, l[1].FindingID = l[1].FindingID, l[0].FindingID

	cr := Compare(c, res)
	if cr.Totals.Mismatched != 2 || cr.Totals.AgreeUsage != 0 || cr.Totals.AgreeNoUsage != 0 || !cr.Totals.Failed() {
		t.Errorf("totals = %+v, want 2 label mismatches, no agreement, failed", cr.Totals)
	}
}

func TestLoadCase_RejectsInputsFromDifferentScans(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(syntheticRoot, "synthetic-closed-set")
	for _, name := range []string{LabelsFile, CanonicalScanFile, UsageGraphFile, LocalisationFile} {
		b, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatal(err)
		}
		if name == LocalisationFile {
			b = bytes.Replace(b, []byte(`"scan-audit-synthetic"`), []byte(`"scan-older"`), 1)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadCase(dir); err == nil || !strings.Contains(err.Error(), "scan-older") {
		t.Fatalf("err = %v, want a scanId mismatch", err)
	}
}

func TestValidate_RejectsUninspectableLabels(t *testing.T) {
	base := func() LabelSet {
		return LabelSet{
			SchemaVersion: LabelsSchemaVersion, CaseID: "c", LabelledBy: "z", LabelledAt: "2026-10-04",
			Repository: Repository{URL: "https://github.com/x/y", Commit: "d7b5d98515a95f9a8cb0fedef034010ee083a6a9"},
			Labels: []FindingLabel{{FindingID: "f", VulnerabilityID: "CVE-2018-16487", PURL: "pkg:npm/lodash@4.17.4",
				Label: LabelGenuineUsage, Reasoning: "r", Evidence: []string{"a.js:1"}}},
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid set rejected: %v", err)
	}
	breaks := map[string]func(*LabelSet){
		"no reasoning":             func(l *LabelSet) { l.Labels[0].Reasoning = " " },
		"bad label":                func(l *LabelSet) { l.Labels[0].Label = "safe" },
		"branch not commit":        func(l *LabelSet) { l.Repository.Commit = "master" },
		"genuine without evidence": func(l *LabelSet) { l.Labels[0].Evidence = nil },
		"duplicate finding":        func(l *LabelSet) { l.Labels = append(l.Labels, l.Labels[0]) },
		"wrong schema":             func(l *LabelSet) { l.SchemaVersion = "0.9" },
		"no vulnerabilityId":       func(l *LabelSet) { l.Labels[0].VulnerabilityID = "" },
		"no purl":                  func(l *LabelSet) { l.Labels[0].PURL = "" },
	}
	for name, brk := range breaks {
		t.Run(name, func(t *testing.T) {
			l := base()
			brk(&l)
			if err := l.Validate(); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// The harness's own wording obeys the same rules as the report: no banned
// phrase, and the no-direct-usage section is never called safe or low
// urgency.
func TestRenderText_Wording(t *testing.T) {
	rep, err := Run(syntheticRoot)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := RenderText(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if hits := decision.Lint(out); len(hits) > 0 {
		t.Errorf("render contains banned phrases %v:\n%s", hits, out)
	}
	lower := strings.ToLower(out)
	for _, bad := range []string{"low urgency", "informational", "clean", "not reachable", "unaffected"} {
		if strings.Contains(lower, bad) {
			t.Errorf("render contains %q:\n%s", bad, out)
		}
	}
	if !strings.Contains(out, "Downgrades to inspect (1)") || !strings.Contains(out, "RESULT: PASS") {
		t.Errorf("unexpected render:\n%s", out)
	}
}

func TestRun_EmptyRootIsAnError(t *testing.T) {
	_, err := Run(t.TempDir())
	if !errors.Is(err, ErrNoCases) {
		t.Fatalf("err = %v, want ErrNoCases", err)
	}
}

func TestLoadLabels_RejectsUnknownField(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(syntheticRoot, "synthetic-closed-set", LabelsFile))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), LabelsFile)
	b = bytes.Replace(b, []byte(`"evidence"`), []byte(`"evidance"`), 1)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLabels(path); err == nil || !strings.Contains(err.Error(), "evidance") {
		t.Fatalf("err = %v, want unknown field evidance rejected", err)
	}
}

func loadSynthetic(t *testing.T) Case {
	t.Helper()
	c, err := LoadCase(filepath.Join(syntheticRoot, "synthetic-closed-set"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}
