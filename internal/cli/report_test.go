package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// decideSample runs `sbomber decide` on the contract samples and returns
// the decision-results.json path, so the report is tested on real decide
// output (with remediationGroups), not only on the hand-built fixture.
func decideSample(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "decision-results.json")
	var stdout, stderr bytes.Buffer
	code := Main([]string{
		"decide",
		"--canonical-scan", contractFixtures + "canonical-scan.sample.json",
		"--usage-graph", contractFixtures + "usage-graph.sample.json",
		"--localisation", contractFixtures + "localisation.sample.json",
		"--out", out,
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("decide exit %d, stderr: %s", code, stderr.String())
	}
	return out
}

func runReportCmd(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Main(append([]string{"report"}, args...), strings.NewReader(""), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestReport_HTMLFromDecideOutput(t *testing.T) {
	dr := decideSample(t)
	out := filepath.Join(t.TempDir(), "report.html")
	code, stdout, stderr := runReportCmd(t,
		"--decision-results", dr,
		"--usage-graph", contractFixtures+"usage-graph.sample.json",
		"--out", out)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Wrote "+out) {
		t.Errorf("stdout = %q", stdout)
	}
	if strings.Contains(stderr, "Warning") {
		t.Errorf("unexpected warning with --usage-graph: %q", stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	for _, want := range []string{
		"<h2>Update first</h2>",
		"<h2>Insufficient information</h2>",
		"<h2>No direct usage evidence found within the analysed scope</h2>",
		"Files: 142 discovered",
		"pkg:npm/lodash@4.17.20",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

func TestReport_TextToStdoutWithoutCoverageWarns(t *testing.T) {
	code, stdout, stderr := runReportCmd(t, "--decision-results", decideSample(t), "--format", "text")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "== No direct usage evidence found within the analysed scope ==") {
		t.Errorf("text report missing the D1 heading:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Analysis coverage was not provided") {
		t.Error("text report does not state that coverage was missing")
	}
	if !strings.Contains(stderr, "Warning: no --usage-graph") {
		t.Errorf("stderr = %q, want the missing-coverage warning", stderr)
	}
}

func TestReport_InputErrors(t *testing.T) {
	dr := decideSample(t)

	other := filepath.Join(t.TempDir(), "usage-graph.json")
	data, err := os.ReadFile(contractFixtures + "usage-graph.sample.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["scanId"] = "scan-some-other-scan"
	data, _ = json.Marshal(doc)
	if err := os.WriteFile(other, data, 0o644); err != nil {
		t.Fatal(err)
	}

	cases := map[string][]string{
		"no decision results":     {},
		"bad format":              {"--decision-results", dr, "--format", "pdf"},
		"missing file":            {"--decision-results", filepath.Join(t.TempDir(), "nope.json")},
		"usage graph as results":  {"--decision-results", contractFixtures + "usage-graph.sample.json"},
		"results as usage graph":  {"--decision-results", dr, "--usage-graph", dr},
		"usage graph, other scan": {"--decision-results", dr, "--usage-graph", other},
		"stray argument":          {"--decision-results", dr, "extra"},
	}
	for name, args := range cases {
		code, _, stderr := runReportCmd(t, args...)
		if code != 2 {
			t.Errorf("%s: exit %d, want 2 (stderr %q)", name, code, stderr)
		}
	}
}

func TestReport_Filters(t *testing.T) {
	dr := decideSample(t)
	code, stdout, stderr := runReportCmd(t, "--decision-results", dr, "--format", "text",
		"--usage-graph", contractFixtures+"usage-graph.sample.json", "--state", "unknown")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "showing 3 of 4 finding(s)") {
		t.Errorf("filtered text report missing the filter line:\n%s", stdout)
	}
	if !strings.Contains(stdout, "1 finding in this section hidden by the filter.") {
		t.Errorf("filtered text report missing the hidden count:\n%s", stdout)
	}

	for name, args := range map[string][]string{
		"bad section": {"--section", "Update first"},
		"bad band":    {"--band", "urgent"},
		"bad state":   {"--state", "safe"},
	} {
		code, _, _ := runReportCmd(t, append([]string{"--decision-results", dr}, args...)...)
		if code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
}
