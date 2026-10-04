package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const contractFixtures = "../../contracts/fixtures/"

func TestDecide_WritesDecisionResultsFromSampleContracts(t *testing.T) {
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
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		SchemaVersion string `json:"schemaVersion"`
		ScanID        string `json:"scanId"`
		Decisions     []struct {
			FindingID string `json:"findingId"`
			State     string `json:"state"`
		} `json:"decisions"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != "1.1.0" || doc.ScanID == "" || len(doc.Decisions) != 4 {
		t.Fatalf("unexpected document header: %+v", doc)
	}
	for _, phrase := range []string{"not affected", "is safe", "no risk", "false positive"} {
		if strings.Contains(strings.ToLower(string(data)), phrase) {
			t.Errorf("output contains banned phrase %q", phrase)
		}
	}
}

func TestDecide_MissingInputsIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Main([]string{"decide", "--canonical-scan", "x.json"}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "Usage: sbomber decide") {
		t.Errorf("stderr should show usage, got %q", stderr.String())
	}
}
