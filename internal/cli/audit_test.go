package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const auditSyntheticCases = "../audit/testdata/cases"

func TestAudit_SyntheticCasePassesAndWritesJSON(t *testing.T) {
	out := filepath.Join(t.TempDir(), "audit-results.json")
	var stdout, stderr bytes.Buffer
	code := Main([]string{"audit", "--cases", auditSyntheticCases, "--out", out}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "RESULT: PASS") {
		t.Errorf("stdout missing RESULT: PASS:\n%s", stdout.String())
	}

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		SchemaVersion string `json:"schemaVersion"`
		Totals        struct {
			Findings   int `json:"findings"`
			Downgrades int `json:"downgrades"`
		} `json:"totals"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != "1.0.0" || got.Totals.Findings != 2 || got.Totals.Downgrades != 1 {
		t.Errorf("audit-results.json = %+v", got)
	}
}

func TestAudit_EmptyCasesDirIsAnError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Main([]string{"audit", "--cases", t.TempDir()}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "no labelled cases found") {
		t.Fatalf("exit %d, stderr=%s", code, stderr.String())
	}
}
