package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVEXCommandWritesOpenVEX(t *testing.T) {
	t.Parallel()

	tests := []struct {
		subject     string
		wantProduct string
	}{
		{"application", "pkg:generic/demo-app@8f2a1c9d4e7b3a5f6c8d9e0a1b2c3d4e5f6a7b8c"},
		{"package", "pkg:npm/lodash@4.17.20"},
	}
	for _, tt := range tests {
		t.Run(tt.subject, func(t *testing.T) {
			t.Parallel()
			out := filepath.Join(t.TempDir(), "vex.openvex.json")
			var stdout, stderr bytes.Buffer
			code := Main([]string{"vex",
				"--decisions", "../../contracts/fixtures/decision-results.sample.json",
				"--canonical-scan", "../../contracts/fixtures/canonical-scan.sample.json",
				"--subject", tt.subject, "--out", out}, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit %d, stderr: %s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), "1 affected, 3 under_investigation") {
				t.Fatalf("stdout = %s", stdout.String())
			}
			data, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Context    string `json:"@context"`
				Statements []struct {
					Status   string `json:"status"`
					Products []struct {
						ID string `json:"@id"`
					} `json:"products"`
				} `json:"statements"`
			}
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			if doc.Context != "https://openvex.dev/ns/v0.2.0" || len(doc.Statements) != 4 {
				t.Fatalf("document = %s", data)
			}
			if got := doc.Statements[0].Products[0].ID; got != tt.wantProduct {
				t.Fatalf("first product = %s, want %s", got, tt.wantProduct)
			}
		})
	}
}

func TestVEXCommandRejectsMixedVocabulary(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	in := filepath.Join(dir, "decision-results.json")
	if err := os.WriteFile(in, []byte(`{"schemaVersion":"1.1.0","scanId":"scan-1","decisions":[
 {"findingId":"find-001","vulnerabilityId":"CVE-1","purl":"pkg:npm/a@1.0.0","state":"unknown","justification":"x","vexMapping":{"statement":"under_investigation"}},
 {"findingId":"find-002","vulnerabilityId":"CVE-2","purl":"pkg:npm/b@1.0.0","state":"unknown","justification":"x","vexMapping":{"statement":"in_triage"}}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "vex.json")
	var stdout, stderr bytes.Buffer
	code := Main([]string{"vex", "--decisions", in, "--subject", "package", "--out", out}, nil, &stdout, &stderr)
	if code == 0 {
		t.Fatal("mixed vocabulary accepted")
	}
	if !strings.Contains(stderr.String(), "mixed VEX vocabulary") {
		t.Fatalf("stderr = %s", stderr.String())
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a document was written despite the rejection")
	}
}

func TestVEXCommandNeedsDecisions(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"vex"}, nil, &stdout, &stderr); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if code := Main([]string{"vex", "--decisions", "x.json", "--subject", "repo"}, nil, &stdout, &stderr); code != 2 {
		t.Fatalf("unknown subject: exit %d, want 2", code)
	}
}
