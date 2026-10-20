package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// localiseVerifyDoc is a minimal 1.1.0 document whose one candidate cites a
// verified advisory artefact.
func localiseVerifyDoc(schema string, verified bool) map[string]any {
	return map[string]any{
		"schemaVersion": schema, "scanId": "scan-1",
		"results": []any{map[string]any{
			"findingId": "f1", "vulnerabilityId": "CVE-2020-7788", "purl": "pkg:npm/ini@1.3.5",
			"method": "advisory_text", "confidence": "medium",
			"candidateSymbols": []any{map[string]any{"symbol": "parse", "evidence": []string{"advisory"}}},
			"provenance": map[string]any{"advisorySource": "osv", "artefacts": []any{map[string]any{
				"id": "advisory", "kind": "advisory", "url": "https://api.osv.dev/v1/vulns/GHSA-qqgx-2p2h-9c37",
				"sha256": strings.Repeat("ab", 32), "verified": verified, "executed": false,
			}}},
		}},
	}
}

func TestLocaliseVerifyExitCodes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name string, v any) string {
		p := filepath.Join(dir, name)
		b, _ := json.Marshal(v)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	report := filepath.Join(dir, "report.json")
	tests := []struct {
		name string
		args []string
		want int
		out  string
	}{
		{"traced", []string{"--verify", write("ok.json", localiseVerifyDoc("1.1.0", true)), "--verify-report", report}, 0,
			"OK: every candidate is traceable"},
		{"unverified artefact", []string{"--verify", write("bad.json", localiseVerifyDoc("1.1.0", false))}, 1,
			"cited artefact is not verified"},
		{"1.0.0 document", []string{"--verify", write("old.json", localiseVerifyDoc("1.0.0", true))}, 1,
			"records no per-candidate evidence"},
		{"missing file", []string{"--verify", filepath.Join(dir, "nope.json")}, 2, ""},
		{"not json", []string{"--verify", write("junk.json", "not a document")}, 2, ""},
	}
	for _, tc := range tests {
		var stdout, stderr bytes.Buffer
		if got := runLocalise(tc.args, &stdout, &stderr); got != tc.want {
			t.Errorf("%s: exit %d, want %d\n%s%s", tc.name, got, tc.want, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), tc.out) {
			t.Errorf("%s: output lacks %q:\n%s", tc.name, tc.out, stdout.String())
		}
	}
	var v struct {
		CandidatesTraced int `json:"candidatesTraced"`
	}
	b, err := os.ReadFile(report)
	if err != nil || json.Unmarshal(b, &v) != nil || v.CandidatesTraced != 1 {
		t.Errorf("verify report = %s (%v)", b, err)
	}
}

func TestLocaliseVerificationFlagsRequireVerificationMode(t *testing.T) {
	for _, args := range [][]string{{"--online"}, {"--verify-report", "report.json"}, {"--verify", "doc.json", "--canonical-scan", "scan.json"}} {
		var stdout, stderr bytes.Buffer
		if got := runLocalise(args, &stdout, &stderr); got != 2 {
			t.Errorf("%v: got %d want usage error", args, got)
		}
	}
}

func TestLocaliseVerifyRejectsMissingIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion":"1.1.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if got := runLocalise([]string{"--verify", path}, &stdout, &stderr); got != 1 {
		t.Fatalf("got %d: %s%s", got, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "no scanId") || !strings.Contains(stdout.String(), "no results array") {
		t.Fatalf("missing identity explanation: %s", stdout.String())
	}
}
