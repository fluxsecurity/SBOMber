package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/decision"
	"github.com/Xsamsx/SBOMber/internal/inventory"
	"github.com/Xsamsx/SBOMber/internal/usagegraph"
	"github.com/Xsamsx/SBOMber/internal/vex"
)

// scanWorkspace makes a home directory for the SBOM output and one npm
// repository with a lockfile and a source file that imports a dependency.
func scanWorkspace(t *testing.T) (root, repo string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SOURCE_DATE_EPOCH", "1792400000")

	root = t.TempDir()
	repo = filepath.Join(root, "demo-app")
	mustMkdirAll(t, filepath.Join(repo, ".git"))
	mustWriteFile(t, filepath.Join(repo, "package.json"), `{
  "name": "demo-app",
  "dependencies": { "lodash": "^4.17.0", "legacy-reporter": "^2.1.0" },
  "devDependencies": { "build-helper": "^4.0.0" }
}`)
	mustWriteFile(t, filepath.Join(repo, "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "": { "dependencies": { "lodash": "^4.17.0", "legacy-reporter": "^2.1.0" }, "devDependencies": { "build-helper": "^4.0.0" } },
    "node_modules/lodash": { "version": "4.17.20" },
    "node_modules/legacy-reporter": { "version": "2.1.0", "dependencies": { "lodash": "^3.10.0" } },
    "node_modules/legacy-reporter/node_modules/lodash": { "version": "3.10.1" },
    "node_modules/build-helper": { "version": "4.0.2", "dev": true }
  }
}`)
	mustWriteFile(t, filepath.Join(repo, "index.js"), "const _ = require('lodash');\nmodule.exports = function main(x) { return _.merge({}, x); };\n")
	return root, repo
}

// Success: scan writes canonical-scan.json that every consumer reads, and
// usage accounts for every occurrence in it.
func TestScanWritesCanonicalScanTheConsumersRead(t *testing.T) {
	root, _ := scanWorkspace(t)
	out := filepath.Join(root, "out", "canonical-scan.json")

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"scan", "--no-color", "--canonical-scan", out, "--", root}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("scan exit %d, stderr %q", code, stderr.String())
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc inventory.Document
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		t.Fatalf("canonical-scan.json: %v", err)
	}
	if doc.Scan.Status != inventory.StatusComplete || len(doc.Occurrences) != 4 || doc.Scan.Repositories[0].Path != "../demo-app" {
		t.Errorf("scan = %+v, occurrences %d", doc.Scan, len(doc.Occurrences))
	}

	file, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := usagegraph.ReadCanonicalScan(file, 0); err != nil {
		t.Errorf("usage cannot read it: %v", err)
	}
	_ = file.Close()
	if _, err := decision.LoadCanonicalScan(out); err != nil {
		t.Errorf("decide cannot read it: %v", err)
	}
	if _, err := vex.LoadCanonicalScan(out); err != nil {
		t.Errorf("vex cannot read it: %v", err)
	}

	graphPath := filepath.Join(root, "out", "usage-graph.json")
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"usage", "--canonical-scan", out, "--out", graphPath}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("usage exit %d, stderr %q, stdout %q", code, stderr.String(), stdout.String())
	}
	var graph struct {
		Observations []struct {
			OccurrenceID string `json:"occurrenceId"`
		} `json:"observations"`
		Unanalysed []struct {
			OccurrenceID string `json:"occurrenceId"`
		} `json:"unanalysedOccurrences"`
	}
	raw, err := os.ReadFile(graphPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &graph); err != nil {
		t.Fatal(err)
	}
	accounted := map[string]bool{}
	for _, o := range graph.Observations {
		accounted[o.OccurrenceID] = true
	}
	for _, o := range graph.Unanalysed {
		accounted[o.OccurrenceID] = true
	}
	for _, o := range doc.Occurrences {
		if !accounted[o.OccurrenceID] {
			t.Errorf("occurrence %s (%s) is neither observed nor unanalysed", o.OccurrenceID, o.InstallPath)
		}
	}

	// Same inputs, same SOURCE_DATE_EPOCH: the same file.
	again := filepath.Join(root, "again", "canonical-scan.json")
	if code := Main([]string{"scan", "--no-color", "--canonical-scan", again, "--", root}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("second scan exit %d", code)
	}
	second, err := os.ReadFile(again)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, second) {
		t.Error("two scans of the same repository wrote different canonical-scan.json")
	}
}

// Failure path: a repository whose manifest cannot be read is a tool error
// (2), and canonical-scan.json says which repository failed instead of
// listing it as empty.
func TestScanUnreadableManifestIsToolError(t *testing.T) {
	root, repo := scanWorkspace(t)
	mustWriteFile(t, filepath.Join(repo, "package.json"), `{ "dependencies": `)
	out := filepath.Join(root, "out", "canonical-scan.json")

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"scan", "--no-color", "--canonical-scan", out, "--", root}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("exit %d, want 2; stderr %q", code, stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("canonical-scan.json should still be written: %v", err)
	}
	var doc inventory.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Scan.Status != inventory.StatusFailed || len(doc.Scan.StatusDetail.FailedFiles) == 0 {
		t.Errorf("scan = %+v", doc.Scan)
	}
}

// Boundary: a bad SOURCE_DATE_EPOCH is rejected before anything is written,
// and a scan that finds no repository cannot write canonical-scan.json.
func TestScanCanonicalScanBoundaries(t *testing.T) {
	root, _ := scanWorkspace(t)
	out := filepath.Join(root, "out", "canonical-scan.json")
	var stdout, stderr bytes.Buffer

	t.Setenv("SOURCE_DATE_EPOCH", "yesterday")
	if code := Main([]string{"scan", "--canonical-scan", out, "--", root}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Errorf("bad SOURCE_DATE_EPOCH: exit %d, want 2", code)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("nothing should be written when SOURCE_DATE_EPOCH is invalid")
	}

	t.Setenv("SOURCE_DATE_EPOCH", "1792400000")
	empty := t.TempDir()
	if code := Main([]string{"scan", "--canonical-scan", out, "--", empty}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Errorf("no repository: exit %d, want 2", code)
	}
}

func TestSBOMToScanPrefersCycloneDXAndNeverTheDirectory(t *testing.T) {
	cases := []struct {
		saved []string
		want  string
	}{
		{[]string{"/r/sbom-cyclonedx.xml", "/r/sbom.spdx"}, "/r/sbom-cyclonedx.xml"},
		{[]string{"/r/sbom.spdx"}, "/r/sbom.spdx"},
		{[]string{"/r/sbom-cyclonedx.xml"}, "/r/sbom-cyclonedx.xml"},
		{[]string{"/r/sbom-cyclonedx.json"}, "/r/sbom-cyclonedx.json"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := sbomToScan(c.saved); got != c.want {
			t.Errorf("sbomToScan(%v) = %q, want %q", c.saved, got, c.want)
		}
	}
}
