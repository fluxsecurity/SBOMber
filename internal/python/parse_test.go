package python

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/deps"
)

func TestParseRequirements(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "requirements.txt"), []byte("requests==2.34.0\nflask>=3.0\n# comment\n"), 0o644); err != nil {
		t.Fatalf("write requirements: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "requirements-dev.txt"), []byte("pytest==8.0.0\n"), 0o644); err != nil {
		t.Fatalf("write requirements-dev: %v", err)
	}

	summary, err := ParseRequirements(tmp)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(summary.Direct) != 3 {
		t.Fatalf("expected 3 dependencies, got %d", len(summary.Direct))
	}

	expected := map[string]deps.Scope{
		"flask":    deps.ScopeRuntime,
		"pytest":   deps.ScopeDev,
		"requests": deps.ScopeRuntime,
	}

	for _, dep := range summary.Direct {
		if expected[dep.Name] != dep.Scope {
			t.Fatalf("expected %s scope %s, got %s", dep.Name, expected[dep.Name], dep.Scope)
		}
	}
}

func TestParsePyProjectToml(t *testing.T) {
	tmp := t.TempDir()
	content := `[project]
name = "bdsm"
version = "2.0.0"
requires-python = ">=3.10"

dependencies = [
    "numpy",
    "protobuf>=6.31",
    "confluent-kafka",
    "redis",
    "pyarrow",
    "pyyaml",
    "zstandard",
    "requests",
    "google-cloud-bigquery",
    "google-cloud-bigquery-storage",
]

[project.optional-dependencies]
gpu = ["optax"]
training = ["scikit-learn"]
`
	if err := os.WriteFile(filepath.Join(tmp, "pyproject.toml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write pyproject: %v", err)
	}

	summary, err := ParseRequirements(tmp)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(summary.Direct) != 12 {
		t.Fatalf("expected 12 dependencies, got %d", len(summary.Direct))
	}

	seen := map[string]deps.Scope{}
	for _, dep := range summary.Direct {
		seen[dep.Name] = dep.Scope
	}

	for _, name := range []string{"numpy", "protobuf", "confluent-kafka", "redis", "pyarrow", "pyyaml", "zstandard", "requests", "google-cloud-bigquery", "google-cloud-bigquery-storage"} {
		if scope, ok := seen[name]; !ok || scope != deps.ScopeRuntime {
			t.Fatalf("missing required dependency %s from pyproject parse", name)
		}
	}

	for _, name := range []string{"optax", "scikit-learn"} {
		if scope, ok := seen[name]; !ok || scope != deps.ScopeOptional {
			t.Fatalf("missing optional dependency %s from pyproject parse", name)
		}
	}
}

// The review's fixture: requests in requirements.txt and pyproject.toml,
// pytest in two optional groups. Each must appear once, with a bare
// version, or the CycloneDX SBOM gets duplicate bom-refs.
func TestParseRequirementsDeduplicatesAcrossFiles(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "requirements.txt"), []byte("requests==2.31.0  # pinned\nflask[async]==3.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pyproject := `[project]
name = "demo"
dependencies = ["Requests>=2.0", "click>=8"]

[project.optional-dependencies]
dev = ["pytest>=7"]
test = ["pytest>=7", "coverage==7.4.0"]
`
	if err := os.WriteFile(filepath.Join(tmp, "pyproject.toml"), []byte(pyproject), 0o644); err != nil {
		t.Fatal(err)
	}

	summary, err := ParseRequirements(tmp)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]deps.Dependency{}
	for _, d := range summary.Direct {
		key := normalizeName(d.Name)
		if _, dup := seen[key]; dup {
			t.Fatalf("%s listed twice: %+v", d.Name, summary.Direct)
		}
		seen[key] = d
	}
	want := map[string]struct {
		version string
		scope   deps.Scope
	}{
		"requests": {"2.31.0", deps.ScopeRuntime}, // pin from requirements.txt kept
		"flask":    {"3.0.0", deps.ScopeRuntime},  // extras no longer drop the version
		"click":    {"", deps.ScopeRuntime},       // a range is not a version
		"pytest":   {"", deps.ScopeOptional},
		"coverage": {"7.4.0", deps.ScopeOptional},
	}
	if len(seen) != len(want) {
		t.Fatalf("got %d packages, want %d: %+v", len(seen), len(want), summary.Direct)
	}
	for name, w := range want {
		d := seen[name]
		if d.Version != w.version || d.Scope != w.scope {
			t.Errorf("%s = version %q scope %q, want %q %q", name, d.Version, d.Scope, w.version, w.scope)
		}
	}
}

func TestParsePythonRequirementLine(t *testing.T) {
	cases := []struct{ line, name, version string }{
		{"Django==2.2.0", "Django", "2.2.0"},
		{"Django==2.2.0   # CVE-2019-14232", "Django", "2.2.0"},
		{"requests[security]==2.19.1", "requests", "2.19.1"},
		{"pywin32==306; sys_platform == 'win32'", "pywin32", "306"},
		{"flask>=3.0", "flask", ""},
		{"numpy==1.*", "numpy", ""},
		{"six", "six", ""},
		{"lxml ==4.2.0", "lxml", "4.2.0"},
	}
	for _, c := range cases {
		name, version := parsePythonRequirementLine(c.line)
		if name != c.name || version != c.version {
			t.Errorf("parsePythonRequirementLine(%q) = %q, %q; want %q, %q", c.line, name, version, c.name, c.version)
		}
	}
}
