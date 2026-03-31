package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanReportsDetectedEcosystems(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	goRepo := filepath.Join(root, "alpha")
	npmRepo := filepath.Join(root, "prettier")

	mustMkdirAll(t, filepath.Join(goRepo, ".git"))
	mustMkdirAll(t, filepath.Join(npmRepo, ".git"))
	mustWriteFile(t, filepath.Join(goRepo, "go.mod"))
	mustWriteFile(t, filepath.Join(goRepo, "go.sum"))
	mustWriteFile(t, filepath.Join(npmRepo, "package.json"), `{
  "dependencies": {
    "react": "^19.0.0"
  },
  "devDependencies": {
    "vitest": "^1.0.0"
  }
}`)
	mustWriteFile(t, filepath.Join(npmRepo, "yarn.lock"), `__metadata:
  version: 8

"react@npm:^19.0.0":
  version: 19.1.0
  resolution: "react@npm:19.1.0"
  dependencies:
    loose-envify: "npm:^1.1.0"

"vitest@npm:^1.0.0":
  version: 1.6.1
  resolution: "vitest@npm:1.6.1"
  dependencies:
    vite: "npm:^5.0.0"

"loose-envify@npm:^1.1.0":
  version: 1.4.0
  resolution: "loose-envify@npm:1.4.0"

"vite@npm:^5.0.0":
  version: 5.4.0
  resolution: "vite@npm:5.4.0"
}`)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Main([]string{"scan", "--format", "both", root}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%q", exitCode, stderr.String())
	}

	output := stdout.String()
	for _, expected := range []string{
		"Selected SBOM export format: both",
		"alpha",
		"[go]",
		"prettier",
		"[npm]",
		"direct dependencies (package.json): 2",
		"transitive dependencies (yarn.lock): 2",
		"total known dependencies: 4",
		"sample packages: react, vitest",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("expected output to contain %q, got %q", expected, output)
		}
	}
}

func TestInteractiveScanCurrentFolder(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	repo := filepath.Join(root, "demo")
	mustMkdirAll(t, filepath.Join(repo, ".git"))
	mustWriteFile(t, filepath.Join(repo, "package.json"))

	previousWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		_ = os.Chdir(previousWD)
	}()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Main(nil, strings.NewReader("1\n\n"), &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%q", exitCode, stderr.String())
	}

	output := stdout.String()
	for _, expected := range []string{
		"Choose an option",
		"Choose SBOM export format",
		"Selected SBOM export format: cyclonedx",
		"demo",
		"[npm]",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("expected interactive output to contain %q, got %q", expected, output)
		}
	}
}

func TestNormalizeExportFormat(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"cyclonedx", "spdx", "both", "CycloneDX"} {
		if _, err := normalizeExportFormat(value); err != nil {
			t.Fatalf("expected %q to be accepted, got error %v", value, err)
		}
	}

	if _, err := normalizeExportFormat("xml"); err == nil {
		t.Fatal("expected invalid format to fail")
	}
}

func TestResolveScanRootExpandsHome(t *testing.T) {
	t.Parallel()

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir returned error: %v", err)
	}

	got, err := resolveScanRoot("~/Documents")
	if err != nil {
		t.Fatalf("resolveScanRoot returned error: %v", err)
	}

	want := filepath.Join(home, "Documents")
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()

	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path string, parts ...string) {
	t.Helper()

	content := "test"
	if len(parts) > 0 {
		content = parts[0]
	}

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
