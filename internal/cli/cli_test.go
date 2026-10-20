package cli

import (
	"bytes"
	"io"
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
		"transitive dependencies: 2",
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
	// An empty file is not a manifest: scan reports it as a tool error.
	mustWriteFile(t, filepath.Join(repo, "package.json"), "{}")

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

	// Scan the current folder, default format, no vulnerability scan, and
	// decline the ground-truth check the single-repository scan offers.
	exitCode := Main(nil, strings.NewReader("1\n\nN\nn\n"), &stdout, &stderr)
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

const singleLodashPackageLock = `{
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"lodash": "^4.17.15"}},
    "node_modules/lodash": {"version": "4.18.1"}
  }
}`

// TestInteractiveScanOffersGroundTruthCheck is the success case: after an
// interactive scan of a single repo, answering "y" to the ground-truth
// prompt and pointing at a matching ground-truth SBOM prints a full
// verification report.
func TestInteractiveScanOffersGroundTruthCheck(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	repo := filepath.Join(root, "demo")
	mustMkdirAll(t, filepath.Join(repo, ".git"))
	mustWriteFile(t, filepath.Join(repo, "package.json"), `{"dependencies":{"lodash":"^4.17.15"}}`)
	mustWriteFile(t, filepath.Join(repo, "package-lock.json"), singleLodashPackageLock)

	groundTruth := filepath.Join(root, "ground-truth.cdx.json")
	mustWriteFile(t, groundTruth, `{"bomFormat":"CycloneDX","components":[{"type":"library","name":"lodash","version":"4.18.1","purl":"pkg:npm/lodash@4.18.1"}]}`)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	input := "2\n" + repo + "\n\nN\ny\n" + groundTruth + "\n"
	exitCode := Main(nil, strings.NewReader(input), &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
	}

	output := stdout.String()
	for _, expected := range []string{
		"Check accuracy against a ground-truth SBOM?",
		"SBOM VERIFICATION REPORT",
		"Version Accuracy: 100.0%",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("expected output to contain %q, got %q", expected, output)
		}
	}
}

// TestInteractiveScanGroundTruthMissingFile is the failure/unknown-path
// case: answering "y" but pointing at a ground-truth file that does not
// exist must fail the check cleanly (exit 2, a clear stderr message)
// rather than crash or hang.
func TestInteractiveScanGroundTruthMissingFile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	repo := filepath.Join(root, "demo")
	mustMkdirAll(t, filepath.Join(repo, ".git"))
	mustWriteFile(t, filepath.Join(repo, "package.json"), `{"dependencies":{"lodash":"^4.17.15"}}`)
	mustWriteFile(t, filepath.Join(repo, "package-lock.json"), singleLodashPackageLock)

	missingGroundTruth := filepath.Join(root, "does-not-exist.cdx.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	input := "2\n" + repo + "\n\nN\ny\n" + missingGroundTruth + "\n"
	exitCode := Main(nil, strings.NewReader(input), &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("expected exit code 2 for a missing ground-truth file, got %d, stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "ground-truth check failed") {
		t.Fatalf("expected a ground-truth check error on stderr, got %q", stderr.String())
	}
}

// TestInteractiveScanMultiRepoSkipsGroundTruthPrompt is the boundary case:
// a ground-truth comparison needs exactly one generated SBOM to compare
// against, so scanning a root that contains two repos must skip the prompt
// entirely rather than ask which one to check (or worse, silently pick
// one). The input stream deliberately has no answer queued for a
// ground-truth prompt; if the prompt were shown anyway, reading past the
// end of input would surface as a non-zero exit.
func TestInteractiveScanMultiRepoSkipsGroundTruthPrompt(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	repoA := filepath.Join(root, "alpha")
	repoB := filepath.Join(root, "beta")
	mustMkdirAll(t, filepath.Join(repoA, ".git"))
	mustMkdirAll(t, filepath.Join(repoB, ".git"))
	mustWriteFile(t, filepath.Join(repoA, "package.json"), `{"dependencies":{"lodash":"^4.17.15"}}`)
	mustWriteFile(t, filepath.Join(repoA, "package-lock.json"), singleLodashPackageLock)
	mustWriteFile(t, filepath.Join(repoB, "package.json"), `{"dependencies":{"lodash":"^4.17.15"}}`)
	mustWriteFile(t, filepath.Join(repoB, "package-lock.json"), singleLodashPackageLock)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	input := "2\n" + root + "\n\nN\n"
	exitCode := Main(nil, strings.NewReader(input), &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
	}

	if strings.Contains(stdout.String(), "ground-truth") {
		t.Fatalf("expected no ground-truth prompt when multiple repos were scanned, got %q", stdout.String())
	}
}

func TestMainExitCodes(t *testing.T) {
	t.Parallel()

	if code := Main([]string{"version"}, strings.NewReader(""), io.Discard, io.Discard); code != 0 {
		t.Fatalf("expected success exit code 0, got %d", code)
	}

	if code := Main([]string{"scan", "--bad-flag"}, strings.NewReader(""), io.Discard, io.Discard); code != 2 {
		t.Fatalf("expected invalid-argument exit code 2, got %d", code)
	}

	if code := Main([]string{"scan", "--format", "xml"}, strings.NewReader(""), io.Discard, io.Discard); code != 2 {
		t.Fatalf("expected invalid-format exit code 2, got %d", code)
	}
}

func TestMainRejectsFailOnVulnWithoutInclude(t *testing.T) {
	t.Parallel()

	if code := Main([]string{"scan", "--fail-on-vuln"}, strings.NewReader(""), io.Discard, io.Discard); code != 2 {
		t.Fatalf("expected fail-on-vuln usage error exit code 2, got %d", code)
	}
}

func TestMainNoColorDisablesANSI(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, ".git"))
	mustWriteFile(t, filepath.Join(root, "package.json"), `{"name":"demo"}`)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if code := Main([]string{"scan", "--no-color", root}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("expected success exit code 0, got %d, stderr=%q", code, stderr.String())
	}

	if strings.Contains(stdout.String(), "\033[") {
		t.Fatalf("expected no ANSI color sequences when --no-color is used, got %q", stdout.String())
	}
}

func TestMainMissingGrypeIsToolError(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, ".git"))
	mustWriteFile(t, filepath.Join(root, "package.json"), `{"name":"demo"}`)

	// Hide Grype from PATH and from every fallback install location.
	empty := t.TempDir()
	for _, key := range []string{"PATH", "LOCALAPPDATA", "GOBIN", "GOPATH", "HOME", "USERPROFILE"} {
		t.Setenv(key, empty)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if code := Main([]string{"scan", "--include-vulnerabilities", root}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("expected missing Grype exit code 2, got %d, stderr=%q", code, stderr.String())
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

func TestGitHubScanFailedRepoIsToolError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	var stdout, stderr bytes.Buffer
	// Not a GitHub URL: ScanRepo fails before any request is made.
	code := Main([]string{"github", "not-a-repository-url"}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
}
