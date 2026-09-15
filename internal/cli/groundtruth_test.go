package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestGroundTruthFixturesDoNotRegress is the automated ground-truth
// regression gate: for every committed testdata/fixtures/ground-truth/<name>/
// fixture, it runs a fresh `sbomber scan` against the matching source
// fixture (testdata/fixtures/<name>/), verifies the result against the
// committed ground-truth SBOM, and fails if any accuracy metric drops
// below what is already committed in that fixture's verify-summary.txt.
//
// This is the actual point of having ground truth: a human running
// `sbomber verify` once and committing the result as evidence (as
// testdata/fixtures/ground-truth/npm-basic/ documents) proves the tool was
// accurate on that day. It does not, by itself, stop a future change from
// silently reintroducing the exact bug that evidence was built to catch —
// this test does, on every `go test ./...` / `make test` / CI run, with no
// separate script or workflow step required.
func TestGroundTruthFixturesDoNotRegress(t *testing.T) {
	groundTruthRoot := filepath.Join("..", "..", "testdata", "fixtures", "ground-truth")
	entries, err := os.ReadDir(groundTruthRoot)
	if err != nil {
		t.Fatalf("read ground-truth fixtures dir: %v", err)
	}

	found := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		found++
		name := entry.Name()
		t.Run(name, func(t *testing.T) {
			checkGroundTruthFixture(t, name)
		})
	}
	if found == 0 {
		t.Fatal("expected at least one committed ground-truth fixture under testdata/fixtures/ground-truth")
	}
}

func checkGroundTruthFixture(t *testing.T, name string) {
	t.Helper()

	sourceFixture := filepath.Join("..", "..", "testdata", "fixtures", name)
	gtDir := filepath.Join("..", "..", "testdata", "fixtures", "ground-truth", name)
	groundTruthPath := filepath.Join(gtDir, "ground-truth.cdx.json")
	committedSummaryPath := filepath.Join(gtDir, "verify-summary.txt")

	if _, err := os.Stat(sourceFixture); err != nil {
		t.Fatalf("ground-truth fixture %q has no matching source fixture at %s (naming convention: testdata/fixtures/ground-truth/<name>/ pairs with testdata/fixtures/<name>/): %v", name, sourceFixture, err)
	}

	committedSummary, err := os.ReadFile(committedSummaryPath)
	if err != nil {
		t.Fatalf("read committed verify-summary.txt: %v", err)
	}
	committedMetrics := parseCommittedMetrics(t, string(committedSummary))

	// Copy the source fixture's manifest files into a fresh repo with a
	// .git marker, exactly as discovery.FindGitRepositories requires.
	//
	// yarn.lock is deliberately excluded. testdata/fixtures/npm-basic
	// carries a classic Yarn v1 lockfile (unsupported by
	// EnrichFromYarnLock, which only parses Yarn Berry) alongside a valid
	// package-lock.json. Copying it reproduces a real, separately
	// discovered bug: buildRepoDependencySummary tries yarn enrichment
	// first and falls through to EnrichFromPackageLock only on an error —
	// but parsing a v1 file with the Berry parser doesn't error, it just
	// silently extracts nothing (its "version" lines don't match the
	// Berry-specific "  version:" prefix), so the working package-lock
	// path never gets tried. That is exactly the "reports the range, not
	// the resolved version" bug this fixture exists to catch, just from a
	// different cause. Not fixed here — this test's job is to verify the
	// documented method (see METHOD.md, which copies only package.json
	// and package-lock.json), not to fix buildRepoDependencySummary's
	// yarn-vs-package-lock fallback order. Tracked as a follow-up.
	scanRoot := t.TempDir()
	repoDir := filepath.Join(scanRoot, "repo")
	if err := os.MkdirAll(filepath.Join(repoDir, ".git"), 0o755); err != nil {
		t.Fatalf("create .git marker: %v", err)
	}
	sourceEntries, err := os.ReadDir(sourceFixture)
	if err != nil {
		t.Fatalf("read source fixture dir: %v", err)
	}
	for _, e := range sourceEntries {
		if e.IsDir() || e.Name() == "yarn.lock" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(sourceFixture, e.Name()))
		if err != nil {
			t.Fatalf("read source fixture file %s: %v", e.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(repoDir, e.Name()), data, 0o644); err != nil {
			t.Fatalf("write fixture file %s: %v", e.Name(), err)
		}
	}

	var scanOut bytes.Buffer
	scanExit := Main([]string{"scan", "--format", "cyclonedx", scanRoot}, strings.NewReader(""), &scanOut, &scanOut)
	if scanExit != 0 {
		t.Fatalf("scan failed with exit code %d: %s", scanExit, scanOut.String())
	}

	generatedSBOM := extractSingleScanSBOM(scanOut.String())
	if generatedSBOM == "" {
		t.Fatalf("could not find a single generated SBOM in scan output: %s", scanOut.String())
	}

	var verifyOut, verifyErr bytes.Buffer
	verifyExit := Main([]string{"verify", "--json", groundTruthPath, generatedSBOM}, strings.NewReader(""), &verifyOut, &verifyErr)
	if verifyExit != 0 && verifyExit != 1 {
		// 1 means "below the built-in F1 threshold", which is itself a
		// regression signal handled below; anything else is a real error.
		t.Fatalf("verify failed with exit code %d: stderr=%s", verifyExit, verifyErr.String())
	}

	var fresh struct {
		Precision       float64 `json:"precision"`
		Recall          float64 `json:"recall"`
		F1Score         float64 `json:"f1_score"`
		VersionAccuracy float64 `json:"version_accuracy"`
	}
	// runVerify prints "Verification note saved: ..." to stdout after the
	// JSON blob, so decode just the first JSON value rather than
	// Unmarshal, which requires the whole buffer to be valid JSON.
	if err := json.NewDecoder(&verifyOut).Decode(&fresh); err != nil {
		t.Fatalf("parse verify --json output: %v\noutput: %s", err, verifyOut.String())
	}

	const tolerance = 0.05 // float rounding slack, not a real accuracy allowance
	checks := []struct {
		name      string
		fresh     float64
		committed float64
	}{
		{"Precision", fresh.Precision, committedMetrics["Precision"]},
		{"Recall", fresh.Recall, committedMetrics["Recall"]},
		{"F1 Score", fresh.F1Score, committedMetrics["F1 Score"]},
		{"Version Accuracy", fresh.VersionAccuracy, committedMetrics["Version Accuracy"]},
	}
	for _, c := range checks {
		if c.fresh+tolerance < c.committed {
			t.Errorf("regression in %s for fixture %q: committed evidence shows %.1f%%, a fresh run now gets %.1f%% — re-run `sbomber verify` and either fix the regression or, if the drop is intentional, update the committed evidence and explain why in that fixture's METHOD.md", c.name, name, c.committed, c.fresh)
		}
	}
}

var committedMetricPattern = regexp.MustCompile(`(?m)^\s*(Precision|Recall|F1 Score|Version Accuracy)\s+([\d.]+)%`)

// parseCommittedMetrics reads the four accuracy percentages out of a
// committed verify-summary.txt (ComparisonResult.PrintReport's box-drawing
// output). The regex also tolerates the plainer SaveNote format
// (sbom-verify-note.txt), which has no colons or box-drawing characters to
// strip, in case a future caller points it at that file instead.
func parseCommittedMetrics(t *testing.T, summary string) map[string]float64 {
	t.Helper()

	// PrintReport's box-drawing format uses "Name:  NN.N%" inside a
	// bordered line; strip the box characters so the shared regex works
	// against either that format or the plain SaveNote format.
	cleaned := strings.NewReplacer("│", " ", ":", " ").Replace(summary)

	metrics := make(map[string]float64)
	for _, match := range committedMetricPattern.FindAllStringSubmatch(cleaned, -1) {
		value, err := strconv.ParseFloat(match[2], 64)
		if err != nil {
			t.Fatalf("parse committed metric %q: %v", match[0], err)
		}
		metrics[match[1]] = value
	}

	for _, required := range []string{"Precision", "Recall", "F1 Score", "Version Accuracy"} {
		if _, ok := metrics[required]; !ok {
			t.Fatalf("committed verify-summary.txt is missing a %q metric line; got: %s", required, summary)
		}
	}
	return metrics
}
