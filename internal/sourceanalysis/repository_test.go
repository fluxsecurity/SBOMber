package sourceanalysis

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeTestSource(t *testing.T, root, relative, content string) {
	t.Helper()

	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture %q: %v", relative, err)
	}
}

func skippedReasons(result RepositoryResult) map[string]string {
	reasons := make(map[string]string, len(result.Skipped))
	for _, skipped := range result.Skipped {
		reasons[skipped.Path] = skipped.Reason
	}
	return reasons
}

func TestAnalyzeRepositoryExcludesUntrustedAndGeneratedTrees(t *testing.T) {
	root := t.TempDir()
	writeTestSource(t, root, "src/app.js", `import {merge} from "lodash"; merge({}, {});`)
	writeTestSource(t, root, "node_modules/pkg/index.js", `dangerous()`)
	writeTestSource(t, root, "dist/output.js", `generated()`)
	writeTestSource(t, root, "src/vendor.bundle.js", `bundled()`)
	writeTestSource(t, root, "src/large.js", strings.Repeat("x", 160))
	writeTestSource(t, root, "src/minified.js", strings.Repeat("x", 80))

	result, err := AnalyzeRepository(root, RepositoryOptions{
		MaxSourceFiles:    20,
		MaxSourceBytes:    128,
		MinifiedLineBytes: 64,
	})
	if err != nil {
		t.Fatalf("AnalyzeRepository: %v", err)
	}

	if len(result.Files) != 1 || result.Files[0].Path != "src/app.js" {
		t.Fatalf("expected only src/app.js to be analysed, got %+v", result.Files)
	}

	wantSkipped := map[string]string{
		"dist":                 SkipExcludedDirectory,
		"node_modules":         SkipExcludedDirectory,
		"src/large.js":         SkipSourceTooLarge,
		"src/minified.js":      SkipMinifiedBundle,
		"src/vendor.bundle.js": SkipGeneratedOutput,
	}
	if got := skippedReasons(result); !reflect.DeepEqual(got, wantSkipped) {
		t.Fatalf("unexpected skipped sources\nwant: %#v\n got: %#v", wantSkipped, got)
	}
	if len(result.Failed) != 0 {
		t.Fatalf("unexpected failures: %+v", result.Failed)
	}
	if !reflect.DeepEqual(result.LimitsHit, []string{LimitMaxFileSize}) {
		t.Fatalf("unexpected limits: %+v", result.LimitsHit)
	}
}

func TestAnalyzeRepositoryStopsAtSourceFileLimit(t *testing.T) {
	root := t.TempDir()
	writeTestSource(t, root, "a.js", `a()`)
	writeTestSource(t, root, "b.js", `b()`)
	writeTestSource(t, root, "c.js", `c()`)

	result, err := AnalyzeRepository(root, RepositoryOptions{MaxSourceFiles: 1})
	if err != nil {
		t.Fatalf("AnalyzeRepository: %v", err)
	}

	if len(result.Files) != 1 || result.Files[0].Path != "a.js" {
		t.Fatalf("unexpected analysed files: %+v", result.Files)
	}
	if !reflect.DeepEqual(result.LimitsHit, []string{LimitMaxFiles}) {
		t.Fatalf("unexpected limits: %+v", result.LimitsHit)
	}
	reasons := skippedReasons(result)
	for _, path := range []string{"b.js", "c.js"} {
		if got := reasons[path]; got != SkipSourceFileLimit {
			t.Fatalf("%s skip reason = %q, want %q", path, got, SkipSourceFileLimit)
		}
	}
}

func TestAnalyzeRepositoryRejectsInvalidBoundaryInput(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-directory.js")
	if err := os.WriteFile(file, []byte(`ok()`), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := AnalyzeRepository(file, RepositoryOptions{}); err == nil {
		t.Fatal("expected a non-directory repository root to fail")
	}
	if _, err := AnalyzeRepository(t.TempDir(), RepositoryOptions{MaxSourceFiles: -1}); err == nil {
		t.Fatal("expected a negative limit to fail")
	}
}
