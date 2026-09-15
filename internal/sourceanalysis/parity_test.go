package sourceanalysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file location")
	}

	return filepath.Clean(
		filepath.Join(filepath.Dir(filename), "..", ".."),
	)
}

func TestSourceAnalyzerExactLabelledCorpus(t *testing.T) {
	root := repositoryRoot(t)
	microDir := filepath.Join(
		root,
		"spikes",
		"parser-bindings",
		"corpus",
		"micro",
	)
	expectedDir := filepath.Join(
		root,
		"spikes",
		"parser-bindings",
		"corpus",
		"expected",
	)

	sources, err := filepath.Glob(filepath.Join(microDir, "*"))
	if err != nil {
		t.Fatalf("glob corpus: %v", err)
	}

	tested := 0

	for _, sourcePath := range sources {
		ext := filepath.Ext(sourcePath)
		if ext != ".js" && ext != ".ts" && ext != ".tsx" {
			continue
		}

		name := filepath.Base(sourcePath)
		stem := name[:len(name)-len(ext)]

		t.Run(stem, func(t *testing.T) {
			got, err := AnalyzeSource(sourcePath)
			if err != nil {
				t.Fatalf("AnalyzeSource(%q): %v", sourcePath, err)
			}

			expectedPath := filepath.Join(
				expectedDir,
				stem+".json",
			)

			data, err := os.ReadFile(expectedPath)
			if err != nil {
				t.Fatalf(
					"read expected %q: %v",
					expectedPath,
					err,
				)
			}

			var want Result
			if err := json.Unmarshal(data, &want); err != nil {
				t.Fatalf(
					"decode expected %q: %v",
					expectedPath,
					err,
				)
			}

			if !reflect.DeepEqual(got, want) {
				gotJSON, _ := json.MarshalIndent(got, "", "  ")
				wantJSON, _ := json.MarshalIndent(want, "", "  ")

				t.Fatalf(
					"result differs from hand-labelled expectation\n"+
						"--- want ---\n%s\n"+
						"--- got ---\n%s",
					wantJSON,
					gotJSON,
				)
			}
		})

		tested++
	}

	if tested != 13 {
		t.Fatalf(
			"expected exactly 13 labelled fixtures, tested %d",
			tested,
		)
	}
}
