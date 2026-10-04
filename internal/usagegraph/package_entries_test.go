package usagegraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

func TestPackageMainTopLevelDirectCall(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "src", "boot.js")
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o755); err != nil {
		t.Fatal(err)
	}
	source := `import { merge } from "lodash";
function run() {
  return merge({}, {});
}
run();
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := sourceanalysis.AnalyzeRepository(
		root, sourceanalysis.RepositoryOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := Produce(
		[]RepositoryInput{{
			RepositoryID: "repo-app",
			Result:       result,
			PackageJSON:  []byte(`{"main":"src/boot.js"}`),
		}},
		[]OccurrenceInput{fixtureOccurrence()},
		ProduceOptions{
			ScanID:               "scan-package-main",
			Ecosystem:            "npm",
			AnalyzerID:           AnalyzerID,
			ReachabilityAnalysed: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.EntryPoints) != 1 ||
		graph.EntryPoints[0].Kind != "package_main" ||
		graph.EntryPoints[0].Function != "<module>" ||
		graph.EntryPoints[0].File != "src/boot.js" ||
		graph.EntryPoints[0].Line != 1 {
		t.Fatalf("package main entry = %+v", graph.EntryPoints)
	}
	observation := requireObservationForSymbol(t, graph, "merge")
	if len(observation.CallSites) != 1 {
		t.Fatalf("merge calls = %+v", observation.CallSites)
	}
	call := observation.CallSites[0]
	if call.Reachability != Reachable ||
		call.EntryPointID != graph.EntryPoints[0].EntryPointID ||
		len(call.CallPath) != 2 ||
		call.CallPath[0].Function != "<module>" ||
		call.CallPath[1].Function != "run" {
		t.Fatalf("package main path = %+v", call)
	}
}

func TestPackageBinEntryAndMissingTarget(t *testing.T) {
	for _, test := range []struct {
		name     string
		manifest string
		wantPath bool
	}{
		{
			name:     "bin object",
			manifest: `{"bin":{"sbomber":"bin/cli.js"}}`,
			wantPath: true,
		},
		{
			name:     "missing target",
			manifest: `{"bin":"bin/missing.js"}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			sourcePath := filepath.Join(root, "bin", "cli.js")
			if err := os.MkdirAll(filepath.Dir(sourcePath), 0o755); err != nil {
				t.Fatal(err)
			}
			source := `import { merge } from "lodash";
merge({}, {});
`
			if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := sourceanalysis.AnalyzeRepository(
				root, sourceanalysis.RepositoryOptions{},
			)
			if err != nil {
				t.Fatal(err)
			}
			graph, err := Produce(
				[]RepositoryInput{{
					RepositoryID: "repo-app",
					Result:       result,
					PackageJSON:  []byte(test.manifest),
				}},
				[]OccurrenceInput{fixtureOccurrence()},
				ProduceOptions{
					ScanID:               "scan-package-bin",
					Ecosystem:            "npm",
					AnalyzerID:           AnalyzerID,
					ReachabilityAnalysed: true,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			observation := requireObservationForSymbol(t, graph, "merge")
			if len(observation.CallSites) != 1 {
				t.Fatalf("calls = %+v", observation.CallSites)
			}
			call := observation.CallSites[0]
			if test.wantPath {
				if len(graph.EntryPoints) != 1 ||
					graph.EntryPoints[0].Kind != "package_bin" ||
					graph.EntryPoints[0].Function != "<module>" ||
					graph.EntryPoints[0].File != "bin/cli.js" ||
					call.Reachability != Reachable ||
					call.EntryPointID != graph.EntryPoints[0].EntryPointID ||
					len(call.CallPath) != 1 ||
					call.CallPath[0].Function != "<module>" {
					t.Fatalf("bin entry/path = %+v / %+v", graph.EntryPoints, call)
				}
			} else if len(graph.EntryPoints) != 0 ||
				call.Reachability != ReachUnknown ||
				call.EntryPointID != "" || len(call.CallPath) != 0 {
				t.Fatalf("missing target gained path = %+v / %+v", graph.EntryPoints, call)
			}
		})
	}
}
