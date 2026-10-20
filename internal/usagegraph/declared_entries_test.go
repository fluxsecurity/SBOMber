package usagegraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

func TestDeclaredNamedFunctionEntry(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "src", "custom.js")
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o755); err != nil {
		t.Fatal(err)
	}
	source := `import { merge } from "lodash";
function launch() {
  return merge({}, {});
}
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
		[]RepositoryInput{{RepositoryID: "repo-app", Result: result}},
		[]OccurrenceInput{fixtureOccurrence()},
		ProduceOptions{
			ScanID:               "scan-declared",
			Ecosystem:            "npm",
			AnalyzerID:           AnalyzerID,
			ReachabilityAnalysed: true,
			DeclaredEntryPoints: []DeclaredEntryPoint{{
				RepositoryID: "repo-app",
				File:         "src/custom.js",
				Function:     "launch",
			}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.EntryPoints) != 1 ||
		graph.EntryPoints[0].Kind != "declared" ||
		graph.EntryPoints[0].Function != "launch" ||
		graph.EntryPoints[0].Line != 2 {
		t.Fatalf("declared entry = %+v", graph.EntryPoints)
	}
	observation := requireObservationForSymbol(t, graph, "merge")
	if len(observation.CallSites) != 1 {
		t.Fatalf("calls = %+v", observation.CallSites)
	}
	call := observation.CallSites[0]
	if call.Reachability != Reachable ||
		call.EntryPointID != graph.EntryPoints[0].EntryPointID ||
		len(call.CallPath) != 1 ||
		call.CallPath[0].Function != "launch" {
		t.Fatalf("declared path = %+v", call)
	}
}

func TestDeclaredModuleAndAmbiguousFunction(t *testing.T) {
	cases := []struct {
		name       string
		source     string
		function   string
		wantEntry  bool
		wantLength int
	}{
		{
			name: "module",
			source: `import { merge } from "lodash";
merge({}, {});
`,
			function:   "<module>",
			wantEntry:  true,
			wantLength: 1,
		},
		{
			name: "ambiguous named function",
			source: `import { merge } from "lodash";
function launch() { return merge({}, {}); }
function launch() { return merge({}, {}); }
`,
			function: "launch",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			sourcePath := filepath.Join(root, "src", "custom.js")
			if err := os.MkdirAll(filepath.Dir(sourcePath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sourcePath, []byte(test.source), 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := sourceanalysis.AnalyzeRepository(
				root, sourceanalysis.RepositoryOptions{},
			)
			if err != nil {
				t.Fatal(err)
			}
			graph, err := Produce(
				[]RepositoryInput{{RepositoryID: "repo-app", Result: result}},
				[]OccurrenceInput{fixtureOccurrence()},
				ProduceOptions{
					ScanID:               "scan-declared-safety",
					Ecosystem:            "npm",
					AnalyzerID:           AnalyzerID,
					ReachabilityAnalysed: true,
					DeclaredEntryPoints: []DeclaredEntryPoint{{
						RepositoryID: "repo-app",
						File:         "src/custom.js",
						Function:     test.function,
					}},
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			observation := requireObservationForSymbol(t, graph, "merge")
			if test.wantEntry {
				if len(graph.EntryPoints) != 1 ||
					graph.EntryPoints[0].Kind != "declared" ||
					graph.EntryPoints[0].Function != test.function ||
					graph.EntryPoints[0].Line != 1 ||
					len(observation.CallSites) != 1 {
					t.Fatalf("module entry/calls = %+v / %+v", graph.EntryPoints, observation.CallSites)
				}
				call := observation.CallSites[0]
				if call.Reachability != Reachable ||
					call.EntryPointID != graph.EntryPoints[0].EntryPointID ||
					len(call.CallPath) != test.wantLength ||
					call.CallPath[0].Function != "<module>" {
					t.Fatalf("declared module path = %+v", call)
				}
			} else {
				if len(graph.EntryPoints) != 0 || len(observation.CallSites) == 0 {
					t.Fatalf("ambiguous entry/calls = %+v / %+v", graph.EntryPoints, observation.CallSites)
				}
				for _, call := range observation.CallSites {
					if call.Reachability != ReachUnknown ||
						call.EntryPointID != "" || len(call.CallPath) != 0 {
						t.Fatalf("ambiguous declaration gained a path: %+v", call)
					}
				}
			}
		})
	}
}
