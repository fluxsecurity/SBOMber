package usagegraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

func TestNestedCallbackInsideRouteDoesNotBecomeReachable(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "src", "app.js")
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o755); err != nil {
		t.Fatal(err)
	}
	source := `import { merge } from "lodash";

app.get("/items", () => {
  [1].forEach(() => {
    merge({}, {});
  });
});
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
			ScanID:               "scan-route-callback",
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
		t.Fatalf("merge calls = %+v, want one", observation.CallSites)
	}
	call := observation.CallSites[0]
	if call.Reachability != ReachUnknown ||
		call.EntryPointID != "" ||
		len(call.CallPath) != 0 {
		t.Fatalf("nested callback gained a route path: %+v", call)
	}
}

func TestNamedRouteRequiresUniqueLocalFunction(t *testing.T) {
	cases := []struct {
		name      string
		source    string
		reachable bool
	}{
		{
			name: "unique",
			source: `import { merge } from "lodash";
router.post("/items", handleItems);
function handleItems() {
  return merge({}, {});
}
`,
			reachable: true,
		},
		{
			name: "ambiguous",
			source: `import { merge } from "lodash";
router.post("/items", handleItems);
function handleItems() {
  return merge({}, {});
}
function handleItems() {
  return merge({}, {});
}
`,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			sourcePath := filepath.Join(root, "src", "app.js")
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
					ScanID:               "scan-named-route",
					Ecosystem:            "npm",
					AnalyzerID:           AnalyzerID,
					ReachabilityAnalysed: true,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			observation := requireObservationForSymbol(t, graph, "merge")
			if test.reachable {
				if len(graph.EntryPoints) != 1 ||
					graph.EntryPoints[0].Kind != "route_handler" ||
					graph.EntryPoints[0].Function != "handleItems" ||
					graph.EntryPoints[0].Line != 3 {
					t.Fatalf("unique named entry = %+v", graph.EntryPoints)
				}
				if len(observation.CallSites) != 1 ||
					observation.CallSites[0].Reachability != Reachable ||
					observation.CallSites[0].EntryPointID != graph.EntryPoints[0].EntryPointID ||
					len(observation.CallSites[0].CallPath) != 1 ||
					observation.CallSites[0].CallPath[0].Function != "handleItems" {
					t.Fatalf("unique named route call = %+v", observation.CallSites)
				}
			} else {
				if len(graph.EntryPoints) != 0 {
					t.Fatalf("ambiguous named entries = %+v", graph.EntryPoints)
				}
				for _, call := range observation.CallSites {
					if call.Reachability != ReachUnknown ||
						call.EntryPointID != "" || len(call.CallPath) != 0 {
						t.Fatalf("ambiguous handler gained a path: %+v", call)
					}
				}
			}
		})
	}
}

func TestRouteEntryIdentityDoesNotDuplicateOrGuess(t *testing.T) {
	for _, test := range []struct {
		name        string
		source      string
		wantEntries int
	}{
		{
			name: "two inline handlers on one line",
			source: `import { merge } from "lodash";
app.get("/a", () => merge({}, {})); app.get("/b", () => merge({}, {}));
`,
			wantEntries: 0,
		},
		{
			name: "named handler registered twice",
			source: `import { merge } from "lodash";
app.get("/a", handle); app.get("/b", handle);
function handle() { return merge({}, {}); }
`,
			wantEntries: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			sourcePath := filepath.Join(root, "src", "app.js")
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
					ScanID:               "scan-route-identity",
					Ecosystem:            "npm",
					AnalyzerID:           AnalyzerID,
					ReachabilityAnalysed: true,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(graph.EntryPoints) != test.wantEntries {
				t.Fatalf("entry points = %+v, want %d", graph.EntryPoints, test.wantEntries)
			}
			observation := requireObservationForSymbol(t, graph, "merge")
			if test.wantEntries == 0 {
				for _, call := range observation.CallSites {
					if call.Reachability != ReachUnknown ||
						call.EntryPointID != "" || len(call.CallPath) != 0 {
						t.Fatalf("same-line route gained a path: %+v", call)
					}
				}
			}
		})
	}
}

func TestCoTerminalNestedArrowInsideRouteStaysUnknown(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "src", "app.js")
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o755); err != nil {
		t.Fatal(err)
	}
	source := `import { merge } from "lodash";
app.get("/nested", () => () => merge({}, {}));
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
			ScanID:               "scan-coterminal",
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
	if call.Reachability != ReachUnknown ||
		call.EntryPointID != "" || len(call.CallPath) != 0 {
		t.Fatalf("nested arrow gained a path: %+v", call)
	}
}

func TestExportedNamedArrowDirectCallRemainsReachable(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "src", "index.js")
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o755); err != nil {
		t.Fatal(err)
	}
	source := `import { merge } from "lodash";
export const start = () => merge({}, {});
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
			ScanID:               "scan-named-arrow",
			Ecosystem:            "npm",
			AnalyzerID:           AnalyzerID,
			ReachabilityAnalysed: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.EntryPoints) != 1 ||
		graph.EntryPoints[0].Function != "start" {
		t.Fatalf("exported arrow entry = %+v", graph.EntryPoints)
	}
	observation := requireObservationForSymbol(t, graph, "merge")
	if len(observation.CallSites) != 1 {
		t.Fatalf("calls = %+v", observation.CallSites)
	}
	call := observation.CallSites[0]
	if call.Reachability != Reachable ||
		call.EntryPointID != graph.EntryPoints[0].EntryPointID ||
		len(call.CallPath) != 1 ||
		call.CallPath[0].Function != "start" {
		t.Fatalf("named arrow direct path = %+v", call)
	}
}
