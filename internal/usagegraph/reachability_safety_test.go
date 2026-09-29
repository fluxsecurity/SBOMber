package usagegraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

func TestAmbiguousDirectCallCreatesNoEdge(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "src", "index.js")
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o755); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(sourcePath, []byte(`export function start() {
  helper();
}

function helper() {}
function helper() {}
`), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	result, err := sourceanalysis.AnalyzeRepository(
		root,
		sourceanalysis.RepositoryOptions{},
	)
	if err != nil {
		t.Fatalf("AnalyzeRepository: %v", err)
	}
	repository := RepositoryInput{
		RepositoryID: "repo-app",
		Result:       result,
	}
	entryPoints := detectExportedModuleEntryPoints(
		[]RepositoryInput{repository},
	)
	graph, err := buildApplicationCallGraph(
		[]RepositoryInput{repository},
	)
	if err != nil {
		t.Fatalf("buildApplicationCallGraph: %v", err)
	}

	for _, line := range []int{5, 6} {
		target := sourceanalysis.FunctionID{
			RepositoryID: "repo-app",
			File:         "src/index.js",
			Name:         "helper",
			StartLine:    line,
		}
		if _, path, ok := graph.pathTo(entryPoints, target); ok || len(path) != 0 {
			t.Fatalf("ambiguous call resolved to line %d: %+v", line, path)
		}
	}
}

func TestZeroEntryPointsHasNoPath(t *testing.T) {
	repository := analyseUsageFixture(
		t,
		"component2-usage-reachable",
	)
	graph, err := buildApplicationCallGraph(
		[]RepositoryInput{repository},
	)
	if err != nil {
		t.Fatalf("buildApplicationCallGraph: %v", err)
	}

	target := sourceanalysis.FunctionID{
		RepositoryID: "repo-app",
		File:         "src/service.js",
		Name:         "handleRequest",
		StartLine:    3,
	}
	if _, path, ok := graph.pathTo(nil, target); ok || len(path) != 0 {
		t.Fatalf("zero entry points produced a path: %+v", path)
	}
}

func TestPathSelectionIsDeterministic(t *testing.T) {
	startA := sourceanalysis.FunctionID{
		RepositoryID: "repo-app",
		File:         "src/a.js",
		Name:         "startA",
		StartLine:    1,
	}
	startB := sourceanalysis.FunctionID{
		RepositoryID: "repo-app",
		File:         "src/b.js",
		Name:         "startB",
		StartLine:    1,
	}
	target := sourceanalysis.FunctionID{
		RepositoryID: "repo-app",
		File:         "src/target.js",
		Name:         "target",
		StartLine:    1,
	}
	graph := applicationCallGraph{
		functions: map[sourceanalysis.FunctionID]struct{}{
			startA: {},
			startB: {},
			target: {},
		},
		edges: map[sourceanalysis.FunctionID][]sourceanalysis.FunctionID{
			startA: {target},
			startB: {target},
		},
	}
	entryA := EntryPoint{
		EntryPointID: "ep-a",
		RepositoryID: startA.RepositoryID,
		Function:     startA.Name,
		File:         startA.File,
		Line:         startA.StartLine,
	}
	entryB := EntryPoint{
		EntryPointID: "ep-b",
		RepositoryID: startB.RepositoryID,
		Function:     startB.Name,
		File:         startB.File,
		Line:         startB.StartLine,
	}

	for _, entryPoints := range [][]EntryPoint{
		{entryB, entryA},
		{entryA, entryB},
	} {
		entryPoint, path, ok := graph.pathTo(entryPoints, target)
		if !ok {
			t.Fatal("expected a path to target")
		}
		if entryPoint.EntryPointID != "ep-a" ||
			len(path) != 2 ||
			path[0].Function != "startA" ||
			path[1].Function != "target" {
			t.Fatalf("non-deterministic path selection: %+v, %+v", entryPoint, path)
		}
	}
}

func TestParameterShadowDoesNotCreateDirectCallEdge(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "src", "index.js")
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o755); err != nil {
		t.Fatal(err)
	}
	source := `import { merge } from "lodash";
export function main(helper) {
  helper();
}
function helper() {
  return merge({}, {});
}
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := sourceanalysis.AnalyzeRepository(
		root, sourceanalysis.RepositoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	graph, err := Produce(
		[]RepositoryInput{{RepositoryID: "repo-app", Result: result}},
		[]OccurrenceInput{fixtureOccurrence()},
		ProduceOptions{
			ScanID:               "scan-shadow",
			Ecosystem:            "npm",
			AnalyzerID:           AnalyzerID,
			ReachabilityAnalysed: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.EntryPoints) != 1 ||
		graph.EntryPoints[0].Function != "main" {
		t.Fatalf("entry points = %+v", graph.EntryPoints)
	}
	observation := requireObservationForSymbol(t, graph, "merge")
	if len(observation.CallSites) != 1 {
		t.Fatalf("merge calls = %+v", observation.CallSites)
	}
	call := observation.CallSites[0]
	if call.Reachability != ReachUnknown ||
		call.EntryPointID != "" || len(call.CallPath) != 0 {
		t.Fatalf("shadowed parameter created a path: %+v", call)
	}
}
