package usagegraph

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

func analyseUsageFixture(
	t *testing.T,
	name string,
) RepositoryInput {
	t.Helper()

	root := filepath.Join(
		"..",
		"..",
		"testdata",
		"fixtures",
		name,
	)
	result, err := sourceanalysis.AnalyzeRepository(
		root,
		sourceanalysis.RepositoryOptions{},
	)
	if err != nil {
		t.Fatalf("AnalyzeRepository: %v", err)
	}

	return RepositoryInput{
		RepositoryID: "repo-app",
		Result:       result,
	}
}

func TestFrozenReachabilityPath(t *testing.T) {
	repository := analyseUsageFixture(
		t,
		"component2-usage-reachable",
	)
	entryPoints := detectExportedModuleEntryPoints(
		[]RepositoryInput{repository},
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
	entryPoint, path, ok := graph.pathTo(entryPoints, target)
	if !ok {
		t.Fatal("expected a resolved path to handleRequest")
	}
	if entryPoint.Function != "postWelcome" {
		t.Fatalf("entry point = %+v, want postWelcome", entryPoint)
	}

	want := []CallPathStep{
		{Function: "postWelcome", File: "src/index.js", Line: 3},
		{Function: "handleRequest", File: "src/service.js", Line: 3},
	}
	if !reflect.DeepEqual(path, want) {
		t.Fatalf("call path = %+v, want %+v", path, want)
	}
}

func TestFrozenDisconnectedCallHasNoPath(t *testing.T) {
	repository := analyseUsageFixture(
		t,
		"component2-usage-unknown",
	)
	entryPoints := detectExportedModuleEntryPoints(
		[]RepositoryInput{repository},
	)

	graph, err := buildApplicationCallGraph(
		[]RepositoryInput{repository},
	)
	if err != nil {
		t.Fatalf("buildApplicationCallGraph: %v", err)
	}

	target := sourceanalysis.FunctionID{
		RepositoryID: "repo-app",
		File:         "src/orphan.js",
		Name:         "orphanHelper",
		StartLine:    3,
	}
	if _, path, ok := graph.pathTo(entryPoints, target); ok || len(path) != 0 {
		t.Fatalf("disconnected function received path: %+v", path)
	}
}

func TestBareFunctionReferenceCreatesNoEdge(t *testing.T) {
	root := t.TempDir()
	writeTestSource := func(relative, source string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create fixture directory: %v", err)
		}
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}

	writeTestSource(
		"src/index.js",
		`export function postWelcome(input) {
  return input && helper;
}

function helper(input) {
  return input;
}
`,
	)

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

	target := sourceanalysis.FunctionID{
		RepositoryID: "repo-app",
		File:         "src/index.js",
		Name:         "helper",
		StartLine:    5,
	}
	if _, path, ok := graph.pathTo(entryPoints, target); ok || len(path) != 0 {
		t.Fatalf("bare reference created a call-graph path: %+v", path)
	}
}

func TestRelativeCallPathIntoNewSourceExtensions(t *testing.T) {
	for _, extension := range []string{".jsx", ".mts", ".cts"} {
		t.Run(extension, func(t *testing.T) {
			root := t.TempDir()
			src := filepath.Join(root, "src")
			if err := os.MkdirAll(src, 0o755); err != nil {
				t.Fatal(err)
			}
			index := `import { helper } from "./helper";
export function start() { return helper(); }
`
			helper := `import { merge } from "lodash";
export function helper() { return merge({}, {}); }
`
			if err := os.WriteFile(filepath.Join(src, "index.js"),
				[]byte(index), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(src, "helper"+extension),
				[]byte(helper), 0o600); err != nil {
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
					ScanID:               "scan-extension-path",
					Ecosystem:            "npm",
					AnalyzerID:           AnalyzerID,
					ReachabilityAnalysed: true,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			observation := requireObservationForSymbol(t, graph, "merge")
			if len(observation.CallSites) != 1 ||
				observation.CallSites[0].Reachability != Reachable ||
				len(observation.CallSites[0].CallPath) != 2 {
				t.Fatalf("relative path = %+v", observation.CallSites)
			}
		})
	}
}
