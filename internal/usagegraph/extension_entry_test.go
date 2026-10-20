package usagegraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

func TestNewSourceExtensionsProduceEntryPoints(t *testing.T) {
	for _, extension := range []string{".jsx", ".mts", ".cts"} {
		t.Run("exported index "+extension, func(t *testing.T) {
			root := t.TempDir()
			src := filepath.Join(root, "src")
			if err := os.MkdirAll(src, 0o755); err != nil {
				t.Fatal(err)
			}
			source := `import { merge } from "lodash";
export function start() { return merge({}, {}); }
`
			if err := os.WriteFile(filepath.Join(src, "index"+extension),
				[]byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := sourceanalysis.AnalyzeRepository(root, sourceanalysis.RepositoryOptions{})
			if err != nil {
				t.Fatal(err)
			}
			graph, err := Produce(
				[]RepositoryInput{{RepositoryID: "repo-app", Result: result}},
				[]OccurrenceInput{fixtureOccurrence()},
				ProduceOptions{
					ScanID: "scan-extended-index", Ecosystem: "npm",
					AnalyzerID: AnalyzerID, ReachabilityAnalysed: true,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(graph.EntryPoints) != 1 ||
				graph.EntryPoints[0].Kind != "exported_module" {
				t.Fatalf("index entry points = %+v", graph.EntryPoints)
			}
			call := requireObservationForSymbol(t, graph, "merge").CallSites[0]
			if call.Reachability != Reachable {
				t.Fatalf("index path = %+v", call)
			}
		})

		t.Run("package main "+extension, func(t *testing.T) {
			root := t.TempDir()
			src := filepath.Join(root, "src")
			if err := os.MkdirAll(src, 0o755); err != nil {
				t.Fatal(err)
			}
			source := `import { merge } from "lodash";
function run() { return merge({}, {}); }
run();
`
			if err := os.WriteFile(filepath.Join(src, "boot"+extension),
				[]byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := sourceanalysis.AnalyzeRepository(root, sourceanalysis.RepositoryOptions{})
			if err != nil {
				t.Fatal(err)
			}
			graph, err := Produce(
				[]RepositoryInput{{
					RepositoryID: "repo-app", Result: result,
					PackageJSON: []byte(`{"main":"src/boot"}`),
				}},
				[]OccurrenceInput{fixtureOccurrence()},
				ProduceOptions{
					ScanID: "scan-extended-main", Ecosystem: "npm",
					AnalyzerID: AnalyzerID, ReachabilityAnalysed: true,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(graph.EntryPoints) != 1 ||
				graph.EntryPoints[0].Kind != "package_main" {
				t.Fatalf("package main entry points = %+v", graph.EntryPoints)
			}
			call := requireObservationForSymbol(t, graph, "merge").CallSites[0]
			if call.Reachability != Reachable || len(call.CallPath) != 2 {
				t.Fatalf("package main path = %+v", call)
			}
		})
	}
}
