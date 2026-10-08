package usagegraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

func TestNodeNextJsSpecifierResolvesUniqueTypeScriptFile(t *testing.T) {
	for _, test := range []struct {
		name       string
		extensions []string
		reachable  bool
	}{
		{name: "ts", extensions: []string{".ts"}, reachable: true},
		{name: "tsx", extensions: []string{".tsx"}, reachable: true},
		{name: "mts", extensions: []string{".mts"}, reachable: true},
		{name: "ambiguous", extensions: []string{".ts", ".mts"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			src := filepath.Join(root, "src")
			if err := os.MkdirAll(src, 0o755); err != nil {
				t.Fatal(err)
			}
			index := `import { helper } from "./service.js";
export function start() { return helper(); }
`
			if err := os.WriteFile(filepath.Join(src, "index.ts"), []byte(index), 0o600); err != nil {
				t.Fatal(err)
			}
			service := `import { merge } from "lodash";
export function helper() { return merge({}, {}); }
`
			for _, extension := range test.extensions {
				if err := os.WriteFile(filepath.Join(src, "service"+extension),
					[]byte(service), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			result, err := sourceanalysis.AnalyzeRepository(root, sourceanalysis.RepositoryOptions{})
			if err != nil {
				t.Fatal(err)
			}
			graph, err := Produce(
				[]RepositoryInput{{RepositoryID: "repo-app", Result: result}},
				[]OccurrenceInput{fixtureOccurrence()},
				ProduceOptions{
					ScanID: "scan-nodenext", Ecosystem: "npm",
					AnalyzerID: AnalyzerID, ReachabilityAnalysed: true,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			observation := requireObservationForSymbol(t, graph, "merge")
			for _, call := range observation.CallSites {
				if test.reachable {
					if call.Reachability != Reachable || len(call.CallPath) != 2 {
						t.Fatalf("missing NodeNext path: %+v", call)
					}
				} else if call.Reachability != ReachUnknown ||
					call.EntryPointID != "" || len(call.CallPath) != 0 {
					t.Fatalf("ambiguous target gained a path: %+v", call)
				}
			}
		})
	}
}
