package usagegraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

func TestParameterShadowBlocksRelativeNamespaceEdge(t *testing.T) {
	for _, test := range []struct {
		name      string
		parameter string
		reachable bool
	}{
		{name: "unshadowed", parameter: "input", reachable: true},
		{name: "shadowed", parameter: "helpers", reachable: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			src := filepath.Join(root, "src")
			if err := os.MkdirAll(src, 0o755); err != nil {
				t.Fatal(err)
			}
			index := `import * as helpers from "./helper.js";
export function start(` + test.parameter + `) {
  return helpers.callPackage();
}
`
			helper := `import { merge } from "lodash";
export function callPackage() {
  return merge({}, {});
}
`
			if err := os.WriteFile(filepath.Join(src, "index.js"), []byte(index), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(src, "helper.js"), []byte(helper), 0o600); err != nil {
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
					ScanID: "scan-namespace-shadow", Ecosystem: "npm",
					AnalyzerID: AnalyzerID, ReachabilityAnalysed: true,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			observation := requireObservationForSymbol(t, graph, "merge")
			if len(observation.CallSites) != 1 {
				t.Fatalf("merge calls = %+v", observation.CallSites)
			}
			call := observation.CallSites[0]
			if test.reachable {
				if call.Reachability != Reachable || len(call.CallPath) != 2 {
					t.Fatalf("unshadowed path = %+v", call)
				}
			} else if call.Reachability != ReachUnknown ||
				call.EntryPointID != "" || len(call.CallPath) != 0 {
				t.Fatalf("shadowed namespace gained a path: %+v", call)
			}
		})
	}
}
