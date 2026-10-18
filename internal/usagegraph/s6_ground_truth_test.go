package usagegraph

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestS6GroundTruth runs in ordinary go test/CI; evidence export is optional.
// Bindings, call multiplicity, excluded calls and declared safety fields are
// checked against the same labels consumed by the Python evaluator.
func TestS6GroundTruth(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "testdata", "fixtures", "usage-ground-truth", "component2-s6-*", "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) < 21 {
		t.Fatalf("missing S6 labels: got %d", len(paths))
	}
	for _, path := range paths {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var labels struct {
				Fixture  string                      `json:"fixture"`
				Expected map[string][]map[string]any `json:"expected"`
			}
			if err := json.Unmarshal(data, &labels); err != nil {
				t.Fatal(err)
			}
			graph := produceS6FixtureGraph(t, labels.Fixture)
			if graph.Analysis.Status != AnalysisComplete {
				t.Fatalf("incomplete graph: %+v", graph.Analysis)
			}
			encoded, err := json.Marshal(graph)
			if err != nil {
				t.Fatal(err)
			}
			var public map[string]any
			if err := json.Unmarshal(encoded, &public); err != nil {
				t.Fatal(err)
			}
			raw := public["observations"].([]any)
			imports := labels.Expected["thirdPartyImports"]
			if len(raw) != len(imports) {
				t.Fatalf("imports: got %d want %d", len(raw), len(imports))
			}
			for _, label := range imports {
				var matched []map[string]any
				for _, item := range raw {
					obs := item.(map[string]any)
					loc := obs["location"].(map[string]any)
					if reflect.DeepEqual([]any{loc["file"], loc["line"], obs["importedSpecifier"], valueOr(obs, "importedSymbol", ""), valueOr(obs, "localAlias", ""), obs["importKind"]}, []any{label["file"], label["line"], label["specifier"], valueOr(label, "imported", ""), valueOr(label, "local", ""), label["kind"]}) {
						matched = append(matched, obs)
					}
				}
				if len(matched) != 1 {
					t.Fatalf("binding must be unique: %+v; matches=%d", label, len(matched))
				}
				obs := matched[0]
				state := valueOr(label, "resolution", "resolved")
				if obs["resolution"] != state {
					t.Errorf("import resolution: got %v want %v", obs["resolution"], state)
				}
				for _, field := range []string{"purl", "computedSpecifier", "unresolvedReason", "evidenceLevel"} {
					if want, ok := label[field]; ok && !reflect.DeepEqual(valueOr(obs, field, ""), want) {
						t.Errorf("%s: got %v want %v", field, obs[field], want)
					}
				}
				want := map[string]int{}
				got := map[string]int{}
				for _, category := range []string{"thirdPartyCalls", "unresolvedCalls"} {
					for _, call := range labels.Expected[category] {
						if !s6CallSelects(call, label) {
							continue
						}
						state := "resolved"
						if category == "unresolvedCalls" {
							state = "unresolved"
						}
						want[s6CallKey(call["file"], call["line"], valueOr(call, "symbol", ""), state)]++
					}
				}
				for _, item := range obs["callSites"].([]any) {
					call := item.(map[string]any)
					state := call["resolution"]
					if obs["resolution"] != "resolved" {
						state = "unresolved"
					}
					got[s6CallKey(call["file"], call["line"], valueOr(call, "calledSymbol", ""), state)]++
					for _, category := range []string{"thirdPartyCalls", "unresolvedCalls", "excludedCalls"} {
						for _, expected := range labels.Expected[category] {
							if !s6CallSelects(expected, label) || expected["file"] != call["file"] || expected["line"] != call["line"] || valueOr(expected, "symbol", "") != valueOr(call, "calledSymbol", "") {
								continue
							}
							if category == "excludedCalls" {
								t.Errorf("excluded call attributed: %+v", expected)
							}
							for _, field := range []string{"reachability", "unresolvedReason"} {
								if value, ok := expected[field]; ok && call[field] != value {
									t.Errorf("call %s: got %v want %v", field, call[field], value)
								}
							}
						}
					}
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("calls for %+v: got %v want %v", label, got, want)
				}
			}
			for _, expected := range labels.Expected["unanalysedOccurrences"] {
				found := false
				for _, item := range graph.UnanalysedOccurrences {
					if item.PURL == expected["purl"] && item.Reason == expected["reason"] {
						found = true
					}
				}
				if !found {
					t.Errorf("missing unanalysed occurrence: %+v", expected)
				}
			}
		})
	}
}

func valueOr(item map[string]any, key string, fallback any) any {
	if value, ok := item[key]; ok {
		return value
	}
	return fallback
}
func s6CallKey(file, line, symbol, state any) string {
	return fmt.Sprintf("%v:%v:%v:%v", file, line, symbol, state)
}
func s6CallSelects(call, imported map[string]any) bool {
	for selector, field := range map[string]string{"importFile": "file", "importLine": "line", "importSpecifier": "specifier", "importLocal": "local", "imported": "imported", "importKind": "kind"} {
		if value, ok := call[selector]; ok && valueOr(imported, field, "") != value {
			return false
		}
	}
	return true
}
