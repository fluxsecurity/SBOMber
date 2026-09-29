package usagegraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

func produceSourceTree(t *testing.T, files map[string]string) Graph {
	t.Helper()
	root := t.TempDir()
	for relative, content := range files {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
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
			ScanID:               "scan-import-forms",
			Ecosystem:            "npm",
			AnalyzerID:           AnalyzerID,
			ReachabilityAnalysed: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return graph
}

func assertNoNegativeForLodash(t *testing.T, graph Graph) {
	t.Helper()
	for _, occurrence := range graph.UnanalysedOccurrences {
		if occurrence.OccurrenceID == "occ-lodash" &&
			occurrence.Reason == "not_imported_by_analysed_source" {
			t.Fatalf("lodash is loaded but reported as not imported: %+v", graph)
		}
	}
}

func singleObservation(t *testing.T, graph Graph) Observation {
	t.Helper()
	if len(graph.Observations) != 1 {
		t.Fatalf("observations = %+v", graph.Observations)
	}
	return graph.Observations[0]
}

// Each form used to leave lodash as not_imported_by_analysed_source on a
// complete analysis, which is the one reason that may support
// no_usage_detected.
func TestImportFormsNeverReadAsNotImported(t *testing.T) {
	t.Run("named re-export", func(t *testing.T) {
		graph := produceSourceTree(t, map[string]string{
			"src/utils.js": "export { merge } from 'lodash';\n",
		})
		assertNoNegativeForLodash(t, graph)
		observation := singleObservation(t, graph)
		if observation.ImportKind != "esm_reexport" ||
			observation.Resolution != ImportResolved ||
			observation.OccurrenceID != "occ-lodash" ||
			observation.ImportedSymbol != "merge" ||
			observation.EvidenceLevel != 1 ||
			len(observation.CallSites) != 1 {
			t.Fatalf("re-export = %+v", observation)
		}
		callSite := observation.CallSites[0]
		if callSite.Resolution != CallUnresolved ||
			callSite.UnresolvedReason != "reexport_chain" ||
			callSite.Reachability != ReachUnknown {
			t.Fatalf("re-export call site = %+v", callSite)
		}
	})

	t.Run("side-effect import", func(t *testing.T) {
		graph := produceSourceTree(t, map[string]string{
			"src/setup.js": "import 'lodash';\n",
		})
		assertNoNegativeForLodash(t, graph)
		observation := singleObservation(t, graph)
		if observation.ImportKind != "esm_side_effect" ||
			observation.Resolution != ImportResolved ||
			observation.EvidenceLevel != 1 ||
			len(observation.CallSites) != 0 {
			t.Fatalf("side-effect import = %+v", observation)
		}
	})

	t.Run("computed require", func(t *testing.T) {
		graph := produceSourceTree(t, map[string]string{
			"src/plugins.js": "export function load(name) { return require(name); }\n",
		})
		if len(graph.UnanalysedOccurrences) != 1 ||
			graph.UnanalysedOccurrences[0].Reason != "computed_specifier" {
			t.Fatalf("computed require allowed a negative: %+v",
				graph.UnanalysedOccurrences)
		}
	})

	t.Run("require passed as an argument", func(t *testing.T) {
		graph := produceSourceTree(t, map[string]string{
			"src/wrap.js": "export const api = wrap(require('lodash'));\n",
		})
		assertNoNegativeForLodash(t, graph)
		observation := singleObservation(t, graph)
		if len(observation.CallSites) != 1 ||
			observation.CallSites[0].Resolution != CallUnresolved ||
			observation.CallSites[0].UnresolvedReason != "outside_supported_syntax" {
			t.Fatalf("escaped require = %+v", observation)
		}
	})
}

// Success path: chained and member-bound requires now yield the real
// package symbol and can reach an entry point.
func TestRequireMemberCallsResolveSymbol(t *testing.T) {
	t.Run("chained call is reachable", func(t *testing.T) {
		graph := produceSourceTree(t, map[string]string{
			"src/index.js": "export function handle(x) { return require('lodash').merge({}, x); }\n",
		})
		observation := singleObservation(t, graph)
		if observation.EvidenceLevel != 3 || len(observation.CallSites) != 1 {
			t.Fatalf("chained require = %+v", observation)
		}
		callSite := observation.CallSites[0]
		if callSite.CalledSymbol != "merge" ||
			callSite.Resolution != CallResolved ||
			callSite.Reachability != Reachable ||
			len(callSite.CallPath) != 1 ||
			callSite.CallPath[0].Function != "handle" {
			t.Fatalf("chained call site = %+v", callSite)
		}
	})

	t.Run("directly called require reports default", func(t *testing.T) {
		graph := produceSourceTree(t, map[string]string{
			"src/index.js": "export function main() { return require('lodash')('x'); }\n",
		})
		observation := singleObservation(t, graph)
		if len(observation.CallSites) != 1 {
			t.Fatalf("direct require call = %+v", observation)
		}
		callSite := observation.CallSites[0]
		if callSite.CalledSymbol != "default" ||
			callSite.Resolution != CallResolved ||
			callSite.Reachability != Reachable {
			t.Fatalf("direct require call site = %+v", callSite)
		}
	})

	t.Run("member bound to a name reports the member", func(t *testing.T) {
		graph := produceSourceTree(t, map[string]string{
			"src/util.js": "const merge = require('lodash').merge;\nexport function f(x) { return merge({}, x); }\n",
		})
		observation := singleObservation(t, graph)
		if observation.ImportKind != "cjs_destructured" ||
			len(observation.CallSites) != 1 ||
			observation.CallSites[0].CalledSymbol != "merge" {
			t.Fatalf("member-bound require = %+v", observation)
		}
	})

	t.Run("TypeScript import-equals", func(t *testing.T) {
		graph := produceSourceTree(t, map[string]string{
			"src/util.ts": "import _ = require('lodash');\nexport function f() { return _.merge({}, {}); }\n",
		})
		observation := singleObservation(t, graph)
		if observation.ImportKind != "cjs_require" ||
			len(observation.CallSites) != 1 ||
			observation.CallSites[0].CalledSymbol != "merge" {
			t.Fatalf("import-equals = %+v", observation)
		}
	})
}

// Boundary: a Vue file cannot be parsed, so a complete-looking scan must
// not let its imports vanish.
func TestUnsupportedSourceFormatMakesAnalysisPartial(t *testing.T) {
	graph := produceSourceTree(t, map[string]string{
		"src/main.js": "export function main() { return 1; }\n",
		"src/App.vue": "<script>\nimport _ from 'lodash';\n</script>\n",
	})
	if graph.Analysis.Status != AnalysisPartial ||
		graph.Coverage.FilesSkipped != 1 {
		t.Fatalf("analysis = %+v coverage = %+v", graph.Analysis, graph.Coverage)
	}
	assertNoNegativeForLodash(t, graph)
}

func lodashReachability(t *testing.T, graph Graph) CallSite {
	t.Helper()
	for _, observation := range graph.Observations {
		if observation.OccurrenceID == "occ-lodash" &&
			len(observation.CallSites) == 1 {
			return observation.CallSites[0]
		}
	}
	t.Fatalf("no single lodash call site: %+v", graph.Observations)
	return CallSite{}
}

// A local declaration with the same name as a module function or import
// must not create a direct-call edge.
func TestLocalDeclarationsBlockShadowedEdges(t *testing.T) {
	helper := "import { merge } from 'lodash';\nfunction helper(x) { return merge({}, x); }\n"
	cases := map[string]string{
		"const":        helper + "function other() { return 1; }\nexport function main() { const helper = other; return helper(); }\n",
		"for of":       helper + "export function main(list) { for (const helper of list) { helper(); } }\n",
		"catch":        helper + "export function main() { try { return 1; } catch (helper) { helper(); } }\n",
		"destructured": helper + "export function main(options) { const { helper } = options; return helper(); }\n",
		"nested class": helper + "export function main() { class helper {} return helper(); }\n",
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			graph := produceSourceTree(t, map[string]string{"src/index.js": source})
			callSite := lodashReachability(t, graph)
			if callSite.Reachability != ReachUnknown || len(callSite.CallPath) != 0 {
				t.Fatalf("shadowed name produced a path: %+v", callSite)
			}
		})
	}

	t.Run("import shadowed by a local object", func(t *testing.T) {
		graph := produceSourceTree(t, map[string]string{
			"src/index.js": "import * as svc from './svc.js';\nexport function main() { const svc = { run() { return 1; } }; return svc.run(); }\n",
			"src/svc.js":   "import { merge } from 'lodash';\nexport function run() { return merge({}, {}); }\n",
		})
		callSite := lodashReachability(t, graph)
		if callSite.Reachability != ReachUnknown {
			t.Fatalf("shadowed import produced a path: %+v", callSite)
		}
	})

	// Nested helpers are real functions, not shadows. These resolved before
	// the local-binding check was added and must keep resolving.
	nested := map[string]string{
		"nested function declaration":      "import { merge } from 'lodash';\nexport function main(x) {\n  return helper(x);\n  function helper(y) { return merge({}, y); }\n}\n",
		"nested arrow":                     "import { merge } from 'lodash';\nexport function main(x) {\n  const helper = (y) => merge({}, y);\n  return helper(x);\n}\n",
		"nested named function expression": "import { merge } from 'lodash';\nexport function main(x) {\n  const helper = function helper(y) { return merge({}, y); };\n  return helper(x);\n}\n",
	}
	for name, source := range nested {
		t.Run(name, func(t *testing.T) {
			graph := produceSourceTree(t, map[string]string{"src/index.js": source})
			callSite := lodashReachability(t, graph)
			if callSite.Reachability != Reachable ||
				len(callSite.CallPath) != 2 ||
				callSite.CallPath[1].Function != "helper" {
				t.Fatalf("nested helper lost its path: %+v", callSite)
			}
		})
	}

	// A nested helper with the same name as a module function is ambiguous:
	// no edge, whichever one the call means.
	t.Run("nested helper shadowing a module function", func(t *testing.T) {
		graph := produceSourceTree(t, map[string]string{
			"src/index.js": helper + "export function main(x) {\n  const helper = (y) => y;\n  return helper(x);\n}\n",
		})
		callSite := lodashReachability(t, graph)
		if callSite.Reachability != ReachUnknown {
			t.Fatalf("ambiguous nested helper produced a path: %+v", callSite)
		}
	})

	// An anonymous function expression is not tracked by name, so its
	// binding must still shadow the module function.
	t.Run("anonymous function expression still shadows", func(t *testing.T) {
		graph := produceSourceTree(t, map[string]string{
			"src/index.js": helper + "export function main(x) {\n  const helper = function (y) { return y; };\n  return helper(x);\n}\n",
		})
		callSite := lodashReachability(t, graph)
		if callSite.Reachability != ReachUnknown {
			t.Fatalf("anonymous shadow produced a path: %+v", callSite)
		}
	})

	// Control: without shadowing the same code still resolves, so the check
	// is not simply blocking every edge.
	t.Run("unshadowed control stays reachable", func(t *testing.T) {
		graph := produceSourceTree(t, map[string]string{
			"src/index.js": helper + "export function main() { const value = 1; return helper(value); }\n",
		})
		callSite := lodashReachability(t, graph)
		if callSite.Reachability != Reachable ||
			len(callSite.CallPath) != 2 ||
			callSite.CallPath[1].Function != "helper" {
			t.Fatalf("control lost its path: %+v", callSite)
		}
	})
}

// Boundary: unbound imports on one line must still get distinct IDs, and
// bound imports must keep the identity they had before this change.
func TestUnboundImportsOnOneLineHaveDistinctIDs(t *testing.T) {
	graph := produceSourceTree(t, map[string]string{
		"src/index.js": "export function f(x) { wrap(require('lodash')); return require('lodash').pick(x); }\n",
	})
	if len(graph.Observations) != 2 {
		t.Fatalf("observations = %+v", graph.Observations)
	}
	if graph.Observations[0].ObservationID == graph.Observations[1].ObservationID {
		t.Fatalf("duplicate observation ID %s", graph.Observations[0].ObservationID)
	}

	bound := produceSourceTree(t, map[string]string{
		"src/index.js": "import { merge } from 'lodash';\n",
	})
	want := stableID("obs", "occ-lodash", "repo-app", "src/index.js", "1",
		"merge", "merge", "esm_named")
	if got := singleObservation(t, bound).ObservationID; got != want {
		t.Fatalf("bound observation ID changed: %s, want %s", got, want)
	}
}

func TestEscapedModuleNamesResolveToOccurrence(t *testing.T) {
	for _, test := range []struct {
		name   string
		source string
	}{
		{
			name:   "identity escape",
			source: "import { merge } from 'lod\\ash';\n",
		},
		{
			name:   "Unicode code point escape",
			source: "import { merge } from \"lod\\u{61}sh\";\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			graph := produceSourceTree(t, map[string]string{
				"src/index.js": test.source,
			})
			assertNoNegativeForLodash(t, graph)
			if len(graph.Observations) != 1 ||
				graph.Observations[0].Resolution != ImportResolved ||
				graph.Observations[0].OccurrenceID != "occ-lodash" {
				t.Fatalf("escaped import did not resolve: %+v", graph.Observations)
			}
		})
	}
}

func TestNestedHelperDoesNotEscapeItsScope(t *testing.T) {
	graph := produceSourceTree(t, map[string]string{
		"src/index.js": `import { merge } from 'lodash';
export function main() {
  function inner() {
    const helper = () => merge({}, {});
    return 0;
  }
  return helper();
}
`,
	})
	callSite := lodashReachability(t, graph)
	if callSite.Reachability != ReachUnknown ||
		len(callSite.CallPath) != 0 {
		t.Fatalf("out-of-scope helper gained a path: %+v", callSite)
	}
}

func TestTrackedHelpersInNestedScopesDoNotCreatePaths(t *testing.T) {
	for _, test := range []struct {
		name   string
		source string
	}{
		{
			name: "block scoped arrow",
			source: `import { merge } from 'lodash';
export function main() {
  if (true) {
    const helper = () => merge({}, {});
  }
  return helper();
}
`,
		},
		{
			name: "function declaration inside another helper",
			source: `import { merge } from 'lodash';
export function main() {
  function inner() {
    function helper() { return merge({}, {}); }
  }
  return helper();
}
`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			graph := produceSourceTree(t, map[string]string{
				"src/index.js": test.source,
			})
			callSite := lodashReachability(t, graph)
			if callSite.Reachability != ReachUnknown ||
				len(callSite.CallPath) != 0 {
				t.Fatalf("nested-scope helper gained a path: %+v", callSite)
			}
		})
	}
}
