package usagegraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

func produceWithAliases(t *testing.T, files map[string]string, aliases []PathAlias) Graph {
	t.Helper()
	root := t.TempDir()
	for relative, content := range files {
		target := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := sourceanalysis.AnalyzeRepository(root, sourceanalysis.RepositoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	graph, err := Produce(
		[]RepositoryInput{{RepositoryID: "repo-app", Result: result, PathAliases: aliases}},
		[]OccurrenceInput{fixtureOccurrence()},
		ProduceOptions{ScanID: "scan-alias", Ecosystem: "npm", AnalyzerID: AnalyzerID, ReachabilityAnalysed: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	return graph
}

func TestDynamicImportsResolveSymbolsAndEdges(t *testing.T) {
	t.Run("named dynamic import reports the export", func(t *testing.T) {
		graph := produceSourceTree(t, map[string]string{
			"src/index.js": "export async function main(x) { const { merge } = await import('lodash'); return merge({}, x); }\n",
		})
		callSite := lodashReachability(t, graph)
		if callSite.CalledSymbol != "merge" || callSite.Reachability != Reachable {
			t.Fatalf("call site = %+v", callSite)
		}
	})

	t.Run("awaited relative module is followed", func(t *testing.T) {
		graph := produceSourceTree(t, map[string]string{
			"src/index.js": "export async function main() { const svc = await import('./svc.js'); return svc.run(); }\n",
			"src/svc.js":   "import { merge } from 'lodash';\nexport function run() { return merge({}, {}); }\n",
		})
		callSite := lodashReachability(t, graph)
		if callSite.Reachability != Reachable || len(callSite.CallPath) != 2 ||
			callSite.CallPath[1].Function != "run" {
			t.Fatalf("call site = %+v", callSite)
		}
	})

	t.Run("binding is not visible in another function", func(t *testing.T) {
		graph := produceSourceTree(t, map[string]string{
			"src/index.js": "async function load() { const svc = await import('./svc.js'); return svc; }\n" +
				"export function main(svcLike) { return svc.run(); }\n",
			"src/svc.js": "import { merge } from 'lodash';\nexport function run() { return merge({}, {}); }\n",
		})
		callSite := lodashReachability(t, graph)
		if callSite.Reachability != ReachUnknown {
			t.Fatalf("out-of-scope dynamic binding produced a path: %+v", callSite)
		}
	})

	t.Run("then callback keeps the package non-negative", func(t *testing.T) {
		graph := produceSourceTree(t, map[string]string{
			"src/index.js": "import('lodash').then((m) => m.merge({}, {}));\n",
		})
		assertNoNegativeForLodash(t, graph)
		observation := singleObservation(t, graph)
		if len(observation.CallSites) != 1 ||
			observation.CallSites[0].UnresolvedReason != "outside_supported_syntax" {
			t.Fatalf("observation = %+v", observation)
		}
	})
}

func TestComputedImportDetailNamesTheLine(t *testing.T) {
	graph := produceSourceTree(t, map[string]string{
		"scripts/build.mjs": "export async function load(name) { return import(name); }\n",
	})
	if len(graph.UnanalysedOccurrences) != 1 ||
		graph.UnanalysedOccurrences[0].Reason != "computed_specifier" ||
		graph.UnanalysedOccurrences[0].Detail != "computed import at scripts/build.mjs:1 could load this package" {
		t.Fatalf("unanalysed = %+v", graph.UnanalysedOccurrences)
	}
}

func TestParseTSConfigPaths(t *testing.T) {
	aliases, err := ParseTSConfigPaths([]byte(`{
  // comments and trailing commas are allowed in tsconfig
  "compilerOptions": {
    "baseUrl": "./src", /* block comment */
    "paths": {
      "@app/*": ["./*", "generated/*",],
      "config": ["./config/index"],
      "bad/*/*": ["./x"],
      "escape/*": ["../../outside/*"],
      "url": ["https://example.com/*"],
    },
  },
}`))
	if err != nil {
		t.Fatal(err)
	}
	byPattern := map[string][]string{}
	for _, alias := range aliases {
		byPattern[alias.Pattern] = alias.Targets
	}
	if strings.Join(byPattern["@app/*"], ",") != "src/*,src/generated/*" ||
		strings.Join(byPattern["config"], ",") != "src/config/index" {
		t.Fatalf("aliases = %v", byPattern)
	}
	if _, found := byPattern["bad/*/*"]; found {
		t.Fatal("pattern with two wildcards accepted")
	}
	if _, found := byPattern["escape/*"]; found {
		t.Fatal("target outside the repository accepted")
	}

	if _, err := ParseTSConfigPaths([]byte("{ not json")); err == nil {
		t.Fatal("malformed tsconfig accepted")
	}

	paths, ok := matchPathAlias(aliases, "@app/models/user")
	if !ok || strings.Join(paths, ",") != "src/models/user,src/generated/models/user" {
		t.Fatalf("match = %v %v", paths, ok)
	}
	if paths, ok := matchPathAlias(aliases, "config"); !ok || paths[0] != "src/config/index" {
		t.Fatalf("exact match = %v %v", paths, ok)
	}
	if _, ok := matchPathAlias(aliases, "lodash"); ok {
		t.Fatal("unrelated specifier matched")
	}
}

func TestPathAliasesAreApplicationCode(t *testing.T) {
	aliases := []PathAlias{{Pattern: "@app/*", Targets: []string{"src/*"}}}

	t.Run("alias import is not a package and is followed", func(t *testing.T) {
		graph := produceWithAliases(t, map[string]string{
			"src/index.ts":        "import { handle } from '@app/services/api';\nexport function main() { return handle(); }\n",
			"src/services/api.ts": "import { merge } from 'lodash';\nexport function handle() { return merge({}, {}); }\n",
		}, aliases)
		for _, observation := range graph.Observations {
			if observation.ImportedSpecifier == "@app/services/api" {
				t.Fatalf("alias import reported as a package: %+v", observation)
			}
		}
		callSite := lodashReachability(t, graph)
		if callSite.Reachability != Reachable || len(callSite.CallPath) != 2 ||
			callSite.CallPath[1].Function != "handle" {
			t.Fatalf("alias edge not followed: %+v", callSite)
		}
	})

	// Safety: an alias that matches an inventory package never hides it.
	t.Run("alias cannot hide a real package", func(t *testing.T) {
		graph := produceWithAliases(t, map[string]string{
			"src/index.ts":         "import { merge } from 'lodash';\nexport function main() { return merge({}, {}); }\n",
			"src/vendor/lodash.ts": "export function merge() { return 1; }\n",
		}, []PathAlias{{Pattern: "lodash", Targets: []string{"src/vendor/lodash"}}})
		assertNoNegativeForLodash(t, graph)
		if singleObservation(t, graph).OccurrenceID != "occ-lodash" {
			t.Fatalf("real package hidden by alias: %+v", graph.Observations)
		}
	})

	t.Run("ambiguous alias targets add no edge", func(t *testing.T) {
		graph := produceWithAliases(t, map[string]string{
			"src/index.ts": "import { handle } from '@app/api';\nexport function main() { return handle(); }\n",
			"src/api.ts":   "import { merge } from 'lodash';\nexport function handle() { return merge({}, {}); }\n",
			"lib/api.ts":   "export function handle() { return 1; }\n",
		}, []PathAlias{{Pattern: "@app/*", Targets: []string{"src/*", "lib/*"}}})
		callSite := lodashReachability(t, graph)
		if callSite.Reachability != ReachUnknown {
			t.Fatalf("ambiguous alias produced a path: %+v", callSite)
		}
	})
}

func TestAwaitedDynamicImportRespectsBlockScope(t *testing.T) {
	for _, test := range []struct {
		name string
		main string
		want string
	}{
		{
			name: "call inside declaring block",
			main: `export async function main(flag) {
  if (flag) {
    const svc = await import('./svc.js');
    return svc.run();
  }
}
`,
			want: Reachable,
		},
		{
			name: "call outside declaring block",
			main: `export async function main(flag) {
  if (flag) {
    const svc = await import('./svc.js');
  }
  return svc.run();
}
`,
			want: ReachUnknown,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			graph := produceSourceTree(t, map[string]string{
				"src/index.js": test.main,
				"src/svc.js": `import { merge } from 'lodash';
export function run() { return merge({}, {}); }
`,
			})
			callSite := lodashReachability(t, graph)
			if callSite.Reachability != test.want {
				t.Fatalf("reachability = %q, want %q: %+v",
					callSite.Reachability, test.want, callSite)
			}
		})
	}
}

func TestMissingAliasTargetCannotSupportNegative(t *testing.T) {
	graph := produceWithAliases(t, map[string]string{
		"src/index.ts": "import { handle } from '@app/missing';\nexport function main() { return handle(); }\n",
	}, []PathAlias{{Pattern: "@app/*", Targets: []string{"src/*"}}})

	for _, occurrence := range graph.UnanalysedOccurrences {
		if occurrence.OccurrenceID == "occ-lodash" &&
			occurrence.Reason == "not_imported_by_analysed_source" {
			t.Fatalf("missing alias target allowed a negative: %+v", occurrence)
		}
	}
}
