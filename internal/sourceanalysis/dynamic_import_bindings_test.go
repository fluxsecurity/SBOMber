package sourceanalysis

import (
	"os"
	"path/filepath"
	"testing"

	treesitter "github.com/tree-sitter/go-tree-sitter"
)

// Only an awaited import() yields the module. Everything else must either
// bind nothing (side effect) or carry an unresolved use.
func TestDynamicImportBindings(t *testing.T) {
	cases := []struct {
		name   string
		source string
		want   []wantImport
	}{
		{"awaited namespace", "export async function f() { const m = await import('lodash'); return m.merge(); }\n",
			[]wantImport{{specifier: "lodash", kind: "dynamic_static_literal", local: "m", imported: "*"}}},
		{"awaited destructuring with default key", "async function f() { const { default: run, merge, pick: p } = await import('lodash'); }\n",
			[]wantImport{
				// Sorted by local name: imports share one line and column.
				{specifier: "lodash", kind: "dynamic_static_literal", local: "merge", imported: "merge"},
				{specifier: "lodash", kind: "dynamic_static_literal", local: "p", imported: "pick"},
				{specifier: "lodash", kind: "dynamic_static_literal", local: "run", imported: "default"},
			}},
		{"awaited assignment", "let m;\nasync function f() { m = await import('lodash'); }\n",
			[]wantImport{{specifier: "lodash", kind: "dynamic_static_literal", local: "m", imported: "*"}}},
		{"awaited side effect", "async function f() { await import('lodash'); }\n",
			[]wantImport{{specifier: "lodash", kind: "dynamic_static_literal", imported: "*"}}},
		{"promise kept in a variable", "const pending = import('lodash');\n",
			[]wantImport{{specifier: "lodash", kind: "dynamic_static_literal", imported: "*", unresolvedUse: "outside_supported_syntax"}}},
		{"then callback", "import('lodash').then((m) => m.merge());\n",
			[]wantImport{{specifier: "lodash", kind: "dynamic_static_literal", imported: "*", unresolvedUse: "outside_supported_syntax"}}},
		{"nested value is not bound", "async function f() { const x = wrap(await import('lodash')); }\n",
			[]wantImport{{specifier: "lodash", kind: "dynamic_static_literal", imported: "*", unresolvedUse: "outside_supported_syntax"}}},
		{"destructuring with a default value", "async function f() { const { merge, pick = null } = await import('lodash'); }\n",
			[]wantImport{{specifier: "lodash", kind: "dynamic_static_literal", local: "merge", imported: "merge", unresolvedUse: "outside_supported_syntax"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := analyzeSnippet(t, "a.js", tc.source)
			if len(result.Imports) != len(tc.want) {
				t.Fatalf("imports = %+v, want %d", result.Imports, len(tc.want))
			}
			for index, want := range tc.want {
				got := result.Imports[index]
				if got.Specifier != want.specifier || got.Kind != want.kind ||
					got.Local != want.local || got.Imported != want.imported ||
					got.UnresolvedUse != want.unresolvedUse {
					t.Fatalf("import %d = %+v, want %+v", index, got, want)
				}
			}
		})
	}
}

// The dynamic import binding is not a shadow; other locals still are.
func TestDynamicImportBindingIsNotALocalShadow(t *testing.T) {
	result := analyzeSnippet(t, "a.js",
		"async function app() { const server = await import('./server'); const other = 1; await server.start(); }\n")
	for _, function := range result.Functions {
		if function.Name != "app" {
			continue
		}
		if hasString(function.LocalBindings, "server") || !hasString(function.LocalBindings, "other") {
			t.Fatalf("local bindings = %v", function.LocalBindings)
		}
		return
	}
	t.Fatal("function app not found")
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// The cursor-based walk must return exactly what the recursive walk it
// replaced returned, in the same order, on every labelled corpus file.
func TestCollectNodesByTypeMatchesRecursiveWalk(t *testing.T) {
	var recursive func(node *treesitter.Node, kind string) []*treesitter.Node
	recursive = func(node *treesitter.Node, kind string) []*treesitter.Node {
		nodes := []*treesitter.Node{}
		if node.Kind() == kind {
			nodes = append(nodes, node)
		}
		for index := uint(0); index < node.ChildCount(); index++ {
			nodes = append(nodes, recursive(node.Child(index), kind)...)
		}
		return nodes
	}

	paths, err := filepath.Glob(filepath.Join("..", "..", "spikes", "parser-bindings", "corpus", "micro", "*"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("corpus not found: %v", err)
	}
	kinds := []string{"identifier", "call_expression", "arrow_function", "string", "variable_declarator"}
	for _, sourcePath := range paths {
		language, err := treeSitterLanguageForPath(sourcePath)
		if err != nil {
			continue
		}
		source, err := os.ReadFile(sourcePath)
		if err != nil {
			t.Fatal(err)
		}
		parser := treesitter.NewParser()
		if err := parser.SetLanguage(language); err != nil {
			t.Fatal(err)
		}
		tree := parser.Parse(source, nil)
		root := tree.RootNode()
		for _, kind := range kinds {
			want := recursive(root, kind)
			got := collectNodesByType(root, kind)
			if len(got) != len(want) {
				t.Fatalf("%s %s: %d nodes, want %d", sourcePath, kind, len(got), len(want))
			}
			for index := range want {
				if got[index].StartByte() != want[index].StartByte() || got[index].EndByte() != want[index].EndByte() {
					t.Fatalf("%s %s: node %d differs", sourcePath, kind, index)
				}
			}
		}
		tree.Close()
		parser.Close()
	}
}

func TestCompiledUsageQueryIsCachedPerLanguage(t *testing.T) {
	first, err := compiledUsageQuery("typescript")
	if err != nil {
		t.Fatal(err)
	}
	second, err := compiledUsageQuery("typescript")
	if err != nil {
		t.Fatal(err)
	}
	other, err := compiledUsageQuery("javascript")
	if err != nil {
		t.Fatal(err)
	}
	if first.query != second.query || first.query == other.query {
		t.Fatal("query cache does not hold one compiled query per language")
	}
	if _, err := compiledUsageQuery("cobol"); err == nil {
		t.Fatal("unknown language accepted")
	}
}
