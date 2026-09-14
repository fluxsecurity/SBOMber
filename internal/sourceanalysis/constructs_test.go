package sourceanalysis

import (
	"path/filepath"
	"testing"
)

func analyzeCorpusFixture(t *testing.T, name string) Result {
	t.Helper()

	result, err := AnalyzeSource(filepath.Join(
		repositoryRoot(t),
		"spikes",
		"parser-bindings",
		"corpus",
		"micro",
		name,
	))
	if err != nil {
		t.Fatalf("AnalyzeSource(%q): %v", name, err)
	}

	return result
}

func TestRequiredConstructs(t *testing.T) {
	t.Run("namespace import stays resolved", func(t *testing.T) {
		result := analyzeCorpusFixture(t, "03-esm-namespace.js")
		if len(result.Imports) != 1 || result.Imports[0].Kind != "esm_namespace" {
			t.Fatalf("namespace import not recorded correctly: %+v", result.Imports)
		}
		if result.Imports[0].Specifier != "lodash" || result.Imports[0].Local != "_" {
			t.Fatalf("namespace package binding not preserved: %+v", result.Imports[0])
		}
	})

	t.Run("destructured CommonJS preserves alias", func(t *testing.T) {
		result := analyzeCorpusFixture(t, "05-cjs-destructured.js")
		if len(result.Imports) != 2 {
			t.Fatalf("expected two destructured imports, got %+v", result.Imports)
		}
		if result.Imports[1].Kind != "cjs_destructured" || result.Imports[1].Imported != "merge" || result.Imports[1].Local != "mergeDeep" {
			t.Fatalf("CommonJS alias not preserved: %+v", result.Imports[1])
		}
	})

	t.Run("package subpaths stay exact", func(t *testing.T) {
		result := analyzeCorpusFixture(t, "06-subpath.js")
		if len(result.Imports) != 2 || result.Imports[0].Specifier != "lodash/template" || result.Imports[1].Specifier != "@babel/parser/lib/index.js" {
			t.Fatalf("package subpaths not preserved: %+v", result.Imports)
		}
	})

	t.Run("type-only import creates no runtime call", func(t *testing.T) {
		result := analyzeCorpusFixture(t, "08-type-only.ts")
		if len(result.Imports) != 2 || result.Imports[0].Kind != "esm_type_only" || !result.Imports[0].TypeOnly {
			t.Fatalf("type-only import not recorded: %+v", result.Imports)
		}
		for _, call := range result.Calls {
			if call.Callee != nil && *call.Callee == "DebouncedFunc" {
				t.Fatalf("type-only symbol produced runtime-call evidence: %+v", call)
			}
		}
	})

	t.Run("computed dynamic import stays unresolved", func(t *testing.T) {
		result := analyzeCorpusFixture(t, "07-dynamic-import.js")
		if len(result.Imports) != 2 || result.Imports[0].Kind != "dynamic_static_literal" || result.Imports[1].Kind != "dynamic_computed" {
			t.Fatalf("dynamic import kinds not distinguished: %+v", result.Imports)
		}
		if result.Imports[1].Specifier != "NAME" {
			t.Fatalf("computed expression not preserved: %+v", result.Imports[1])
		}
		if len(result.Unresolved) != 1 || result.Unresolved[0].Kind != "computed_dynamic_import" {
			t.Fatalf("computed dynamic import not unresolved: %+v", result.Unresolved)
		}
	})
}
