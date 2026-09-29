package sourceanalysis

import (
	"path/filepath"
	"testing"
)

func requireFunctionsNotExported(
	t *testing.T,
	result Result,
	name string,
) {
	t.Helper()

	found := false
	for _, function := range result.Functions {
		if function.Name != name {
			continue
		}

		found = true
		if function.Exported || len(function.ExportedNames) != 0 {
			t.Fatalf(
				"function %q unexpectedly exported: %+v",
				name,
				function,
			)
		}
	}

	if !found {
		t.Fatalf("function %q not found: %+v", name, result.Functions)
	}
}

func TestCommonJSIdentifierExport(t *testing.T) {
	root := t.TempDir()
	writeTestSource(
		t,
		root,
		"exports.js",
		`function helper() {}
module.exports.member = helper;
`,
	)

	result, err := AnalyzeSource(filepath.Join(root, "exports.js"))
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}

	function := requireFunctionNamed(t, result, "helper")
	if !function.Exported ||
		len(function.ExportedNames) != 1 ||
		function.ExportedNames[0] != "member" {
		t.Fatalf("CommonJS identifier export not resolved: %+v", function)
	}
}

func TestUnresolvedExportBindingsAreNotMarkedExported(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{
			name: "ambiguous local name",
			source: `function helper() {}
function wrapper() {
  function helper() {}
}
export { helper };
`,
		},
		{
			name: "computed CommonJS target",
			source: `function helper() {}
module.exports[name] = helper;
`,
		},
		{
			name: "cross-module re-export",
			source: `function helper() {}
export { helper as remoteHelper } from "./other.js";
`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeTestSource(t, root, "exports.js", test.source)

			result, err := AnalyzeSource(filepath.Join(root, "exports.js"))
			if err != nil {
				t.Fatalf("AnalyzeSource: %v", err)
			}

			requireFunctionsNotExported(t, result, "helper")
		})
	}
}
