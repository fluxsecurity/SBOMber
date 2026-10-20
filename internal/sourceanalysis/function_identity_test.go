package sourceanalysis

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestFunctionIDDistinguishesDuplicateNames(t *testing.T) {
	first := FunctionID{
		RepositoryID: "repo-a",
		File:         "src/first.js",
		Name:         "handleRequest",
		StartLine:    1,
	}
	secondFile := FunctionID{
		RepositoryID: "repo-a",
		File:         "src/second.js",
		Name:         "handleRequest",
		StartLine:    1,
	}
	secondRepository := FunctionID{
		RepositoryID: "repo-b",
		File:         "src/first.js",
		Name:         "handleRequest",
		StartLine:    1,
	}
	secondLine := FunctionID{
		RepositoryID: "repo-a",
		File:         "src/first.js",
		Name:         "handleRequest",
		StartLine:    9,
	}

	for label, candidate := range map[string]FunctionID{
		"different file":       secondFile,
		"different repository": secondRepository,
		"different start line": secondLine,
	} {
		if candidate == first {
			t.Fatalf("%s did not change function identity: %+v", label, candidate)
		}
	}
}

func TestFunctionExportedNames(t *testing.T) {
	root := t.TempDir()
	writeTestSource(
		t,
		root,
		"exports.js",
		`export function named() {}

export default function primary() {}

export const arrow = () => {};

module.exports = function commonDefault() {};

module.exports.member = function commonMember() {};

const helper = () => {};
export { helper as publicHelper };
export default helper;
`,
	)

	result, err := AnalyzeSource(filepath.Join(root, "exports.js"))
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}

	want := []struct {
		name          string
		exportedNames []string
	}{
		{name: "named", exportedNames: []string{"named"}},
		{name: "primary", exportedNames: []string{"default"}},
		{name: "arrow", exportedNames: []string{"arrow"}},
		{name: "commonDefault", exportedNames: []string{"default"}},
		{name: "commonMember", exportedNames: []string{"member"}},
		{name: "helper", exportedNames: []string{"default", "publicHelper"}},
	}

	for _, expected := range want {
		function := requireFunctionNamed(t, result, expected.name)
		if !function.Exported {
			t.Fatalf("function %q was not marked exported: %+v", expected.name, function)
		}
		if !reflect.DeepEqual(function.ExportedNames, expected.exportedNames) {
			t.Fatalf(
				"%s exported names = %v, want %v",
				expected.name,
				function.ExportedNames,
				expected.exportedNames,
			)
		}
	}
}
