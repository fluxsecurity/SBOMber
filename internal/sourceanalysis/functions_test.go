package sourceanalysis

import (
	"path/filepath"
	"testing"
)

func requireFunctionNamed(
	t *testing.T,
	result Result,
	name string,
) Function {
	t.Helper()

	for _, function := range result.Functions {
		if function.Name == name {
			return function
		}
	}

	t.Fatalf("function %q not found: %+v", name, result.Functions)
	return Function{}
}

func requireCallNamedAtLine(
	t *testing.T,
	result Result,
	name string,
	line int,
) Call {
	t.Helper()

	for _, call := range result.Calls {
		if call.Callee != nil &&
			*call.Callee == name &&
			call.Line == line {
			return call
		}
	}

	t.Fatalf("call %s at line %d not found: %+v", name, line, result.Calls)
	return Call{}
}

func TestFunctionRangesAndEnclosingFunction(t *testing.T) {
	root := t.TempDir()
	writeTestSource(
		t,
		root,
		"nested.js",
		`function outer(input) {
  const inner = (value) => {
    return merge({}, value);
  };
  return inner(input);
}

merge({}, {});

const helper = function namedHelper(value) {
  return value;
};
`,
	)

	result, err := AnalyzeSource(filepath.Join(root, "nested.js"))
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}

	for name, wantEndLine := range map[string]int{
		"outer":       6,
		"inner":       4,
		"namedHelper": 12,
	} {
		function := requireFunctionNamed(t, result, name)
		if function.EndLine != wantEndLine {
			t.Fatalf(
				"%s end line = %d, want %d: %+v",
				name,
				function.EndLine,
				wantEndLine,
				function,
			)
		}
		if function.EndLine < function.Line ||
			(function.EndLine == function.Line &&
				function.EndColumn <= function.Column) {
			t.Fatalf("%s has invalid range: %+v", name, function)
		}
	}

	nestedCall := requireCallNamedAtLine(t, result, "merge", 3)
	nestedFunction, ok := EnclosingFunction(result.Functions, nestedCall)
	if !ok || nestedFunction.Name != "inner" {
		t.Fatalf("nested call owner = %+v, found = %v", nestedFunction, ok)
	}

	outerCall := requireCallNamedAtLine(t, result, "inner", 5)
	outerFunction, ok := EnclosingFunction(result.Functions, outerCall)
	if !ok || outerFunction.Name != "outer" {
		t.Fatalf("outer call owner = %+v, found = %v", outerFunction, ok)
	}

	topLevelCall := requireCallNamedAtLine(t, result, "merge", 8)
	if function, ok := EnclosingFunction(result.Functions, topLevelCall); ok {
		t.Fatalf("top-level call was assigned to %+v", function)
	}
}
