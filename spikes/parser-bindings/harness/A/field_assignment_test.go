package main

import (
	"testing"

	treesitter "github.com/tree-sitter/go-tree-sitter"
	javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
)

func findNodeByKind(
	node *treesitter.Node,
	kind string,
) *treesitter.Node {
	if node == nil {
		return nil
	}

	if node.Kind() == kind {
		return node
	}

	for i := uint(0); i < node.NamedChildCount(); i++ {
		child := node.NamedChild(i)
		if found := findNodeByKind(child, kind); found != nil {
			return found
		}
	}

	return nil
}

func parseFieldFixture(
	t *testing.T,
	source []byte,
) (*treesitter.Parser, *treesitter.Tree) {
	t.Helper()

	language := treesitter.NewLanguage(javascript.Language())
	if language == nil {
		t.Fatal("javascript language is nil")
	}

	parser := treesitter.NewParser()
	if parser == nil {
		t.Fatal("parser is nil")
	}

	if err := parser.SetLanguage(language); err != nil {
		parser.Close()
		t.Fatalf("set language: %v", err)
	}

	tree := parser.Parse(source, nil)
	if tree == nil {
		parser.Close()
		t.Fatal("parser returned nil tree")
	}

	return parser, tree
}

func requireField(
	t *testing.T,
	node *treesitter.Node,
	field string,
	wantKind string,
) *treesitter.Node {
	t.Helper()

	if node == nil {
		t.Fatalf("cannot read field %q from nil node", field)
	}

	child := node.ChildByFieldName(field)
	if child == nil {
		t.Fatalf(
			"%s has no field %q",
			node.Kind(),
			field,
		)
	}

	if child.Kind() != wantKind {
		t.Fatalf(
			"%s field %q: got kind %q, want %q",
			node.Kind(),
			field,
			child.Kind(),
			wantKind,
		)
	}

	t.Logf(
		"%s.%s -> %s",
		node.Kind(),
		field,
		child.Kind(),
	)

	return child
}

func TestCandidateAFieldAssignments(t *testing.T) {
	source := []byte(`
import { merge as combine } from "lodash";

const fn = () => 1;

module.exports = fn;

obj.method();

function demo() {
	return combine({}, {});
}
`)

	parser, tree := parseFieldFixture(t, source)
	defer parser.Close()
	defer tree.Close()

	root := tree.RootNode()

	t.Run("import_statement_source", func(t *testing.T) {
		node := findNodeByKind(root, "import_statement")
		requireField(t, node, "source", "string")
	})

	t.Run("import_specifier_name_alias", func(t *testing.T) {
		node := findNodeByKind(root, "import_specifier")
		requireField(t, node, "name", "identifier")
		requireField(t, node, "alias", "identifier")
	})

	t.Run("variable_declarator_name_value", func(t *testing.T) {
		node := findNodeByKind(root, "variable_declarator")
		requireField(t, node, "name", "identifier")
		requireField(t, node, "value", "arrow_function")
	})

	t.Run("assignment_left_right", func(t *testing.T) {
		node := findNodeByKind(root, "assignment_expression")
		requireField(t, node, "left", "member_expression")
		requireField(t, node, "right", "identifier")
	})

	t.Run("member_call_function_object_property", func(t *testing.T) {
		var memberCall *treesitter.Node

		var walk func(*treesitter.Node)
		walk = func(node *treesitter.Node) {
			if node == nil || memberCall != nil {
				return
			}

			if node.Kind() == "call_expression" {
				function := node.ChildByFieldName("function")
				if function != nil &&
					function.Kind() == "member_expression" {
					memberCall = node
					return
				}
			}

			for i := uint(0); i < node.NamedChildCount(); i++ {
				walk(node.NamedChild(i))
			}
		}

		walk(root)

		if memberCall == nil {
			t.Fatal("member call not found")
		}

		function := requireField(
			t,
			memberCall,
			"function",
			"member_expression",
		)

		requireField(t, function, "object", "identifier")
		requireField(
			t,
			function,
			"property",
			"property_identifier",
		)
	})

	t.Run("function_declaration_name", func(t *testing.T) {
		node := findNodeByKind(root, "function_declaration")
		requireField(t, node, "name", "identifier")
	})
}
