package main

import (
	"os"
	"testing"

	treesitter "github.com/tree-sitter/go-tree-sitter"
	javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
)

const t3TargetCall = `require("node:path")`

type t3Range struct {
	StartByte uint
	EndByte   uint
	Line      int
	Column    int
	EndLine   int
	EndColumn int
}

func t3RangeForNode(node *treesitter.Node) t3Range {
	start := node.StartPosition()
	end := node.EndPosition()

	return t3Range{
		StartByte: node.StartByte(),
		EndByte:   node.EndByte(),
		Line:      int(start.Row) + 1,
		Column:    int(start.Column),
		EndLine:   int(end.Row) + 1,
		EndColumn: int(end.Column),
	}
}

func t3IsTargetCall(
	node *treesitter.Node,
	source []byte,
) bool {
	return node != nil &&
		node.Kind() == "call_expression" &&
		node.Utf8Text(source) == t3TargetCall
}

func t3FindByChildIndex(
	node *treesitter.Node,
	source []byte,
) *treesitter.Node {
	if node == nil {
		return nil
	}

	if t3IsTargetCall(node, source) {
		return node
	}

	for index := uint(0); index < node.ChildCount(); index++ {
		found := t3FindByChildIndex(
			node.Child(index),
			source,
		)

		if found != nil {
			return found
		}
	}

	return nil
}

func t3FindByNamedChildIndex(
	node *treesitter.Node,
	source []byte,
) *treesitter.Node {
	if node == nil {
		return nil
	}

	if t3IsTargetCall(node, source) {
		return node
	}

	for index := uint(0); index < node.NamedChildCount(); index++ {
		found := t3FindByNamedChildIndex(
			node.NamedChild(index),
			source,
		)

		if found != nil {
			return found
		}
	}

	return nil
}

func t3FindByCursor(
	root *treesitter.Node,
	source []byte,
) (t3Range, bool) {
	cursor := root.Walk()
	if cursor == nil {
		return t3Range{}, false
	}
	defer cursor.Close()

	for {
		node := cursor.Node()

		if t3IsTargetCall(node, source) {
			return t3RangeForNode(node), true
		}

		if cursor.GotoFirstChild() {
			continue
		}

		for {
			if cursor.GotoNextSibling() {
				break
			}

			if !cursor.GotoParent() {
				return t3Range{}, false
			}
		}
	}
}

func TestTraversalAgreement(t *testing.T) {
	source, err := os.ReadFile(
		"../../corpus/micro/04-cjs-require.js",
	)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	language := treesitter.NewLanguage(
		javascript.Language(),
	)
	if language == nil {
		t.Fatal("JavaScript language factory returned nil")
	}

	parser := treesitter.NewParser()
	if parser == nil {
		t.Fatal("parser creation returned nil")
	}
	defer parser.Close()

	if err := parser.SetLanguage(language); err != nil {
		t.Fatalf("set parser language: %v", err)
	}

	tree := parser.Parse(source, nil)
	if tree == nil {
		t.Fatal("parser returned nil tree")
	}
	defer tree.Close()

	root := tree.RootNode()

	if root.HasError() {
		t.Fatal("valid fixture contains parser errors")
	}

	childNode := t3FindByChildIndex(root, source)
	if childNode == nil {
		t.Fatalf(
			"direct Child traversal did not find %q",
			t3TargetCall,
		)
	}

	namedNode := t3FindByNamedChildIndex(root, source)
	if namedNode == nil {
		t.Fatalf(
			"NamedChild traversal did not find %q",
			t3TargetCall,
		)
	}

	cursorRange, ok := t3FindByCursor(root, source)
	if !ok {
		t.Fatalf(
			"tree cursor traversal did not find %q",
			t3TargetCall,
		)
	}

	childRange := t3RangeForNode(childNode)
	namedRange := t3RangeForNode(namedNode)

	expected := t3Range{
		StartByte: 42,
		EndByte:   62,
		Line:      2,
		Column:    13,
		EndLine:   2,
		EndColumn: 33,
	}

	results := []struct {
		name  string
		value t3Range
	}{
		{name: "Child", value: childRange},
		{name: "NamedChild", value: namedRange},
		{name: "TreeCursor", value: cursorRange},
	}

	for _, result := range results {
		t.Logf(
			"%s: bytes=%d-%d line=%d column=%d endLine=%d endColumn=%d",
			result.name,
			result.value.StartByte,
			result.value.EndByte,
			result.value.Line,
			result.value.Column,
			result.value.EndLine,
			result.value.EndColumn,
		)

		if result.value != expected {
			t.Errorf(
				"%s range mismatch: got %+v, expected %+v",
				result.name,
				result.value,
				expected,
			)
		}
	}

	if childRange != namedRange ||
		childRange != cursorRange {
		t.Fatalf(
			"traversal disagreement: Child=%+v NamedChild=%+v TreeCursor=%+v",
			childRange,
			namedRange,
			cursorRange,
		)
	}
}
