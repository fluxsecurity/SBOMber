package main

import (
	"os"
	"testing"

	gotreesitter "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

const t3TargetCall = `require("node:path")`

type t3Range struct {
	StartByte uint32
	EndByte   uint32
	Line      int
	Column    int
	EndLine   int
	EndColumn int
}

func t3RangeForNode(node *gotreesitter.Node) t3Range {
	start := node.StartPoint()
	end := node.EndPoint()

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
	node *gotreesitter.Node,
	language *gotreesitter.Language,
	source []byte,
) bool {
	return node != nil &&
		node.Type(language) == "call_expression" &&
		node.Text(source) == t3TargetCall
}

func t3FindByChildIndex(
	node *gotreesitter.Node,
	language *gotreesitter.Language,
	source []byte,
) *gotreesitter.Node {
	if node == nil {
		return nil
	}

	if t3IsTargetCall(node, language, source) {
		return node
	}

	for index := 0; index < node.ChildCount(); index++ {
		found := t3FindByChildIndex(
			node.Child(index),
			language,
			source,
		)

		if found != nil {
			return found
		}
	}

	return nil
}

func t3FindByNamedChildIndex(
	node *gotreesitter.Node,
	language *gotreesitter.Language,
	source []byte,
) *gotreesitter.Node {
	if node == nil {
		return nil
	}

	if t3IsTargetCall(node, language, source) {
		return node
	}

	for index := 0; index < node.NamedChildCount(); index++ {
		found := t3FindByNamedChildIndex(
			node.NamedChild(index),
			language,
			source,
		)

		if found != nil {
			return found
		}
	}

	return nil
}

func t3FindByCursor(
	root *gotreesitter.Node,
	tree *gotreesitter.Tree,
	language *gotreesitter.Language,
	source []byte,
) (t3Range, bool) {
	cursor := gotreesitter.NewTreeCursor(root, tree)
	if cursor == nil {
		return t3Range{}, false
	}

	for {
		node := cursor.CurrentNode()

		if t3IsTargetCall(node, language, source) {
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

	language := grammars.JavascriptLanguage()
	if language == nil {
		t.Fatal("JavaScript language factory returned nil")
	}

	parser := gotreesitter.NewParser(language)
	if parser == nil {
		t.Fatal("parser creation returned nil")
	}

	tree, err := parser.Parse(source)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	if tree == nil {
		t.Fatal("parser returned nil tree")
	}
	defer tree.Release()

	root := tree.RootNode()
	if root == nil {
		t.Fatal("tree returned nil root")
	}

	if root.HasError() {
		t.Fatal("valid fixture contains parser errors")
	}

	childNode := t3FindByChildIndex(
		root,
		language,
		source,
	)
	if childNode == nil {
		t.Fatalf(
			"direct Child traversal did not find %q",
			t3TargetCall,
		)
	}

	namedNode := t3FindByNamedChildIndex(
		root,
		language,
		source,
	)
	if namedNode == nil {
		t.Fatalf(
			"NamedChild traversal did not find %q",
			t3TargetCall,
		)
	}

	cursorRange, ok := t3FindByCursor(
		root,
		tree,
		language,
		source,
	)
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
