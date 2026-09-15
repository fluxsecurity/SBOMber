package main

import (
	"os"
	"testing"

	gotreesitter "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

func hasDirectChildType(
	node *gotreesitter.Node,
	language *gotreesitter.Language,
	expectedType string,
) bool {
	if node == nil {
		return false
	}

	for index := 0; index < node.ChildCount(); index++ {
		child := node.Child(index)
		if child == nil {
			continue
		}

		if child.Type(language) == expectedType {
			return true
		}
	}

	return false
}

func TestTypeOnlyImportIsDistinguishable(t *testing.T) {
	source, err := os.ReadFile(
		"../../corpus/micro/08-type-only.ts",
	)
	if err != nil {
		t.Fatalf("read TypeScript fixture: %v", err)
	}

	language := grammars.TypescriptLanguage()
	if language == nil {
		t.Fatal("TypeScript language factory returned nil")
	}

	parser := gotreesitter.NewParser(language)
	if parser == nil {
		t.Fatal("parser creation returned nil")
	}

	tree, err := parser.Parse(source)
	if err != nil {
		t.Fatalf("parse TypeScript fixture: %v", err)
	}

	if tree == nil {
		t.Fatal("parser returned nil tree")
	}

	defer tree.Release()

	root := tree.RootNode()
	if root == nil {
		t.Fatal("tree returned nil root node")
	}

	var imports []*gotreesitter.Node

	for index := 0; index < root.ChildCount(); index++ {
		child := root.Child(index)
		if child == nil {
			continue
		}

		if child.Type(language) == "import_statement" {
			imports = append(imports, child)
		}
	}

	if len(imports) != 2 {
		t.Fatalf(
			"expected two import statements, got %d",
			len(imports),
		)
	}

	firstIsTypeOnly := hasDirectChildType(
		imports[0],
		language,
		"type",
	)

	secondIsTypeOnly := hasDirectChildType(
		imports[1],
		language,
		"type",
	)

	t.Logf(
		"first import bytes=%d-%d typeOnly=%t text=%q",
		imports[0].StartByte(),
		imports[0].EndByte(),
		firstIsTypeOnly,
		imports[0].Text(source),
	)

	t.Logf(
		"second import bytes=%d-%d typeOnly=%t text=%q",
		imports[1].StartByte(),
		imports[1].EndByte(),
		secondIsTypeOnly,
		imports[1].Text(source),
	)

	if !firstIsTypeOnly {
		t.Fatal("first import was not identified as type-only")
	}

	if secondIsTypeOnly {
		t.Fatal("value import was incorrectly identified as type-only")
	}
}
