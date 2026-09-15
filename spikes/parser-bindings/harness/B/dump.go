package main

import (
	"fmt"
	"os"
	"strings"

	gotreesitter "github.com/odvcencio/gotreesitter"
)

func dumpNode(
	node *gotreesitter.Node,
	language *gotreesitter.Language,
	source []byte,
	depth int,
	field string,
) {
	if node == nil {
		return
	}

	nodeType := node.Type(language)
	text := node.Text(source)

	fmt.Printf(
		"%sfield=%q type=%q named=%t bytes=%d-%d text=%q\n",
		strings.Repeat("  ", depth),
		field,
		nodeType,
		node.IsNamed(),
		node.StartByte(),
		node.EndByte(),
		text,
	)

	for index := 0; index < node.ChildCount(); index++ {
		child := node.Child(index)
		childField := node.FieldNameForChild(index, language)

		dumpNode(
			child,
			language,
			source,
			depth+1,
			childField,
		)
	}
}

func runNodeDump(fixturePath string) error {
	source, err := os.ReadFile(fixturePath)
	if err != nil {
		return fmt.Errorf("read fixture: %w", err)
	}

	language, err := languageForFixture(fixturePath)
	if err != nil {
		return err
	}

	parser := gotreesitter.NewParser(language)
	if parser == nil {
		return fmt.Errorf("parser creation returned nil")
	}

	tree, err := parser.Parse(source)
	if err != nil {
		return fmt.Errorf("parse fixture: %w", err)
	}

	if tree == nil {
		return fmt.Errorf("parser returned nil tree")
	}

	defer tree.Release()

	root := tree.RootNode()
	if root == nil {
		return fmt.Errorf("tree returned nil root node")
	}

	dumpNode(root, language, source, 0, "")
	return nil
}
