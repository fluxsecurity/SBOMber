package main

import (
	"os"
	"testing"

	treesitter "github.com/tree-sitter/go-tree-sitter"
	javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
)

func t3FindNodeByTypeAndRange(
	node *treesitter.Node,
	nodeType string,
	startByte uint,
	endByte uint,
) *treesitter.Node {
	if node == nil {
		return nil
	}

	if node.Kind() == nodeType &&
		node.StartByte() == startByte &&
		node.EndByte() == endByte {
		return node
	}

	for index := uint(0); index < node.ChildCount(); index++ {
		found := t3FindNodeByTypeAndRange(
			node.Child(index),
			nodeType,
			startByte,
			endByte,
		)

		if found != nil {
			return found
		}
	}

	return nil
}

func t3NormaliseBOMColumns(
	source []byte,
	value t3Range,
) t3Range {
	hasBOM := len(source) >= 3 &&
		source[0] == 0xef &&
		source[1] == 0xbb &&
		source[2] == 0xbf

	if !hasBOM {
		return value
	}

	if value.Line == 1 && value.Column >= 3 {
		value.Column -= 3
	}

	if value.EndLine == 1 && value.EndColumn >= 3 {
		value.EndColumn -= 3
	}

	return value
}

func TestEdgeFixtureLocations(t *testing.T) {
	source, err := os.ReadFile(
		"../../corpus/micro/12-edge.js",
	)
	if err != nil {
		t.Fatalf("read edge fixture: %v", err)
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
		t.Fatal("valid edge fixture contains parser errors")
	}

	cases := []struct {
		name     string
		nodeType string
		expected t3Range
	}{
		{
			name:     "imported local binding",
			nodeType: "identifier",
			expected: t3Range{
				StartByte: 12,
				EndByte:   20,
				Line:      1,
				Column:    9,
				EndLine:   1,
				EndColumn: 17,
			},
		},
		{
			name:     "UTF-8 declared identifier",
			nodeType: "identifier",
			expected: t3Range{
				StartByte: 45,
				EndByte:   50,
				Line:      2,
				Column:    6,
				EndLine:   2,
				EndColumn: 11,
			},
		},
		{
			name:     "call after UTF-8 identifier",
			nodeType: "call_expression",
			expected: t3Range{
				StartByte: 53,
				EndByte:   66,
				Line:      2,
				Column:    14,
				EndLine:   2,
				EndColumn: 27,
			},
		},
		{
			name:     "default export identifier",
			nodeType: "identifier",
			expected: t3Range{
				StartByte: 84,
				EndByte:   89,
				Line:      3,
				Column:    15,
				EndLine:   3,
				EndColumn: 20,
			},
		},
	}

	for _, item := range cases {
		t.Run(
			item.name,
			func(t *testing.T) {
				node := t3FindNodeByTypeAndRange(
					root,
					item.nodeType,
					item.expected.StartByte,
					item.expected.EndByte,
				)

				if node == nil {
					t.Fatalf(
						"node %s at bytes %d-%d was not found",
						item.nodeType,
						item.expected.StartByte,
						item.expected.EndByte,
					)
				}

				raw := t3RangeForNode(node)
				normalised := t3NormaliseBOMColumns(
					source,
					raw,
				)

				t.Logf(
					"raw=%+v normalised=%+v",
					raw,
					normalised,
				)

				if normalised != item.expected {
					t.Fatalf(
						"location mismatch: got %+v, expected %+v",
						normalised,
						item.expected,
					)
				}
			},
		)
	}
}
