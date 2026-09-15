package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	gotreesitter "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

const t3EdgeExpectedSHA = "5ede488bbef4d6e50ccf5210cdfcc876ef66cb603928739579f5e18450875eac"

func t3FindNodeByTypeAndRange(
	node *gotreesitter.Node,
	language *gotreesitter.Language,
	nodeType string,
	startByte uint32,
	endByte uint32,
) *gotreesitter.Node {
	if node == nil {
		return nil
	}

	if node.Type(language) == nodeType &&
		node.StartByte() == startByte &&
		node.EndByte() == endByte {
		return node
	}

	for index := 0; index < node.ChildCount(); index++ {
		found := t3FindNodeByTypeAndRange(
			node.Child(index),
			language,
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

func TestEdgeFixtureChecksum(t *testing.T) {
	source, err := os.ReadFile(
		"../../corpus/micro/12-edge.js",
	)
	if err != nil {
		t.Fatalf("read edge fixture: %v", err)
	}

	sum := sha256.Sum256(source)
	actual := hex.EncodeToString(sum[:])

	t.Logf(
		"edge fixture bytes=%d sha256=%s",
		len(source),
		actual,
	)

	if actual != t3EdgeExpectedSHA {
		t.Fatalf(
			"edge fixture checksum mismatch: got %s, expected %s",
			actual,
			t3EdgeExpectedSHA,
		)
	}
}

func TestEdgeFixtureLocations(t *testing.T) {
	source, err := os.ReadFile(
		"../../corpus/micro/12-edge.js",
	)
	if err != nil {
		t.Fatalf("read edge fixture: %v", err)
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
		t.Fatalf("parse edge fixture: %v", err)
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
					language,
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
