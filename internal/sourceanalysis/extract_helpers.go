package sourceanalysis

import (
	"bytes"
	"fmt"
	"strings"

	treesitter "github.com/tree-sitter/go-tree-sitter"
)

func nodeLocation(
	source []byte,
	node *treesitter.Node,
) (int, int) {
	point := node.StartPosition()
	column := int(point.Column)

	// Keep Candidate B's BOM-normalisation convention.
	if point.Row == 0 &&
		bytes.HasPrefix(source, []byte{0xef, 0xbb, 0xbf}) &&
		column >= 3 {
		column -= 3
	}

	return int(point.Row) + 1, column
}

func stringPointer(value string) *string {
	return &value
}

// unquoteJavaScriptString strips a JavaScript string literal's quotes and
// resolves its backslash escapes.
//
// This cannot delegate to strconv.Unquote: Go's unquoter treats a
// single-quoted value as a rune literal, which requires exactly one
// character and therefore fails on any import specifier longer than one
// character — e.g. 'lodash'. Single-quoted specifiers are extremely common
// (Prettier's default, the Standard and Airbnb style guides all use them),
// so this previously made import extraction fail on any file using them.
func unquoteJavaScriptString(value string) (string, error) {
	if len(value) < 2 {
		return "", fmt.Errorf(
			"invalid JavaScript string %q",
			value,
		)
	}

	quote := value[0]
	if (quote != '\'' && quote != '"' && quote != '`') || value[len(value)-1] != quote {
		return "", fmt.Errorf(
			"invalid JavaScript string %q",
			value,
		)
	}

	body := value[1 : len(value)-1]

	var out strings.Builder
	out.Grow(len(body))

	for i := 0; i < len(body); i++ {
		c := body[i]
		if c != '\\' || i == len(body)-1 {
			out.WriteByte(c)
			continue
		}

		i++
		switch next := body[i]; next {
		case 'n':
			out.WriteByte('\n')
		case 't':
			out.WriteByte('\t')
		case 'r':
			out.WriteByte('\r')
		case '\n':
			// Line continuation: an escaped newline contributes nothing.
		default:
			// Covers \', \", \`, \\ and any other escaped character —
			// JavaScript treats an unrecognized escape as the literal
			// character that follows the backslash.
			out.WriteByte(next)
		}
	}

	return out.String(), nil
}

func collectNodesByType(
	node *treesitter.Node,
	nodeType string,
) []*treesitter.Node {
	if node == nil {
		return nil
	}

	nodes := make([]*treesitter.Node, 0)

	if node.Kind() == nodeType {
		nodes = append(nodes, node)
	}

	for index := uint(0); index < node.ChildCount(); index++ {
		nodes = append(
			nodes,
			collectNodesByType(
				node.Child(index),
				nodeType,
			)...,
		)
	}

	return nodes
}

func nodeHasDirectChildType(
	node *treesitter.Node,
	nodeType string,
) bool {
	if node == nil {
		return false
	}

	for index := uint(0); index < node.ChildCount(); index++ {
		child := node.Child(index)

		if child != nil && child.Kind() == nodeType {
			return true
		}
	}

	return false
}

func nearestAncestorByType(
	node *treesitter.Node,
	nodeType string,
) *treesitter.Node {
	if node == nil {
		return nil
	}

	for current := node.Parent(); current != nil; current = current.Parent() {
		if current.Kind() == nodeType {
			return current
		}
	}

	return nil
}

func firstNamedChild(
	node *treesitter.Node,
) *treesitter.Node {
	if node == nil {
		return nil
	}

	for index := uint(0); index < node.ChildCount(); index++ {
		child := node.Child(index)

		if child != nil && child.IsNamed() {
			return child
		}
	}

	return nil
}
