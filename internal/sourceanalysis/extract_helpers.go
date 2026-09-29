package sourceanalysis

import (
	"bytes"
	"fmt"
	"strconv"
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

func nodeEndLocation(
	source []byte,
	node *treesitter.Node,
) (int, int) {
	point := node.EndPosition()
	column := int(point.Column)

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

func unquoteJavaScriptString(value string) (string, error) {
	if len(value) < 2 {
		return "", fmt.Errorf(
			"invalid JavaScript string %q",
			value,
		)
	}

	literal := value
	if value[0] == '\'' && value[len(value)-1] == '\'' {
		var converted strings.Builder
		converted.WriteByte('"')
		for index := 1; index < len(value)-1; index++ {
			current := value[index]
			if current == '\\' && index+1 < len(value)-1 {
				switch value[index+1] {
				case '\\':
					converted.WriteString(`\\`)
					index++
					continue
				case '\'':
					converted.WriteByte('\'')
					index++
					continue
				case '"':
					converted.WriteString(`\"`)
					index++
					continue
				case '/':
					converted.WriteByte('/')
					index++
					continue
				case '0':
					converted.WriteString(`\x00`)
					index++
					continue
				}
			}
			if current == '"' {
				converted.WriteString(`\"`)
			} else {
				converted.WriteByte(current)
			}
		}
		converted.WriteByte('"')
		literal = converted.String()
	}

	unquoted, err := strconv.Unquote(literal)
	if err != nil {
		return "", fmt.Errorf(
			"unquote JavaScript string %q: %w",
			value,
			err,
		)
	}

	return unquoted, nil
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
