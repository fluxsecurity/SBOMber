package sourceanalysis

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

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
	if len(value) < 2 ||
		(value[0] != '\'' && value[0] != '"') ||
		value[len(value)-1] != value[0] {
		return "", fmt.Errorf("invalid JavaScript string %q", value)
	}

	end := len(value) - 1
	var decoded strings.Builder
	invalid := func() (string, error) {
		return "", fmt.Errorf("invalid JavaScript string escape in %q", value)
	}

	for index := 1; index < end; {
		current := value[index]
		index++
		if current != '\\' {
			decoded.WriteByte(current)
			continue
		}
		if index >= end {
			return invalid()
		}

		escaped := value[index]
		index++
		switch escaped {
		case '0':
			if index < end && value[index] >= '0' && value[index] <= '9' {
				return invalid()
			}
			decoded.WriteByte(0)
		case 'b':
			decoded.WriteByte('\b')
		case 'f':
			decoded.WriteByte('\f')
		case 'n':
			decoded.WriteByte('\n')
		case 'r':
			decoded.WriteByte('\r')
		case 't':
			decoded.WriteByte('\t')
		case 'v':
			decoded.WriteByte('\v')
		case '\n':
			// A backslash followed by a line break continues the string.
		case '\r':
			if index < end && value[index] == '\n' {
				index++
			}
		case 'x', 'u':
			digits := 4
			if escaped == 'x' {
				digits = 2
			}
			braced := escaped == 'u' && index < end && value[index] == '{'
			if braced {
				index++
				start := index
				for index < end && value[index] != '}' {
					index++
				}
				if index == end || index == start || index-start > 6 {
					return invalid()
				}
				code, err := strconv.ParseUint(value[start:index], 16, 32)
				if err != nil || !utf8.ValidRune(rune(code)) {
					return invalid()
				}
				decoded.WriteRune(rune(code))
				index++
				continue
			}
			if index+digits > end {
				return invalid()
			}
			code, err := strconv.ParseUint(value[index:index+digits], 16, 32)
			if err != nil {
				return invalid()
			}
			index += digits
			character := rune(code)
			if escaped == 'u' && character >= 0xD800 && character <= 0xDBFF {
				if index+6 > end || value[index:index+2] != `\u` {
					return invalid()
				}
				next, err := strconv.ParseUint(value[index+2:index+6], 16, 32)
				if err != nil || next < 0xDC00 || next > 0xDFFF {
					return invalid()
				}
				character = utf16.DecodeRune(character, rune(next))
				index += 6
			}
			if !utf8.ValidRune(character) {
				return invalid()
			}
			decoded.WriteRune(character)
		default:
			if escaped >= '0' && escaped <= '9' {
				return invalid()
			}
			// JavaScript identity escapes such as \a represent "a".
			decoded.WriteByte(escaped)
		}
	}
	return decoded.String(), nil
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
