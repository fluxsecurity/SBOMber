package main

import (
	"fmt"
	"strings"

	treesitter "github.com/tree-sitter/go-tree-sitter"
)

func appendStructuralCalls(
	result *Result,
	root *treesitter.Node,
	source []byte,
) error {
	callExpressions := collectNodesByType(
		root,
		"call_expression",
	)

	for _, site := range callExpressions {
		function := site.ChildByFieldName("function")
		if function == nil {
			continue
		}

		switch function.Kind() {
		case "subscript_expression":
			receiverNode := function.ChildByFieldName("object")
			if receiverNode == nil {
				return fmt.Errorf(
					"computed call at bytes %d-%d has no object",
					site.StartByte(),
					site.EndByte(),
				)
			}

			line, column := nodeLocation(source, site)
			receiver := receiverNode.Utf8Text(source)

			result.Calls = append(
				result.Calls,
				Call{
					Callee:   nil,
					Receiver: stringPointer(receiver),
					Line:     line,
					Column:   column,
					Note:     "computed member property",
				},
			)

			result.Unresolved = append(
				result.Unresolved,
				Unresolved{
					Kind:       "computed_member",
					Expression: site.Utf8Text(source),
					Line:       line,
					Column:     column,
					Reason: "property name is computed " +
						"at runtime",
				},
			)

		case "member_expression":
			receiverNode := function.ChildByFieldName("object")
			propertyNode := function.ChildByFieldName("property")

			if receiverNode == nil ||
				propertyNode == nil ||
				receiverNode.Kind() != "call_expression" {
				continue
			}

			line, column := nodeLocation(source, site)

			result.Calls = append(
				result.Calls,
				Call{
					Callee: stringPointer(
						propertyNode.Utf8Text(source),
					),
					Receiver: stringPointer(
						receiverNode.Utf8Text(source),
					),
					Line:   line,
					Column: column,
					Note:   "call on result of another call",
				},
			)
		}
	}

	return nil
}

func isCommonJSExportAssignment(
	node *treesitter.Node,
	source []byte,
) bool {
	assignment := nearestAncestorByType(
		node,
		"assignment_expression",
	)
	if assignment == nil {
		return false
	}

	right := assignment.ChildByFieldName("right")
	if right == nil ||
		right.StartByte() != node.StartByte() ||
		right.EndByte() != node.EndByte() {
		return false
	}

	left := assignment.ChildByFieldName("left")
	if left == nil {
		return false
	}

	target := left.Utf8Text(source)

	return target == "module.exports" ||
		strings.HasPrefix(target, "module.exports.")
}

func arrowFunctionBinding(
	node *treesitter.Node,
) (*treesitter.Node, bool) {
	if node == nil {
		return nil, false
	}

	declarator := node.Parent()
	if declarator == nil ||
		declarator.Kind() != "variable_declarator" {
		return nil, false
	}

	value := declarator.ChildByFieldName("value")
	if value == nil ||
		value.StartByte() != node.StartByte() ||
		value.EndByte() != node.EndByte() {
		return nil, false
	}

	name := declarator.ChildByFieldName("name")
	if name == nil ||
		name.Kind() != "identifier" {
		return nil, false
	}

	exported := false
	declaration := declarator.Parent()

	if declaration != nil {
		parent := declaration.Parent()

		if parent != nil &&
			parent.Kind() == "export_statement" {
			exported = true
		}
	}

	return name, exported
}

func appendAdditionalFunctions(
	result *Result,
	root *treesitter.Node,
	source []byte,
) error {
	functionExpressions := collectNodesByType(
		root,
		"function_expression",
	)

	for _, expression := range functionExpressions {
		name := expression.ChildByFieldName("name")
		if name == nil {
			continue
		}

		line, column := nodeLocation(source, name)

		result.Functions = append(
			result.Functions,
			Function{
				Name:   name.Utf8Text(source),
				Line:   line,
				Column: column,
				Exported: isCommonJSExportAssignment(
					expression,
					source,
				),
			},
		)
	}

	arrowFunctions := collectNodesByType(
		root,
		"arrow_function",
	)

	for _, arrow := range arrowFunctions {
		name, exported := arrowFunctionBinding(arrow)
		if name == nil {
			continue
		}

		line, column := nodeLocation(source, name)

		result.Functions = append(
			result.Functions,
			Function{
				Name:     name.Utf8Text(source),
				Line:     line,
				Column:   column,
				Exported: exported,
			},
		)
	}

	return nil
}
