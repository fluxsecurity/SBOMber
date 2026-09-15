package main

import (
	"fmt"
	"strings"

	gotreesitter "github.com/odvcencio/gotreesitter"
)

func appendStructuralCalls(
	result *Result,
	root *gotreesitter.Node,
	language *gotreesitter.Language,
	source []byte,
) error {
	callExpressions := collectNodesByType(
		root,
		language,
		"call_expression",
	)

	for _, site := range callExpressions {
		function := site.ChildByFieldName("function", language)
		if function == nil {
			continue
		}

		switch function.Type(language) {
		case "subscript_expression":
			receiverNode := function.ChildByFieldName(
				"object",
				language,
			)
			if receiverNode == nil {
				return fmt.Errorf(
					"computed call at bytes %d-%d has no object",
					site.StartByte(),
					site.EndByte(),
				)
			}

			line, column := nodeLocation(source, site)
			receiver := receiverNode.Text(source)

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
					Expression: site.Text(source),
					Line:       line,
					Column:     column,
					Reason: "property name is computed " +
						"at runtime",
				},
			)

		case "member_expression":
			receiverNode := function.ChildByFieldName(
				"object",
				language,
			)
			propertyNode := function.ChildByFieldName(
				"property",
				language,
			)

			if receiverNode == nil ||
				propertyNode == nil ||
				receiverNode.Type(language) != "call_expression" {
				continue
			}

			line, column := nodeLocation(source, site)

			result.Calls = append(
				result.Calls,
				Call{
					Callee: stringPointer(
						propertyNode.Text(source),
					),
					Receiver: stringPointer(
						receiverNode.Text(source),
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
	node *gotreesitter.Node,
	language *gotreesitter.Language,
	source []byte,
) bool {
	assignment := nearestAncestorByType(
		node,
		language,
		"assignment_expression",
	)
	if assignment == nil {
		return false
	}

	right := assignment.ChildByFieldName("right", language)
	if right == nil ||
		right.StartByte() != node.StartByte() ||
		right.EndByte() != node.EndByte() {
		return false
	}

	left := assignment.ChildByFieldName("left", language)
	if left == nil {
		return false
	}

	target := left.Text(source)

	return target == "module.exports" ||
		strings.HasPrefix(target, "module.exports.")
}

func arrowFunctionBinding(
	node *gotreesitter.Node,
	language *gotreesitter.Language,
) (*gotreesitter.Node, bool) {
	if node == nil {
		return nil, false
	}

	declarator := node.Parent()
	if declarator == nil ||
		declarator.Type(language) != "variable_declarator" {
		return nil, false
	}

	value := declarator.ChildByFieldName("value", language)
	if value == nil ||
		value.StartByte() != node.StartByte() ||
		value.EndByte() != node.EndByte() {
		return nil, false
	}

	name := declarator.ChildByFieldName("name", language)
	if name == nil ||
		name.Type(language) != "identifier" {
		return nil, false
	}

	exported := false
	declaration := declarator.Parent()

	if declaration != nil {
		parent := declaration.Parent()

		if parent != nil &&
			parent.Type(language) == "export_statement" {
			exported = true
		}
	}

	return name, exported
}

func appendAdditionalFunctions(
	result *Result,
	root *gotreesitter.Node,
	language *gotreesitter.Language,
	source []byte,
) error {
	functionExpressions := collectNodesByType(
		root,
		language,
		"function_expression",
	)

	for _, expression := range functionExpressions {
		name := expression.ChildByFieldName("name", language)
		if name == nil {
			continue
		}

		line, column := nodeLocation(source, name)

		result.Functions = append(
			result.Functions,
			Function{
				Name:   name.Text(source),
				Line:   line,
				Column: column,
				Exported: isCommonJSExportAssignment(
					expression,
					language,
					source,
				),
			},
		)
	}

	arrowFunctions := collectNodesByType(
		root,
		language,
		"arrow_function",
	)

	for _, arrow := range arrowFunctions {
		name, exported := arrowFunctionBinding(
			arrow,
			language,
		)
		if name == nil {
			continue
		}

		line, column := nodeLocation(source, name)

		result.Functions = append(
			result.Functions,
			Function{
				Name:     name.Text(source),
				Line:     line,
				Column:   column,
				Exported: exported,
			},
		)
	}

	return nil
}
