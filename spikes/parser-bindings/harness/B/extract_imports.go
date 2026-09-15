package main

import (
	"fmt"

	gotreesitter "github.com/odvcencio/gotreesitter"
)

func nearestAncestorByType(
	node *gotreesitter.Node,
	language *gotreesitter.Language,
	nodeType string,
) *gotreesitter.Node {
	if node == nil {
		return nil
	}

	for current := node.Parent(); current != nil; current = current.Parent() {
		if current.Type(language) == nodeType {
			return current
		}
	}

	return nil
}

func firstNamedChild(node *gotreesitter.Node) *gotreesitter.Node {
	if node == nil {
		return nil
	}

	for index := 0; index < node.ChildCount(); index++ {
		child := node.Child(index)

		if child != nil && child.IsNamed() {
			return child
		}
	}

	return nil
}

func appendESMNamespaceImports(
	result *Result,
	statement *gotreesitter.Node,
	language *gotreesitter.Language,
	source []byte,
	specifier string,
	typeOnly bool,
) error {
	namespaceImports := collectNodesByType(
		statement,
		language,
		"namespace_import",
	)

	for _, namespaceImport := range namespaceImports {
		localNode := firstNamedChild(namespaceImport)
		if localNode == nil ||
			localNode.Type(language) != "identifier" {
			return fmt.Errorf(
				"namespace import at bytes %d-%d has no local identifier",
				namespaceImport.StartByte(),
				namespaceImport.EndByte(),
			)
		}

		line, column := nodeLocation(source, localNode)

		result.Imports = append(
			result.Imports,
			Import{
				Specifier: specifier,
				Kind:      "esm_namespace",
				Local:     localNode.Text(source),
				Imported:  "*",
				TypeOnly:  typeOnly,
				Line:      line,
				Column:    column,
			},
		)
	}

	return nil
}

func appendRequireImports(
	result *Result,
	call *gotreesitter.Node,
	sourceNode *gotreesitter.Node,
	language *gotreesitter.Language,
	source []byte,
) error {
	if call == nil || sourceNode == nil {
		return fmt.Errorf(
			"CommonJS require match is missing required captures",
		)
	}

	specifier, err := unquoteJavaScriptString(sourceNode.Text(source))
	if err != nil {
		return err
	}

	declarator := nearestAncestorByType(
		call,
		language,
		"variable_declarator",
	)
	if declarator == nil {
		return fmt.Errorf(
			"require call at bytes %d-%d has no variable declarator",
			call.StartByte(),
			call.EndByte(),
		)
	}

	binding := declarator.ChildByFieldName("name", language)
	if binding == nil {
		return fmt.Errorf(
			"require declarator at bytes %d-%d has no binding",
			declarator.StartByte(),
			declarator.EndByte(),
		)
	}

	switch binding.Type(language) {
	case "identifier":
		line, column := nodeLocation(source, binding)

		result.Imports = append(
			result.Imports,
			Import{
				Specifier: specifier,
				Kind:      "cjs",
				Local:     binding.Text(source),
				Imported:  "*",
				TypeOnly:  false,
				Line:      line,
				Column:    column,
			},
		)

	case "object_pattern":
		for index := 0; index < binding.ChildCount(); index++ {
			child := binding.Child(index)
			if child == nil || !child.IsNamed() {
				continue
			}

			var importedNode *gotreesitter.Node
			var localNode *gotreesitter.Node

			switch child.Type(language) {
			case "shorthand_property_identifier_pattern":
				importedNode = child
				localNode = child

			case "pair_pattern":
				importedNode = child.ChildByFieldName(
					"key",
					language,
				)
				localNode = child.ChildByFieldName(
					"value",
					language,
				)
			}

			if importedNode == nil || localNode == nil {
				continue
			}

			line, column := nodeLocation(source, localNode)

			result.Imports = append(
				result.Imports,
				Import{
					Specifier: specifier,
					Kind:      "cjs_destructured",
					Local:     localNode.Text(source),
					Imported:  importedNode.Text(source),
					TypeOnly:  false,
					Line:      line,
					Column:    column,
				},
			)
		}

	default:
		return fmt.Errorf(
			"unsupported require binding type %q",
			binding.Type(language),
		)
	}

	return nil
}

func appendDynamicImport(
	result *Result,
	call *gotreesitter.Node,
	arguments *gotreesitter.Node,
	language *gotreesitter.Language,
	source []byte,
) error {
	if call == nil || arguments == nil {
		return fmt.Errorf(
			"dynamic import match is missing required captures",
		)
	}

	declarator := nearestAncestorByType(
		call,
		language,
		"variable_declarator",
	)
	if declarator == nil {
		return fmt.Errorf(
			"dynamic import at bytes %d-%d has no variable declarator",
			call.StartByte(),
			call.EndByte(),
		)
	}

	localNode := declarator.ChildByFieldName("name", language)
	if localNode == nil ||
		localNode.Type(language) != "identifier" {
		return fmt.Errorf(
			"dynamic import declarator has no identifier binding",
		)
	}

	argument := firstNamedChild(arguments)
	if argument == nil {
		return fmt.Errorf("dynamic import has no argument")
	}

	specifier := "<computed>"
	computed := true

	if argument.Type(language) == "string" {
		var err error

		specifier, err = unquoteJavaScriptString(
			argument.Text(source),
		)
		if err != nil {
			return err
		}

		computed = false
	}

	line, column := nodeLocation(source, call)

	result.Imports = append(
		result.Imports,
		Import{
			Specifier: specifier,
			Kind:      "dynamic",
			Local:     localNode.Text(source),
			Imported:  "*",
			TypeOnly:  false,
			Line:      line,
			Column:    column,
		},
	)

	result.Calls = append(
		result.Calls,
		Call{
			Callee:   stringPointer("import"),
			Receiver: nil,
			Line:     line,
			Column:   column,
		},
	)

	if computed {
		result.Unresolved = append(
			result.Unresolved,
			Unresolved{
				Kind:       "computed_dynamic_import",
				Expression: call.Text(source),
				Reason: "module specifier is computed " +
					"at runtime",
				Line:   line,
				Column: column,
			},
		)
	}

	return nil
}
