package main

import (
	"fmt"

	treesitter "github.com/tree-sitter/go-tree-sitter"
)

func appendESMNamespaceImports(
	result *Result,
	statement *treesitter.Node,
	source []byte,
	specifier string,
	typeOnly bool,
) error {
	namespaceImports := collectNodesByType(
		statement,
		"namespace_import",
	)

	for _, namespaceImport := range namespaceImports {
		localNode := firstNamedChild(namespaceImport)
		if localNode == nil ||
			localNode.Kind() != "identifier" {
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
				Local:     localNode.Utf8Text(source),
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
	call *treesitter.Node,
	sourceNode *treesitter.Node,
	source []byte,
) error {
	if call == nil || sourceNode == nil {
		return fmt.Errorf(
			"CommonJS require match is missing required captures",
		)
	}

	specifier, err := unquoteJavaScriptString(
		sourceNode.Utf8Text(source),
	)
	if err != nil {
		return err
	}

	declarator := nearestAncestorByType(
		call,
		"variable_declarator",
	)
	if declarator == nil {
		return fmt.Errorf(
			"require call at bytes %d-%d has no variable declarator",
			call.StartByte(),
			call.EndByte(),
		)
	}

	binding := declarator.ChildByFieldName("name")
	if binding == nil {
		return fmt.Errorf(
			"require declarator at bytes %d-%d has no binding",
			declarator.StartByte(),
			declarator.EndByte(),
		)
	}

	switch binding.Kind() {
	case "identifier":
		line, column := nodeLocation(source, binding)

		result.Imports = append(
			result.Imports,
			Import{
				Specifier: specifier,
				Kind:      "cjs",
				Local:     binding.Utf8Text(source),
				Imported:  "*",
				TypeOnly:  false,
				Line:      line,
				Column:    column,
			},
		)

	case "object_pattern":
		for index := uint(0); index < binding.ChildCount(); index++ {
			child := binding.Child(index)
			if child == nil || !child.IsNamed() {
				continue
			}

			var importedNode *treesitter.Node
			var localNode *treesitter.Node

			switch child.Kind() {
			case "shorthand_property_identifier_pattern":
				importedNode = child
				localNode = child

			case "pair_pattern":
				importedNode = child.ChildByFieldName("key")
				localNode = child.ChildByFieldName("value")
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
					Local:     localNode.Utf8Text(source),
					Imported:  importedNode.Utf8Text(source),
					TypeOnly:  false,
					Line:      line,
					Column:    column,
				},
			)
		}

	default:
		return fmt.Errorf(
			"unsupported require binding type %q",
			binding.Kind(),
		)
	}

	return nil
}

func appendDynamicImport(
	result *Result,
	call *treesitter.Node,
	arguments *treesitter.Node,
	source []byte,
) error {
	if call == nil || arguments == nil {
		return fmt.Errorf(
			"dynamic import match is missing required captures",
		)
	}

	declarator := nearestAncestorByType(
		call,
		"variable_declarator",
	)
	if declarator == nil {
		return fmt.Errorf(
			"dynamic import at bytes %d-%d has no variable declarator",
			call.StartByte(),
			call.EndByte(),
		)
	}

	localNode := declarator.ChildByFieldName("name")
	if localNode == nil ||
		localNode.Kind() != "identifier" {
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

	if argument.Kind() == "string" {
		var err error

		specifier, err = unquoteJavaScriptString(
			argument.Utf8Text(source),
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
			Local:     localNode.Utf8Text(source),
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
				Expression: call.Utf8Text(source),
				Reason: "module specifier is computed " +
					"at runtime",
				Line:   line,
				Column: column,
			},
		)
	}

	return nil
}
