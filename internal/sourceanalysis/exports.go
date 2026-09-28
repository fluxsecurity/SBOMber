package sourceanalysis

import (
	"sort"

	treesitter "github.com/tree-sitter/go-tree-sitter"
)

func resolveFunctionExports(
	result *Result,
	root *treesitter.Node,
	source []byte,
) {
	for index := range result.Functions {
		result.Functions[index].Exported = false
		result.Functions[index].ExportedNames = nil
	}

	resolveDirectESMFunctionExports(result, root, source)
	resolveCommonJSFunctionExports(result, root, source)
	resolveIdentifierFunctionExports(result, root, source)
	normalizeFunctionExports(result)
}

func resolveDirectESMFunctionExports(
	result *Result,
	root *treesitter.Node,
	source []byte,
) {
	for _, declaration := range collectNodesByType(
		root,
		"function_declaration",
	) {
		name := declaration.ChildByFieldName("name")
		if name == nil {
			continue
		}

		statement := declaration.Parent()
		if statement == nil || statement.Kind() != "export_statement" {
			continue
		}

		exportedName := name.Utf8Text(source)
		if nodeHasDirectChildType(statement, "default") {
			exportedName = "default"
		}

		addExportNameAtNode(result, name, exportedName, source)
	}

	for _, arrow := range collectNodesByType(root, "arrow_function") {
		name, exported := arrowFunctionBinding(arrow)
		if name == nil || !exported {
			continue
		}

		addExportNameAtNode(
			result,
			name,
			name.Utf8Text(source),
			source,
		)
	}
}

func resolveCommonJSFunctionExports(
	result *Result,
	root *treesitter.Node,
	source []byte,
) {
	for _, assignment := range collectNodesByType(
		root,
		"assignment_expression",
	) {
		exportedName, ok := commonJSAssignmentExportName(
			assignment,
			source,
		)
		if !ok {
			continue
		}

		right := assignment.ChildByFieldName("right")
		if right == nil {
			continue
		}

		switch right.Kind() {
		case "function_expression":
			name := right.ChildByFieldName("name")
			if name != nil {
				addExportNameAtNode(
					result,
					name,
					exportedName,
					source,
				)
			}

		case "identifier":
			addExportNameByUniqueLocal(
				result,
				right.Utf8Text(source),
				exportedName,
			)
		}
	}
}

func commonJSAssignmentExportName(
	assignment *treesitter.Node,
	source []byte,
) (string, bool) {
	left := assignment.ChildByFieldName("left")
	if left == nil {
		return "", false
	}

	if left.Utf8Text(source) == "module.exports" {
		return "default", true
	}

	if left.Kind() != "member_expression" {
		return "", false
	}

	object := left.ChildByFieldName("object")
	property := left.ChildByFieldName("property")
	if object == nil || property == nil ||
		object.Utf8Text(source) != "module.exports" {
		return "", false
	}

	return property.Utf8Text(source), true
}

func resolveIdentifierFunctionExports(
	result *Result,
	root *treesitter.Node,
	source []byte,
) {
	for _, statement := range collectNodesByType(root, "export_statement") {
		// A source string means this is a re-export, not a local binding.
		if len(collectNodesByType(statement, "string")) != 0 {
			continue
		}

		for _, specifier := range collectNodesByType(
			statement,
			"export_specifier",
		) {
			name := specifier.ChildByFieldName("name")
			if name == nil {
				continue
			}

			exportedName := name.Utf8Text(source)
			if alias := specifier.ChildByFieldName("alias"); alias != nil {
				exportedName = alias.Utf8Text(source)
			}

			addExportNameByUniqueLocal(
				result,
				name.Utf8Text(source),
				exportedName,
			)
		}

		if !nodeHasDirectChildType(statement, "default") {
			continue
		}

		for index := uint(0); index < statement.ChildCount(); index++ {
			child := statement.Child(index)
			if child == nil || child.Kind() != "identifier" {
				continue
			}

			addExportNameByUniqueLocal(
				result,
				child.Utf8Text(source),
				"default",
			)
		}
	}
}

func addExportNameAtNode(
	result *Result,
	name *treesitter.Node,
	exportedName string,
	source []byte,
) {
	line, column := nodeLocation(source, name)
	localName := name.Utf8Text(source)

	for index := range result.Functions {
		function := &result.Functions[index]
		if function.Name == localName &&
			function.Line == line &&
			function.Column == column {
			function.ExportedNames = append(
				function.ExportedNames,
				exportedName,
			)
			return
		}
	}
}

func addExportNameByUniqueLocal(
	result *Result,
	localName string,
	exportedName string,
) {
	matched := -1

	for index := range result.Functions {
		if result.Functions[index].Name != localName {
			continue
		}

		if matched != -1 {
			// Ambiguous bindings must not become entry-point evidence.
			return
		}

		matched = index
	}

	if matched == -1 {
		return
	}

	result.Functions[matched].ExportedNames = append(
		result.Functions[matched].ExportedNames,
		exportedName,
	)
}

func normalizeFunctionExports(result *Result) {
	for index := range result.Functions {
		function := &result.Functions[index]
		sort.Strings(function.ExportedNames)

		unique := function.ExportedNames[:0]
		for _, name := range function.ExportedNames {
			if name == "" ||
				(len(unique) != 0 && unique[len(unique)-1] == name) {
				continue
			}

			unique = append(unique, name)
		}

		function.ExportedNames = unique
		function.Exported = len(unique) != 0
	}
}
