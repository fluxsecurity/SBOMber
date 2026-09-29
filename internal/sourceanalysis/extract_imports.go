package sourceanalysis

import (
	"fmt"
	"strings"

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

		kind := "esm_namespace"
		if typeOnly {
			kind = "esm_type_only"
		}

		result.Imports = append(
			result.Imports,
			Import{
				Specifier: specifier,
				Kind:      kind,
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
	arguments *treesitter.Node,
	source []byte,
) error {
	if call == nil || arguments == nil {
		return fmt.Errorf(
			"CommonJS require match is missing required captures",
		)
	}

	argument := firstNamedChild(arguments)
	if argument == nil {
		// require() with no argument loads nothing.
		return nil
	}

	specifier, static, err := staticModuleSpecifier(argument, source)
	if err != nil {
		return err
	}
	if !static {
		// require(name) can load any package. Record it as a computed
		// import so no occurrence in this repository reads as unused.
		line, column := nodeLocation(source, call)
		local := ""
		if parent := call.Parent(); parent != nil &&
			parent.Kind() == "variable_declarator" &&
			sameNode(parent.ChildByFieldName("value"), call) {
			if name := parent.ChildByFieldName("name"); name != nil &&
				name.Kind() == "identifier" {
				local = name.Utf8Text(source)
			}
		}
		result.Imports = append(result.Imports, Import{
			Specifier: argument.Utf8Text(source),
			Kind:      "dynamic_computed",
			Local:     local,
			Imported:  "*",
			Line:      line,
			Column:    column,
		})
		return nil
	}

	parent := call.Parent()
	switch {
	case parent != nil && parent.Kind() == "variable_declarator" &&
		sameNode(parent.ChildByFieldName("value"), call):
		return appendBoundRequire(result, call, parent, specifier, source)

	case parent != nil && parent.Kind() == "assignment_expression" &&
		sameNode(parent.ChildByFieldName("right"), call):
		if left := parent.ChildByFieldName("left"); left != nil &&
			left.Kind() == "identifier" {
			line, column := nodeLocation(source, left)
			result.Imports = append(result.Imports, Import{
				Specifier: specifier,
				Kind:      "cjs_require",
				Local:     left.Utf8Text(source),
				Imported:  "*",
				Line:      line,
				Column:    column,
			})
			return nil
		}

	case parent != nil && parent.Kind() == "member_expression" &&
		sameNode(parent.ChildByFieldName("object"), call):
		if appendMemberRequire(result, call, parent, specifier, source) {
			return nil
		}

	case parent != nil && parent.Kind() == "call_expression" &&
		sameNode(parent.ChildByFieldName("function"), call):
		// require("pkg")(...) calls the module's default export directly,
		// e.g. require("debug")("app").
		line, column := nodeLocation(source, call)
		callLine, callColumn := nodeLocation(source, parent)
		result.Imports = append(result.Imports, Import{
			Specifier: specifier,
			Kind:      "cjs_require",
			Imported:  "*",
			Line:      line,
			Column:    column,
			InlineCalls: []Call{{
				Callee: stringPointer("default"),
				Line:   callLine,
				Column: callColumn,
			}},
		})
		return nil

	case parent != nil && parent.Kind() == "expression_statement":
		// require("x"); loads the module for its side effects only.
		// Nothing can be called through it.
		line, column := nodeLocation(source, call)
		result.Imports = append(result.Imports, Import{
			Specifier: specifier,
			Kind:      "cjs_require",
			Imported:  "*",
			Line:      line,
			Column:    column,
		})
		return nil
	}

	// The module value escapes into an expression this analyser does not
	// track (an argument, a return value, module.exports, ...). Record the
	// import with an unresolved use rather than dropping it.
	line, column := nodeLocation(source, call)
	result.Imports = append(result.Imports, Import{
		Specifier:     specifier,
		Kind:          "cjs_require",
		Imported:      "*",
		Line:          line,
		Column:        column,
		UnresolvedUse: "outside_supported_syntax",
	})
	return nil
}

// appendBoundRequire handles const x = require("pkg") and
// const { a, b: c } = require("pkg").
func appendBoundRequire(
	result *Result,
	call *treesitter.Node,
	declarator *treesitter.Node,
	specifier string,
	source []byte,
) error {
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
				Kind:      "cjs_require",
				Local:     binding.Utf8Text(source),
				Imported:  "*",
				TypeOnly:  false,
				Line:      line,
				Column:    column,
			},
		)
		return nil

	case "object_pattern":
		appended := 0
		unsupported := false
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

			if importedNode == nil || localNode == nil ||
				(localNode.Kind() != "identifier" &&
					localNode.Kind() != "shorthand_property_identifier_pattern") {
				// Defaults, nested patterns and rest elements are not
				// tracked; they are recorded below, not dropped.
				unsupported = true
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
			appended++
		}
		if appended != 0 && !unsupported {
			return nil
		}
	}

	// Array patterns, rest elements and other bindings: keep the import and
	// mark its use unresolved.
	line, column := nodeLocation(source, call)
	result.Imports = append(result.Imports, Import{
		Specifier:     specifier,
		Kind:          "cjs_require",
		Imported:      "*",
		Line:          line,
		Column:        column,
		UnresolvedUse: "outside_supported_syntax",
	})
	return nil
}

// appendMemberRequire handles require("pkg").name used directly:
// const merge = require("pkg").merge and require("pkg").merge(x).
// It reports false when the member expression is used some other way.
func appendMemberRequire(
	result *Result,
	call *treesitter.Node,
	member *treesitter.Node,
	specifier string,
	source []byte,
) bool {
	property := member.ChildByFieldName("property")
	if property == nil || property.Kind() != "property_identifier" {
		return false
	}
	name := property.Utf8Text(source)
	outer := member.Parent()
	if outer == nil {
		return false
	}

	switch {
	case outer.Kind() == "variable_declarator" &&
		sameNode(outer.ChildByFieldName("value"), member):
		local := outer.ChildByFieldName("name")
		if local == nil || local.Kind() != "identifier" {
			return false
		}
		line, column := nodeLocation(source, local)
		result.Imports = append(result.Imports, Import{
			Specifier: specifier,
			Kind:      "cjs_destructured",
			Local:     local.Utf8Text(source),
			Imported:  name,
			Line:      line,
			Column:    column,
		})
		return true

	case outer.Kind() == "call_expression" &&
		sameNode(outer.ChildByFieldName("function"), member):
		line, column := nodeLocation(source, call)
		callLine, callColumn := nodeLocation(source, outer)
		result.Imports = append(result.Imports, Import{
			Specifier: specifier,
			Kind:      "cjs_require",
			Imported:  "*",
			Line:      line,
			Column:    column,
			InlineCalls: []Call{{
				Callee: stringPointer(name),
				Line:   callLine,
				Column: callColumn,
			}},
		})
		return true
	}
	return false
}

// appendImportRequireClauses handles TypeScript import x = require("pkg").
// The node type exists only in the TypeScript grammars, so it is found by
// walking the tree rather than through the shared query.
func appendImportRequireClauses(
	result *Result,
	root *treesitter.Node,
	source []byte,
) error {
	for _, clause := range collectNodesByType(root, "import_require_clause") {
		sourceNode := clause.ChildByFieldName("source")
		local := firstNamedChild(clause)
		if sourceNode == nil || local == nil || local.Kind() != "identifier" {
			return fmt.Errorf(
				"import-equals at bytes %d-%d has no binding or source",
				clause.StartByte(),
				clause.EndByte(),
			)
		}
		specifier, err := unquoteJavaScriptString(sourceNode.Utf8Text(source))
		if err != nil {
			return err
		}
		typeOnly := nodeHasDirectChildType(clause.Parent(), "type")
		kind := "cjs_require"
		if typeOnly {
			kind = "esm_type_only"
		}
		line, column := nodeLocation(source, local)
		result.Imports = append(result.Imports, Import{
			Specifier: specifier,
			Kind:      kind,
			Local:     local.Utf8Text(source),
			Imported:  "*",
			TypeOnly:  typeOnly,
			Line:      line,
			Column:    column,
		})
	}
	return nil
}

// appendReexports handles export { a, b as c } from "pkg",
// export * from "pkg" and export * as ns from "pkg". The package is loaded
// and its symbols leave this file under names this analyser does not
// follow, so each re-export carries an unresolved reexport_chain use.
func appendReexports(
	result *Result,
	statement *treesitter.Node,
	sourceNode *treesitter.Node,
	source []byte,
) error {
	if statement == nil || sourceNode == nil {
		return fmt.Errorf("re-export match is missing required captures")
	}
	specifier, err := unquoteJavaScriptString(sourceNode.Utf8Text(source))
	if err != nil {
		return err
	}
	statementTypeOnly := nodeHasDirectChildType(statement, "type")

	add := func(node *treesitter.Node, imported string, typeOnly bool) {
		line, column := nodeLocation(source, node)
		entry := Import{
			Specifier: specifier,
			Kind:      "esm_reexport",
			Imported:  imported,
			Line:      line,
			Column:    column,
		}
		if typeOnly {
			entry.Kind = "esm_type_only"
			entry.TypeOnly = true
		} else {
			entry.UnresolvedUse = "reexport_chain"
		}
		result.Imports = append(result.Imports, entry)
	}

	specifiers := collectNodesByType(statement, "export_specifier")
	for _, exported := range specifiers {
		name := exported.ChildByFieldName("name")
		if name == nil {
			return fmt.Errorf(
				"export specifier at bytes %d-%d has no name",
				exported.StartByte(),
				exported.EndByte(),
			)
		}
		add(name, name.Utf8Text(source),
			statementTypeOnly || nodeHasDirectChildType(exported, "type"))
	}
	if len(specifiers) == 0 {
		add(statement, "*", statementTypeOnly)
	}
	return nil
}

// staticModuleSpecifier returns the module name when the argument is a
// plain string or a template literal without substitutions.
func staticModuleSpecifier(
	argument *treesitter.Node,
	source []byte,
) (string, bool, error) {
	switch argument.Kind() {
	case "string":
		specifier, err := unquoteJavaScriptString(argument.Utf8Text(source))
		if err != nil {
			return "", false, err
		}
		return specifier, true, nil

	case "template_string":
		var specifier strings.Builder
		for index := uint(0); index < argument.NamedChildCount(); index++ {
			child := argument.NamedChild(index)
			if child == nil || child.Kind() != "string_fragment" {
				// Substitutions and escape sequences are not resolved.
				return "", false, nil
			}
			specifier.WriteString(child.Utf8Text(source))
		}
		if specifier.Len() == 0 {
			return "", false, nil
		}
		return specifier.String(), true, nil
	}
	return "", false, nil
}

func sameNode(left, right *treesitter.Node) bool {
	return left != nil && right != nil &&
		left.StartByte() == right.StartByte() &&
		left.EndByte() == right.EndByte() &&
		left.Kind() == right.Kind()
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

	local := ""
	if declarator := nearestAncestorByType(call, "variable_declarator"); declarator != nil {
		if name := declarator.ChildByFieldName("name"); name != nil &&
			name.Kind() == "identifier" {
			local = name.Utf8Text(source)
		}
	}

	argument := firstNamedChild(arguments)
	if argument == nil {
		return fmt.Errorf("dynamic import has no argument")
	}

	specifier, static, err := staticModuleSpecifier(argument, source)
	if err != nil {
		return err
	}
	computed := !static
	if computed {
		specifier = argument.Utf8Text(source)
	}

	line, column := nodeLocation(source, call)

	kind := "dynamic_computed"
	if !computed {
		kind = "dynamic_static_literal"
	}

	result.Imports = append(
		result.Imports,
		Import{
			Specifier: specifier,
			Kind:      kind,
			Local:     local,
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
