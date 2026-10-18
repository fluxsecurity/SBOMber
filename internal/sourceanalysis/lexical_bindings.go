package sourceanalysis

import treesitter "github.com/tree-sitter/go-tree-sitter"

// LexicalBinding is internal evidence about a declaration and its actual scope.
// It deliberately separates observation attribution from the conservative
// function-level shadows used when constructing reachability edges.
type LexicalBinding struct {
	Name                                       string
	Line, Column                               int
	ImportLine, ImportColumn                   int
	StartLine, StartColumn, EndLine, EndColumn int
}

func bindingNodes(node *treesitter.Node) []*treesitter.Node {
	if node == nil {
		return nil
	}
	switch node.Kind() {
	case "identifier", "shorthand_property_identifier_pattern":
		return []*treesitter.Node{node}
	case "assignment_pattern", "object_assignment_pattern":
		return bindingNodes(node.ChildByFieldName("left"))
	case "pair_pattern":
		return bindingNodes(node.ChildByFieldName("value"))
	case "required_parameter", "optional_parameter":
		if pattern := node.ChildByFieldName("pattern"); pattern != nil {
			return bindingNodes(pattern)
		}
		return bindingNodes(node.ChildByFieldName("name"))
	case "formal_parameters", "object_pattern", "array_pattern", "rest_pattern":
		var names []*treesitter.Node
		for i := uint(0); i < node.NamedChildCount(); i++ {
			names = append(names, bindingNodes(node.NamedChild(i))...)
		}
		return names
	}
	return nil
}

func functionScope(node *treesitter.Node) bool {
	switch node.Kind() {
	case "function_declaration", "generator_function_declaration", "function_expression", "generator_function", "arrow_function", "method_definition":
		return true
	}
	return false
}

func enclosingScope(node *treesitter.Node, functionOnly bool) *treesitter.Node {
	for scope := node.Parent(); scope != nil; scope = scope.Parent() {
		if scope.Kind() == "program" {
			return scope
		}
		if functionScope(scope) {
			// Body var bindings are not visible in a non-simple parameter
			// initializer's separate environment.
			if functionOnly {
				if body := scope.ChildByFieldName("body"); body != nil {
					return body
				}
			}
			return scope
		}
		if !functionOnly {
			switch scope.Kind() {
			case "statement_block", "for_statement", "for_in_statement", "catch_clause", "switch_body":
				return scope
			}
		}
	}
	return nil
}

func appendLexicalBindings(result *Result, root *treesitter.Node, source []byte) {
	add := func(pattern, scope *treesitter.Node) {
		if scope == nil {
			return
		}
		for _, name := range bindingNodes(pattern) {
			line, column := nodeLocation(source, name)
			startLine, startColumn := nodeLocation(source, scope)
			endLine, endColumn := nodeEndLocation(source, scope)
			binding := LexicalBinding{Name: name.Utf8Text(source), Line: line, Column: column, ImportLine: line, ImportColumn: column, StartLine: startLine, StartColumn: startColumn, EndLine: endLine, EndColumn: endColumn}
			for declaration := name.Parent(); declaration != nil; declaration = declaration.Parent() {
				if declaration.Kind() == "variable_declarator" {
					if declaresDynamicImport(declaration) {
						beginLine, beginColumn := nodeLocation(source, declaration)
						endLine, endColumn := nodeEndLocation(source, declaration)
						for _, imported := range result.Imports {
							if imported.Kind == "dynamic_static_literal" && imported.Local == binding.Name && positionAtOrAfter(imported.Line, imported.Column, beginLine, beginColumn) && !positionAtOrAfter(imported.Line, imported.Column, endLine, endColumn) {
								binding.ImportLine, binding.ImportColumn = imported.Line, imported.Column
							}
						}
					}
					break
				}
				if functionScope(declaration) {
					break
				}
			}
			result.LexicalBindings = append(result.LexicalBindings, binding)
		}
	}
	var walk func(*treesitter.Node)
	walk = func(node *treesitter.Node) {
		if functionScope(node) {
			parameters := node.ChildByFieldName("parameters")
			if parameters == nil {
				parameters = node.ChildByFieldName("parameter")
			}
			add(parameters, node)
			if node.Kind() == "function_expression" || node.Kind() == "generator_function" {
				add(node.ChildByFieldName("name"), node)
			}
		}
		switch node.Kind() {
		case "variable_declarator":
			declaration := node.Parent()
			add(node.ChildByFieldName("name"), enclosingScope(node, declaration != nil && declaration.Kind() == "variable_declaration"))
		case "function_declaration", "generator_function_declaration", "class_declaration":
			add(node.ChildByFieldName("name"), enclosingScope(node, false))
		case "catch_clause":
			add(node.ChildByFieldName("parameter"), node)
		case "for_in_statement":
			// A bare left-hand identifier is an assignment, not a declaration.
			if kind := node.ChildByFieldName("kind"); kind != nil {
				add(node.ChildByFieldName("left"), enclosingLoopScope(node, kind.Utf8Text(source) == "var"))
			}
		}
		for i := uint(0); i < node.NamedChildCount(); i++ {
			walk(node.NamedChild(i))
		}
	}
	walk(root)
}

func enclosingLoopScope(node *treesitter.Node, functionOnly bool) *treesitter.Node {
	if !functionOnly {
		return node
	}
	return enclosingScope(node, true)
}

func positionAtOrAfter(line, column, otherLine, otherColumn int) bool {
	return line > otherLine || line == otherLine && column >= otherColumn
}

func (binding LexicalBinding) contains(call Call) bool {
	return positionAtOrAfter(call.Line, call.Column, binding.StartLine, binding.StartColumn) &&
		!positionAtOrAfter(call.Line, call.Column, binding.EndLine, binding.EndColumn)
}

// ImportOwnsCall checks the nearest enclosing declaration. In particular, a
// require binding is its own declaration, not a shadow of itself. Declarations
// in sibling blocks/functions do not remove genuine calls.
func ImportOwnsCall(result Result, imported Import, call Call) bool {
	nearest := nearestLexicalBinding(result, imported.Local, call)
	if imported.BindingAssignment {
		// An assignment reuses the declaration visible at its left-hand side.
		// Compare declaration identities at both sites, rather than treating the
		// earlier let/var/parameter declaration as a shadow of its own import.
		target := nearestLexicalBinding(result, imported.Local, Call{Line: imported.Line, Column: imported.Column})
		return nearest == target
	}
	// Repeated var declarations share a scope. Their source order alone does
	// not prove which runtime value a call uses; keep the possible import
	// and let the producer record uncertainty instead of deleting its call.
	if ImportBindingAmbiguous(result, imported, call) {
		for i := range result.LexicalBindings {
			own := &result.LexicalBindings[i]
			if own.Name == imported.Local && own.ImportLine == imported.Line && own.ImportColumn == imported.Column && sameBindingScope(own, nearest) {
				return true
			}
		}
	}
	for i := range result.LexicalBindings {
		own := &result.LexicalBindings[i]
		if own.Name == imported.Local && own.ImportLine == imported.Line && own.ImportColumn == imported.Column && !own.contains(call) {
			return false
		}
	}
	return nearest == nil || nearest.ImportLine == imported.Line && nearest.ImportColumn == imported.Column
}

func nearestLexicalBinding(result Result, name string, call Call) *LexicalBinding {
	var nearest *LexicalBinding
	for i := range result.LexicalBindings {
		binding := &result.LexicalBindings[i]
		if binding.Name != name || !binding.contains(call) {
			continue
		}
		if nearest == nil || positionAtOrAfter(binding.StartLine, binding.StartColumn, nearest.StartLine, nearest.StartColumn) &&
			!positionAtOrAfter(binding.EndLine, binding.EndColumn, nearest.EndLine, nearest.EndColumn+1) {
			nearest = binding
		}
	}
	return nearest
}

func sameBindingScope(a, b *LexicalBinding) bool {
	return a != nil && b != nil && a.StartLine == b.StartLine && a.StartColumn == b.StartColumn && a.EndLine == b.EndLine && a.EndColumn == b.EndColumn
}

// ImportBindingAmbiguous reports repeated declarations at the nearest scope.
// Without assignment-flow analysis they cannot establish package ownership.
func ImportBindingAmbiguous(result Result, imported Import, call Call) bool {
	nearest := nearestLexicalBinding(result, imported.Local, call)
	count := 0
	for i := range result.LexicalBindings {
		binding := &result.LexicalBindings[i]
		if binding.Name == imported.Local && sameBindingScope(binding, nearest) {
			count++
		}
	}
	return count > 1
}
