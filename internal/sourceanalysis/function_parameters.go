package sourceanalysis

import treesitter "github.com/tree-sitter/go-tree-sitter"

// parameterNames records possible parameter bindings for conservative call
// resolution. These names are internal and never enter parser JSON.
func parameterNames(node *treesitter.Node, source []byte) []string {
	parameters := node.ChildByFieldName("parameters")
	if parameters == nil {
		parameters = node.ChildByFieldName("parameter")
	}
	if parameters == nil {
		return nil
	}

	names := make([]string, 0)
	seen := make(map[string]struct{})
	for _, identifier := range collectNodesByType(parameters, "identifier") {
		name := identifier.Utf8Text(source)
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

// localBindingNames records names declared anywhere inside a function body:
// const/let/var declarators (including destructuring), for-in/for-of
// bindings, catch parameters, and nested function and class names. Any of
// these can hide a same-named module function or import, so call
// resolution treats them the same way as parameters. Collection is
// deliberately over-inclusive: a name declared in a nested block or nested
// function still blocks an edge, which can only turn a path into unknown.
func localBindingNames(node *treesitter.Node, source []byte) []string {
	body := node.ChildByFieldName("body")
	if body == nil {
		return nil
	}

	names := make([]string, 0)
	seen := make(map[string]struct{})
	add := func(binding *treesitter.Node) {
		if binding == nil {
			return
		}
		candidates := []*treesitter.Node{}
		switch binding.Kind() {
		case "identifier", "shorthand_property_identifier_pattern":
			candidates = append(candidates, binding)
		default:
			found := collectNodesByTypes(binding,
				"identifier", "shorthand_property_identifier_pattern")
			candidates = append(candidates, found["identifier"]...)
			candidates = append(candidates, found["shorthand_property_identifier_pattern"]...)
		}
		for _, candidate := range candidates {
			name := candidate.Utf8Text(source)
			if _, exists := seen[name]; exists {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}

	nodes := collectNodesByTypes(body,
		"variable_declarator", "for_in_statement", "catch_clause",
		"function_declaration", "generator_function_declaration", "class_declaration")

	for _, declarator := range nodes["variable_declarator"] {
		if declaresDynamicImport(declarator) {
			// const m = await import("x") is the import binding itself; the
			// usage graph scopes it to this function instead.
			continue
		}
		if declaration := declarator.Parent(); declaration != nil &&
			sameNode(declaration.Parent(), body) &&
			declaresTrackedFunction(declarator, source) {
			continue
		}
		add(declarator.ChildByFieldName("name"))
	}
	for _, loop := range nodes["for_in_statement"] {
		add(loop.ChildByFieldName("left"))
	}
	for _, clause := range nodes["catch_clause"] {
		add(clause.ChildByFieldName("parameter"))
	}
	// A function declared directly in this body is tracked. Declarations
	// in deeper blocks or functions remain conservative shadows. Generators
	// and classes are not tracked, so they also remain shadows.
	for _, kind := range []string{
		"function_declaration",
		"generator_function_declaration",
		"class_declaration",
	} {
		for _, declaration := range nodes[kind] {
			if kind == "function_declaration" &&
				sameNode(declaration.Parent(), body) {
				continue
			}
			add(declaration.ChildByFieldName("name"))
		}
	}
	return names
}

// declaresTrackedFunction reports const f = () => ... and
// const f = function f() {...}: the parser records these as functions named
// f, so f is resolved directly instead of being treated as a shadow.
func declaresTrackedFunction(declarator *treesitter.Node, source []byte) bool {
	name := declarator.ChildByFieldName("name")
	value := declarator.ChildByFieldName("value")
	if name == nil || value == nil || name.Kind() != "identifier" {
		return false
	}
	switch value.Kind() {
	case "arrow_function":
		return true
	case "function_expression":
		own := value.ChildByFieldName("name")
		return own != nil && own.Utf8Text(source) == name.Utf8Text(source)
	}
	return false
}

// declaresDynamicImport reports const m = await import("x") and
// const { a } = await import("x").
func declaresDynamicImport(declarator *treesitter.Node) bool {
	value := declarator.ChildByFieldName("value")
	if value != nil && value.Kind() == "await_expression" {
		value = firstNamedChild(value)
	}
	if value == nil || value.Kind() != "call_expression" {
		return false
	}
	function := value.ChildByFieldName("function")
	return function != nil && function.Kind() == "import"
}
