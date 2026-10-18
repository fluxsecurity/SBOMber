package sourceanalysis

import treesitter "github.com/tree-sitter/go-tree-sitter"

// markCopiedImports conservatively records imported values copied into another
// binding or container. Tracking the eventual call through that value is outside
// the supported direct-call analysis. An unresolved use prevents a closed
// localisation set from turning that missing call into a negative verdict.
func markCopiedImports(result *Result, root *treesitter.Node, source []byte) {
	var valueImports func(*treesitter.Node)
	valueImports = func(n *treesitter.Node) {
		if n == nil {
			return
		}
		switch n.Kind() {
		case "call_expression", "new_expression", "function_expression", "function", "arrow_function", "generator_function", "class":
			// The result of invoking a function is not a copy of its callee.
			return
		case "identifier", "shorthand_property_identifier":
			name := n.Utf8Text(source)
			for i := range result.Imports {
				imp := &result.Imports[i]
				if !imp.TypeOnly && imp.Local != "" && imp.Local == name && imp.UnresolvedUse == "" {
					imp.UnresolvedUse = "outside_supported_syntax"
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			valueImports(n.NamedChild(i))
		}
	}
	var walk func(*treesitter.Node)
	walk = func(n *treesitter.Node) {
		if n == nil {
			return
		}
		switch n.Kind() {
		case "variable_declarator":
			valueImports(n.ChildByFieldName("value"))
		case "assignment_expression":
			valueImports(n.ChildByFieldName("right"))
		case "return_statement":
			for i := uint(0); i < n.NamedChildCount(); i++ {
				valueImports(n.NamedChild(i))
			}
		case "arrow_function":
			if body := n.ChildByFieldName("body"); body != nil && body.Kind() != "statement_block" {
				valueImports(body)
			}
		case "call_expression", "new_expression":
			valueImports(n.ChildByFieldName("arguments"))
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(root)
}
