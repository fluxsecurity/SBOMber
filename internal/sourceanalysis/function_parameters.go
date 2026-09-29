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
