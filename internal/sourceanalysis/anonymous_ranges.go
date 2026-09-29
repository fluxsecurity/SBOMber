package sourceanalysis

import treesitter "github.com/tree-sitter/go-tree-sitter"

// These ranges are internal attribution boundaries, not public Functions.
func appendAnonymousFunctionRanges(
	result *Result,
	root *treesitter.Node,
	source []byte,
) {
	for _, kind := range []string{"arrow_function", "function_expression"} {
		for _, node := range collectNodesByType(root, kind) {
			line, column := nodeLocation(source, node)
			endLine, endColumn := nodeEndLocation(source, node)
			result.AnonymousFunctions = append(
				result.AnonymousFunctions,
				Function{
					Line: line, Column: column,
					EndLine: endLine, EndColumn: endColumn,
					Parameters: parameterNames(node, source),
				},
			)
		}
	}
}
