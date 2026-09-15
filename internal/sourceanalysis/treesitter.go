package sourceanalysis

import (
	"fmt"

	treesitter "github.com/tree-sitter/go-tree-sitter"
	javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	typescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"
)

// TreeSitterAnalyzer implements SourceAnalyzer for JS, TS and TSX.
type TreeSitterAnalyzer struct{}

func (TreeSitterAnalyzer) Analyze(path string) (Result, error) {
	if _, err := languageForPath(path); err != nil {
		return Result{}, err
	}

	return extractFile(path)
}

func treeSitterLanguageForPath(path string) (*treesitter.Language, error) {
	language, err := languageForPath(path)
	if err != nil {
		return nil, err
	}

	switch language {
	case "javascript":
		return treesitter.NewLanguage(javascript.Language()), nil
	case "typescript":
		return treesitter.NewLanguage(typescript.LanguageTypescript()), nil
	case "tsx":
		return treesitter.NewLanguage(typescript.LanguageTSX()), nil
	default:
		return nil, fmt.Errorf("internal unsupported language %q", language)
	}
}

var _ SourceAnalyzer = TreeSitterAnalyzer{}
