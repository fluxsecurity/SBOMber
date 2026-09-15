package sourceanalysis

// AnalyzerForPath selects the analyser for a source file.
//
// JavaScript, TypeScript and TSX currently share the Tree-sitter analyser.
// Unsupported source types return UnsupportedLanguageError.
func AnalyzerForPath(path string) (SourceAnalyzer, error) {
	if _, err := languageForPath(path); err != nil {
		return nil, err
	}

	return TreeSitterAnalyzer{}, nil
}

// AnalyzeSource is the language-neutral entry point used by callers.
func AnalyzeSource(path string) (Result, error) {
	analyzer, err := AnalyzerForPath(path)
	if err != nil {
		return Result{}, err
	}

	return analyzer.Analyze(path)
}
