package sourceanalysis

import "fmt"

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

// AnalyzeSource is the language-neutral file-based entry point used by callers.
func AnalyzeSource(path string) (Result, error) {
	analyzer, err := AnalyzerForPath(path)
	if err != nil {
		return Result{}, err
	}

	return analyzer.Analyze(path)
}

// byteSourceAnalyzer is implemented by analysers that can consume source bytes
// already read by the repository scanner.
type byteSourceAnalyzer interface {
	AnalyzeBytes(path string, source []byte) (Result, error)
}

// AnalyzeSourceBytes analyses source that the caller has already read.
// Repository scanning uses this entry point to avoid reopening every source file.
func AnalyzeSourceBytes(path string, source []byte) (Result, error) {
	analyzer, err := AnalyzerForPath(path)
	if err != nil {
		return Result{}, err
	}

	byteAnalyzer, ok := analyzer.(byteSourceAnalyzer)
	if !ok {
		return Result{}, fmt.Errorf(
			"source analyzer for %q does not support byte input",
			path,
		)
	}

	return byteAnalyzer.AnalyzeBytes(path, source)
}
