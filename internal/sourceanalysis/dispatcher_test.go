package sourceanalysis

import (
	"errors"
	"testing"
)

func TestAnalyzerForPathSupportedLanguages(t *testing.T) {
	for _, path := range []string{
		"app.js",
		"app.mjs",
		"app.cjs",
		"app.ts",
		"app.tsx",
	} {
		t.Run(path, func(t *testing.T) {
			analyzer, err := AnalyzerForPath(path)
			if err != nil {
				t.Fatalf("AnalyzerForPath(%q): %v", path, err)
			}
			if analyzer == nil {
				t.Fatalf("AnalyzerForPath(%q) returned nil analyser", path)
			}
		})
	}
}

func TestAnalyzerForPathUnsupportedLanguage(t *testing.T) {
	_, err := AnalyzerForPath("main.py")
	if err == nil {
		t.Fatal("expected unsupported-language error")
	}

	var unsupported *UnsupportedLanguageError
	if !errors.As(err, &unsupported) {
		t.Fatalf(
			"expected UnsupportedLanguageError, got %T: %v",
			err,
			err,
		)
	}

	if unsupported.Extension != ".py" {
		t.Fatalf(
			"expected extension .py, got %q",
			unsupported.Extension,
		)
	}
}
