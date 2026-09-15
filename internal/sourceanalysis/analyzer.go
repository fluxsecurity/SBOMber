package sourceanalysis

import (
	"fmt"
	"path/filepath"
	"strings"
)

// SourceAnalyzer is the language-neutral boundary used by callers.
// Implementations may use Tree-sitter or another parser internally.
type SourceAnalyzer interface {
	Analyze(path string) (Result, error)
}

type Result struct {
	Fixture    string       `json:"fixture"`
	Language   string       `json:"language"`
	HasError   bool         `json:"hasError"`
	Imports    []Import     `json:"imports"`
	Calls      []Call       `json:"calls"`
	Functions  []Function   `json:"functions"`
	Unresolved []Unresolved `json:"unresolved"`
}

type Import struct {
	Specifier string `json:"specifier"`
	Kind      string `json:"kind"`
	Local     string `json:"local"`
	Imported  string `json:"imported"`
	TypeOnly  bool   `json:"typeOnly"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
}

type Call struct {
	Callee   *string `json:"callee"`
	Receiver *string `json:"receiver"`
	Line     int     `json:"line"`
	Column   int     `json:"column"`
	Note     string  `json:"note,omitempty"`
}

type Function struct {
	Name     string `json:"name"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Exported bool   `json:"exported"`
}

type Unresolved struct {
	Kind       string `json:"kind"`
	Expression string `json:"expression"`
	Line       int    `json:"line"`
	Column     int    `json:"column"`
	Reason     string `json:"reason"`
}

// UnsupportedLanguageError is returned when the dispatcher cannot select
// an analyser for a source-file extension.
type UnsupportedLanguageError struct {
	Path      string
	Extension string
}

func (e *UnsupportedLanguageError) Error() string {
	return fmt.Sprintf(
		"unsupported source language for %q (extension %q)",
		e.Path,
		e.Extension,
	)
}

func languageForPath(path string) (string, error) {
	lower := strings.ToLower(path)

	switch {
	case strings.HasSuffix(lower, ".tsx"):
		return "tsx", nil
	case strings.HasSuffix(lower, ".ts"):
		return "typescript", nil
	case strings.HasSuffix(lower, ".js"),
		strings.HasSuffix(lower, ".mjs"),
		strings.HasSuffix(lower, ".cjs"):
		return "javascript", nil
	default:
		return "", &UnsupportedLanguageError{
			Path:      path,
			Extension: filepath.Ext(path),
		}
	}
}

func newResult(path, language string) Result {
	return Result{
		Fixture:    filepath.Base(path),
		Language:   language,
		Imports:    []Import{},
		Calls:      []Call{},
		Functions:  []Function{},
		Unresolved: []Unresolved{},
	}
}
