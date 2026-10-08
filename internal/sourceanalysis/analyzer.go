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
	Fixture            string         `json:"fixture"`
	Language           string         `json:"language"`
	HasError           bool           `json:"hasError"`
	Imports            []Import       `json:"imports"`
	Calls              []Call         `json:"calls"`
	Functions          []Function     `json:"functions"`
	RouteHandlers      []RouteHandler `json:"-"`
	AnonymousFunctions []Function     `json:"-"`
	Unresolved         []Unresolved   `json:"unresolved"`
}

type Import struct {
	Specifier string `json:"specifier"`
	Kind      string `json:"kind"`
	Local     string `json:"local"`
	Imported  string `json:"imported"`
	TypeOnly  bool   `json:"typeOnly"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`

	// InlineCalls are member calls made directly on an unbound import
	// expression, for example require("x").merge(). Internal only.
	InlineCalls []Call `json:"-"`
	// UnresolvedUse names why the imported value escapes static tracking,
	// for example a re-export or require() passed as an argument. The usage
	// graph records one unresolved call site for it so downstream components
	// cannot read the import as unused. Internal only.
	UnresolvedUse string `json:"-"`
	// BindingScopeEnd bounds a dynamic import binding to its lexical block.
	// Zero means the binding is at module level or has no block boundary.
	BindingScopeEndLine   int `json:"-"`
	BindingScopeEndColumn int `json:"-"`
}

type Call struct {
	Callee   *string `json:"callee"`
	Receiver *string `json:"receiver"`
	Line     int     `json:"line"`
	Column   int     `json:"column"`
	Note     string  `json:"note,omitempty"`
}

type Function struct {
	Name      string `json:"name"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	EndLine   int    `json:"-"`
	EndColumn int    `json:"-"`
	// NodeLine and NodeColumn locate the start of the function's own syntax
	// node (Line and Column locate its name). Anonymous ranges start at the
	// node, so this identifies a function's own range exactly. Internal only.
	NodeLine      int      `json:"-"`
	NodeColumn    int      `json:"-"`
	ExportedNames []string `json:"-"`
	Parameters    []string `json:"-"`
	LocalBindings []string `json:"-"`
	Exported      bool     `json:"exported"`
}

// RouteHandler is a statically recognised Express-style entry candidate.
type RouteHandler struct {
	Receiver  string
	Method    string
	Function  string
	Line      int
	Column    int
	EndLine   int
	EndColumn int
	Synthetic bool
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
	case strings.HasSuffix(lower, ".ts"),
		strings.HasSuffix(lower, ".mts"),
		strings.HasSuffix(lower, ".cts"):
		return "typescript", nil
	case strings.HasSuffix(lower, ".js"),
		strings.HasSuffix(lower, ".jsx"),
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
