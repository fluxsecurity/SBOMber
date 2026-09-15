package sourceanalysis

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnquoteJavaScriptString(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "double-quoted", value: `"lodash"`, want: "lodash"},
		// strconv.Unquote treats a single-quoted value as a Go rune
		// literal, which only accepts exactly one character — this is
		// the overwhelmingly common case for import specifiers and was
		// silently broken before this fix.
		{name: "single-quoted, multi-character", value: `'lodash'`, want: "lodash"},
		{name: "single-quoted, package subpath", value: `'lodash/template'`, want: "lodash/template"},
		{name: "single-quoted, scoped package", value: `'@babel/parser'`, want: "@babel/parser"},
		{name: "single-quoted, single character", value: `'a'`, want: "a"},
		{name: "backtick-quoted", value: "`lodash`", want: "lodash"},
		{name: "escaped single quote inside single-quoted string", value: `'it\'s-fine'`, want: "it's-fine"},
		{name: "escaped double quote inside double-quoted string", value: `"say \"hi\""`, want: `say "hi"`},
		{name: "escaped backslash", value: `'a\\b'`, want: `a\b`},
		{name: "mismatched quotes", value: `'lodash"`, wantErr: true},
		{name: "too short", value: `'`, wantErr: true},
		{name: "empty", value: ``, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unquoteJavaScriptString(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("unquoteJavaScriptString(%q) = %q, want an error", tt.value, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unquoteJavaScriptString(%q) returned error: %v", tt.value, err)
			}
			if got != tt.want {
				t.Errorf("unquoteJavaScriptString(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

// TestSingleQuotedImportsAreExtracted proves the fix end-to-end: a file
// using single-quoted specifiers — Prettier's default, and what the
// Standard and Airbnb style guides both use — previously failed extraction
// entirely rather than just mis-parsing one field, because
// unquoteJavaScriptString returned an error that aborted the whole file.
func TestSingleQuotedImportsAreExtracted(t *testing.T) {
	src := "import defaultExport from 'left-pad';\n" +
		"import { named } from 'lodash/template';\n" +
		"const pkg = require('axios');\n"

	dir := t.TempDir()
	path := filepath.Join(dir, "single-quotes.js")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	result, err := AnalyzeSource(path)
	if err != nil {
		t.Fatalf("AnalyzeSource returned error for single-quoted imports: %v", err)
	}
	if result.HasError {
		t.Fatal("result.HasError = true for syntactically valid single-quoted source")
	}

	specifiers := make(map[string]bool, len(result.Imports))
	for _, imp := range result.Imports {
		specifiers[imp.Specifier] = true
	}

	for _, want := range []string{"left-pad", "lodash/template", "axios"} {
		if !specifiers[want] {
			t.Errorf("expected specifier %q to be extracted, got imports: %+v", want, result.Imports)
		}
	}
	if len(result.Imports) != 3 {
		t.Errorf("expected 3 imports, got %d: %+v", len(result.Imports), result.Imports)
	}
}
