package sourceanalysis

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSingleQuotedESMImport(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "app.js")
	source := "import { merge } from 'lodash';\nmerge({}, {});\n"
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := AnalyzeSource(sourcePath)
	if err != nil {
		t.Fatalf("single-quoted import failed: %v", err)
	}
	if len(result.Imports) != 1 ||
		result.Imports[0].Specifier != "lodash" ||
		result.Imports[0].Imported != "merge" {
		t.Fatalf("imports = %+v", result.Imports)
	}
}

func TestJavaScriptImportStringQuotes(t *testing.T) {
	for _, test := range []struct {
		name    string
		literal string
		want    string
	}{
		{"double", `"lodash"`, "lodash"},
		{"single", `'lodash'`, "lodash"},
		{"escaped apostrophe", `'some\'pkg'`, "some'pkg"},
		{"double quote inside single", `'some"pkg'`, `some"pkg`},
		{"escaped backslash", `'some\\pkg'`, `some\pkg`},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := unquoteJavaScriptString(test.literal)
			if err != nil || got != test.want {
				t.Fatalf("unquote %q = %q, %v; want %q",
					test.literal, got, err, test.want)
			}
		})
	}
}

func TestJavaScriptStringEscapesMatchModuleNames(t *testing.T) {
	for _, test := range []struct {
		literal string
		want    string
	}{
		{`'lod\ash'`, "lodash"},
		{`'lod\u{61}sh'`, "lodash"},
		{`"lod\u{61}sh"`, "lodash"},
		{`'lod\x61sh'`, "lodash"},
		{`'lod\ash\u{61}'`, "lodasha"},
	} {
		got, err := unquoteJavaScriptString(test.literal)
		if err != nil || got != test.want {
			t.Errorf("unquote %q = %q, %v; want %q",
				test.literal, got, err, test.want)
		}
	}
}
