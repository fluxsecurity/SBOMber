package localisation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadFixture(t *testing.T, name string) *FileSymbols {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := ParseSymbols(name, src)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return fs
}

func lineOf(t *testing.T, name, needle string) int {
	t.Helper()
	src, _ := os.ReadFile(filepath.Join("testdata", name))
	for i, l := range strings.Split(string(src), "\n") {
		if strings.Contains(l, needle) {
			return i + 1
		}
	}
	t.Fatalf("%s: %q not found", name, needle)
	return 0
}

func TestEnclosingFunction_ChainedCommonJSExportAlias(t *testing.T) {
	fs := loadFixture(t, "ini_like.js")
	fn := fs.EnclosingFunction(lineOf(t, "ini_like.js", "if (line === '__proto__') return"))
	if fn == nil || fn.Name != "decode" {
		t.Fatalf("expected decode, got %+v", fn)
	}
	got := fs.ExportedNames("decode")
	if len(got) != 2 || got[0] != "parse" || got[1] != "decode" {
		t.Errorf("exports of decode = %v, want [parse decode]", got)
	}
	if fs.ExportedNames("encode")[0] != "stringify" {
		t.Errorf("exports of encode = %v", fs.ExportedNames("encode"))
	}
}

func TestEnclosingFunction_NestedInsideAnonymousDefaultExport(t *testing.T) {
	fs := loadFixture(t, "minimist_like.js")
	fn := fs.EnclosingFunction(lineOf(t, "minimist_like.js", "if (key === '__proto__') return;"))
	if fn == nil || fn.Name != "setKey" {
		t.Fatalf("expected setKey (skipping the forEach callback), got %+v", fn)
	}
	outer := fs.EnclosingFunction(lineOf(t, "minimist_like.js", "var argv = { _: [] };"))
	if outer == nil || outer.Name != "default" {
		t.Fatalf("module.exports = function should be named default, got %+v", outer)
	}
}

func TestEnclosingFunction_AnonymousArrowAssignedToModuleExports(t *testing.T) {
	fs := loadFixture(t, "ansi_regex_like.js")
	fn := fs.EnclosingFunction(lineOf(t, "ansi_regex_like.js", "u0007"))
	if fn == nil || fn.Name != "default" || fn.Kind != "arrow" {
		t.Fatalf("expected default arrow, got %+v", fn)
	}
}

func TestEnclosingFunction_DoublyNamedFunctionExpression(t *testing.T) {
	fs := loadFixture(t, "qs_like.js")
	fn := fs.EnclosingFunction(lineOf(t, "qs_like.js", "chain[0] !== '__proto__'"))
	if fn == nil || fn.Name != "parseObject" {
		t.Fatalf("expected parseObject, got %+v", fn)
	}
	if len(fn.Aliases) != 1 || fn.Aliases[0] != "parseObjectRecursive" {
		t.Errorf("aliases = %v, want [parseObjectRecursive]", fn.Aliases)
	}
	if fs.ExportedNames("parseObject") != nil {
		t.Errorf("parseObject is private, got exports %v", fs.ExportedNames("parseObject"))
	}
}

func TestEnclosingFunction_ClassMethodsAndModuleArrows(t *testing.T) {
	fs := loadFixture(t, "semver_like.js")
	ctor := fs.EnclosingFunction(lineOf(t, "semver_like.js", "this.raw = range.trim()"))
	if ctor == nil || ctor.Name != "constructor" || ctor.Class != "Range" {
		t.Fatalf("expected Range constructor, got %+v", ctor)
	}
	m := fs.EnclosingFunction(lineOf(t, "semver_like.js", "return range.split(' ')"))
	if m == nil || m.Name != "parseRange" || m.Class != "Range" {
		t.Fatalf("expected Range.parseRange, got %+v", m)
	}
	arrow := fs.EnclosingFunction(lineOf(t, "semver_like.js", "replaceTilde(c, options)"))
	if arrow == nil || arrow.Name != "replaceTildes" {
		t.Fatalf("expected replaceTildes, got %+v", arrow)
	}
	if exp := fs.ExportedNames("Range"); len(exp) != 1 || exp[0] != "default" {
		t.Errorf("Range exports = %v, want [default]", exp)
	}
}

func TestEnclosingFunction_SkipsIIFEWrapperAndFindsInnerFunction(t *testing.T) {
	fs := loadFixture(t, "lodash_like.js")
	fn := fs.EnclosingFunction(lineOf(t, "lodash_like.js", "reForbiddenIdentifierChars.test(variable)"))
	if fn == nil || fn.Name != "template" {
		t.Fatalf("expected template, got %+v", fn)
	}
	if fs.EnclosingFunction(lineOf(t, "lodash_like.js", "var reForbiddenIdentifierChars")) != nil {
		t.Error("a module-level regex inside the IIFE must not be attributed to a function")
	}
	// The IIFE is anonymous, so nothing named encloses the top-level declaration
	// and it should not be reported as a Declaration either (depth 1 inside the IIFE).
}

func TestParseSymbols_ESMDefaultAndAliasedExports(t *testing.T) {
	fs := loadFixture(t, "esm_like.mjs")
	fn := fs.EnclosingFunction(lineOf(t, "esm_like.mjs", "throw new Error('blocked')"))
	if fn == nil || fn.Name != "fetch" {
		t.Fatalf("expected fetch, got %+v", fn)
	}
	if exp := fs.ExportedNames("fetch"); len(exp) != 1 || exp[0] != "default" {
		t.Errorf("fetch exports = %v, want [default]", exp)
	}
	if exp := fs.ExportedNames("helper"); len(exp) != 1 || exp[0] != "publicHelper" {
		t.Errorf("helper exports = %v, want [publicHelper]", exp)
	}
	get := fs.EnclosingFunction(lineOf(t, "esm_like.mjs", "return name;"))
	if get == nil || get.Name != "get" || get.Class != "Headers" {
		t.Fatalf("expected Headers.get, got %+v", get)
	}
	if exp := fs.ExportedNames("Headers"); len(exp) != 1 || exp[0] != "Headers" {
		t.Errorf("Headers exports = %v", exp)
	}
}

// Failure path: a file with syntax errors still yields spans and reports the error.
func TestParseSymbols_SyntaxErrorsAreReportedNotFatal(t *testing.T) {
	src := []byte("function ok() { return 1 }\nfunction broken( { \n  return 2\n")
	fs, err := ParseSymbols("broken.js", src)
	if err != nil {
		t.Fatal(err)
	}
	if !fs.HasError {
		t.Error("expected HasError")
	}
	if fn := fs.EnclosingFunction(1); fn == nil || fn.Name != "ok" {
		t.Errorf("expected ok, got %+v", fn)
	}
}

// Boundary / untrusted input: declaration files, oversized files, minified
// files and unsupported extensions are refused or flagged, never parsed blind.
func TestParseSymbols_Boundaries(t *testing.T) {
	if _, err := ParseSymbols("types.d.ts", []byte("export declare function f(): void;")); err == nil {
		t.Error("declaration files carry no code and must be rejected")
	}
	if _, err := ParseSymbols("image.png", []byte{0x89, 'P', 'N', 'G'}); err == nil {
		t.Error("unsupported extension must be rejected")
	}
	big := make([]byte, maxSourceBytes+1)
	if _, err := ParseSymbols("big.js", big); err == nil {
		t.Error("oversized source must be rejected")
	}
	min := []byte("var a=1;" + strings.Repeat("a=a+1;", 1000))
	fs, err := ParseSymbols("lib.min.js", min)
	if err != nil {
		t.Fatal(err)
	}
	if !fs.Minified || len(fs.Functions) != 0 {
		t.Errorf("minified file should be flagged and not attributed, got %+v", fs)
	}
	empty, err := ParseSymbols("empty.js", nil)
	if err != nil || len(empty.Functions) != 0 {
		t.Errorf("empty file: %v %+v", err, empty)
	}
}
