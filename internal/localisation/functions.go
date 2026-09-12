package localisation

import (
	"fmt"
	"path"
	"sort"
	"strings"

	treesitter "github.com/tree-sitter/go-tree-sitter"
	javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	typescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"
)

// FunctionSpan is a function-like declaration and the lines it covers.
type FunctionSpan struct {
	// Name is the resolved name. Anonymous functions assigned to
	// module.exports or exported as default are named "default", matching the
	// usage-graph convention for whole-module bindings.
	Name string
	// Aliases are other names the same function is known by in this file:
	// a named function expression's own name, or export aliases.
	Aliases []string
	// Kind is function, generator, method, class, arrow or function_expression.
	Kind string
	// Class is the enclosing class for methods.
	Class     string
	StartLine int // 1-based, inclusive
	EndLine   int // 1-based, inclusive
	Depth     int // number of function-like ancestors
	Anonymous bool
}

// Declaration is a module-level declaration that is not a function, such as a
// regex constant. Changes to these are recorded but are not candidates.
type Declaration struct {
	Name      string
	StartLine int
	EndLine   int
}

// FileSymbols is what the parser knows about one source file.
type FileSymbols struct {
	Path      string
	Language  string
	HasError  bool
	Minified  bool
	Functions []FunctionSpan
	// Exports maps an internal name to the names it is exported under.
	// "default" marks module.exports = name or export default name.
	Exports      map[string][]string
	Declarations []Declaration
}

// Source-file limits. Files beyond them are reported, never silently skipped.
const (
	maxSourceBytes    = 4 << 20 // lodash.js is ~540 KB; bundles up to a few MB
	minifiedLineBytes = 4000    // any single line longer than this marks the file minified
)

// SupportedSourceFile reports whether the path is JavaScript or TypeScript
// source this package can parse. Declaration files carry no code.
func SupportedSourceFile(p string) bool {
	lower := strings.ToLower(p)
	if strings.HasSuffix(lower, ".d.ts") || strings.HasSuffix(lower, ".d.mts") || strings.HasSuffix(lower, ".d.cts") {
		return false
	}
	switch path.Ext(lower) {
	case ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx":
		return true
	}
	return false
}

func languageFor(p string) (*treesitter.Language, string, error) {
	lower := strings.ToLower(p)
	switch path.Ext(lower) {
	case ".js", ".mjs", ".cjs", ".jsx":
		return treesitter.NewLanguage(javascript.Language()), "javascript", nil
	case ".ts", ".mts", ".cts":
		return treesitter.NewLanguage(typescript.LanguageTypescript()), "typescript", nil
	case ".tsx":
		return treesitter.NewLanguage(typescript.LanguageTSX()), "tsx", nil
	}
	return nil, "", fmt.Errorf("unsupported source file %q", p)
}

// ParseSymbols parses one source file and collects its function spans,
// export aliases and module-level declarations. The source is parsed, never
// evaluated. Syntax errors do not stop extraction; HasError records them.
func ParseSymbols(p string, source []byte) (*FileSymbols, error) {
	if !SupportedSourceFile(p) {
		return nil, fmt.Errorf("unsupported source file %q", p)
	}
	if len(source) > maxSourceBytes {
		return nil, fmt.Errorf("%s: %d bytes exceeds the %d byte source limit", p, len(source), maxSourceBytes)
	}
	fs := &FileSymbols{Path: p, Exports: map[string][]string{}}
	if isMinifiedName(p) || isMinified(source) {
		fs.Minified = true
		return fs, nil
	}
	lang, name, err := languageFor(p)
	if err != nil {
		return nil, err
	}
	fs.Language = name

	parser := treesitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(lang); err != nil {
		return nil, fmt.Errorf("set language for %s: %w", p, err)
	}
	tree := parser.Parse(source, nil)
	if tree == nil {
		return nil, fmt.Errorf("parse %s: no tree", p)
	}
	defer tree.Close()
	root := tree.RootNode()
	fs.HasError = root.HasError()

	w := &symbolWalker{fs: fs, src: source}
	w.walk(root, 0, "")
	sort.SliceStable(fs.Functions, func(i, j int) bool {
		if fs.Functions[i].StartLine != fs.Functions[j].StartLine {
			return fs.Functions[i].StartLine < fs.Functions[j].StartLine
		}
		return fs.Functions[i].Depth < fs.Functions[j].Depth
	})
	return fs, nil
}

// isMinifiedName catches build artefacts by name; their identifiers are
// meaningless to an application and would only add noise.
func isMinifiedName(p string) bool {
	lower := strings.ToLower(p)
	return strings.HasSuffix(lower, ".min.js") || strings.HasSuffix(lower, ".min.mjs") || strings.HasSuffix(lower, ".min.cjs")
}

func isMinified(src []byte) bool {
	run := 0
	for _, c := range src {
		if c == '\n' {
			run = 0
			continue
		}
		run++
		if run > minifiedLineBytes {
			return true
		}
	}
	return false
}

// EnclosingFunction returns the innermost named function span containing the
// line, or nil when the line is at module level or only inside anonymous
// wrappers (for example lodash's IIFE).
func (fs *FileSymbols) EnclosingFunction(line int) *FunctionSpan {
	var best *FunctionSpan
	for i := range fs.Functions {
		f := &fs.Functions[i]
		if f.Anonymous || line < f.StartLine || line > f.EndLine {
			continue
		}
		if best == nil || f.Depth > best.Depth || (f.Depth == best.Depth && f.StartLine >= best.StartLine) {
			best = f
		}
	}
	return best
}

// EnclosingDeclaration returns the module-level non-function declaration
// containing the line, if any.
func (fs *FileSymbols) EnclosingDeclaration(line int) *Declaration {
	for i := range fs.Declarations {
		d := &fs.Declarations[i]
		if line >= d.StartLine && line <= d.EndLine {
			return d
		}
	}
	return nil
}

// ExportedNames returns the public names for an internal function name,
// including the name itself when it is exported directly.
func (fs *FileSymbols) ExportedNames(internal string) []string {
	return fs.Exports[internal]
}

type symbolWalker struct {
	fs  *FileSymbols
	src []byte
}

func (w *symbolWalker) text(n *treesitter.Node) string {
	if n == nil {
		return ""
	}
	return n.Utf8Text(w.src)
}

func (w *symbolWalker) walk(n *treesitter.Node, depth int, class string) {
	if n == nil {
		return
	}
	kind := n.Kind()
	childDepth := depth
	childClass := class

	switch kind {
	case "function_declaration", "generator_function_declaration":
		name := w.text(n.ChildByFieldName("name"))
		span := w.span(n, name, "function", class, depth, name == "")
		if n.Parent() != nil && n.Parent().Kind() == "export_statement" {
			w.addExport(name, w.exportName(n.Parent(), name))
		}
		w.fs.Functions = append(w.fs.Functions, span)
		childDepth = depth + 1

	case "class_declaration", "class":
		name := w.text(n.ChildByFieldName("name"))
		if name == "" {
			name = w.nameFromParent(n)
		}
		if name != "" {
			w.fs.Functions = append(w.fs.Functions, w.span(n, name, "class", class, depth, false))
		}
		if n.Parent() != nil && n.Parent().Kind() == "export_statement" && name != "" {
			w.addExport(name, w.exportName(n.Parent(), name))
		}
		childClass = name

	case "method_definition":
		name := w.text(n.ChildByFieldName("name"))
		w.fs.Functions = append(w.fs.Functions, w.span(n, name, "method", class, depth, name == ""))
		childDepth = depth + 1

	case "function_expression", "function", "arrow_function", "generator_function":
		name := w.nameFromParent(n)
		own := w.text(n.ChildByFieldName("name"))
		anonymous := name == ""
		if anonymous && own != "" {
			name, anonymous = own, false
		}
		k := "function_expression"
		if kind == "arrow_function" {
			k = "arrow"
		}
		span := w.span(n, name, k, class, depth, anonymous)
		if own != "" && own != name {
			span.Aliases = append(span.Aliases, own)
		}
		w.fs.Functions = append(w.fs.Functions, span)
		childDepth = depth + 1

	case "assignment_expression":
		w.recordCommonJSExport(n)

	case "export_statement":
		w.recordESMExport(n)

	case "variable_declarator":
		// Module-level declarations that are not functions: regex constants,
		// error strings. Only at depth 0 to keep the list meaningful.
		if depth == 0 {
			value := n.ChildByFieldName("value")
			if value != nil && !isFunctionLike(value.Kind()) {
				name := w.text(n.ChildByFieldName("name"))
				if isSimpleIdentifier(name) {
					w.fs.Declarations = append(w.fs.Declarations, Declaration{
						Name:      name,
						StartLine: int(n.StartPosition().Row) + 1,
						EndLine:   int(n.EndPosition().Row) + 1,
					})
				}
			}
		}
	}

	count := int(n.ChildCount())
	for i := 0; i < count; i++ {
		w.walk(n.Child(uint(i)), childDepth, childClass)
	}
}

func isFunctionLike(kind string) bool {
	switch kind {
	case "function_expression", "function", "arrow_function", "generator_function",
		"function_declaration", "generator_function_declaration", "class", "class_declaration":
		return true
	}
	return false
}

func (w *symbolWalker) span(n *treesitter.Node, name, kind, class string, depth int, anonymous bool) FunctionSpan {
	return FunctionSpan{
		Name:      name,
		Kind:      kind,
		Class:     class,
		StartLine: int(n.StartPosition().Row) + 1,
		EndLine:   int(n.EndPosition().Row) + 1,
		Depth:     depth,
		Anonymous: anonymous,
	}
}

// nameFromParent resolves the name of a function expression, arrow function
// or class expression from how it is bound.
func (w *symbolWalker) nameFromParent(n *treesitter.Node) string {
	p := n.Parent()
	if p == nil {
		return ""
	}
	switch p.Kind() {
	case "variable_declarator":
		return w.text(p.ChildByFieldName("name"))
	case "assignment_expression":
		left := w.text(p.ChildByFieldName("left"))
		return nameFromAssignmentTarget(left)
	case "pair":
		key := w.text(p.ChildByFieldName("key"))
		return strings.Trim(key, "\"'`")
	case "export_statement":
		if hasDefaultKeyword(p) {
			return "default"
		}
	case "parenthesized_expression":
		return w.nameFromParent(p)
	}
	return ""
}

// nameFromAssignmentTarget maps assignment targets to a symbol name:
//
//	module.exports        -> default
//	exports.parse         -> parse
//	module.exports.parse  -> parse
//	Range.prototype.test  -> test
//	obj.method            -> method
//	name                  -> name
func nameFromAssignmentTarget(left string) string {
	left = strings.TrimSpace(left)
	switch left {
	case "module.exports", "exports":
		return "default"
	}
	if strings.HasPrefix(left, "module.exports.") {
		return strings.TrimPrefix(left, "module.exports.")
	}
	if strings.HasPrefix(left, "exports.") {
		return strings.TrimPrefix(left, "exports.")
	}
	if i := strings.LastIndex(left, "."); i >= 0 {
		left = left[i+1:]
	}
	if !isSimpleIdentifier(left) {
		return "" // computed members such as prototype[n]
	}
	return left
}

// isSimpleIdentifier accepts plain JavaScript identifiers only, so
// destructuring patterns and computed members never become symbol names.
func isSimpleIdentifier(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_' || r == '$' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

func hasDefaultKeyword(n *treesitter.Node) bool {
	count := int(n.ChildCount())
	for i := 0; i < count; i++ {
		if n.Child(uint(i)).Kind() == "default" {
			return true
		}
	}
	return false
}

func (w *symbolWalker) exportName(exportStmt *treesitter.Node, internal string) string {
	if hasDefaultKeyword(exportStmt) {
		return "default"
	}
	return internal
}

func (w *symbolWalker) addExport(internal, public string) {
	if internal == "" || public == "" {
		return
	}
	for _, existing := range w.fs.Exports[internal] {
		if existing == public {
			return
		}
	}
	w.fs.Exports[internal] = append(w.fs.Exports[internal], public)
}

// recordCommonJSExport handles:
//
//	module.exports = decode
//	exports.parse = exports.decode = decode        (chained)
//	module.exports = { parse: decode, encode }
//	exports.parse = function decode () {}          (function span named by parent)
func (w *symbolWalker) recordCommonJSExport(n *treesitter.Node) {
	var targets []string
	cur := n
	for cur != nil && cur.Kind() == "assignment_expression" {
		left := w.text(cur.ChildByFieldName("left"))
		if name := exportTargetName(left); name != "" {
			targets = append(targets, name)
		}
		cur = cur.ChildByFieldName("right")
	}
	if cur == nil || len(targets) == 0 {
		return
	}
	switch cur.Kind() {
	case "identifier":
		for _, t := range targets {
			w.addExport(w.text(cur), t)
		}
	case "object":
		// module.exports = { parse: decode, encode }
		count := int(cur.NamedChildCount())
		for i := 0; i < count; i++ {
			prop := cur.NamedChild(uint(i))
			switch prop.Kind() {
			case "pair":
				key := strings.Trim(w.text(prop.ChildByFieldName("key")), "\"'`")
				value := prop.ChildByFieldName("value")
				if value != nil && value.Kind() == "identifier" {
					w.addExport(w.text(value), key)
				} else if value != nil && isFunctionLike(value.Kind()) {
					w.addExport(key, key)
				}
			case "shorthand_property_identifier":
				name := w.text(prop)
				w.addExport(name, name)
			}
		}
	default:
		// exports.parse = function () {} — the function span itself is named
		// by nameFromParent; record it as exported under that name.
		if isFunctionLike(cur.Kind()) {
			for _, t := range targets {
				w.addExport(t, t)
			}
		}
	}
}

// exportTargetName returns the public name for an assignment target that is an
// export, or "" when the target is not an export.
func exportTargetName(left string) string {
	left = strings.TrimSpace(left)
	switch {
	case left == "module.exports" || left == "exports":
		return "default"
	case strings.HasPrefix(left, "module.exports."):
		return strings.TrimPrefix(left, "module.exports.")
	case strings.HasPrefix(left, "exports."):
		return strings.TrimPrefix(left, "exports.")
	}
	return ""
}

// recordESMExport handles:
//
//	export default decode
//	export { decode as parse, encode }
//	export default function () {}   (span named "default" by nameFromParent)
func (w *symbolWalker) recordESMExport(n *treesitter.Node) {
	isDefault := hasDefaultKeyword(n)
	count := int(n.NamedChildCount())
	for i := 0; i < count; i++ {
		c := n.NamedChild(uint(i))
		switch c.Kind() {
		case "identifier":
			if isDefault {
				w.addExport(w.text(c), "default")
			}
		case "export_clause":
			specs := int(c.NamedChildCount())
			for j := 0; j < specs; j++ {
				spec := c.NamedChild(uint(j))
				if spec.Kind() != "export_specifier" {
					continue
				}
				name := w.text(spec.ChildByFieldName("name"))
				alias := w.text(spec.ChildByFieldName("alias"))
				if alias == "" {
					alias = name
				}
				w.addExport(name, alias)
			}
		}
	}
}
