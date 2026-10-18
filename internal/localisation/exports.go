package localisation

import (
	"fmt"
	"path"
	"strings"

	treesitter "github.com/tree-sitter/go-tree-sitter"
)

// exportTarget is what one export name of a module refers to.
type exportTarget struct {
	// Local is a top-level name in the module (a function, class or
	// variable).
	Local string
	// Module is a package file the export comes from, for
	// `x: require('./m')`, `export { a } from './m'` and the like; Member is
	// the member of that module, "" for the whole module.
	Module string
	Member string
	// Start and End are the lines of an inline function or class, as in
	// `module.exports = function () {}`.
	Start, End int
}

// binding is a top-level name bound to another package file.
type binding struct {
	Module string
	Member string // "" for the whole module
}

// identRef is one identifier occurrence, for "is this function used by
// other code in its module".
type identRef struct {
	Name string
	Line int
}

// moduleInfo is what visibility resolution needs from one file of the
// published package: what it exports, which package files it loads, and
// anything that stops its export list from being complete. The file is
// parsed, never run.
type moduleInfo struct {
	Path    string
	Symbols *FileSymbols
	// Names maps each export name to what it refers to. "*" collects
	// `export * from` re-exports.
	Names map[string][]exportTarget
	// Dynamic lists reasons the export list may be incomplete.
	Dynamic []string
	// Requires are the package files this module loads, anywhere in it.
	Requires []string
	// Bindings are top-level names bound to package files.
	Bindings map[string]binding
	// NonLiteral is set by require(expr) or import(expr): the module may
	// load any file.
	NonLiteral bool
	refs       []identRef
	// exportRefs are byte offsets of identifiers that only name an export
	// (`module.exports = { decode }`); they are not uses of the function.
	exportRefs map[uint]bool
}

// allNames lists the module's export names, without "*".
func (m *moduleInfo) allNames() []string {
	var out []string
	for name := range m.Names {
		if name != "*" {
			out = append(out, name)
		}
	}
	return out
}

// usedOutside reports whether name is referenced in the module outside the
// lines [start, end] (the function's own body) and outside export lists.
func (m *moduleInfo) usedOutside(name string, start, end int) bool {
	for _, r := range m.refs {
		if r.Name == name && (r.Line < start || r.Line > end) {
			return true
		}
	}
	return false
}

// moduleWalker analyses one file.
type moduleWalker struct {
	m     *moduleInfo
	src   []byte
	files map[string]bool
	// accounted are offsets of module.exports / exports nodes that belong
	// to a recognised export statement.
	accounted map[uint]bool
	declNames map[uint]bool
}

// analyseModule parses one package file. files is the set of package source
// paths, for resolving relative requires.
func analyseModule(p string, src []byte, files map[string]bool) (*moduleInfo, error) {
	syms, err := ParseSymbols(p, src)
	if err != nil {
		return nil, err
	}
	m := &moduleInfo{Path: p, Symbols: syms, Names: map[string][]exportTarget{}, Bindings: map[string]binding{},
		exportRefs: map[uint]bool{}}
	if syms.Minified {
		m.Dynamic = append(m.Dynamic, "minified, not analysed")
		return m, nil
	}
	lang, _, err := languageFor(p)
	if err != nil {
		return nil, err
	}
	parser := treesitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(lang); err != nil {
		return nil, fmt.Errorf("set language for %s: %w", p, err)
	}
	tree := parser.Parse(src, nil)
	if tree == nil {
		return nil, fmt.Errorf("parse %s: no tree", p)
	}
	defer tree.Close()
	root := tree.RootNode()
	if root.HasError() {
		m.Dynamic = append(m.Dynamic, "parsed with syntax errors")
	}
	w := &moduleWalker{m: m, src: src, files: files, accounted: map[uint]bool{}, declNames: map[uint]bool{}}
	count := int(root.NamedChildCount())
	for i := 0; i < count; i++ {
		w.topLevel(root.NamedChild(uint(i)))
	}
	w.scan(root)
	// An export of a name bound to another file is that file's export.
	for name, targets := range m.Names {
		for i, t := range targets {
			if b, ok := m.Bindings[t.Local]; ok && t.Local != "" {
				targets[i] = exportTarget{Module: b.Module, Member: b.Member}
			}
		}
		m.Names[name] = targets
	}
	return m, nil
}

func (w *moduleWalker) text(n *treesitter.Node) string {
	if n == nil {
		return ""
	}
	return n.Utf8Text(w.src)
}

func line(n *treesitter.Node) int { return int(n.StartPosition().Row) + 1 }

func endLine(n *treesitter.Node) int { return int(n.EndPosition().Row) + 1 }

func (w *moduleWalker) add(name string, t exportTarget) {
	if name == "" {
		return
	}
	w.m.Names[name] = append(w.m.Names[name], t)
}

func (w *moduleWalker) dynamic(format string, args ...any) {
	w.m.Dynamic = append(w.m.Dynamic, fmt.Sprintf(format, args...))
}

// literal returns the value of a string literal, or ok=false.
func (w *moduleWalker) literal(n *treesitter.Node) (string, bool) {
	if n == nil {
		return "", false
	}
	switch n.Kind() {
	case "string":
		t := w.text(n)
		if len(t) >= 2 {
			return t[1 : len(t)-1], true
		}
	case "template_string":
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if n.NamedChild(uint(i)).Kind() == "template_substitution" {
				return "", false
			}
		}
		t := w.text(n)
		if len(t) >= 2 {
			return t[1 : len(t)-1], true
		}
	}
	return "", false
}

// requireOf returns the module a `require('x')` call loads, and whether the
// node is such a call.
func (w *moduleWalker) requireOf(n *treesitter.Node) (string, bool) {
	if n == nil || n.Kind() != "call_expression" {
		return "", false
	}
	fn := n.ChildByFieldName("function")
	if fn == nil || fn.Kind() != "identifier" || w.text(fn) != "require" {
		return "", false
	}
	args := n.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() != 1 {
		return "", false
	}
	spec, ok := w.literal(args.NamedChild(0))
	if !ok {
		return "", false
	}
	return resolveModule(w.m.Path, spec, w.files), true
}

// topLevel records exports and bindings from one top-level statement.
func (w *moduleWalker) topLevel(n *treesitter.Node) {
	switch n.Kind() {
	case "expression_statement":
		if e := n.NamedChild(0); e != nil && e.Kind() == "assignment_expression" {
			w.commonJSExport(e)
		}
	case "lexical_declaration", "variable_declaration":
		for i := 0; i < int(n.NamedChildCount()); i++ {
			d := n.NamedChild(uint(i))
			if d.Kind() != "variable_declarator" {
				continue
			}
			value := d.ChildByFieldName("value")
			if value != nil && value.Kind() == "assignment_expression" {
				// const re = exports.re = []
				w.commonJSExport(value)
				continue
			}
			w.bindRequire(d.ChildByFieldName("name"), value)
		}
	case "import_statement":
		w.esmImport(n)
	case "export_statement":
		w.esmExport(n)
	}
}

// bindRequire records `const x = require('./m')`, `const { a, b: c } =
// require('./m')` and `const y = require('./m').a`.
func (w *moduleWalker) bindRequire(name, value *treesitter.Node) {
	if name == nil || value == nil {
		return
	}
	member := ""
	if value.Kind() == "member_expression" {
		member = w.text(value.ChildByFieldName("property"))
		value = value.ChildByFieldName("object")
	}
	mod, ok := w.requireOf(value)
	if !ok || mod == "" {
		return
	}
	switch name.Kind() {
	case "identifier":
		w.m.Bindings[w.text(name)] = binding{Module: mod, Member: member}
	case "object_pattern":
		for i := 0; i < int(name.NamedChildCount()); i++ {
			p := name.NamedChild(uint(i))
			switch p.Kind() {
			case "shorthand_property_identifier_pattern":
				w.m.Bindings[w.text(p)] = binding{Module: mod, Member: w.text(p)}
			case "pair_pattern":
				key := strings.Trim(w.text(p.ChildByFieldName("key")), "\"'`")
				if v := p.ChildByFieldName("value"); v != nil && v.Kind() == "identifier" {
					w.m.Bindings[w.text(v)] = binding{Module: mod, Member: key}
				}
			}
		}
	}
}

// commonJSExport handles assignments to module.exports and exports.
func (w *moduleWalker) commonJSExport(n *treesitter.Node) {
	var targets []string
	cur := n
	for cur != nil && cur.Kind() == "assignment_expression" {
		left := cur.ChildByFieldName("left")
		lt := strings.TrimSpace(w.text(left))
		if name := exportTargetName(lt); name != "" {
			targets = append(targets, name)
			w.account(left)
		} else if strings.HasPrefix(lt, "module.exports[") || strings.HasPrefix(lt, "exports[") {
			w.dynamic("computed export %s at line %d", lt, line(cur))
			w.account(left)
		}
		cur = cur.ChildByFieldName("right")
	}
	if cur == nil || len(targets) == 0 {
		return
	}
	for _, t := range targets {
		w.exportValue(t, cur)
	}
}

// exportValue records what export name refers to.
func (w *moduleWalker) exportValue(name string, v *treesitter.Node) {
	switch v.Kind() {
	case "identifier":
		w.add(name, exportTarget{Local: w.text(v)})
		w.m.exportRefs[v.StartByte()] = true
	case "function_expression", "function", "arrow_function", "generator_function", "class":
		w.add(name, exportTarget{Start: line(v), End: endLine(v)})
	case "call_expression":
		if mod, ok := w.requireOf(v); ok && mod != "" {
			w.add(name, exportTarget{Module: mod})
			return
		}
		w.dynamic("export %s is the result of a call at line %d", name, line(v))
	case "member_expression":
		if mod, ok := w.requireOf(v.ChildByFieldName("object")); ok && mod != "" {
			w.add(name, exportTarget{Module: mod, Member: w.text(v.ChildByFieldName("property"))})
			return
		}
		w.dynamic("export %s is a member expression at line %d", name, line(v))
	case "object":
		if name != "default" {
			// exports.x = { ... }: x is an object; its members are reached
			// through x, so record x as the whole object.
			w.add(name, exportTarget{Start: line(v), End: endLine(v)})
			return
		}
		for i := 0; i < int(v.NamedChildCount()); i++ {
			prop := v.NamedChild(uint(i))
			switch prop.Kind() {
			case "pair":
				key := strings.Trim(w.text(prop.ChildByFieldName("key")), "\"'`")
				if !isSimpleIdentifier(key) {
					w.dynamic("export key %s at line %d", key, line(prop))
					continue
				}
				w.exportValue(key, prop.ChildByFieldName("value"))
			case "shorthand_property_identifier":
				w.add(w.text(prop), exportTarget{Local: w.text(prop)})
				w.m.exportRefs[prop.StartByte()] = true
			case "method_definition":
				w.add(w.text(prop.ChildByFieldName("name")), exportTarget{Start: line(prop), End: endLine(prop)})
			default:
				w.dynamic("%s in the exports object at line %d", prop.Kind(), line(prop))
			}
		}
	default:
		w.dynamic("export %s is a %s at line %d", name, v.Kind(), line(v))
	}
}

func (w *moduleWalker) account(n *treesitter.Node) {
	if n == nil {
		return
	}
	w.accounted[n.StartByte()] = true
	for i := 0; i < int(n.NamedChildCount()); i++ {
		w.account(n.NamedChild(uint(i)))
	}
}

func (w *moduleWalker) esmImport(n *treesitter.Node) {
	spec, ok := w.literal(n.ChildByFieldName("source"))
	if !ok {
		return
	}
	mod := resolveModule(w.m.Path, spec, w.files)
	if mod == "" {
		return
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		clause := n.NamedChild(uint(i))
		if clause.Kind() != "import_clause" {
			continue
		}
		for j := 0; j < int(clause.NamedChildCount()); j++ {
			c := clause.NamedChild(uint(j))
			switch c.Kind() {
			case "identifier":
				w.m.Bindings[w.text(c)] = binding{Module: mod, Member: "default"}
			case "namespace_import":
				if id := c.NamedChild(0); id != nil {
					w.m.Bindings[w.text(id)] = binding{Module: mod}
				}
			case "named_imports":
				for k := 0; k < int(c.NamedChildCount()); k++ {
					s := c.NamedChild(uint(k))
					if s.Kind() != "import_specifier" {
						continue
					}
					name := w.text(s.ChildByFieldName("name"))
					alias := w.text(s.ChildByFieldName("alias"))
					if alias == "" {
						alias = name
					}
					w.m.Bindings[alias] = binding{Module: mod, Member: name}
				}
			}
		}
	}
}

func (w *moduleWalker) esmExport(n *treesitter.Node) {
	source := ""
	if spec, ok := w.literal(n.ChildByFieldName("source")); ok {
		source = resolveModule(w.m.Path, spec, w.files)
		if source == "" {
			return // a re-export from another package
		}
	}
	isDefault := hasDefaultKeyword(n)
	if decl := n.ChildByFieldName("declaration"); decl != nil {
		switch decl.Kind() {
		case "function_declaration", "generator_function_declaration", "class_declaration":
			name := w.text(decl.ChildByFieldName("name"))
			if isDefault {
				w.add("default", exportTarget{Local: name, Start: line(decl), End: endLine(decl)})
			} else {
				w.add(name, exportTarget{Local: name})
			}
		case "lexical_declaration", "variable_declaration":
			for i := 0; i < int(decl.NamedChildCount()); i++ {
				d := decl.NamedChild(uint(i))
				if d.Kind() == "variable_declarator" {
					name := w.text(d.ChildByFieldName("name"))
					w.add(name, exportTarget{Local: name})
				}
			}
		}
		return
	}
	if v := n.ChildByFieldName("value"); v != nil && isDefault {
		w.exportValue("default", v)
		return
	}
	starOnly := true
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(uint(i))
		switch c.Kind() {
		case "export_clause":
			starOnly = false
			for j := 0; j < int(c.NamedChildCount()); j++ {
				s := c.NamedChild(uint(j))
				if s.Kind() != "export_specifier" {
					continue
				}
				name := w.text(s.ChildByFieldName("name"))
				alias := w.text(s.ChildByFieldName("alias"))
				if alias == "" {
					alias = name
				}
				if source != "" {
					w.add(alias, exportTarget{Module: source, Member: name})
				} else {
					w.add(alias, exportTarget{Local: name})
					if id := s.ChildByFieldName("name"); id != nil {
						w.m.exportRefs[id.StartByte()] = true
					}
				}
			}
		case "namespace_export":
			starOnly = false
			if id := c.NamedChild(0); id != nil && source != "" {
				w.add(w.text(id), exportTarget{Module: source})
			}
		case "identifier":
			if isDefault {
				starOnly = false
				w.add("default", exportTarget{Local: w.text(c)})
				w.m.exportRefs[c.StartByte()] = true
			}
		}
	}
	if starOnly && source != "" {
		w.add("*", exportTarget{Module: source})
	}
}

// scan walks the whole tree for loads of other files, identifier uses, and
// uses of module.exports or exports that no recognised export accounts for.
func (w *moduleWalker) scan(n *treesitter.Node) {
	switch n.Kind() {
	case "call_expression":
		fn := n.ChildByFieldName("function")
		if fn != nil && (fn.Kind() == "import" || fn.Kind() == "identifier" && w.text(fn) == "require") {
			args := n.ChildByFieldName("arguments")
			if args != nil && args.NamedChildCount() == 1 {
				if spec, ok := w.literal(args.NamedChild(0)); ok {
					if mod := resolveModule(w.m.Path, spec, w.files); mod != "" {
						w.m.Requires = addEvidence(w.m.Requires, mod)
					}
				} else {
					w.m.NonLiteral = true
				}
			} else {
				w.m.NonLiteral = true
			}
		}
	case "import_statement", "export_statement":
		if spec, ok := w.literal(n.ChildByFieldName("source")); ok {
			if mod := resolveModule(w.m.Path, spec, w.files); mod != "" {
				w.m.Requires = addEvidence(w.m.Requires, mod)
			}
		}
	case "member_expression":
		if w.text(n) == "module.exports" && !w.accounted[n.StartByte()] {
			w.dynamic("module.exports used outside a plain assignment at line %d", line(n))
		}
	case "identifier":
		name := w.text(n)
		if name == "exports" && !w.accounted[n.StartByte()] {
			if p := n.Parent(); p == nil || p.Kind() != "member_expression" || w.text(p) != "module.exports" {
				w.dynamic("exports used outside a plain assignment at line %d", line(n))
			}
		}
		if !w.m.exportRefs[n.StartByte()] && !isDeclarationName(n) {
			w.m.refs = append(w.m.refs, identRef{Name: name, Line: line(n)})
		}
	case "shorthand_property_identifier":
		if !w.m.exportRefs[n.StartByte()] {
			w.m.refs = append(w.m.refs, identRef{Name: w.text(n), Line: line(n)})
		}
	}
	for i := 0; i < int(n.ChildCount()); i++ {
		w.scan(n.Child(uint(i)))
	}
}

// isDeclarationName reports whether an identifier is the name being
// declared, not a use.
func isDeclarationName(n *treesitter.Node) bool {
	p := n.Parent()
	if p == nil {
		return false
	}
	switch p.Kind() {
	case "function_declaration", "generator_function_declaration", "class_declaration",
		"function_expression", "function", "generator_function", "class", "variable_declarator":
		name := p.ChildByFieldName("name")
		return name != nil && name.StartByte() == n.StartByte()
	}
	return false
}

// resolveModule resolves a relative specifier from one package file to
// another, the way Node does for files and directories. Bare specifiers
// (other packages) and paths that leave the package resolve to "".
func resolveModule(from, spec string, files map[string]bool) string {
	if !strings.HasPrefix(spec, "./") && !strings.HasPrefix(spec, "../") && spec != "." && spec != ".." {
		return ""
	}
	p := path.Clean(path.Join(path.Dir(from), spec))
	if p == ".." || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") {
		return ""
	}
	for _, c := range []string{p, p + ".js", p + ".cjs", p + ".mjs", p + ".ts", p + ".cts", p + ".mts",
		p + "/index.js", p + "/index.cjs", p + "/index.mjs", p + "/index.ts"} {
		if files[c] {
			return c
		}
	}
	return ""
}
