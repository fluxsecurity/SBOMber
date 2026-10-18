package localisation

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Visibility fields of the localisation join rule
// (docs/design/localisation-join-rule.md). Component 4 reads them: a
// candidate set is closed, and so can support no_usage_detected, only when
// every candidate is public or internal with a complete, code-derived list of
// the public names it is reached through.
const (
	VisibilityPublic   = "public"
	VisibilityInternal = "internal"
	VisibilityUnknown  = "unknown"

	ExposedViaExportResolution = "export_resolution"
)

// packageModel is the published vulnerable package, statically: its entry
// module, which files can be imported directly, and every file's exports and
// imports. Nothing in it is run.
type packageModel struct {
	entry string
	mods  map[string]*moduleInfo
	// deep is true when any file can be imported by path
	// (require('pkg/lib/x')): no "exports" map, or one with a pattern.
	deep bool
	// subpaths are the files an "exports" map makes importable by path.
	subpaths map[string]bool
	// importers maps a file to the files that load it.
	importers map[string][]string
	// definers maps a function name to the files that define one.
	definers map[string][]string
	// problems stop every candidate's routes from being complete.
	problems []string
}

type manifest struct {
	Main    string          `json:"main"`
	Module  string          `json:"module"`
	Browser json.RawMessage `json:"browser"`
	Exports json.RawMessage `json:"exports"`
}

// buildPackageModel analyses a verified tarball. An error means visibility
// cannot be resolved at all.
func buildPackageModel(tb *Tarball) (*packageModel, error) {
	if len(tb.Manifest) == 0 {
		return nil, fmt.Errorf("the tarball has no package.json")
	}
	var man manifest
	if err := json.Unmarshal(tb.Manifest, &man); err != nil {
		return nil, fmt.Errorf("package.json: %w", err)
	}
	files := map[string]bool{}
	for p := range tb.Files {
		files[p] = true
	}
	pm := &packageModel{mods: map[string]*moduleInfo{}, subpaths: map[string]bool{},
		importers: map[string][]string{}, definers: map[string][]string{}}

	entrySpec := man.Main
	if entrySpec == "" {
		entrySpec = "index.js"
	}
	if len(man.Exports) > 0 && string(man.Exports) != "null" {
		dot, subs, pattern, err := parseExportsMap(man.Exports)
		if err != nil {
			return nil, err
		}
		if dot != "" {
			entrySpec = dot
		}
		pm.deep = pattern
		if exportsUnresolved(man.Exports) {
			pm.problems = append(pm.problems, "package.json exports has alternate or unsupported targets")
		}
		for _, s := range subs {
			if f := resolveModule("package.json", "./"+strings.TrimPrefix(s, "./"), files); f != "" {
				pm.subpaths[f] = true
			}
		}
	} else {
		pm.deep = true
	}
	pm.entry = resolveModule("package.json", "./"+strings.TrimPrefix(entrySpec, "./"), files)
	if pm.entry == "" {
		return nil, fmt.Errorf("entry module %q is not a source file in the package", entrySpec)
	}
	if man.Module != "" {
		if alt := resolveModule("package.json", "./"+strings.TrimPrefix(man.Module, "./"), files); alt != pm.entry {
			pm.problems = append(pm.problems, "package.json names a separate \"module\" entry for bundlers ("+man.Module+")")
		}
	}
	if len(man.Browser) > 0 && string(man.Browser) != "null" && string(man.Browser) != "false" {
		pm.problems = append(pm.problems, "package.json remaps files for browsers")
	}

	for _, skipped := range tb.Skipped {
		if SupportedSourceFile(strings.Split(skipped, " (")[0]) {
			pm.problems = append(pm.problems, "package source was skipped: "+skipped)
		}
	}
	paths := make([]string, 0, len(tb.Files))
	for p := range tb.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		m, err := analyseModule(p, tb.Files[p], files)
		if err != nil {
			pm.problems = append(pm.problems, p+" could not be analysed")
			continue
		}
		pm.mods[p] = m
		if m.Symbols.Minified || m.Symbols.HasError {
			pm.problems = append(pm.problems, p+" is not fully parsed")
		}
		if m.NonLiteral {
			pm.problems = append(pm.problems, p+" loads a module by a computed path")
		}
		for _, r := range m.Requires {
			pm.importers[r] = addEvidence(pm.importers[r], p)
		}
		for _, f := range m.Symbols.Functions {
			if !f.Anonymous && f.Name != "" && f.Name != "default" {
				pm.definers[f.Name] = addEvidence(pm.definers[f.Name], p)
			}
		}
	}
	return pm, nil
}

// parseExportsMap reads package.json "exports": the "." target, explicit
// subpath targets, and whether any subpath is a pattern.
func parseExportsMap(raw json.RawMessage) (dot string, subs []string, pattern bool, err error) {
	var any interface{}
	if err := json.Unmarshal(raw, &any); err != nil {
		return "", nil, false, fmt.Errorf("package.json exports: %w", err)
	}
	switch v := any.(type) {
	case string:
		return v, nil, false, nil
	case map[string]interface{}:
		subpathKeys := false
		for k := range v {
			if strings.HasPrefix(k, ".") {
				subpathKeys = true
			}
		}
		if !subpathKeys {
			return conditionTarget(v), nil, false, nil
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			target := ""
			switch t := v[k].(type) {
			case string:
				target = t
			case map[string]interface{}:
				target = conditionTarget(t)
			}
			if strings.Contains(k, "*") || strings.HasSuffix(k, "/") {
				pattern = true
				continue
			}
			if k == "." {
				dot = target
			} else if target != "" {
				subs = append(subs, target)
			}
		}
		return dot, subs, pattern, nil
	}
	return "", nil, false, nil
}

// conditionTarget picks the CommonJS target from a conditions object.
func conditionTarget(c map[string]interface{}) string {
	for _, k := range []string{"require", "node", "default", "import"} {
		switch t := c[k].(type) {
		case string:
			return t
		case map[string]interface{}:
			if s := conditionTarget(t); s != "" {
				return s
			}
		}
	}
	return ""
}

// candidateVisibility is the resolved join-rule fields for one candidate.
type candidateVisibility struct {
	Visibility string
	ExposedVia []string
	Complete   bool
	Why        string
}

// resolve places one candidate. modulePath is the candidate's file in the
// published package.
func (pm *packageModel) resolve(symbol, modulePath string) candidateVisibility {
	unknown := func(why string) candidateVisibility {
		return candidateVisibility{Visibility: VisibilityUnknown, Why: why}
	}
	m := pm.mods[modulePath]
	if m == nil {
		return unknown(modulePath + " is not in the published vulnerable package")
	}
	if len(m.Dynamic) > 0 && strings.HasPrefix(m.Dynamic[0], "minified") {
		return unknown(modulePath + " is minified")
	}

	// The candidate's own spans, or the function an export name points to.
	var spans []FunctionSpan
	for _, f := range m.Symbols.Functions {
		if f.Name == symbol || contains(f.Aliases, symbol) {
			spans = append(spans, f)
		}
	}
	if len(spans) == 0 {
		for _, t := range m.Names[symbol] {
			for _, f := range m.Symbols.Functions {
				if t.Local != "" && f.Name == t.Local || t.Start != 0 && f.StartLine == t.Start && f.EndLine == t.End {
					spans = append(spans, f)
				}
			}
		}
	}
	if len(spans) == 0 {
		return unknown(symbol + " is not defined in " + modulePath + " in the published package")
	}

	// Each span's owner is the outermost top-level function or class around
	// it: code nested in a function is reached only through that function.
	var why []string
	loadTime := false
	ownOnly := true
	var moduleNames []string
	for _, s := range spans {
		o := pm.owner(m, s)
		for _, ref := range m.refs {
			if ref.LoadTime && (ref.Name == o.Name || contains(o.Aliases, ref.Name)) {
				loadTime = true
			}
		}
		names, own, reason := pm.ownerNames(m, o)
		ownOnly = ownOnly && own && o.StartLine == s.StartLine && o.EndLine == s.EndLine
		if reason != "" {
			why = append(why, reason)
		}
		moduleNames = addEvidence(moduleNames, names...)
	}
	if len(moduleNames) == 0 {
		switch {
		case len(m.Dynamic) > 0:
			return unknown("the exports of " + modulePath + " could not be resolved statically: " + m.Dynamic[0])
		case modulePath == pm.entry || len(pm.importers[modulePath]) > 0:
			return unknown("the exports of " + modulePath + " could not be resolved statically")
		}
		return unknown(modulePath + " exports nothing, so " + symbol + " runs only when the file is loaded")
	}

	public, complete, routeWhy := pm.publicNames(m, moduleNames)
	why = append(why, routeWhy...)
	if loadTime {
		complete = false
		why = append(why, "candidate owner is referenced during module initialisation")
	}
	if others := without(pm.definers[symbol], modulePath); len(others) > 0 {
		complete = false
		why = append(why, "another copy of "+symbol+" is in "+strings.Join(others, ", "))
	}
	if len(pm.problems) > 0 {
		complete = false
		why = append(why, pm.problems...)
	}
	sort.Strings(public)
	if len(public) == 0 {
		return unknown(symbol + " has no route to a public name")
	}
	if ownOnly && complete && len(spans) == 1 && len(public) == 1 && public[0] == symbol {
		return candidateVisibility{Visibility: VisibilityPublic, Complete: true, Why: "exported as " + strings.Join(public, ", ")}
	}
	return candidateVisibility{Visibility: VisibilityInternal, ExposedVia: public, Complete: complete,
		Why: strings.Join(why, "; ")}
}

// owner returns the outermost depth-0 span containing s.
func (pm *packageModel) owner(m *moduleInfo, s FunctionSpan) FunctionSpan {
	best := s
	for _, f := range m.Symbols.Functions {
		if f.Depth == 0 && f.StartLine <= s.StartLine && f.EndLine >= s.EndLine &&
			(f.EndLine-f.StartLine > best.EndLine-best.StartLine || best.Depth > 0) {
			best = f
		}
	}
	return best
}

// ownerNames lists the module's export names that reach a top-level owner.
// When the owner is exported and nothing else in the module uses it, those
// are its own export names (own=true). Otherwise any export of the module
// may reach it, so all of them are listed.
func (pm *packageModel) ownerNames(m *moduleInfo, o FunctionSpan) (names []string, own bool, why string) {
	for name, targets := range m.Names {
		for _, t := range targets {
			if t.Local != "" && (t.Local == o.Name || contains(o.Aliases, t.Local)) ||
				t.Start != 0 && t.Start == o.StartLine && t.End == o.EndLine {
				names = addEvidence(names, name)
			}
		}
	}
	used := false
	if !o.Anonymous && o.Name != "" && o.Name != "default" {
		used = m.usedOutside(o.Name, o.StartLine, o.EndLine)
		for _, a := range o.Aliases {
			used = used || m.usedOutside(a, o.StartLine, o.EndLine)
		}
	}
	switch {
	case len(names) > 0 && !used:
		sort.Strings(names)
		return names, true, ""
	case len(names) > 0:
		why = o.Name + " is also used by other code in " + m.Path
	default:
		why = o.Name + " is not exported from " + m.Path
		if o.Name == "" {
			why = "the function is not exported from " + m.Path
		}
	}
	all := m.allNames()
	sort.Strings(all)
	return all, false, why
}

// publicNames maps a module's export names to the names an application
// calls: through the entry module, and by importing the file directly when
// the package allows it. complete is false when another route may exist.
func (pm *packageModel) publicNames(m *moduleInfo, moduleNames []string) (public []string, complete bool, why []string) {
	complete = true
	if len(m.Dynamic) > 0 {
		complete = false
		why = append(why, m.Path+": "+m.Dynamic[0])
	}
	if pm.deep || pm.subpaths[m.Path] {
		public = addEvidence(public, moduleNames...)
	}
	if m.Path == pm.entry {
		public = addEvidence(public, moduleNames...)
		if imp := pm.importers[m.Path]; len(imp) > 0 {
			complete = false
			why = append(why, m.Path+" is also loaded by "+strings.Join(imp, ", "))
		}
		return public, complete, why
	}

	entry := pm.mods[pm.entry]
	for _, imp := range pm.importers[m.Path] {
		if imp != pm.entry {
			complete = false
			why = append(why, m.Path+" is loaded by "+imp+", which is not the entry module (only one hop is resolved)")
		}
	}
	if entry == nil {
		return public, false, append(why, "the entry module could not be analysed")
	}
	if len(entry.Dynamic) > 0 {
		complete = false
		why = append(why, entry.Path+": "+entry.Dynamic[0])
	}
	direct := false
	for name, targets := range entry.Names {
		for _, t := range targets {
			if t.Module != m.Path {
				continue
			}
			direct = true
			switch {
			case name == "*":
				public = addEvidence(public, moduleNames...)
			case t.Member == "":
				// The whole module under one name: pkg.name() calls its
				// default, pkg.name.member() its members.
				public = addEvidence(public, name)
				public = addEvidence(public, without(moduleNames, "default")...)
			case contains(moduleNames, t.Member):
				public = addEvidence(public, name)
			}
		}
	}
	// The entry loads the module but also uses it inside its own code, so
	// any of the entry's exports may reach it.
	for local, b := range entry.Bindings {
		if b.Module == m.Path && entry.usedOutside(local, 0, -1) {
			public = addEvidence(public, entry.allNames()...)
			direct = true
		}
	}
	if contains(pm.importers[m.Path], pm.entry) && !direct {
		public = addEvidence(public, entry.allNames()...)
	}
	return public, complete, why
}

// applyVisibility fills the join-rule fields on code-derived candidates.
// Candidates from advisory prose are left alone: the join rule never closes
// a prose-derived set.
func applyVisibility(res *Result, pm *packageModel) (closed int) {
	for i := range res.CandidateSymbols {
		c := &res.CandidateSymbols[i]
		v := pm.resolve(c.Symbol, c.ModulePath)
		c.Visibility = v.Visibility
		if v.Visibility == VisibilityInternal {
			c.ExposedVia = v.ExposedVia
			c.ExposedViaSource = ExposedViaExportResolution
			complete := v.Complete
			c.ExposedViaComplete = &complete
		}
		note := "visibility " + v.Visibility
		if v.Visibility == VisibilityInternal {
			note += " via " + strings.Join(v.ExposedVia, ", ")
			if v.Complete {
				note += " (complete)"
			} else {
				note += " (incomplete)"
			}
		}
		if v.Why != "" {
			note += ": " + v.Why
		}
		if c.Note != "" {
			c.Note += "; "
		}
		c.Note += note
		if v.Visibility == VisibilityPublic || v.Visibility == VisibilityInternal && v.Complete {
			closed++
		}
	}
	return closed
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func without(list []string, s string) []string {
	var out []string
	for _, x := range list {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

// exportsUnresolved detects routes not represented by the single selected entry.
// A condition may depend on the consumer or bundler; choosing require alone
// cannot establish that all public routes have been found.
func exportsUnresolved(raw json.RawMessage) bool {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return true
	}
	var visit func(any) bool
	visit = func(node any) bool {
		switch x := node.(type) {
		case string, nil:
			return false
		case map[string]any:
			conditions := true
			for key := range x {
				if strings.HasPrefix(key, ".") {
					conditions = false
				}
			}
			if conditions {
				targets := map[string]bool{}
				var collect func(any)
				collect = func(n any) {
					switch z := n.(type) {
					case string:
						targets[z] = true
					case map[string]any:
						for _, child := range z {
							collect(child)
						}
					}
				}
				collect(x)
				if len(targets) > 1 || conditionTarget(x) == "" {
					return true
				}
			}
			for _, child := range x {
				if visit(child) {
					return true
				}
			}
			return false
		default:
			return true
		}
	}
	return visit(v)
}
