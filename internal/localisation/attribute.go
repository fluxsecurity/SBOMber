package localisation

import (
	"fmt"
	"sort"
	"strings"
)

// changedFile is one file's change with the sources needed to attribute it.
type changedFile struct {
	Path        string
	Status      string // added, removed, modified, renamed
	NewSource   []byte // nil when the file was removed or could not be fetched
	OldSource   []byte // nil when the file was added or could not be fetched
	Added       []int  // new-file line numbers
	Removed     []int  // old-file line numbers
	Approximate bool
	FetchError  string
}

// attribution is the outcome of mapping changed lines to functions.
type attribution struct {
	Candidates  []Candidate
	NonFunction []string
	Excluded    []string
	Notes       []string
	SourceFiles int // files that were actually attributed
}

// maxCandidateSymbols is where a candidate set stops being useful to
// Component 4 and starts being a version diff of a refactor.
const maxCandidateSymbols = 60

// classifyPath decides whether a changed file is code worth attributing or
// one of the excluded kinds the contract names.
func classifyPath(p string) (excluded string) {
	lower := strings.ToLower(p)
	base := lower
	if i := strings.LastIndex(lower, "/"); i >= 0 {
		base = lower[i+1:]
	}
	switch {
	case strings.HasPrefix(lower, "test/"), strings.HasPrefix(lower, "tests/"), strings.HasPrefix(lower, "__tests__/"),
		strings.Contains(lower, "/test/"), strings.Contains(lower, "/tests/"), strings.Contains(lower, "/__tests__/"),
		strings.HasSuffix(base, ".test.js"), strings.HasSuffix(base, ".spec.js"), strings.HasSuffix(base, ".test.ts"),
		strings.HasSuffix(base, ".spec.ts"), base == "test.js", base == "test.ts", strings.HasPrefix(lower, "spec/"):
		return "tests"
	case strings.HasSuffix(base, ".md"), strings.HasSuffix(base, ".markdown"), strings.HasSuffix(base, ".txt"),
		strings.HasPrefix(lower, "docs/"), strings.HasPrefix(lower, "doc/"), base == "license", base == "licence",
		strings.HasPrefix(base, "changelog"), strings.HasPrefix(base, "history"), strings.HasPrefix(base, "readme"):
		return "docs"
	case strings.HasPrefix(lower, ".github/"), strings.HasPrefix(base, ".travis"), strings.HasPrefix(base, ".eslintrc"),
		base == ".npmignore", base == ".gitignore", base == ".editorconfig", base == ".npmrc", strings.HasPrefix(base, ".nycrc"),
		base == "appveyor.yml", base == ".circleci", strings.HasPrefix(lower, ".circleci/"):
		return "ci_config"
	case base == "package.json", base == "package-lock.json", base == "yarn.lock", base == "pnpm-lock.yaml",
		strings.HasPrefix(base, "rollup.config"), strings.HasPrefix(base, "webpack"), strings.HasPrefix(base, "tsconfig"),
		strings.HasPrefix(base, "babel.config"), base == ".babelrc", base == "makefile", strings.HasPrefix(base, "gulpfile"),
		strings.HasPrefix(base, "gruntfile"), base == "bower.json":
		return "build"
	}
	return ""
}

// attributeChanges maps every changed line to the innermost named function
// containing it, in the fixed file for additions and in the vulnerable file
// for removals. Anonymous wrappers are skipped, module-level declarations are
// recorded separately, and export aliases are added as candidates so a
// private name can be joined to the public one an application calls.
func attributeChanges(files []changedFile) attribution {
	var out attribution
	seenCand := map[string]int{} // symbol@path -> index
	seenExcl := map[string]bool{}
	seenNon := map[string]bool{}
	addCand := func(c Candidate) {
		key := c.Symbol + "@" + c.ModulePath
		if i, ok := seenCand[key]; ok {
			if out.Candidates[i].Note == "" && c.Note != "" {
				out.Candidates[i].Note = c.Note
			}
			return
		}
		seenCand[key] = len(out.Candidates)
		out.Candidates = append(out.Candidates, c)
	}

	for _, f := range files {
		if kind := classifyPath(f.Path); kind != "" {
			if !seenExcl[kind] {
				seenExcl[kind] = true
				out.Excluded = append(out.Excluded, kind)
			}
			continue
		}
		if !SupportedSourceFile(f.Path) {
			continue
		}
		if f.FetchError != "" {
			out.Notes = append(out.Notes, fmt.Sprintf("%s: %s", f.Path, f.FetchError))
			continue
		}
		out.SourceFiles++
		if f.Approximate {
			out.Notes = append(out.Notes, f.Path+": region too large to align exactly; every line in it counted as changed")
		}
		changeKind := "modified"
		switch f.Status {
		case "added":
			changeKind = "added"
		case "removed":
			changeKind = "removed"
		}

		attributeSide := func(src []byte, lines []int, kind string) {
			if src == nil || len(lines) == 0 {
				return
			}
			fs, err := ParseSymbols(f.Path, src)
			if err != nil {
				out.Notes = append(out.Notes, fmt.Sprintf("%s: %v", f.Path, err))
				return
			}
			if fs.Minified {
				out.Notes = append(out.Notes, f.Path+": minified, not attributed")
				return
			}
			if fs.HasError {
				out.Notes = append(out.Notes, f.Path+": parsed with syntax errors; attribution may be incomplete")
			}
			moduleLevel := 0
			srcLines := splitLines(src)
			for _, ln := range lines {
				// Comment-only and blank lines carry no behaviour. A fix that adds a
				// doc comment above a new helper would otherwise attribute the
				// comment to whatever outer function encloses it.
				if ln >= 1 && ln <= len(srcLines) && !isCodeLine(srcLines[ln-1]) {
					continue
				}
				fn := fs.EnclosingFunction(ln)
				if fn == nil {
					if d := fs.EnclosingDeclaration(ln); d != nil {
						key := d.Name + "@" + f.Path
						if !seenNon[key] {
							seenNon[key] = true
							out.NonFunction = append(out.NonFunction, d.Name+" ("+f.Path+")")
						}
					} else {
						moduleLevel++
					}
					continue
				}
				c := Candidate{Symbol: fn.Name, ModulePath: f.Path, ChangeKind: kind, Note: describeSpan(fn, fs)}
				addCand(c)
				for _, alias := range fs.ExportedNames(fn.Name) {
					if alias == fn.Name {
						continue
					}
					addCand(Candidate{Symbol: alias, ModulePath: f.Path, ChangeKind: kind,
						Note: "export alias of " + fn.Name})
				}
				for _, alias := range fn.Aliases {
					addCand(Candidate{Symbol: alias, ModulePath: f.Path, ChangeKind: kind,
						Note: "also named " + alias + " (function expression name of " + fn.Name + ")"})
				}
			}
			if moduleLevel > 0 {
				out.Notes = append(out.Notes, fmt.Sprintf("%s: %d changed line(s) at module level outside any function", f.Path, moduleLevel))
			}
		}
		attributeSide(f.NewSource, f.Added, changeKind)
		attributeSide(f.OldSource, f.Removed, changeKind)
	}
	sort.Strings(out.Excluded)
	if len(out.Candidates) > maxCandidateSymbols {
		out.Notes = append(out.Notes, fmt.Sprintf("%d candidate symbols exceed the %d useful maximum; this looks like a release diff, not a fix", len(out.Candidates), maxCandidateSymbols))
	}
	return out
}

func describeSpan(fn *FunctionSpan, fs *FileSymbols) string {
	var parts []string
	if fn.Kind == "method" && fn.Class != "" {
		parts = append(parts, "method of class "+fn.Class)
	}
	if fn.Kind == "class" {
		parts = append(parts, "class")
	}
	// Name the nearest named ancestor so "setKey nested in default" is visible.
	var outer *FunctionSpan
	for i := range fs.Functions {
		o := &fs.Functions[i]
		if o == fn || o.Anonymous || o.Depth >= fn.Depth {
			continue
		}
		if fn.StartLine >= o.StartLine && fn.EndLine <= o.EndLine {
			if outer == nil || o.Depth > outer.Depth {
				outer = o
			}
		}
	}
	if outer != nil {
		parts = append(parts, "nested in "+outer.Name)
	}
	if exp := fs.ExportedNames(fn.Name); len(exp) > 0 {
		parts = append(parts, "exported as "+strings.Join(exp, ", "))
	} else if fn.Name != "default" && fn.Depth == 0 && fn.Kind != "method" {
		parts = append(parts, "not exported from this file")
	}
	return strings.Join(parts, "; ")
}

// isCodeLine reports whether a source line is more than whitespace or a
// comment. Block-comment bodies conventionally start with "*".
func isCodeLine(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return false
	}
	for _, prefix := range []string{"//", "/*", "*", "*/"} {
		if strings.HasPrefix(t, prefix) {
			return false
		}
	}
	return true
}
