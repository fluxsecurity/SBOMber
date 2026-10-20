package python

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/Xsamsx/SBOMber/internal/deps"
)

type pyprojectFile struct {
	Project struct {
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
}

// ParseRequirements reads Python requirements files and returns a normalized dependency summary.
// It supports requirements.txt, requirements-dev.txt, and PEP 621 dependency declarations in pyproject.toml.
//
// A package declared more than once (in several files, or in several
// optional-dependency groups) is reported once: an SBOM with two components
// for the same package has duplicate bom-refs and is invalid CycloneDX.
func ParseRequirements(root string) (deps.Summary, error) {
	summary := deps.Summary{
		Direct: make([]deps.Dependency, 0),
	}
	index := map[string]int{} // normalised name -> position in summary.Direct

	appendDep := func(name, version string, scope deps.Scope, filename, path string) {
		if name == "" {
			return
		}
		key := normalizeName(name)
		if i, ok := index[key]; ok {
			existing := &summary.Direct[i]
			if scopeRank(scope) > scopeRank(existing.Scope) {
				existing.Scope = scope
			}
			if existing.Version == "" && version != "" {
				existing.Version = version
			}
			return
		}
		index[key] = len(summary.Direct)
		summary.Direct = append(summary.Direct, deps.Dependency{
			Name:           name,
			Version:        version,
			Scope:          scope,
			Ecosystem:      "pypi",
			IsDirect:       true,
			SourceFile:     filename,
			SourceLocation: path,
		})
	}

	parseFile := func(filename string, scope deps.Scope) error {
		path := filepath.Join(root, filename)
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		defer func() { _ = f.Close() }()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "-r ") || strings.HasPrefix(line, "--requirement") || strings.HasPrefix(line, "-") {
				continue
			}

			name, version := parsePythonRequirementLine(line)
			appendDep(name, version, scope, filename, path)
		}

		return scanner.Err()
	}

	if err := parseFile("requirements.txt", deps.ScopeRuntime); err != nil {
		return deps.Summary{}, err
	}
	if err := parseFile("requirements-dev.txt", deps.ScopeDev); err != nil {
		return deps.Summary{}, err
	}

	if err := parsePyProjectToml(root, appendDep); err != nil {
		return deps.Summary{}, err
	}

	if len(summary.Direct) > 1 {
		sort.SliceStable(summary.Direct, func(i, j int) bool {
			return summary.Direct[i].Name < summary.Direct[j].Name
		})
	}

	return summary, nil
}

func parsePyProjectToml(root string, appendDep func(name, version string, scope deps.Scope, filename, path string)) error {
	path := filepath.Join(root, "pyproject.toml")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var doc pyprojectFile
	if _, err := toml.Decode(string(b), &doc); err != nil {
		return err
	}

	for _, req := range doc.Project.Dependencies {
		name, version := parsePythonRequirementLine(req)
		appendDep(name, version, deps.ScopeRuntime, "pyproject.toml", path)
	}

	// Map order is random; read groups in a fixed order so the output is
	// reproducible.
	groups := make([]string, 0, len(doc.Project.OptionalDependencies))
	for g := range doc.Project.OptionalDependencies {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	for _, g := range groups {
		for _, req := range doc.Project.OptionalDependencies[g] {
			name, version := parsePythonRequirementLine(req)
			appendDep(name, version, deps.ScopeOptional, "pyproject.toml", path)
		}
	}

	return nil
}

// parsePythonRequirementLine returns a requirement's name and its pinned
// version ("" for a range). Environment markers ("; python_version<3"),
// inline comments and extras ("name[security]") are ignored.
func parsePythonRequirementLine(line string) (name, version string) {
	line = strings.SplitN(line, ";", 2)[0]
	if i := strings.Index(line, "#"); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	sepIndex := strings.IndexAny(line, "=<>~![ \t")
	if sepIndex == -1 {
		return line, ""
	}
	name = strings.TrimSpace(line[:sepIndex])
	rest := strings.TrimSpace(line[sepIndex:])
	if strings.HasPrefix(rest, "[") {
		if end := strings.Index(rest, "]"); end >= 0 {
			rest = strings.TrimSpace(rest[end+1:])
		}
	}
	return name, PinnedVersion(rest)
}

var nameSeparators = regexp.MustCompile(`[-_.]+`)

// normalizeName is the PEP 503 normalised form: "Flask_Login" and
// "flask-login" are the same package.
func normalizeName(name string) string {
	return nameSeparators.ReplaceAllString(strings.ToLower(name), "-")
}

// scopeRank orders scopes so a runtime declaration wins over an optional or
// development one when a package is declared in several places.
func scopeRank(s deps.Scope) int {
	switch s {
	case deps.ScopeRuntime:
		return 3
	case deps.ScopeOptional:
		return 2
	case deps.ScopeDev:
		return 1
	default:
		return 0
	}
}
