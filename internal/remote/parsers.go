package remote

import (
	"bufio"
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/Xsamsx/SBOMber/internal/deps"
)

// ParseContent parses a manifest file's raw content given its path.
func ParseContent(path string, content []byte) (deps.Summary, error) {
	return parseManifestContent(path, content)
}

func parseManifestContent(path string, content []byte) (deps.Summary, error) {
	filename := getFilename(path)

	switch filename {
	case "package.json":
		return parsePackageJSON(content)
	case "package-lock.json":
		return parsePackageLockJSON(content)
	case "requirements.txt":
		return parseRequirementsTxt(content)
	case "go.mod":
		return parseGoMod(content)
	case "pom.xml":
		return parsePomXML(content)
	case "Gemfile.lock":
		return parseGemfileLock(content)
	case "Cargo.lock":
		return parseCargoLock(content)
	case "composer.lock":
		return parseComposerLock(content)
	case "packages.lock.json":
		return parseNuGetLock(content)
	default:
		return deps.Summary{}, nil
	}
}

type packageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func parsePackageJSON(content []byte) (deps.Summary, error) {
	var manifest packageJSON
	if err := json.Unmarshal(content, &manifest); err != nil {
		return deps.Summary{}, err
	}

	summary := deps.Summary{
		Direct: make([]deps.Dependency, 0),
	}

	addDeps := func(scope deps.Scope, values map[string]string) {
		names := sortedKeys(values)
		for _, name := range names {
			version := cleanVersion(values[name])
			summary.Direct = append(summary.Direct, deps.Dependency{
				Name:      name,
				Version:   version,
				Scope:     scope,
				Ecosystem: "npm",
			})
		}
	}

	addDeps(deps.ScopeRuntime, manifest.Dependencies)
	addDeps(deps.ScopeDev, manifest.DevDependencies)
	addDeps(deps.ScopePeer, manifest.PeerDependencies)
	addDeps(deps.ScopeOptional, manifest.OptionalDependencies)

	return summary, nil
}

type packageLockJSON struct {
	Packages map[string]struct {
		Version string `json:"version"`
		Dev     bool   `json:"dev"`
	} `json:"packages"`
	Dependencies map[string]struct {
		Version string `json:"version"`
		Dev     bool   `json:"dev"`
	} `json:"dependencies"`
}

func parsePackageLockJSON(content []byte) (deps.Summary, error) {
	var lock packageLockJSON
	if err := json.Unmarshal(content, &lock); err != nil {
		return deps.Summary{}, err
	}

	summary := deps.Summary{
		Transitive: make([]deps.Dependency, 0),
	}

	if len(lock.Packages) > 0 {
		for path, pkg := range lock.Packages {
			if path == "" {
				continue
			}
			name := packageLockPackageName(path)
			if name == "" {
				continue
			}

			scope := deps.ScopeRuntime
			if pkg.Dev {
				scope = deps.ScopeDev
			}

			summary.Transitive = append(summary.Transitive, deps.Dependency{
				Name:      name,
				Version:   pkg.Version,
				Scope:     scope,
				Ecosystem: "npm",
			})
		}
	} else if len(lock.Dependencies) > 0 {
		for name, dep := range lock.Dependencies {
			scope := deps.ScopeRuntime
			if dep.Dev {
				scope = deps.ScopeDev
			}
			summary.Transitive = append(summary.Transitive, deps.Dependency{
				Name:      name,
				Version:   dep.Version,
				Scope:     scope,
				Ecosystem: "npm",
			})
		}
	}

	return summary, nil
}

func packageLockPackageName(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	path = strings.TrimPrefix(path, "node_modules/")
	if idx := strings.LastIndex(path, "/node_modules/"); idx >= 0 {
		return path[idx+len("/node_modules/"):]
	}
	return path
}

func parseRequirementsTxt(content []byte) (deps.Summary, error) {
	summary := deps.Summary{
		Direct: make([]deps.Dependency, 0),
	}

	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-") {
			continue
		}

		name, version := parsePythonRequirement(line)
		if name == "" {
			continue
		}

		summary.Direct = append(summary.Direct, deps.Dependency{
			Name:      name,
			Version:   version,
			Scope:     deps.ScopeRuntime,
			Ecosystem: "pypi",
		})
	}

	return summary, nil
}

var pyReqPattern = regexp.MustCompile(`^([a-zA-Z0-9._-]+)\s*(?:\[.*?\])?\s*([<>=!~]+.+)?`)

func parsePythonRequirement(line string) (name, version string) {
	line = strings.Split(line, ";")[0]
	line = strings.Split(line, "#")[0]
	line = strings.TrimSpace(line)

	matches := pyReqPattern.FindStringSubmatch(line)
	if len(matches) >= 2 {
		name = strings.ToLower(matches[1])
		if len(matches) >= 3 {
			version = strings.TrimSpace(matches[2])
		}
	}
	return
}

var goModRequire = regexp.MustCompile(`^\s*([^\s]+)\s+([^\s]+)`)

func parseGoMod(content []byte) (deps.Summary, error) {
	summary := deps.Summary{
		Direct: make([]deps.Dependency, 0),
	}

	lines := strings.Split(string(content), "\n")
	inRequire := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		if strings.HasPrefix(line, "require ") {
			line = strings.TrimPrefix(line, "require ")
		} else if !inRequire {
			continue
		}

		if strings.Contains(line, "// indirect") {
			continue
		}

		matches := goModRequire.FindStringSubmatch(line)
		if len(matches) >= 3 {
			summary.Direct = append(summary.Direct, deps.Dependency{
				Name:      matches[1],
				Version:   matches[2],
				Scope:     deps.ScopeRuntime,
				Ecosystem: "go",
			})
		}
	}

	return summary, nil
}

var pomDepPattern = regexp.MustCompile(`<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]*)</version>)?`)

func parsePomXML(content []byte) (deps.Summary, error) {
	summary := deps.Summary{
		Direct: make([]deps.Dependency, 0),
	}

	matches := pomDepPattern.FindAllStringSubmatch(string(content), -1)
	for _, match := range matches {
		if len(match) >= 3 {
			name := match[1] + ":" + match[2]
			version := ""
			if len(match) >= 4 {
				version = match[3]
			}
			summary.Direct = append(summary.Direct, deps.Dependency{
				Name:      name,
				Version:   version,
				Scope:     deps.ScopeRuntime,
				Ecosystem: "maven",
			})
		}
	}

	return summary, nil
}

func parseGemfileLock(content []byte) (deps.Summary, error) {
	summary := deps.Summary{
		Direct: make([]deps.Dependency, 0),
	}

	lines := strings.Split(string(content), "\n")
	inSpecs := false
	gemPattern := regexp.MustCompile(`^\s{4}([a-zA-Z0-9_-]+)\s+\(([^)]+)\)`)

	for _, line := range lines {
		if strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}
		if inSpecs && len(line) > 0 && line[0] != ' ' {
			inSpecs = false
			continue
		}

		if inSpecs {
			matches := gemPattern.FindStringSubmatch(line)
			if len(matches) >= 3 {
				summary.Direct = append(summary.Direct, deps.Dependency{
					Name:      matches[1],
					Version:   matches[2],
					Scope:     deps.ScopeRuntime,
					Ecosystem: "rubygems",
				})
			}
		}
	}

	return summary, nil
}

func parseCargoLock(content []byte) (deps.Summary, error) {
	summary := deps.Summary{
		Direct:     make([]deps.Dependency, 0),
		Transitive: make([]deps.Dependency, 0),
	}

	type cargoPkg struct {
		name         string
		version      string
		source       string
		dependencies []string
	}

	var packages []cargoPkg
	var current *cargoPkg
	inDeps := false

	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			if current != nil {
				packages = append(packages, *current)
			}
			current = &cargoPkg{}
			inDeps = false
			continue
		}
		if current == nil {
			continue
		}
		if line == "dependencies = [" {
			inDeps = true
			continue
		}
		if inDeps && line == "]" {
			inDeps = false
			continue
		}
		if inDeps {
			dep := strings.Trim(line, `",`)
			if dep != "" {
				current.dependencies = append(current.dependencies, strings.Fields(dep)[0])
			}
			continue
		}
		idx := strings.Index(line, " = ")
		if idx != -1 {
			key := strings.TrimSpace(line[:idx])
			val := strings.Trim(strings.TrimSpace(line[idx+3:]), `"`)
			switch key {
			case "name":
				current.name = val
			case "version":
				current.version = val
			case "source":
				current.source = val
			}
		}
	}
	if current != nil {
		packages = append(packages, *current)
	}

	directNames := make(map[string]bool)
	for _, pkg := range packages {
		if pkg.source == "" || strings.HasPrefix(pkg.source, "path+") {
			for _, dep := range pkg.dependencies {
				directNames[dep] = true
			}
		}
	}

	for _, pkg := range packages {
		if !strings.Contains(pkg.source, "registry+") && !strings.Contains(pkg.source, "git+") {
			continue
		}
		isDirect := directNames[pkg.name]
		depth := 1
		if isDirect {
			depth = 0
		}
		d := deps.Dependency{
			Name:      pkg.name,
			Version:   pkg.version,
			Scope:     deps.ScopeRuntime,
			Ecosystem: "cargo",
			IsDirect:  isDirect,
			Depth:     depth,
		}
		if isDirect {
			summary.Direct = append(summary.Direct, d)
		} else {
			summary.Transitive = append(summary.Transitive, d)
		}
	}

	return summary, nil
}

type composerLockJSON struct {
	Packages    []struct{ Name, Version string } `json:"packages"`
	PackagesDev []struct{ Name, Version string } `json:"packages-dev"`
}

func parseComposerLock(content []byte) (deps.Summary, error) {
	var lock composerLockJSON
	if err := json.Unmarshal(content, &lock); err != nil {
		return deps.Summary{}, err
	}
	summary := deps.Summary{Direct: make([]deps.Dependency, 0)}
	for _, pkg := range lock.Packages {
		summary.Direct = append(summary.Direct, deps.Dependency{
			Name: pkg.Name, Version: pkg.Version,
			Scope: deps.ScopeRuntime, Ecosystem: "composer", IsDirect: true,
		})
	}
	for _, pkg := range lock.PackagesDev {
		summary.Direct = append(summary.Direct, deps.Dependency{
			Name: pkg.Name, Version: pkg.Version,
			Scope: deps.ScopeDev, Ecosystem: "composer", IsDirect: true,
		})
	}
	return summary, nil
}

type nugetLockJSON struct {
	Dependencies map[string]map[string]struct {
		Type     string `json:"type"`
		Resolved string `json:"resolved"`
	} `json:"dependencies"`
}

func parseNuGetLock(content []byte) (deps.Summary, error) {
	var lock nugetLockJSON
	if err := json.Unmarshal(content, &lock); err != nil {
		return deps.Summary{}, err
	}
	summary := deps.Summary{
		Direct:     make([]deps.Dependency, 0),
		Transitive: make([]deps.Dependency, 0),
	}
	seen := make(map[string]bool)
	for _, frameworkDeps := range lock.Dependencies {
		for name, dep := range frameworkDeps {
			key := strings.ToLower(name)
			if seen[key] {
				continue
			}
			seen[key] = true
			isDirect := strings.EqualFold(dep.Type, "Direct")
			depth := 1
			if isDirect {
				depth = 0
			}
			d := deps.Dependency{
				Name: name, Version: dep.Resolved,
				Scope: deps.ScopeRuntime, Ecosystem: "nuget",
				IsDirect: isDirect, Depth: depth,
			}
			if isDirect {
				summary.Direct = append(summary.Direct, d)
			} else {
				summary.Transitive = append(summary.Transitive, d)
			}
		}
	}
	return summary, nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func cleanVersion(v string) string {
	v = strings.TrimPrefix(v, "^")
	v = strings.TrimPrefix(v, "~")
	v = strings.TrimPrefix(v, ">=")
	v = strings.TrimPrefix(v, "<=")
	v = strings.TrimPrefix(v, ">")
	v = strings.TrimPrefix(v, "<")
	v = strings.TrimPrefix(v, "=")
	return strings.TrimSpace(v)
}
