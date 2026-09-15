package python

import (
	"bufio"
	"os"
	"path/filepath"
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
func ParseRequirements(root string) (deps.Summary, error) {
	summary := deps.Summary{
		Direct: make([]deps.Dependency, 0),
	}

	appendDep := func(name, version string, scope deps.Scope, filename, path string) {
		if name == "" {
			return
		}

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
			if strings.HasPrefix(line, "-r ") || strings.HasPrefix(line, "--requirement") || strings.HasPrefix(line, "--") {
				continue
			}

			name, version := parsePythonRequirementLine(line)
			if name == "" {
				continue
			}
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

	if err := parsePyProjectToml(root, &summary); err != nil {
		return deps.Summary{}, err
	}

	if len(summary.Direct) > 1 {
		sort.SliceStable(summary.Direct, func(i, j int) bool {
			return summary.Direct[i].Name < summary.Direct[j].Name
		})
	}

	return summary, nil
}

func parsePyProjectToml(root string, summary *deps.Summary) error {
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
		name, version := parsePyProjectRequirement(req)
		if name == "" {
			continue
		}
		summary.Direct = append(summary.Direct, deps.Dependency{
			Name:           name,
			Version:        version,
			Scope:          deps.ScopeRuntime,
			Ecosystem:      "pypi",
			IsDirect:       true,
			SourceFile:     "pyproject.toml",
			SourceLocation: path,
		})
	}

	for _, depsList := range doc.Project.OptionalDependencies {
		for _, req := range depsList {
			name, version := parsePyProjectRequirement(req)
			if name == "" {
				continue
			}
			summary.Direct = append(summary.Direct, deps.Dependency{
				Name:           name,
				Version:        version,
				Scope:          deps.ScopeOptional,
				Ecosystem:      "pypi",
				IsDirect:       true,
				SourceFile:     "pyproject.toml",
				SourceLocation: path,
			})
		}
	}

	return nil
}

func parsePythonRequirementLine(line string) (name, version string) {
	sepIndex := strings.IndexAny(line, "=<>~!")
	if sepIndex == -1 {
		name = strings.TrimSpace(line)
		return name, ""
	}

	name = strings.TrimSpace(line[:sepIndex])
	version = strings.TrimSpace(line[sepIndex:])
	return name, version
}

func parsePyProjectRequirement(line string) (name, version string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}
	if idx := strings.Index(line, ";"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	if idx := strings.Index(line, "["); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	if idx := strings.IndexAny(line, "=<>~!"); idx >= 0 {
		name = strings.TrimSpace(line[:idx])
		version = strings.TrimSpace(line[idx:])
		return name, version
	}
	return strings.TrimSpace(line), ""
}
