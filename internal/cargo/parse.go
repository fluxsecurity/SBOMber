package cargo

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Xsamsx/SBOMber/internal/deps"
)

type cargoPackage struct {
	name         string
	version      string
	source       string
	dependencies []string
}

// ParseCargoLock reads Cargo.lock and returns a normalized dependency summary.
func ParseCargoLock(root string) (deps.Summary, error) {
	path := filepath.Join(root, "Cargo.lock")
	f, err := os.Open(path)
	if err != nil {
		return deps.Summary{}, err
	}
	defer func() { _ = f.Close() }()

	packages, err := parseCargoLock(f)
	if err != nil {
		return deps.Summary{}, err
	}

	sourceFile := "Cargo.lock"
	sourcePath := path

	// Collect direct dep names from root/workspace packages (those with no source or path+ source)
	directNames := make(map[string]bool)
	for _, pkg := range packages {
		isLocal := pkg.source == "" || strings.HasPrefix(pkg.source, "path+")
		if isLocal {
			for _, dep := range pkg.dependencies {
				directNames[extractDepName(dep)] = true
			}
		}
	}

	summary := deps.Summary{
		Direct:     make([]deps.Dependency, 0),
		Transitive: make([]deps.Dependency, 0),
	}

	for _, pkg := range packages {
		// Skip local workspace members
		isExternal := strings.Contains(pkg.source, "registry+") || strings.Contains(pkg.source, "git+")
		if !isExternal {
			continue
		}

		isDirect := directNames[pkg.name]
		depth := 1
		if isDirect {
			depth = 0
		}

		d := deps.Dependency{
			Name:           pkg.name,
			Version:        pkg.version,
			Scope:          deps.ScopeRuntime,
			Ecosystem:      "cargo",
			IsDirect:       isDirect,
			Depth:          depth,
			SourceFile:     sourceFile,
			SourceLocation: sourcePath,
		}

		if isDirect {
			summary.Direct = append(summary.Direct, d)
		} else {
			summary.Transitive = append(summary.Transitive, d)
		}
	}

	return summary, nil
}

func parseCargoLock(r io.Reader) ([]cargoPackage, error) {
	scanner := bufio.NewScanner(r)

	var packages []cargoPackage
	var current *cargoPackage
	inDeps := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			if current != nil {
				packages = append(packages, *current)
			}
			current = &cargoPackage{}
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
				current.dependencies = append(current.dependencies, dep)
			}
			continue
		}

		if kv, ok := splitKV(line); ok {
			switch kv[0] {
			case "name":
				current.name = kv[1]
			case "version":
				current.version = kv[1]
			case "source":
				current.source = kv[1]
			}
		}
	}

	if current != nil {
		packages = append(packages, *current)
	}

	return packages, scanner.Err()
}

// splitKV parses `key = "value"` lines, returning [key, value].
func splitKV(line string) ([2]string, bool) {
	idx := strings.Index(line, " = ")
	if idx == -1 {
		return [2]string{}, false
	}
	key := strings.TrimSpace(line[:idx])
	val := strings.TrimSpace(line[idx+3:])
	val = strings.Trim(val, `"`)
	return [2]string{key, val}, true
}

// extractDepName returns the package name from a Cargo dependency reference.
// Refs have the form: "name", "name version", or "name version (source)".
func extractDepName(dep string) string {
	parts := strings.Fields(dep)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
