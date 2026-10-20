package npm

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Xsamsx/SBOMber/internal/deps"
)

type yarnEntry struct {
	Selectors    []string
	Name         string
	Version      string
	Dependencies []string // names of dependencies
}

// EnrichFromYarnLock reads a Yarn Berry lockfile and appends transitive
// dependency information to an existing npm summary.
func EnrichFromYarnLock(root string, summary deps.Summary) (deps.Summary, error) {
	path := filepath.Join(root, "yarn.lock")
	file, err := os.Open(path)
	if err != nil {
		return summary, err
	}
	defer func() { _ = file.Close() }()

	entries, err := parseYarnLock(file)
	if err != nil {
		return summary, err
	}

	directSelectors := make(map[string]struct{}, len(summary.Direct)*2)
	directNames := make(map[string]int) // maps name to index in summary.Direct
	for i, dependency := range summary.Direct {
		directSelectors[dependency.Name+"@"+dependency.Version] = struct{}{}
		directSelectors[dependency.Name+"@npm:"+dependency.Version] = struct{}{}
		directNames[dependency.Name] = i
	}

	directLocked := make(map[string]struct{})
	transitive := make(map[string]deps.Dependency)
	entryByName := make(map[string]*yarnEntry) // for looking up dependencies

	// First pass: identify all entries
	for i := range entries {
		entry := &entries[i]
		if entry.Name == "" || entry.Version == "" {
			continue
		}
		entryByName[entry.Name] = entry
	}

	// Second pass: classify as direct or transitive
	for i := range entries {
		entry := &entries[i]
		if entry.Name == "" || entry.Version == "" {
			continue
		}

		key := entry.Name + "@" + entry.Version

		isDirect := false
		for _, selector := range entry.Selectors {
			if _, ok := directSelectors[selector]; ok {
				isDirect = true
				break
			}
		}

		if isDirect {
			directLocked[key] = struct{}{}
			// The direct dependency's range becomes the version yarn
			// resolved it to, as with package-lock.json; a range left in
			// Version reaches the SBOM as if it were a version.
			if idx, ok := directNames[entry.Name]; ok {
				summary.Direct[idx].Version = entry.Version
				summary.Direct[idx].Children = entry.Dependencies
			}
			continue
		}

		if _, ok := directLocked[key]; ok {
			continue
		}

		transitive[key] = deps.Dependency{
			Name:           entry.Name,
			Version:        entry.Version,
			Scope:          deps.Scope("transitive"),
			Ecosystem:      "npm",
			Children:       entry.Dependencies,
			SourceFile:     "yarn.lock",
			SourceLocation: path,
		}
	}

	keys := make([]string, 0, len(transitive))
	for key := range transitive {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	summary.Transitive = make([]deps.Dependency, 0, len(keys))
	for _, key := range keys {
		summary.Transitive = append(summary.Transitive, transitive[key])
	}

	return summary, nil
}

func parseYarnLock(file *os.File) ([]yarnEntry, error) {
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	entries := make([]yarnEntry, 0)
	var current *yarnEntry
	inDependencies := false

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}

		switch {
		case !strings.HasPrefix(line, " "):
			key := strings.TrimSuffix(line, ":")
			key = cleanYarnValue(key)
			if key == "__metadata" {
				current = nil
				inDependencies = false
				continue
			}

			entry := yarnEntry{
				Selectors:    splitSelectors(key),
				Dependencies: make([]string, 0),
			}
			entry.Name = selectorName(entry.Selectors)
			entries = append(entries, entry)
			current = &entries[len(entries)-1]
			inDependencies = false
		case current == nil:
			continue
		case strings.HasPrefix(line, "  version:"):
			current.Version = cleanYarnValue(strings.TrimSpace(strings.TrimPrefix(line, "  version:")))
			inDependencies = false
		case strings.HasPrefix(line, "  version "):
			// Yarn v1 (classic): `  version "1.19.0"`.
			current.Version = cleanYarnValue(strings.TrimSpace(strings.TrimPrefix(line, "  version ")))
			inDependencies = false
		case strings.HasPrefix(line, "  resolution:"):
			resolution := cleanYarnValue(strings.TrimSpace(strings.TrimPrefix(line, "  resolution:")))
			if name := nameFromDescriptor(resolution); name != "" {
				current.Name = name
			}
			inDependencies = false
		case strings.HasPrefix(line, "  dependencies:"):
			inDependencies = true
		case strings.HasPrefix(line, "  peerDependencies:"), strings.HasPrefix(line, "  optionalDependencies:"):
			inDependencies = false
		case inDependencies && strings.HasPrefix(line, "    "):
			// Berry: `    lodash: ^4.17.21`; v1: `    lodash "^4.17.21"`.
			if depName := yarnDependencyName(strings.TrimSpace(line)); depName != "" {
				current.Dependencies = append(current.Dependencies, depName)
			}
		case strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    "):
			// Any other top-level property ends the dependencies section
			inDependencies = false
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

// yarnDependencyName is the package name in one dependencies line, in either
// lockfile format. A scoped name is quoted, so the quotes are read first.
func yarnDependencyName(line string) string {
	if strings.HasPrefix(line, `"`) {
		if end := strings.Index(line[1:], `"`); end >= 0 {
			return line[1 : end+1]
		}
		return ""
	}
	if idx := strings.IndexAny(line, ": "); idx > 0 {
		return line[:idx]
	}
	return ""
}

func splitSelectors(value string) []string {
	parts := strings.Split(value, ",")
	selectors := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(cleanYarnValue(part))
		if part == "" {
			continue
		}

		selectors = append(selectors, part)
	}

	return selectors
}

func selectorName(selectors []string) string {
	for _, selector := range selectors {
		if name := nameFromDescriptor(selector); name != "" {
			return name
		}
	}

	return ""
}

func nameFromDescriptor(descriptor string) string {
	if idx := strings.LastIndex(descriptor, "@npm:"); idx > 0 {
		return descriptor[:idx]
	}
	if idx := strings.LastIndex(descriptor, "@"); idx > 0 {
		return descriptor[:idx]
	}

	return ""
}

func cleanYarnValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}

	unquoted, err := strconv.Unquote(value)
	if err == nil {
		return unquoted
	}

	return strings.Trim(value, `"`)
}
