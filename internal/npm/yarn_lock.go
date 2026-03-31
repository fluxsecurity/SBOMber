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
	Selectors []string
	Name      string
	Version   string
}

// EnrichFromYarnLock reads a Yarn Berry lockfile and appends transitive
// dependency information to an existing npm summary.
func EnrichFromYarnLock(root string, summary deps.Summary) (deps.Summary, error) {
	path := filepath.Join(root, "yarn.lock")
	file, err := os.Open(path)
	if err != nil {
		return summary, err
	}
	defer file.Close()

	entries, err := parseYarnLock(file)
	if err != nil {
		return summary, err
	}

	directSelectors := make(map[string]struct{}, len(summary.Direct)*2)
	for _, dependency := range summary.Direct {
		directSelectors[dependency.Name+"@"+dependency.Version] = struct{}{}
		directSelectors[dependency.Name+"@npm:"+dependency.Version] = struct{}{}
	}

	directLocked := make(map[string]struct{})
	transitive := make(map[string]deps.Dependency)

	for _, entry := range entries {
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
			continue
		}

		if _, ok := directLocked[key]; ok {
			continue
		}

		transitive[key] = deps.Dependency{
			Name:    entry.Name,
			Version: entry.Version,
			Scope:   deps.Scope("transitive"),
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
				continue
			}

			entry := yarnEntry{
				Selectors: splitSelectors(key),
			}
			entry.Name = selectorName(entry.Selectors)
			entries = append(entries, entry)
			current = &entries[len(entries)-1]
		case current == nil:
			continue
		case strings.HasPrefix(line, "  version:"):
			current.Version = cleanYarnValue(strings.TrimSpace(strings.TrimPrefix(line, "  version:")))
		case strings.HasPrefix(line, "  resolution:"):
			resolution := cleanYarnValue(strings.TrimSpace(strings.TrimPrefix(line, "  resolution:")))
			if name := nameFromDescriptor(resolution); name != "" {
				current.Name = name
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
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
