package npm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Xsamsx/SBOMber/internal/deps"
)

type packageLockFile struct {
	LockfileVersion int                         `json:"lockfileVersion"`
	Packages        map[string]packageLockEntry `json:"packages"`
}

type packageLockEntry struct {
	Version      string            `json:"version"`
	Dev          bool              `json:"dev"`
	Optional     bool              `json:"optional"`
	Dependencies map[string]string `json:"dependencies"`
}

// EnrichFromPackageLock reads an npm lockfile (lockfileVersion 2 or 3, the
// flat "packages" map format) and reconciles it against an existing npm
// summary built from package.json:
//
//   - Each direct dependency's Version (a semver range like "^4.17.15") is
//     replaced in place with the exact version npm actually resolved and
//     would install, read from packages["node_modules/<name>"].version. The
//     dependency stays a single Direct entry, still classified direct — it
//     is corrected, not duplicated.
//   - Every other entry in the lockfile becomes a Transitive dependency,
//     keyed by name+"@"+version so that the same package resolved to two
//     different versions under two different node_modules install paths
//     (a real npm outcome when a nested dependency needs an incompatible
//     version of something already hoisted) produces two distinct entries,
//     not one collapsed-by-name entry.
//
// Only lockfileVersion 2/3's "packages" map is supported; a v1 lockfile
// (nested "dependencies" tree, no top-level "packages" key) is reported as
// an error and left for the caller to fall back on package.json alone, the
// same way a missing yarn.lock is handled by EnrichFromYarnLock.
func EnrichFromPackageLock(root string, summary deps.Summary) (deps.Summary, error) {
	path := filepath.Join(root, "package-lock.json")
	content, err := os.ReadFile(path)
	if err != nil {
		return summary, err
	}

	var lock packageLockFile
	if err := json.Unmarshal(content, &lock); err != nil {
		return summary, err
	}
	if len(lock.Packages) == 0 {
		return summary, fmt.Errorf("package-lock.json: unsupported format (no top-level \"packages\" map; lockfileVersion 1 is not supported)")
	}

	directIndex := make(map[string]int, len(summary.Direct))
	for i, dependency := range summary.Direct {
		directIndex[dependency.Name] = i
	}

	// Reconcile direct dependencies to their resolved, exact version.
	for name, idx := range directIndex {
		if entry, ok := lock.Packages["node_modules/"+name]; ok && entry.Version != "" {
			summary.Direct[idx].Version = entry.Version
			summary.Direct[idx].Children = dependencyNames(entry.Dependencies)
		}
	}

	transitive := make(map[string]deps.Dependency)
	for pkgPath, entry := range lock.Packages {
		if pkgPath == "" || entry.Version == "" {
			continue
		}

		name := packageNameFromPath(pkgPath)
		if name == "" {
			continue
		}

		// Already represented as a direct dependency at its top-level
		// install path — skip so it isn't duplicated into Transitive.
		if _, isDirect := directIndex[name]; isDirect && pkgPath == "node_modules/"+name {
			continue
		}

		key := name + "@" + entry.Version
		transitive[key] = deps.Dependency{
			Name:           name,
			Version:        entry.Version,
			Scope:          packageLockScope(entry),
			Ecosystem:      "npm",
			Children:       dependencyNames(entry.Dependencies),
			SourceFile:     "package-lock.json",
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

// packageNameFromPath extracts a package name from an npm lockfile install
// path such as "node_modules/lodash" or the nested
// "node_modules/foo/node_modules/lodash", returning "lodash" in both cases.
// Scoped packages (e.g. "node_modules/@babel/core") are returned whole,
// since only "node_modules/" is used as the split delimiter.
func packageNameFromPath(pkgPath string) string {
	parts := strings.Split(pkgPath, "node_modules/")
	return parts[len(parts)-1]
}

func packageLockScope(entry packageLockEntry) deps.Scope {
	switch {
	case entry.Dev:
		return deps.ScopeDev
	case entry.Optional:
		return deps.ScopeOptional
	default:
		return deps.ScopeRuntime
	}
}

func dependencyNames(dependencies map[string]string) []string {
	if len(dependencies) == 0 {
		return nil
	}
	names := make([]string, 0, len(dependencies))
	for name := range dependencies {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
