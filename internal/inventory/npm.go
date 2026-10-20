package inventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Xsamsx/SBOMber/internal/deps"
)

// maxManifestBytes bounds how much of package.json or package-lock.json is
// read. A larger file is an error, never a truncated parse.
const maxManifestBytes = 128 << 20

type packageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type lockFile struct {
	LockfileVersion int                  `json:"lockfileVersion"`
	Packages        map[string]lockEntry `json:"packages"`
}

type lockEntry struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dev                  bool              `json:"dev"`
	Optional             bool              `json:"optional"`
	DevOptional          bool              `json:"devOptional"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// npmPackage is one installed package found by walking the lockfile.
type npmPackage struct {
	name               string
	version            string
	installPath        string // node_modules/a/node_modules/b
	workspace          string // "" for the repository root
	direct             bool
	scope              string
	declaredConstraint string
	dependencyPath     []npmRef // direct dependency first, parent last
	manifest           string
}

type npmRef struct{ name, version string }

// declared is one dependency a project root (the repository or a workspace)
// declares, with the scope its declaration gives it.
type declared struct {
	name, constraint, scope string
}

// readNPM returns every installed npm package in a repository. Without a
// lockfile only the direct dependencies are known, each with the version
// package.json pins or, for a range, no version; the returned note says so.
func readNPM(root string) (packages []npmPackage, note string, err error) {
	var manifest packageJSON
	found, err := readJSON(filepath.Join(root, "package.json"), &manifest)
	if err != nil || !found {
		return nil, "", err
	}

	var lock lockFile
	haveLock, err := readJSON(filepath.Join(root, "package-lock.json"), &lock)
	if err != nil {
		return nil, "", err
	}
	if !haveLock || len(lock.Packages) == 0 {
		why := "no package-lock.json"
		if haveLock {
			why = "package-lock.json has no \"packages\" map (lockfileVersion 1 is not supported)"
		}
		return directOnly(manifest), "npm: " + why + "; versions are as declared and transitive dependencies are not listed", nil
	}
	return walkLock(manifest, lock), "", nil
}

// yarnPackages returns the npm packages scan resolved from yarn.lock, or nil
// when the repository has no yarn.lock or scan resolved nothing from it.
func yarnPackages(root string, summary deps.Summary) []npmPackage {
	if _, err := os.Stat(filepath.Join(root, "yarn.lock")); err != nil {
		return nil
	}
	var packages []npmPackage
	resolved := false
	add := func(dep deps.Dependency, direct bool) {
		if !strings.EqualFold(dep.Ecosystem, "npm") {
			return
		}
		pkg := npmPackage{name: dep.Name, direct: direct, scope: contractScope(dep.Scope), manifest: "yarn.lock"}
		if direct {
			pkg.manifest = "package.json"
			pkg.installPath = "node_modules/" + dep.Name
		}
		if isExactVersion(dep.Version) {
			pkg.version = dep.Version
		} else {
			pkg.declaredConstraint = dep.Version
		}
		packages = append(packages, pkg)
	}
	for _, dep := range summary.Direct {
		if strings.EqualFold(dep.Ecosystem, "npm") && isExactVersion(dep.Version) {
			resolved = true
		}
		add(dep, true)
	}
	for _, dep := range summary.Transitive {
		if strings.EqualFold(dep.Ecosystem, "npm") {
			resolved = true
		}
		add(dep, false)
	}
	if !resolved {
		return nil
	}
	return packages
}

func directOnly(manifest packageJSON) []npmPackage {
	packages := make([]npmPackage, 0)
	for _, dep := range declaredDependencies(manifest.Dependencies, manifest.DevDependencies, manifest.OptionalDependencies, manifest.PeerDependencies) {
		pkg := npmPackage{
			name:        dep.name,
			installPath: "node_modules/" + dep.name,
			direct:      true,
			scope:       dep.scope,
			manifest:    "package.json",
		}
		if isExactVersion(dep.constraint) {
			pkg.version = dep.constraint
		} else {
			pkg.declaredConstraint = dep.constraint
		}
		packages = append(packages, pkg)
	}
	return packages
}

// declaredDependencies lists a project's declared dependencies, sorted by
// name. A name declared in several groups takes the first group's scope,
// in the order runtime, development, optional, peer.
func declaredDependencies(runtime, dev, optional, peer map[string]string) []declared {
	seen := make(map[string]bool)
	var out []declared
	add := func(values map[string]string, scope string) {
		names := make([]string, 0, len(values))
		for name := range values {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, declared{name: name, constraint: values[name], scope: scope})
		}
	}
	add(runtime, "runtime")
	add(dev, "development")
	add(optional, "optional")
	add(peer, "runtime")
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// walkLock follows npm's own resolution through the lockfile: a package
// installed at P that requires N gets the nearest P/node_modules/N, then
// each enclosing node_modules up to the project root. Each package's
// dependency path is the shortest chain from a direct dependency.
func walkLock(manifest packageJSON, lock lockFile) []npmPackage {
	// Project roots: the repository ("") and its workspaces, which the
	// lockfile lists under their folder path with no node_modules segment.
	roots := []string{""}
	for key, entry := range lock.Packages {
		if key != "" && !strings.Contains(key, "node_modules/") && !entry.Link {
			roots = append(roots, key)
		}
	}
	sort.Strings(roots)

	found := make(map[string]*npmPackage)
	type step struct {
		installPath string
		path        []npmRef
	}
	var queue []step

	visit := func(installPath string, parentPath []npmRef, dep declared, direct bool, workspace string) {
		entry, ok := lock.Packages[installPath]
		if !ok || entry.Link {
			return
		}
		if existing, seen := found[installPath]; seen {
			// A package declared by a project root is direct even when
			// something else reached it first.
			if direct && !existing.direct {
				existing.direct = true
				existing.dependencyPath = nil
				existing.scope = dep.scope
				existing.manifest = manifestFor(workspace)
				existing.declaredConstraint = dep.constraint
			}
			return
		}
		pkg := &npmPackage{
			name:        packageName(installPath, entry),
			version:     entry.Version,
			installPath: installPath,
			workspace:   workspaceOf(installPath),
			direct:      direct,
			scope:       lockScope(entry),
			manifest:    "package-lock.json",
		}
		if direct {
			pkg.scope = dep.scope
			pkg.manifest = manifestFor(workspace)
			pkg.declaredConstraint = dep.constraint
		} else {
			pkg.dependencyPath = parentPath
		}
		found[installPath] = pkg
		queue = append(queue, step{installPath: installPath, path: append(append([]npmRef{}, parentPath...), npmRef{pkg.name, pkg.version})})
	}

	// Direct dependencies first, so every direct package is marked direct
	// before any transitive path reaches it.
	for _, root := range roots {
		var deps []declared
		if root == "" {
			deps = declaredDependencies(manifest.Dependencies, manifest.DevDependencies, manifest.OptionalDependencies, manifest.PeerDependencies)
		} else {
			entry := lock.Packages[root]
			deps = declaredDependencies(entry.Dependencies, entry.DevDependencies, entry.OptionalDependencies, entry.PeerDependencies)
		}
		for _, dep := range deps {
			if installPath, ok := resolve(lock, root, dep.name); ok {
				visit(installPath, nil, dep, true, root)
			}
		}
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		entry := lock.Packages[current.installPath]
		for _, dep := range declaredDependencies(entry.Dependencies, nil, entry.OptionalDependencies, entry.PeerDependencies) {
			if installPath, ok := resolve(lock, current.installPath, dep.name); ok {
				visit(installPath, current.path, dep, false, "")
			}
		}
	}

	// Anything installed but unreachable (an extraneous package) is still
	// listed, as transitive with no known path, rather than dropped.
	keys := make([]string, 0, len(lock.Packages))
	for key := range lock.Packages {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		entry := lock.Packages[key]
		if _, seen := found[key]; seen || entry.Link || !strings.Contains(key, "node_modules/") {
			continue
		}
		found[key] = &npmPackage{
			name:        packageName(key, entry),
			version:     entry.Version,
			installPath: key,
			workspace:   workspaceOf(key),
			scope:       lockScope(entry),
			manifest:    "package-lock.json",
		}
	}

	packages := make([]npmPackage, 0, len(found))
	for _, pkg := range found {
		packages = append(packages, *pkg)
	}
	sort.Slice(packages, func(i, j int) bool { return packages[i].installPath < packages[j].installPath })
	return packages
}

// resolve finds where the package at from would load name from.
func resolve(lock lockFile, from, name string) (string, bool) {
	dir := from
	for {
		candidate := "node_modules/" + name
		if dir != "" {
			candidate = dir + "/" + candidate
		}
		if _, ok := lock.Packages[candidate]; ok {
			return candidate, true
		}
		if dir == "" {
			return "", false
		}
		// Step out of the innermost node_modules/<package>; from a top-level
		// package or a workspace folder, out to the repository root.
		if i := strings.LastIndex(dir, "/node_modules/"); i >= 0 {
			dir = dir[:i]
		} else {
			dir = ""
		}
	}
}

// packageName is the name after the last node_modules/ segment, which
// includes an npm scope ("@scope/name"). A lockfile entry's own name field
// wins: it differs for aliased installs.
func packageName(installPath string, entry lockEntry) string {
	if entry.Name != "" {
		return entry.Name
	}
	if i := strings.LastIndex(installPath, "node_modules/"); i >= 0 {
		return installPath[i+len("node_modules/"):]
	}
	return installPath
}

// workspaceOf returns the workspace folder an install path sits in, or ""
// for the repository root's node_modules.
func workspaceOf(installPath string) string {
	if i := strings.Index(installPath, "/node_modules/"); i > 0 && !strings.HasPrefix(installPath, "node_modules/") {
		return installPath[:i]
	}
	return ""
}

func manifestFor(workspace string) string {
	if workspace == "" {
		return "package.json"
	}
	return workspace + "/package.json"
}

func lockScope(entry lockEntry) string {
	switch {
	case entry.Dev:
		return "development"
	case entry.Optional, entry.DevOptional:
		return "optional"
	default:
		return "runtime"
	}
}

// readJSON decodes a bounded JSON file. found is false when it does not exist.
func readJSON(path string, into any) (found bool, err error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
	if err != nil {
		return false, err
	}
	if len(data) > maxManifestBytes {
		return false, fmt.Errorf("%s is larger than %d bytes", path, maxManifestBytes)
	}
	if err := json.Unmarshal(data, into); err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	return true, nil
}
