package deps

import (
	"fmt"
	"sort"
	"strings"
)

// Scope identifies how a dependency is used by a project.
type Scope string

const (
	ScopeRuntime  Scope = "runtime"
	ScopeDev      Scope = "development"
	ScopePeer     Scope = "peer"
	ScopeOptional Scope = "optional"
	ScopeTest     Scope = "test"
	ScopeBuild    Scope = "build"
)

// Dependency describes a single dependency declared by a manifest.
type Dependency struct {
	Name      string
	Version   string
	Scope     Scope
	Ecosystem string

	// Chain tracking fields
	ParentName string   // Name of parent dependency (empty for direct deps)
	Children   []string // Names of child dependencies
	Depth      int      // Hops from root (0 for direct deps)
	Chain      string   // Full path: "root > pkg-a > pkg-b"
	IsDirect   bool     // True if this is a direct dependency

	// Source tracking fields
	SourceFile     string // Manifest file that introduced this dep (e.g., "package.json", "go.mod")
	SourceLocation string // Full path to the manifest in the repo

	// False positive detection
	IsTestDep    bool   // True if from test directory or test manifest
	IsExampleDep bool   // True if from example/sample directory
	FPReason     string // Reason why this might be a false positive
}

// Purl returns the Package URL for this dependency.
func (d Dependency) Purl() string {
	if d.Name == "" {
		return ""
	}
	ecosystem := d.Ecosystem
	if ecosystem == "" {
		ecosystem = "generic"
	}
	// Handle scoped npm packages
	name := d.Name
	if strings.HasPrefix(name, "@") {
		// npm scoped package: @scope/name -> %40scope/name
		name = strings.Replace(name, "@", "%40", 1)
	}
	if d.Version == "" {
		return fmt.Sprintf("pkg:%s/%s", ecosystem, name)
	}
	return fmt.Sprintf("pkg:%s/%s@%s", ecosystem, name, d.Version)
}

// BuildScope returns the build scope classification.
func (d Dependency) BuildScope() string {
	switch d.Scope {
	case ScopeRuntime:
		return "runtime"
	case ScopeDev:
		return "dev"
	case ScopeTest:
		return "test"
	case ScopeBuild:
		return "build-tooling"
	default:
		return "runtime"
	}
}

// Summary is a normalized dependency view that can later feed SBOM generation.
type Summary struct {
	Direct     []Dependency
	Transitive []Dependency
	// DependencyGraph maps package name to its dependency entry for chain lookups
	DependencyGraph map[string]*Dependency
}

// Count returns the total number of direct dependencies.
func (s Summary) Count() int {
	return len(s.Direct)
}

// TransitiveCount returns the total number of transitive dependencies.
func (s Summary) TransitiveCount() int {
	return len(s.Transitive)
}

// TotalCount returns the total number of known dependencies.
func (s Summary) TotalCount() int {
	return len(s.Direct) + len(s.Transitive)
}

// CountByScope returns the number of direct dependencies in the requested scope.
func (s Summary) CountByScope(scope Scope) int {
	count := 0
	for _, dependency := range s.Direct {
		if dependency.Scope == scope {
			count++
		}
	}

	return count
}

// PreviewNames returns up to limit dependency names in sorted order.
func (s Summary) PreviewNames(limit int) []string {
	if limit <= 0 || len(s.Direct) == 0 {
		return nil
	}

	names := make([]string, 0, len(s.Direct))
	for _, dependency := range s.Direct {
		names = append(names, dependency.Name)
	}

	sort.Strings(names)
	if len(names) > limit {
		names = names[:limit]
	}

	return names
}

// BuildGraph constructs the dependency graph and populates chain information.
// rootName is the name of the root project.
func (s *Summary) BuildGraph(rootName string) {
	s.DependencyGraph = make(map[string]*Dependency)

	// Add all dependencies to the graph
	for i := range s.Direct {
		s.Direct[i].IsDirect = true
		s.Direct[i].Depth = 0
		s.Direct[i].Chain = rootName + " > " + s.Direct[i].Name
		s.DependencyGraph[s.Direct[i].Name] = &s.Direct[i]
	}

	for i := range s.Transitive {
		s.Transitive[i].IsDirect = false
		s.DependencyGraph[s.Transitive[i].Name] = &s.Transitive[i]
	}

	// Calculate depths and chains for transitive deps using BFS
	visited := make(map[string]bool)
	queue := make([]string, 0)

	// Start with direct deps
	for _, d := range s.Direct {
		visited[d.Name] = true
		queue = append(queue, d.Name)
	}

	// BFS to calculate depths
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		dep := s.DependencyGraph[current]
		if dep == nil {
			continue
		}

		for _, childName := range dep.Children {
			child := s.DependencyGraph[childName]
			if child == nil {
				continue
			}

			// Only update if not visited or found shorter path
			if !visited[childName] || child.Depth > dep.Depth+1 {
				child.Depth = dep.Depth + 1
				child.ParentName = current
				child.Chain = dep.Chain + " > " + childName

				if !visited[childName] {
					visited[childName] = true
					queue = append(queue, childName)
				}
			}
		}
	}

	// Set default chain for unconnected transitive deps
	for i := range s.Transitive {
		if s.Transitive[i].Chain == "" {
			s.Transitive[i].Chain = rootName + " > ... > " + s.Transitive[i].Name
			s.Transitive[i].Depth = 1 // Assume at least 1 hop
		}
	}
}

// TraceChain returns all paths to reach a specific package.
// Returns a slice of chain strings showing how to reach the package.
func (s *Summary) TraceChain(packageName string) []string {
	if s.DependencyGraph == nil {
		return nil
	}

	dep := s.DependencyGraph[packageName]
	if dep == nil {
		// Search by partial name match
		for name, d := range s.DependencyGraph {
			if strings.Contains(strings.ToLower(name), strings.ToLower(packageName)) {
				dep = d
				break
			}
		}
	}

	if dep == nil {
		return nil
	}

	return []string{dep.Chain}
}

// GetDependencyTree returns a tree representation for a package.
// Handles circular dependencies by tracking visited nodes.
func (s *Summary) GetDependencyTree(packageName string, indent string, visited map[string]bool) string {
	if visited == nil {
		visited = make(map[string]bool)
	}

	if visited[packageName] {
		return indent + packageName + " (circular)\n"
	}
	visited[packageName] = true

	dep := s.DependencyGraph[packageName]
	if dep == nil {
		return indent + packageName + " (not found)\n"
	}

	var b strings.Builder
	depType := "transitive"
	if dep.IsDirect {
		depType = "direct"
	}
	_, _ = fmt.Fprintf(&b, "%s%s@%s [%s, depth=%d]\n", indent, dep.Name, dep.Version, depType, dep.Depth)

	for _, child := range dep.Children {
		b.WriteString(s.GetDependencyTree(child, indent+"  ", visited))
	}

	return b.String()
}

// FindDependency searches for a dependency by name (exact or partial match).
func (s *Summary) FindDependency(name string) *Dependency {
	name = strings.ToLower(name)

	// Exact match first
	for i := range s.Direct {
		if strings.ToLower(s.Direct[i].Name) == name {
			return &s.Direct[i]
		}
	}
	for i := range s.Transitive {
		if strings.ToLower(s.Transitive[i].Name) == name {
			return &s.Transitive[i]
		}
	}

	// Partial match
	for i := range s.Direct {
		if strings.Contains(strings.ToLower(s.Direct[i].Name), name) {
			return &s.Direct[i]
		}
	}
	for i := range s.Transitive {
		if strings.Contains(strings.ToLower(s.Transitive[i].Name), name) {
			return &s.Transitive[i]
		}
	}

	return nil
}

// AllDependencies returns all dependencies (direct + transitive) as a single slice.
func (s *Summary) AllDependencies() []Dependency {
	all := make([]Dependency, 0, len(s.Direct)+len(s.Transitive))
	all = append(all, s.Direct...)
	all = append(all, s.Transitive...)
	return all
}

// FilterOptions specifies criteria for filtering dependencies.
type FilterOptions struct {
	Ecosystem  string // Filter by ecosystem (npm, maven, pip, go, etc.)
	Scope      string // Filter by build-scope (runtime, build-tooling, test, dev)
	Type       string // Filter by dependency-type (direct, transitive)
	MinDepth   int    // Minimum depth (0 = direct)
	MaxDepth   int    // Maximum depth (-1 = no limit)
	SourceFile string // Filter by source manifest file
	NameFilter string // Filter by package name (partial match)
}

// NewFilterOptions creates filter options with sensible defaults.
func NewFilterOptions() FilterOptions {
	return FilterOptions{
		MinDepth: 0,
		MaxDepth: -1, // No limit
	}
}

// Filter returns dependencies matching the filter criteria.
func (s *Summary) Filter(opts FilterOptions) []Dependency {
	all := s.AllDependencies()
	filtered := make([]Dependency, 0)

	for _, dep := range all {
		if !matchesFilter(dep, opts) {
			continue
		}
		filtered = append(filtered, dep)
	}

	return filtered
}

// matchesFilter checks if a dependency matches the filter criteria.
func matchesFilter(dep Dependency, opts FilterOptions) bool {
	// Filter by ecosystem
	if opts.Ecosystem != "" && !strings.EqualFold(dep.Ecosystem, opts.Ecosystem) {
		return false
	}

	// Filter by scope/build-scope
	if opts.Scope != "" && !strings.EqualFold(dep.BuildScope(), opts.Scope) {
		return false
	}

	// Filter by type (direct/transitive)
	if opts.Type != "" {
		if strings.EqualFold(opts.Type, "direct") && !dep.IsDirect {
			return false
		}
		if strings.EqualFold(opts.Type, "transitive") && dep.IsDirect {
			return false
		}
	}

	// Filter by depth range
	if dep.Depth < opts.MinDepth {
		return false
	}
	if opts.MaxDepth >= 0 && dep.Depth > opts.MaxDepth {
		return false
	}

	// Filter by source file
	if opts.SourceFile != "" {
		if !strings.Contains(strings.ToLower(dep.SourceFile), strings.ToLower(opts.SourceFile)) &&
			!strings.Contains(strings.ToLower(dep.SourceLocation), strings.ToLower(opts.SourceFile)) {
			return false
		}
	}

	// Filter by name
	if opts.NameFilter != "" && !strings.Contains(strings.ToLower(dep.Name), strings.ToLower(opts.NameFilter)) {
		return false
	}

	return true
}

// GroupBySourceFile returns dependencies grouped by their source manifest file.
func (s *Summary) GroupBySourceFile() map[string][]Dependency {
	groups := make(map[string][]Dependency)
	for _, dep := range s.AllDependencies() {
		key := dep.SourceFile
		if key == "" {
			key = "unknown"
		}
		groups[key] = append(groups[key], dep)
	}
	return groups
}

// GroupByEcosystem returns dependencies grouped by ecosystem.
func (s *Summary) GroupByEcosystem() map[string][]Dependency {
	groups := make(map[string][]Dependency)
	for _, dep := range s.AllDependencies() {
		key := dep.Ecosystem
		if key == "" {
			key = "unknown"
		}
		groups[key] = append(groups[key], dep)
	}
	return groups
}

// DetectFalsePositives scans all dependencies and marks potential false positives.
func (s *Summary) DetectFalsePositives() {
	testPatterns := []string{
		"/test/", "/tests/", "/testing/", "/testdata/",
		"_test.go", "_test.js", "_test.py", "_test.rb",
		"/spec/", "/specs/",
		"test_", "tests_",
	}
	examplePatterns := []string{
		"/example/", "/examples/",
		"/sample/", "/samples/",
		"/demo/", "/demos/",
		"/fixture/", "/fixtures/",
		"/mock/", "/mocks/",
	}

	for i := range s.Direct {
		s.Direct[i].checkFalsePositive(testPatterns, examplePatterns)
	}
	for i := range s.Transitive {
		s.Transitive[i].checkFalsePositive(testPatterns, examplePatterns)
	}
}

func (d *Dependency) checkFalsePositive(testPatterns, examplePatterns []string) {
	pathLower := strings.ToLower(d.SourceLocation)

	for _, pattern := range testPatterns {
		if strings.Contains(pathLower, pattern) {
			d.IsTestDep = true
			d.FPReason = fmt.Sprintf("found in test path (%s)", pattern)
			return
		}
	}

	for _, pattern := range examplePatterns {
		if strings.Contains(pathLower, pattern) {
			d.IsExampleDep = true
			d.FPReason = fmt.Sprintf("found in example path (%s)", pattern)
			return
		}
	}

	// Check scope
	if d.Scope == ScopeTest || d.Scope == ScopeDev {
		d.IsTestDep = true
		d.FPReason = fmt.Sprintf("marked as %s dependency", d.Scope)
	}
}

// IsPotentialFalsePositive returns true if this dependency might be a false positive.
func (d *Dependency) IsPotentialFalsePositive() bool {
	return d.IsTestDep || d.IsExampleDep
}

// GenerateDOTGraph creates a DOT format graph for visualization with Graphviz.
func (s *Summary) GenerateDOTGraph(rootName string) string {
	var b strings.Builder

	b.WriteString("digraph dependencies {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  node [shape=box, style=filled];\n")
	b.WriteString("\n")

	// Root node
	_, _ = fmt.Fprintf(&b, "  \"%s\" [fillcolor=\"#58a6ff\", fontcolor=white, label=\"%s\\n(root)\"];\n", rootName, rootName)

	// Add all dependency nodes
	for _, dep := range s.Direct {
		color := "#3fb950" // green for direct
		if dep.IsPotentialFalsePositive() {
			color = "#d29922" // yellow for potential false positive
		}
		label := fmt.Sprintf("%s\\n%s", dep.Name, dep.Version)
		_, _ = fmt.Fprintf(&b, "  \"%s\" [fillcolor=\"%s\", label=\"%s\"];\n", dep.Name, color, label)
	}

	for _, dep := range s.Transitive {
		color := "#8b949e" // gray for transitive
		if dep.IsPotentialFalsePositive() {
			color = "#d29922" // yellow for potential false positive
		}
		label := fmt.Sprintf("%s\\n%s", dep.Name, dep.Version)
		_, _ = fmt.Fprintf(&b, "  \"%s\" [fillcolor=\"%s\", label=\"%s\"];\n", dep.Name, color, label)
	}

	b.WriteString("\n  // Edges\n")

	// Root -> direct deps
	for _, dep := range s.Direct {
		_, _ = fmt.Fprintf(&b, "  \"%s\" -> \"%s\";\n", rootName, dep.Name)
	}

	// Dependency -> children
	for _, dep := range s.AllDependencies() {
		for _, child := range dep.Children {
			_, _ = fmt.Fprintf(&b, "  \"%s\" -> \"%s\";\n", dep.Name, child)
		}
	}

	b.WriteString("}\n")
	return b.String()
}

// GenerateASCIITree creates an ASCII tree visualization of the dependency graph.
func (s *Summary) GenerateASCIITree(rootName string) string {
	var b strings.Builder

	_, _ = fmt.Fprintf(&b, "%s\n", rootName)

	directCount := len(s.Direct)
	for i, dep := range s.Direct {
		isLast := i == directCount-1
		prefix := "├── "
		if isLast {
			prefix = "└── "
		}

		fpMarker := ""
		if dep.IsPotentialFalsePositive() {
			fpMarker = " ⚠️  [" + dep.FPReason + "]"
		}

		_, _ = fmt.Fprintf(&b, "%s%s@%s (%s)%s\n", prefix, dep.Name, dep.Version, dep.SourceFile, fpMarker)

		// Print children
		childPrefix := "│   "
		if isLast {
			childPrefix = "    "
		}
		s.printChildren(&b, dep.Name, childPrefix, make(map[string]bool))
	}

	return b.String()
}

func (s *Summary) printChildren(b *strings.Builder, depName, prefix string, visited map[string]bool) {
	if visited[depName] {
		return
	}
	visited[depName] = true

	dep := s.DependencyGraph[depName]
	if dep == nil || len(dep.Children) == 0 {
		return
	}

	childCount := len(dep.Children)
	for i, childName := range dep.Children {
		child := s.DependencyGraph[childName]
		if child == nil {
			continue
		}

		isLast := i == childCount-1
		connector := "├── "
		if isLast {
			connector = "└── "
		}

		fpMarker := ""
		if child.IsPotentialFalsePositive() {
			fpMarker = " ⚠️"
		}

		if visited[childName] {
			_, _ = fmt.Fprintf(b, "%s%s%s@%s (circular)%s\n", prefix, connector, child.Name, child.Version, fpMarker)
			continue
		}

		_, _ = fmt.Fprintf(b, "%s%s%s@%s%s\n", prefix, connector, child.Name, child.Version, fpMarker)

		newPrefix := prefix + "│   "
		if isLast {
			newPrefix = prefix + "    "
		}
		s.printChildren(b, childName, newPrefix, visited)
	}
}

// GetConnectionInfo returns detailed information about how a dependency is connected.
func (s *Summary) GetConnectionInfo(depName string) *ConnectionInfo {
	dep := s.FindDependency(depName)
	if dep == nil {
		return nil
	}

	info := &ConnectionInfo{
		Dependency:   dep,
		IntroducedBy: make([]string, 0),
		UsedBy:       make([]string, 0),
		PathsToRoot:  make([][]string, 0),
	}

	// Find who introduced this dependency (parents)
	for _, d := range s.AllDependencies() {
		for _, child := range d.Children {
			if child == depName {
				info.IntroducedBy = append(info.IntroducedBy, d.Name)
			}
		}
	}

	// If no parent found and it's direct, it was introduced by the root
	if len(info.IntroducedBy) == 0 && dep.IsDirect {
		info.IntroducedBy = append(info.IntroducedBy, "(root project)")
	}

	// Find what depends on this (children are already in dep.Children)
	info.UsedBy = dep.Children

	// Build paths to root
	info.PathsToRoot = s.findAllPathsToRoot(depName, make([]string, 0), make(map[string]bool))

	return info
}

// ConnectionInfo contains detailed connection information for a dependency.
type ConnectionInfo struct {
	Dependency   *Dependency
	IntroducedBy []string   // packages that pull in this dependency
	UsedBy       []string   // packages that this dependency pulls in
	PathsToRoot  [][]string // all paths back to root
}

func (s *Summary) findAllPathsToRoot(depName string, currentPath []string, visited map[string]bool) [][]string {
	if visited[depName] {
		return nil // Circular dependency
	}

	currentPath = append([]string{depName}, currentPath...)

	dep := s.DependencyGraph[depName]
	if dep == nil {
		return nil
	}

	// If direct dependency, we've reached the root
	if dep.IsDirect {
		return [][]string{currentPath}
	}

	visited[depName] = true
	defer delete(visited, depName)

	var allPaths [][]string

	// Find parents
	for _, d := range s.AllDependencies() {
		for _, child := range d.Children {
			if child == depName {
				paths := s.findAllPathsToRoot(d.Name, currentPath, visited)
				allPaths = append(allPaths, paths...)
			}
		}
	}

	return allPaths
}
