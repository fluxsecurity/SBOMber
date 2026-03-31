package deps

import "sort"

// Scope identifies how a dependency is used by a project.
type Scope string

const (
	ScopeRuntime  Scope = "runtime"
	ScopeDev      Scope = "development"
	ScopePeer     Scope = "peer"
	ScopeOptional Scope = "optional"
)

// Dependency describes a single direct dependency declared by a manifest.
type Dependency struct {
	Name    string
	Version string
	Scope   Scope
}

// Summary is a normalized dependency view that can later feed SBOM generation.
type Summary struct {
	Direct     []Dependency
	Transitive []Dependency
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
