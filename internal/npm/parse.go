package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"github.com/Xsamsx/SBOMber/internal/deps"
)

type packageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// ParsePackageJSON reads package.json and returns a normalized summary of direct
// dependencies.
func ParsePackageJSON(root string) (deps.Summary, error) {
	path := filepath.Join(root, "package.json")
	content, err := os.ReadFile(path)
	if err != nil {
		return deps.Summary{}, err
	}

	var manifest packageJSON
	if err := json.Unmarshal(content, &manifest); err != nil {
		return deps.Summary{}, err
	}

	summary := deps.Summary{
		Direct: make([]deps.Dependency, 0),
	}

	appendDependencies := func(scope deps.Scope, values map[string]string) {
		if len(values) == 0 {
			return
		}

		names := make([]string, 0, len(values))
		for name := range values {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			summary.Direct = append(summary.Direct, deps.Dependency{
				Name:    name,
				Version: values[name],
				Scope:   scope,
			})
		}
	}

	appendDependencies(deps.ScopeRuntime, manifest.Dependencies)
	appendDependencies(deps.ScopeDev, manifest.DevDependencies)
	appendDependencies(deps.ScopePeer, manifest.PeerDependencies)
	appendDependencies(deps.ScopeOptional, manifest.OptionalDependencies)

	return summary, nil
}
