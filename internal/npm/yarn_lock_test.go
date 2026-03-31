package npm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/deps"
)

func TestEnrichFromYarnLock(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	lockfile := `# yarn lockfile v8

__metadata:
  version: 8

"chalk@npm:^5.0.0":
  version: 5.6.2
  resolution: "chalk@npm:5.6.2"
  dependencies:
    ansi-styles: "npm:^4.3.0"

"ansi-styles@npm:^4.3.0":
  version: 4.3.0
  resolution: "ansi-styles@npm:4.3.0"

"vite@npm:^5.0.0":
  version: 5.4.0
  resolution: "vite@npm:5.4.0"
  dependencies:
    esbuild: "npm:^0.21.0"

"esbuild@npm:^0.21.0":
  version: 0.21.5
  resolution: "esbuild@npm:0.21.5"
`
	if err := os.WriteFile(filepath.Join(root, "yarn.lock"), []byte(lockfile), 0o644); err != nil {
		t.Fatalf("write yarn.lock: %v", err)
	}

	summary := deps.Summary{
		Direct: []deps.Dependency{
			{Name: "chalk", Version: "^5.0.0", Scope: deps.ScopeRuntime},
			{Name: "vite", Version: "^5.0.0", Scope: deps.ScopeDev},
		},
	}

	enriched, err := EnrichFromYarnLock(root, summary)
	if err != nil {
		t.Fatalf("EnrichFromYarnLock returned error: %v", err)
	}

	if enriched.TransitiveCount() != 2 {
		t.Fatalf("expected 2 transitive dependencies, got %d", enriched.TransitiveCount())
	}

	if enriched.Transitive[0].Name != "ansi-styles" || enriched.Transitive[1].Name != "esbuild" {
		t.Fatalf("unexpected transitive dependencies: %#v", enriched.Transitive)
	}
}
