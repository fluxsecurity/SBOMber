package npm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/deps"
)

func TestParsePackageJSON(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	content := `{
  "dependencies": {
    "chalk": "^5.0.0"
  },
  "devDependencies": {
    "vitest": "^1.0.0",
    "eslint": "^9.0.0"
  },
  "optionalDependencies": {
    "fsevents": "^2.0.0"
  }
}`

	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(content), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	summary, err := ParsePackageJSON(root)
	if err != nil {
		t.Fatalf("ParsePackageJSON returned error: %v", err)
	}

	if summary.Count() != 4 {
		t.Fatalf("expected 4 direct dependencies, got %d", summary.Count())
	}

	if got := summary.CountByScope(deps.ScopeRuntime); got != 1 {
		t.Fatalf("expected 1 runtime dependency, got %d", got)
	}

	if got := summary.CountByScope(deps.ScopeDev); got != 2 {
		t.Fatalf("expected 2 development dependencies, got %d", got)
	}

	if got := summary.CountByScope(deps.ScopeOptional); got != 1 {
		t.Fatalf("expected 1 optional dependency, got %d", got)
	}
}
