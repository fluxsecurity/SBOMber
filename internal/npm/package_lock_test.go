package npm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/deps"
)

func writePackageLock(t *testing.T, root, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(content), 0o644); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}
}

// TestEnrichFromPackageLockResolvesDirectVersion is the success case: a
// range-declared direct dependency ("^4.17.15") is resolved by
// package-lock.json to its exact installed version and stays a single
// Direct entry, still classified direct — not duplicated into Transitive.
func TestEnrichFromPackageLockResolvesDirectVersion(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writePackageLock(t, root, `{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "test-vuln", "version": "1.0.0", "dependencies": {"lodash": "^4.17.15"}},
			"node_modules/lodash": {"version": "4.18.1"}
		}
	}`)

	summary := deps.Summary{
		Direct: []deps.Dependency{
			{Name: "lodash", Version: "^4.17.15", Scope: deps.ScopeRuntime, Ecosystem: "npm", IsDirect: true},
		},
	}

	enriched, err := EnrichFromPackageLock(root, summary)
	if err != nil {
		t.Fatalf("EnrichFromPackageLock returned error: %v", err)
	}

	if len(enriched.Direct) != 1 {
		t.Fatalf("expected exactly 1 direct dependency, got %d", len(enriched.Direct))
	}
	if got := enriched.Direct[0]; got.Version != "4.18.1" || !got.IsDirect {
		t.Fatalf("expected lodash resolved to 4.18.1 and still direct, got version=%q isDirect=%v", got.Version, got.IsDirect)
	}
	for _, tr := range enriched.Transitive {
		if tr.Name == "lodash" {
			t.Fatalf("expected lodash not to also appear in Transitive, found version %q", tr.Version)
		}
	}
}

// TestEnrichFromPackageLockMissingFile is the failure/unknown-path case:
// no package-lock.json exists, so the function must return an error and
// leave the summary untouched, matching EnrichFromYarnLock's behavior for
// a missing yarn.lock.
func TestEnrichFromPackageLockMissingFile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	summary := deps.Summary{
		Direct: []deps.Dependency{
			{Name: "lodash", Version: "^4.17.15", Scope: deps.ScopeRuntime, Ecosystem: "npm", IsDirect: true},
		},
	}

	enriched, err := EnrichFromPackageLock(root, summary)
	if err == nil {
		t.Fatal("expected an error when package-lock.json is missing, got nil")
	}
	if enriched.Direct[0].Version != "^4.17.15" {
		t.Fatalf("expected summary to be returned unchanged, got version %q", enriched.Direct[0].Version)
	}
}

// TestEnrichFromPackageLockNestedVersions is the boundary case: the same
// package name resolved to two different versions under two different
// node_modules install paths (a real npm outcome when a nested dependency
// needs an incompatible version of something already hoisted) must produce
// two distinct occurrences, not one collapsed-by-name entry.
func TestEnrichFromPackageLockNestedVersions(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writePackageLock(t, root, `{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "app", "version": "1.0.0", "dependencies": {"foo": "^1.0.0", "lodash": "^4.0.0"}},
			"node_modules/lodash": {"version": "4.18.1"},
			"node_modules/foo": {"version": "1.5.0", "dependencies": {"lodash": "^3.0.0"}},
			"node_modules/foo/node_modules/lodash": {"version": "3.10.1"}
		}
	}`)

	summary := deps.Summary{
		Direct: []deps.Dependency{
			{Name: "foo", Version: "^1.0.0", Scope: deps.ScopeRuntime, Ecosystem: "npm", IsDirect: true},
			{Name: "lodash", Version: "^4.0.0", Scope: deps.ScopeRuntime, Ecosystem: "npm", IsDirect: true},
		},
	}

	enriched, err := EnrichFromPackageLock(root, summary)
	if err != nil {
		t.Fatalf("EnrichFromPackageLock returned error: %v", err)
	}

	var lodashVersions []string
	for _, tr := range enriched.Transitive {
		if tr.Name == "lodash" {
			lodashVersions = append(lodashVersions, tr.Version)
		}
	}
	if len(lodashVersions) != 1 {
		t.Fatalf("expected exactly 1 transitive lodash occurrence (the nested 3.10.1 under foo; the top-level 4.18.1 is the reconciled direct dependency), got %d: %v", len(lodashVersions), lodashVersions)
	}
	if lodashVersions[0] != "3.10.1" {
		t.Fatalf("expected the nested transitive occurrence to be lodash@3.10.1, got %q", lodashVersions[0])
	}

	var directLodash deps.Dependency
	for _, d := range enriched.Direct {
		if d.Name == "lodash" {
			directLodash = d
		}
	}
	if directLodash.Version != "4.18.1" {
		t.Fatalf("expected the direct lodash dependency resolved to 4.18.1, got %q", directLodash.Version)
	}

	// The two lodash occurrences (direct@4.18.1, transitive@3.10.1) are
	// genuinely distinct versions and must not be equal.
	if directLodash.Version == lodashVersions[0] {
		t.Fatalf("expected the direct and nested transitive lodash occurrences to differ in version, both were %q", directLodash.Version)
	}
}
