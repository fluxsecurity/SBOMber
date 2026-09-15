package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/deps"
)

func TestSaveSBOMCreatesFiles(t *testing.T) {
	tmp := t.TempDir()
	summary := deps.Summary{
		Direct: []deps.Dependency{
			{Name: "react", Version: "19.1.0", Scope: deps.ScopeRuntime},
			{Name: "vitest", Version: "1.6.1", Scope: deps.ScopeDev},
		},
		Transitive: []deps.Dependency{
			{Name: "vite", Version: "5.4.0", Scope: deps.ScopeRuntime},
		},
	}

	files, outputDir, err := SaveSBOM(tmp, "prettier", summary, "both")
	if err != nil {
		t.Fatalf("expected no error saving sbom, got %v", err)
	}

	if len(files) != 2 {
		t.Fatalf("expected 2 files saved, got %d", len(files))
	}

	// Output should be in ~/.sbomber/reports/
	if !strings.Contains(outputDir, SBOMberDir) || !strings.Contains(outputDir, ReportsDir) {
		t.Fatalf("expected output dir to be in ~/.sbomber/reports/, got %q", outputDir)
	}

	for _, path := range files {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected file %q to exist, got error %v", path, err)
		}
	}

	cyclonePath := filepath.Join(outputDir, cycloneDXFilename)
	if _, err := os.ReadFile(cyclonePath); err != nil {
		t.Fatalf("expected cyclonedx file to be readable, got %v", err)
	}

	spdxPath := filepath.Join(outputDir, spdxFilename)
	if _, err := os.ReadFile(spdxPath); err != nil {
		t.Fatalf("expected spdx file to be readable, got %v", err)
	}

	// Cleanup test output
	_ = os.RemoveAll(outputDir)
}

// TestCycloneDXScopeReflectsBuildScopeNotDirectness is the success case
// for the scope-semantics fix: a transitive runtime dependency must be
// "required" in CycloneDX output, not "optional" — CycloneDX's optional
// scope means "not needed to build/run", which is unrelated to whether a
// component is direct or transitive.
func TestCycloneDXScopeReflectsBuildScopeNotDirectness(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	summary := deps.Summary{
		Direct: []deps.Dependency{
			{Name: "app-entry", Version: "1.0.0", Scope: deps.ScopeRuntime, Ecosystem: "npm", IsDirect: true, Children: []string{"lodash"}},
		},
		Transitive: []deps.Dependency{
			{Name: "lodash", Version: "4.18.1", Scope: deps.ScopeRuntime, Ecosystem: "npm"},
		},
	}

	path, err := saveCycloneDXJSON(tmp, "repo", summary)
	if err != nil {
		t.Fatalf("saveCycloneDXJSON returned error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated sbom: %v", err)
	}

	var bom cycloneDXJSONBom
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("unmarshal generated sbom: %v", err)
	}

	var lodash *cycloneDXJSONComponent
	for i := range bom.Components {
		if bom.Components[i].Name == "lodash" {
			lodash = &bom.Components[i]
		}
	}
	if lodash == nil {
		t.Fatal("expected a lodash component in the generated sbom")
	}
	if lodash.Scope != "required" {
		t.Errorf("expected transitive runtime dependency lodash to have scope 'required', got %q", lodash.Scope)
	}
}

// TestCycloneDXScopeDevTransitiveStaysOptional is the boundary case
// showing the fix did not just flip every transitive component to
// required: a transitive dependency that is itself dev/test-scoped must
// still be reported as optional.
func TestCycloneDXScopeDevTransitiveStaysOptional(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	summary := deps.Summary{
		Transitive: []deps.Dependency{
			{Name: "test-helper", Version: "1.0.0", Scope: deps.ScopeDev, Ecosystem: "npm"},
		},
	}

	path, err := saveCycloneDXJSON(tmp, "repo", summary)
	if err != nil {
		t.Fatalf("saveCycloneDXJSON returned error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated sbom: %v", err)
	}

	var bom cycloneDXJSONBom
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("unmarshal generated sbom: %v", err)
	}
	if len(bom.Components) != 1 || bom.Components[0].Scope != "optional" {
		t.Fatalf("expected the dev-scoped transitive dependency to stay 'optional', got %+v", bom.Components)
	}
}

// TestCycloneDXBomRefNoCollisionAcrossVersions is the nested-version
// boundary case for the bomRefMap fix: the same package name resolved to
// two different versions (e.g. hoisted at one version, nested under a
// dependency at another) must produce two distinct components with two
// distinct bom-refs in the generated SBOM, not one collapsed-by-name entry.
func TestCycloneDXBomRefNoCollisionAcrossVersions(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	summary := deps.Summary{
		Direct: []deps.Dependency{
			{Name: "lodash", Version: "4.18.1", Scope: deps.ScopeRuntime, Ecosystem: "npm", IsDirect: true},
		},
		Transitive: []deps.Dependency{
			{Name: "lodash", Version: "3.10.1", Scope: deps.ScopeRuntime, Ecosystem: "npm"},
		},
	}

	path, err := saveCycloneDXJSON(tmp, "repo", summary)
	if err != nil {
		t.Fatalf("saveCycloneDXJSON returned error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated sbom: %v", err)
	}

	var bom cycloneDXJSONBom
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("unmarshal generated sbom: %v", err)
	}

	lodashComponents := make(map[string]bool)
	for _, c := range bom.Components {
		if c.Name == "lodash" {
			lodashComponents[c.BOMRef] = true
		}
	}
	if len(lodashComponents) != 2 {
		t.Fatalf("expected 2 distinct bom-refs for the two lodash versions, got %d: %v", len(lodashComponents), lodashComponents)
	}
}
