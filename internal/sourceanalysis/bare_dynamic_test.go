package sourceanalysis

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBareComputedDynamicImportIsRecorded(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "app.js")
	if err := os.WriteFile(sourcePath,
		[]byte("const name = process.env.PKG;\nimport(name);\n"),
		0o600); err != nil {
		t.Fatal(err)
	}

	result, err := AnalyzeSource(sourcePath)
	if err != nil {
		t.Fatalf("bare dynamic import failed: %v", err)
	}
	if result.HasError || len(result.Imports) != 1 ||
		result.Imports[0].Kind != "dynamic_computed" ||
		result.Imports[0].Local != "" ||
		len(result.Unresolved) != 1 {
		t.Fatalf("bare dynamic import = %+v", result)
	}
}
