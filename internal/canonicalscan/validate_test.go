package canonicalscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateSampleFixture(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", "canonical-scan", "sample.canonical-scan.json"))
	if err != nil {
		t.Fatalf("read sample fixture: %v", err)
	}

	if err := Validate(data); err != nil {
		t.Fatalf("expected sample fixture to validate, got: %v", err)
	}
}

func TestValidateMalformedJSON(t *testing.T) {
	t.Parallel()

	err := Validate([]byte("{not valid json"))
	if err == nil {
		t.Fatal("expected an error for malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parse canonical scan document") {
		t.Fatalf("expected a parse error, got: %v", err)
	}
}

func TestValidateMissingNestedRequiredField(t *testing.T) {
	t.Parallel()

	// A boundary case: the document is well-formed JSON and has every
	// top-level key, but one occurrence is missing componentPurl — the
	// field that ties it back to a component. This is the untrusted-input
	// shape a hand-edited or partially-generated document could produce.
	doc := `{
		"schemaVersion": "0.1.0",
		"scan": {"scannedAt": "2026-08-25T00:00:00Z", "sbomberVersion": "0.1.0", "root": "."},
		"components": [],
		"occurrences": [
			{"occurrenceId": "x", "workspace": "repo", "manifestPath": "package.json", "dependencyPath": [], "scope": "direct", "buildScope": "runtime"}
		],
		"findings": [],
		"usageObservations": []
	}`

	err := Validate([]byte(doc))
	if err == nil {
		t.Fatal("expected an error for an occurrence missing componentPurl, got nil")
	}
	if !strings.Contains(err.Error(), `occurrences[0]: missing required field "componentPurl"`) {
		t.Fatalf("expected a missing-componentPurl error, got: %v", err)
	}
}
