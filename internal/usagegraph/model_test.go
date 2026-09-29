package usagegraph

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStableIDIsDeterministicAndTupleSafe(t *testing.T) {
	first := stableID(
		"ep",
		"repo-app",
		"src/index.js",
		"postWelcome",
		"3",
		"exported_module",
	)
	again := stableID(
		"ep",
		"repo-app",
		"src/index.js",
		"postWelcome",
		"3",
		"exported_module",
	)
	changed := stableID(
		"ep",
		"repo-app",
		"src/index.js",
		"postWelcome",
		"4",
		"exported_module",
	)
	joinedDifferently := stableID(
		"ep",
		"repo-app",
		"src/index.js",
		"post",
		"Welcome3",
		"exported_module",
	)

	if first != again {
		t.Fatalf("stable ID changed between identical inputs: %q != %q", first, again)
	}
	if first == changed {
		t.Fatalf("line change did not change stable ID: %q", first)
	}
	if first == joinedDifferently {
		t.Fatalf("different tuples produced the same stable ID: %q", first)
	}
	if !strings.HasPrefix(first, "ep-") {
		t.Fatalf("stable ID %q does not carry its type prefix", first)
	}
}

func TestGraphJSONKeepsRequiredEmptyCollections(t *testing.T) {
	graph := Graph{
		SchemaVersion:         SchemaVersion,
		ScanID:                "scan-test",
		EntryPoints:           []EntryPoint{},
		Observations:          []Observation{},
		UnanalysedOccurrences: []UnanalysedOccurrence{},
		ParseFailures:         []ParseFailure{},
	}

	data, err := json.Marshal(graph)
	if err != nil {
		t.Fatalf("marshal graph: %v", err)
	}

	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode graph: %v", err)
	}

	if document["schemaVersion"] != "1.3.0" {
		t.Fatalf("schema version = %v, want 1.3.0", document["schemaVersion"])
	}

	for _, field := range []string{
		"entryPoints",
		"observations",
		"unanalysedOccurrences",
		"parseFailures",
	} {
		value, ok := document[field].([]any)
		if !ok || len(value) != 0 {
			t.Fatalf("%s was not emitted as an empty array: %#v", field, document[field])
		}
	}
}
