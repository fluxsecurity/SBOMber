package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestResultSchemaAcceptsAllGroundTruth(t *testing.T) {
	files, err := filepath.Glob(
		"../../corpus/expected/[0-9][0-9]-*.json",
	)
	if err != nil {
		t.Fatalf("locate expected files: %v", err)
	}

	if len(files) != 13 {
		t.Fatalf("expected 13 ground-truth files, got %d", len(files))
	}

	totalImports := 0
	totalCalls := 0
	totalFunctions := 0
	totalUnresolved := 0

	for _, path := range files {
		path := path

		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read expected file: %v", err)
			}

			var result Result

			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.DisallowUnknownFields()

			if err := decoder.Decode(&result); err != nil {
				t.Fatalf("decode expected schema: %v", err)
			}

			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatalf("encode result schema: %v", err)
			}

			var expectedValue any
			if err := json.Unmarshal(data, &expectedValue); err != nil {
				t.Fatalf("decode expected JSON value: %v", err)
			}

			var actualValue any
			if err := json.Unmarshal(encoded, &actualValue); err != nil {
				t.Fatalf("decode re-encoded JSON value: %v", err)
			}

			if !reflect.DeepEqual(expectedValue, actualValue) {
				t.Fatal("schema round-trip changed the JSON structure")
			}

			totalImports += len(result.Imports)
			totalCalls += len(result.Calls)
			totalFunctions += len(result.Functions)
			totalUnresolved += len(result.Unresolved)
		})
	}

	if totalImports != 19 {
		t.Fatalf("expected 19 imports, got %d", totalImports)
	}

	if totalCalls != 30 {
		t.Fatalf("expected 30 calls, got %d", totalCalls)
	}

	if totalFunctions != 12 {
		t.Fatalf("expected 12 functions, got %d", totalFunctions)
	}

	if totalUnresolved != 2 {
		t.Fatalf("expected 2 unresolved entries, got %d", totalUnresolved)
	}

	t.Logf(
		"ground truth totals: imports=%d calls=%d functions=%d unresolved=%d",
		totalImports,
		totalCalls,
		totalFunctions,
		totalUnresolved,
	)
}
