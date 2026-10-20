package vex

import (
	"encoding/json"
	"fmt"
	"os"
)

// DecisionResultsSchemaVersion is the decision-results contract this
// exporter was written against.
const DecisionResultsSchemaVersion = "1.1.0"

// LoadDecisionResults reads decision-results.json.
func LoadDecisionResults(path string) (DecisionResults, error) {
	var dr DecisionResults
	data, err := os.ReadFile(path)
	if err != nil {
		return dr, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &dr); err != nil {
		return dr, fmt.Errorf("%s is not a decision-results.json document: %w", path, err)
	}
	if dr.SchemaVersion != DecisionResultsSchemaVersion {
		return dr, fmt.Errorf("%s has schemaVersion %q; this exporter reads %s", path, dr.SchemaVersion, DecisionResultsSchemaVersion)
	}
	return dr, nil
}

// LoadCanonicalScan reads canonical-scan.json.
func LoadCanonicalScan(path string) (*CanonicalScan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var s CanonicalScan
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%s is not a canonical-scan.json document: %w", path, err)
	}
	if s.Scan.ScanID == "" {
		return nil, fmt.Errorf("%s has no scan.scanId", path)
	}
	return &s, nil
}
