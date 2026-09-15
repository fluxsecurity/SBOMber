// Package canonicalscan validates documents against the canonical scan
// schema described in docs/schema/canonical-scan.schema.json. It checks
// required-field presence for the four identities (component, package
// occurrence, vulnerability finding, usage observation) documented in
// docs/design/canonical-scan.md.
package canonicalscan

import (
	"encoding/json"
	"fmt"
)

var (
	rootRequired             = []string{"schemaVersion", "scan", "components", "occurrences", "findings", "usageObservations"}
	scanRequired             = []string{"scannedAt", "sbomberVersion", "root"}
	componentRequired        = []string{"purl", "name", "version", "ecosystem"}
	occurrenceRequired       = []string{"occurrenceId", "componentPurl", "workspace", "manifestPath", "dependencyPath", "scope", "buildScope"}
	findingRequired          = []string{"findingId", "vulnerabilityId", "componentPurl", "severity"}
	usageObservationRequired = []string{"occurrenceId", "symbol", "file", "line"}
)

// Validate parses data as a canonical scan document and checks that every
// required field from the schema is present. It does not check types,
// enum membership, or the additionalProperties:false constraint — callers
// that need full JSON Schema conformance should validate against
// docs/schema/canonical-scan.schema.json directly.
func Validate(data []byte) error {
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse canonical scan document: %w", err)
	}

	var problems []string
	problems = append(problems, missingKeys("root", doc, rootRequired)...)

	if scan, ok := doc["scan"].(map[string]interface{}); ok {
		problems = append(problems, missingKeys("scan", scan, scanRequired)...)
	} else if _, present := doc["scan"]; present {
		problems = append(problems, "scan: expected an object")
	}

	problems = append(problems, validateArray(doc, "components", componentRequired)...)
	problems = append(problems, validateArray(doc, "occurrences", occurrenceRequired)...)
	problems = append(problems, validateArray(doc, "findings", findingRequired)...)
	problems = append(problems, validateArray(doc, "usageObservations", usageObservationRequired)...)

	if len(problems) > 0 {
		return fmt.Errorf("canonical scan document invalid: %v", problems)
	}
	return nil
}

func validateArray(doc map[string]interface{}, field string, required []string) []string {
	raw, ok := doc[field]
	if !ok {
		return nil
	}
	items, ok := raw.([]interface{})
	if !ok {
		return []string{fmt.Sprintf("%s: expected an array", field)}
	}

	var problems []string
	for i, item := range items {
		ctx := fmt.Sprintf("%s[%d]", field, i)
		obj, ok := item.(map[string]interface{})
		if !ok {
			problems = append(problems, ctx+": expected an object")
			continue
		}
		problems = append(problems, missingKeys(ctx, obj, required)...)
	}
	return problems
}

func missingKeys(ctx string, obj map[string]interface{}, keys []string) []string {
	var problems []string
	for _, k := range keys {
		if _, ok := obj[k]; !ok {
			problems = append(problems, fmt.Sprintf("%s: missing required field %q", ctx, k))
		}
	}
	return problems
}
