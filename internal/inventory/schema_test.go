package inventory

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

// checkSchema validates a document against a JSON Schema, for the subset of
// draft 2020-12 the contracts use: type, properties, required,
// additionalProperties: false, items, enum, const, pattern, minItems,
// minimum and maximum. contracts/validate.py is the authority and runs in
// CI; this lets the Go tests check every document they build against the
// published schema, not against this package's own idea of it.
func checkSchema(t *testing.T, schemaPath string, doc any) {
	t.Helper()
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode document: %v", err)
	}
	var value any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatalf("decode document: %v", err)
	}
	var problems []string
	validateNode(schema, value, "$", &problems)
	for _, p := range problems {
		t.Errorf("schema: %s", p)
	}
}

func validateNode(schema map[string]any, value any, at string, problems *[]string) {
	fail := func(format string, args ...any) {
		*problems = append(*problems, at+": "+fmt.Sprintf(format, args...))
	}
	if c, ok := schema["const"]; ok && fmt.Sprint(c) != fmt.Sprint(value) {
		fail("want const %v, got %v", c, value)
	}
	if enum, ok := schema["enum"].([]any); ok {
		found := false
		for _, e := range enum {
			if fmt.Sprint(e) == fmt.Sprint(value) {
				found = true
			}
		}
		if !found {
			fail("%v is not one of %v", value, enum)
		}
	}
	switch schema["type"] {
	case "object":
		object, ok := value.(map[string]any)
		if !ok {
			fail("want object, got %T", value)
			return
		}
		properties, _ := schema["properties"].(map[string]any)
		for _, name := range stringList(schema["required"]) {
			if _, present := object[name]; !present {
				fail("missing required property %q", name)
			}
		}
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			sub, known := properties[key].(map[string]any)
			if !known {
				if extra, ok := schema["additionalProperties"]; ok {
					switch extra := extra.(type) {
					case bool:
						if !extra {
							fail("property %q is not allowed", key)
						}
					case map[string]any:
						validateNode(extra, object[key], at+"."+key, problems)
					}
				}
				continue
			}
			validateNode(sub, object[key], at+"."+key, problems)
		}
	case "array":
		array, ok := value.([]any)
		if !ok {
			fail("want array, got %T", value)
			return
		}
		if min, ok := schema["minItems"].(float64); ok && float64(len(array)) < min {
			fail("want at least %v items, got %d", min, len(array))
		}
		if items, ok := schema["items"].(map[string]any); ok {
			for i, item := range array {
				validateNode(items, item, fmt.Sprintf("%s[%d]", at, i), problems)
			}
		}
	case "string":
		s, ok := value.(string)
		if !ok {
			fail("want string, got %T", value)
			return
		}
		if pattern, ok := schema["pattern"].(string); ok && !regexp.MustCompile(pattern).MatchString(s) {
			fail("%q does not match %s", s, pattern)
		}
	case "number":
		n, ok := value.(float64)
		if !ok {
			fail("want number, got %T", value)
			return
		}
		if min, ok := schema["minimum"].(float64); ok && n < min {
			fail("%v is below %v", n, min)
		}
		if max, ok := schema["maximum"].(float64); ok && n > max {
			fail("%v is above %v", n, max)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			fail("want boolean, got %T", value)
		}
	}
}

func stringList(value any) []string {
	items, _ := value.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

var canonicalSchema = filepath.Join("..", "..", "contracts", "canonical-scan.schema.json")

// The checker itself must catch what it claims to: the published sample
// passes, and a broken copy of it fails for each kind of rule.
func TestSchemaCheckerAgainstPublishedSample(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "fixtures", "canonical-scan.sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	var sample map[string]any
	if err := json.Unmarshal(raw, &sample); err != nil {
		t.Fatal(err)
	}
	checkSchema(t, canonicalSchema, sample)

	broken := []func(doc map[string]any){
		func(doc map[string]any) { doc["unexpected"] = true },
		func(doc map[string]any) { delete(doc["scan"].(map[string]any), "scanId") },
		func(doc map[string]any) { doc["scan"].(map[string]any)["status"] = "done" },
		func(doc map[string]any) { doc["components"].([]any)[0].(map[string]any)["purl"] = "npm/lodash" },
		func(doc map[string]any) { doc["findings"].([]any)[0].(map[string]any)["cvssScore"] = 11.0 },
	}
	for i, breakIt := range broken {
		var doc map[string]any
		_ = json.Unmarshal(raw, &doc)
		breakIt(doc)
		var problems []string
		var schema map[string]any
		schemaRaw, _ := os.ReadFile(canonicalSchema)
		_ = json.Unmarshal(schemaRaw, &schema)
		validateNode(schema, roundTrip(doc), "$", &problems)
		if len(problems) == 0 {
			t.Errorf("broken sample %d passed the schema check", i)
		}
	}
}

func roundTrip(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}
