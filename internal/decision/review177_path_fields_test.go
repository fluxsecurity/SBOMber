package decision

import (
	"strings"
	"testing"
)

func TestReview177MalformedPathCannotCorroborateUsage(t *testing.T) {
	valid := CallPathStep{Function: "handler", File: "src/app.js", Line: 5}
	for _, test := range []struct {
		name  string
		entry string
		path  []CallPathStep
	}{
		{"missing step fields", "ep-001", []CallPathStep{{}}},
		{"missing function", "ep-001", []CallPathStep{{File: "src/app.js", Line: 5}}},
		{"missing file", "ep-001", []CallPathStep{{Function: "handler", Line: 5}}},
		{"zero line", "ep-001", []CallPathStep{{Function: "handler", File: "src/app.js"}}},
		{"negative line", "ep-001", []CallPathStep{{Function: "handler", File: "src/app.js", Line: -1}}},
		{"blank entry", " \t", []CallPathStep{valid}},
		{"blank function", "ep-001", []CallPathStep{{Function: " \t", File: "src/app.js", Line: 5}}},
		{"blank file", "ep-001", []CallPathStep{{Function: "handler", File: " \t", Line: 5}}},
		{"invalid intermediate step", "ep-001", []CallPathStep{valid, {}, valid}},
	} {
		t.Run(test.name, func(t *testing.T) {
			in, dec, result := mergeCase(lodashCallWithReachability("reachable", test.entry, test.path)).decide(t)
			if in.Confidence.DeterministicMethodsAgree || dec.Confidence == ConfidenceHigh {
				t.Fatalf("malformed path corroborated usage: agreement=%t confidence=%s", in.Confidence.DeterministicMethodsAgree, dec.Confidence)
			}
			if strings.Contains(result.Justification, "resolved call path") {
				t.Fatalf("malformed path was cited: %s", result.Justification)
			}
			if dec.State != StateUsageDetected {
				t.Fatalf("resolved symbol evidence was lost: %s", dec.State)
			}
		})
	}
}
