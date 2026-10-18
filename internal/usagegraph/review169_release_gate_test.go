package usagegraph

import (
	"encoding/json"
	"github.com/Xsamsx/SBOMber/internal/decision"
	"testing"
)

// A known call must produce positive evidence or honest uncertainty. Closing
// localisation sets must never turn either pattern into no_usage_detected.
func TestReview169ReleaseGateKnownCalls(t *testing.T) {
	for name, source := range map[string]string{
		"copied member":           "const lodash=require('lodash');\nconst p=lodash.merge;\np({},{});\n",
		"function scoped require": "export function run() {\n const lodash=require('lodash');\n return lodash.merge({},{});\n}\n",
	} {
		t.Run(name, func(t *testing.T) {
			graph := produceSourceTree(t, map[string]string{"src/index.js": source})
			body, err := json.Marshal(graph)
			if err != nil {
				t.Fatal(err)
			}
			var usage decision.UsageGraph
			if err = json.Unmarshal(body, &usage); err != nil {
				t.Fatal(err)
			}
			purl := "pkg:npm/lodash@4.17.21"
			scan := decision.CanonicalScan{Scan: decision.ScanMeta{ScanID: graph.ScanID}, Occurrences: []decision.ScanOccurrence{{OccurrenceID: "occ-lodash", PURL: purl, Relationship: "direct"}}, Findings: []decision.ScanFinding{{FindingID: "f1", VulnerabilityID: "CVE-TEST", PURL: purl, OccurrenceIDs: []string{"occ-lodash"}}}}
			loc := decision.LocalisationReport{SchemaVersion: "1.1.0", Results: []decision.LocalisationResult{{FindingID: "f1", PURL: purl, Method: "patch_reference", Confidence: "high", CandidateSymbols: []decision.CandidateSymbol{{Symbol: "merge", ModulePath: "index.js", Visibility: "public"}}}}}
			inputs := decision.BuildFindingInputs(scan, usage, loc)
			if len(inputs) != 1 {
				t.Fatalf("inputs=%+v", inputs)
			}
			verdict := decision.DetermineState(inputs[0].State)
			if verdict.State == decision.StateNoUsageDetected {
				t.Fatalf("known call misclassified: %+v; observations=%+v", verdict, graph.Observations)
			}
		})
	}
}
