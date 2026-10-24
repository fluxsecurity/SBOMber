package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/decision"
)

// Labels and synthetic dependency implementations are committed separately
// from analyser output. This exercises the production usage and decide CLI
// entry points. Dependency-source is outside the analysed app root.
func TestIssue172UsageToDecide(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "fixtures", "indirect-usage-172")
	for _, name := range []string{"transitive-b", "direct-unimported-b", "direct-positive-b", "copied-function", "destructured-copy", "observed-other-symbol"} {
		t.Run(name, func(t *testing.T) {
			fixture := filepath.Join(root, name)
			var labels struct {
				ExpectedState            string  `json:"expectedState"`
				ExpectedUnanalysedReason *string `json:"expectedUnanalysedReason"`
				RequiresUnresolvedUse    bool    `json:"requiresUnresolvedUse"`
			}
			body, err := os.ReadFile(filepath.Join(fixture, "expected.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(body, &labels); err != nil {
				t.Fatal(err)
			}
			out := t.TempDir()
			graphPath := filepath.Join(out, "usage-graph.json")
			scanPath := filepath.Join(fixture, "canonical-scan.json")
			code, stdout, stderr := runUsageCommand(t, "--canonical-scan", scanPath, "--repo", "repo-172="+filepath.Join(fixture, "app"), "--out", graphPath)
			if code != 0 {
				t.Fatalf("usage exit %d: %s %s", code, stdout, stderr)
			}
			graph := readUsageGraph(t, graphPath)
			if graph.Analysis.Status != "complete" || graph.Coverage.FilesDiscovered != 1 {
				t.Fatalf("unexpected application scope: %+v", graph.Coverage)
			}
			if labels.ExpectedUnanalysedReason != nil && unanalysedReasons(graph)["occ-dep-b"] != *labels.ExpectedUnanalysedReason {
				t.Fatalf("absence evidence changed: %+v", graph.UnanalysedOccurrences)
			}
			if labels.RequiresUnresolvedUse {
				found := false
				for _, obs := range graph.Observations {
					for _, call := range obs.CallSites {
						if obs.OccurrenceID == "occ-dep-b" && call.UnresolvedReason == "outside_supported_syntax" && call.Reachability == "unknown" && len(call.CallPath) == 0 && call.EntryPointID == "" {
							found = true
						}
					}
				}
				if !found {
					t.Fatalf("copied function lost conservative evidence: %+v", graph.Observations)
				}
			}
			var output, errors bytes.Buffer
			decisionPath := filepath.Join(out, "decision-results.json")
			code = runDecide([]string{"--canonical-scan", scanPath, "--usage-graph", graphPath, "--localisation", filepath.Join(fixture, "localisation.json"), "--out", decisionPath}, &output, &errors)
			if code != 0 {
				t.Fatalf("decide exit %d: %s %s", code, output.String(), errors.String())
			}
			body, err = os.ReadFile(decisionPath)
			if err != nil {
				t.Fatal(err)
			}
			var results decision.Results
			if err := json.Unmarshal(body, &results); err != nil {
				t.Fatal(err)
			}
			if len(results.Decisions) != 1 || string(results.Decisions[0].State) != labels.ExpectedState {
				t.Fatalf("decision differs from labels: %+v", results.Decisions)
			}
			got := results.Decisions[0]
			if got.State == decision.StateUnknown && got.RiskPriority.Band != decision.BandInsufficientInformation {
				t.Fatalf("uncertainty lowered priority: %+v", got)
			}
			if got.VEXMapping == nil || got.VEXMapping.Statement == "not_affected" ||
				(got.State != decision.StateUsageDetected && got.VEXMapping.Statement != decision.VEXUnderInvestigation) {
				t.Fatalf("unexpected VEX mapping: %+v", got.VEXMapping)
			}
		})
	}
}
