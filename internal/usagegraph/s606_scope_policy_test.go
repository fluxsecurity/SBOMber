package usagegraph

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/decision"
	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

func s606Repository(t *testing.T, id string, files map[string]string) RepositoryInput {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		file := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := sourceanalysis.AnalyzeRepository(root, sourceanalysis.RepositoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return RepositoryInput{RepositoryID: id, Result: result}
}

// This is a synthetic closed-candidate policy fixture, not CVE evidence.
// It serialises the real producer output into Component 4's consumer types
// and exercises the same join/results path used by sbomber decide.
func s606Decision(t *testing.T, graph Graph, occurrence OccurrenceInput) decision.ResultDecision {
	t.Helper()
	body, err := json.Marshal(graph)
	if err != nil {
		t.Fatal(err)
	}
	var usage decision.UsageGraph
	if err := json.Unmarshal(body, &usage); err != nil {
		t.Fatal(err)
	}
	purl := occurrence.Occurrence.ComponentPurl
	id := occurrence.Occurrence.OccurrenceID
	scan := decision.CanonicalScan{
		Scan: decision.ScanMeta{ScanID: graph.ScanID},
		Occurrences: []decision.ScanOccurrence{{
			OccurrenceID: id, PURL: purl, Relationship: "direct",
		}},
		Findings: []decision.ScanFinding{{
			FindingID: "s606-policy", VulnerabilityID: "S606-SYNTHETIC",
			PURL: purl, OccurrenceIDs: []string{id}, Severity: "high",
		}},
	}
	loc := decision.LocalisationReport{
		SchemaVersion: "1.1.0",
		Results: []decision.LocalisationResult{{
			FindingID: "s606-policy", PURL: purl,
			Method: "patch_reference", Confidence: "high",
			CandidateSymbols: []decision.CandidateSymbol{{
				Symbol: "merge", ModulePath: "index.js", Visibility: "public",
			}},
		}},
	}
	results, err := decision.BuildResults(scan, usage, loc)
	if err != nil {
		t.Fatal(err)
	}
	if len(results.Decisions) != 1 {
		t.Fatalf("decisions = %+v", results.Decisions)
	}
	return results.Decisions[0]
}

func TestS606ComputedImportScope(t *testing.T) {
	for _, file := range []string{"src/load.js", "scripts/package.mjs"} {
		for _, expression := range []string{"require(name)", "import(name)", "import('./plugins/' + name)"} {
			t.Run(file+"/"+expression, func(t *testing.T) {
				graph := produceSourceTree(t, map[string]string{
					"src/index.js": "export function main() { return 1; }\n",
					file:           "const name = process.env.PKG;\n" + expression + ";\n",
				})
				if graph.Analysis.Status != AnalysisComplete || len(graph.UnanalysedOccurrences) != 1 {
					t.Fatalf("unexpected coverage/occurrences: %+v", graph)
				}
				occurrence := graph.UnanalysedOccurrences[0]
				if occurrence.Reason != "computed_specifier" || !strings.Contains(occurrence.Detail, file+":2") {
					t.Fatalf("computed source allowed an unsupported negative: %+v", occurrence)
				}
				verdict := s606Decision(t, graph, fixtureOccurrence())
				if verdict.State != decision.StateUnknown {
					t.Fatalf("computed import decision = %+v, want unknown", verdict)
				}
				if verdict.VEXMapping == nil || verdict.VEXMapping.Statement != decision.VEXUnderInvestigation {
					t.Fatalf("computed uncertainty lost in VEX mapping: %+v", verdict)
				}
			})
		}
	}
}

func TestS606MDXScope(t *testing.T) {
	for _, test := range []struct {
		name, file, content string
		partial             bool
	}{
		{"ordinary markdown", "docs/guide.md", "# Guide\n", false},
		{"plain MDX documentation", "docs/guide.mdx", "# Guide\n", true},
		{"executable MDX", "docs/guide.mdx", "import { merge } from 'lodash'\n\n{merge({}, {})}\n", true},
		{"uppercase MDX", "docs/guide.MDX", "# Guide\n", true},
		{"excluded dependency MDX", "node_modules/pkg/guide.mdx", "# Guide\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := s606Repository(t, "repo-app", map[string]string{
				"src/index.js": "export function main() { return 1; }\n",
				test.file:      test.content,
			})
			graph, err := Produce([]RepositoryInput{repository}, []OccurrenceInput{fixtureOccurrence()}, ProduceOptions{
				ScanID: "scan-s606", Ecosystem: "npm", AnalyzerID: AnalyzerID, ReachabilityAnalysed: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(graph.UnanalysedOccurrences) != 1 || len(graph.Observations) != 0 {
				t.Fatalf("MDX produced invented package evidence: %+v", graph)
			}
			if test.partial {
				found := false
				for _, skipped := range repository.Result.Skipped {
					if skipped.Path == test.file && skipped.Reason == sourceanalysis.SkipUnsupportedSource {
						found = true
					}
				}
				if !found || graph.Analysis.Status != AnalysisPartial || graph.Coverage.FilesSkipped != 1 || graph.Coverage.FilesDiscovered != 2 {
					t.Fatalf("MDX silently excluded from coverage: %+v", graph)
				}
				if graph.UnanalysedOccurrences[0].Reason == "not_imported_by_analysed_source" {
					t.Fatal("unparsed MDX allowed a negative occurrence reason")
				}
				if verdict := s606Decision(t, graph, fixtureOccurrence()); verdict.State != decision.StateUnknown {
					t.Fatalf("unparsed MDX decision = %+v, want unknown", verdict)
				}
			} else if graph.Analysis.Status != AnalysisComplete || graph.Coverage.FilesSkipped != 0 || graph.Coverage.FilesDiscovered != 1 || graph.UnanalysedOccurrences[0].Reason != "not_imported_by_analysed_source" {
				t.Fatalf("declared source-scope boundary changed: %+v", graph)
			}
		})
	}
}

func TestS606PositiveEvidencePreserved(t *testing.T) {
	for _, test := range []struct{ file, content string }{
		{"scripts/package.mjs", "const name = process.env.PKG; require(name);\n"},
		{"docs/guide.mdx", "import other from 'other'\n"},
	} {
		t.Run(test.file, func(t *testing.T) {
			graph := produceSourceTree(t, map[string]string{
				"src/index.js": "import { merge } from 'lodash';\nexport function main(x) { return merge({}, x); }\n",
				test.file:      test.content,
			})
			observation := requireObservationForSymbol(t, graph, "merge")
			if len(observation.CallSites) != 1 || observation.CallSites[0].Reachability != Reachable {
				t.Fatalf("positive path lost: %+v", observation)
			}
			if verdict := s606Decision(t, graph, fixtureOccurrence()); verdict.State != decision.StateUsageDetected {
				t.Fatalf("positive evidence lost in consumer: %+v", verdict)
			}
		})
	}
}

func TestS606ComputedImportRepositoryBoundary(t *testing.T) {
	first, second := fixtureOccurrence(), fixtureOccurrence()
	first.RepositoryID = "repo-first"
	second.RepositoryID = "repo-second"
	second.Occurrence.OccurrenceID = "occ-second"
	graph, err := Produce([]RepositoryInput{
		s606Repository(t, "repo-first", map[string]string{"scripts/package.mjs": "const name = process.env.PKG; require(name);\n"}),
		s606Repository(t, "repo-second", map[string]string{"src/index.js": "export function main() { return 1; }\n"}),
	}, []OccurrenceInput{first, second}, ProduceOptions{
		ScanID: "scan-s606-boundary", Ecosystem: "npm", AnalyzerID: AnalyzerID, ReachabilityAnalysed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]string{}
	for _, occurrence := range graph.UnanalysedOccurrences {
		reasons[occurrence.OccurrenceID] = occurrence.Reason
	}
	if graph.Analysis.Status != AnalysisComplete || reasons[first.Occurrence.OccurrenceID] != "computed_specifier" || reasons[second.Occurrence.OccurrenceID] != "not_imported_by_analysed_source" {
		t.Fatalf("repository boundary lost: %+v", graph)
	}
}

func TestS606ExcludedComputedImport(t *testing.T) {
	graph := produceSourceTree(t, map[string]string{
		"src/index.js":  "export function main() { return 1; }\n",
		"build/load.js": "const name = process.env.PKG; require(name);\n",
	})
	if graph.Analysis.Status != AnalysisComplete || graph.Coverage.FilesDiscovered != 1 || len(graph.Observations) != 0 || len(graph.UnanalysedOccurrences) != 1 || graph.UnanalysedOccurrences[0].Reason != "not_imported_by_analysed_source" {
		t.Fatalf("excluded build tree entered analysed scope: %+v", graph)
	}
}
