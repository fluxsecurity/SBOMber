package usagegraph

import (
	"testing"

	"github.com/Xsamsx/SBOMber/internal/decision"
	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

func TestProduceEmptySourceScopeBlocksNegative(t *testing.T) {
	for _, test := range []struct {
		name         string
		repositories []RepositoryInput
	}{
		{name: "no repositories"},
		{name: "empty repository", repositories: []RepositoryInput{{RepositoryID: "repo-app"}}},
		{
			name: "only excluded dependency source",
			repositories: []RepositoryInput{{
				RepositoryID: "repo-app",
				Result: sourceanalysis.RepositoryResult{
					Skipped: []sourceanalysis.SkippedSource{{
						Path: "node_modules", Reason: sourceanalysis.SkipExcludedDirectory,
						IsDirectory: true,
					}},
				},
			}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, reachability := range []bool{false, true} {
				graph, err := Produce(test.repositories, []OccurrenceInput{fixtureOccurrence()}, ProduceOptions{
					ScanID: "scan-empty", Ecosystem: "npm", AnalyzerID: AnalyzerID,
					ReachabilityAnalysed: reachability,
				})
				if err != nil {
					t.Fatal(err)
				}
				if graph.Analysis.Status != AnalysisPartial || graph.Analysis.ReasonCode != "no_source_files" {
					t.Fatalf("empty scope reported as completed: %+v", graph.Analysis)
				}
				if graph.Coverage.FilesDiscovered != 0 || graph.Coverage.FilesSkipped != 0 ||
					len(graph.Coverage.LimitsHit) != 0 || len(graph.Observations) != 0 {
					t.Fatalf("empty scope invented evidence or counters: %+v", graph)
				}
				if len(graph.UnanalysedOccurrences) != 1 ||
					graph.UnanalysedOccurrences[0].Reason != "no_source_files" {
					t.Fatalf("empty occurrence can support a negative: %+v", graph.UnanalysedOccurrences)
				}
				// Even if a consumer incorrectly supplies complete, the occurrence
				// reason must independently block a negative finding.
				verdict := decision.DetermineState(decision.StateInputs{
					AnalysisStatus:     decision.AnalysisComplete,
					LocalisationMethod: decision.LocalisationAdvisoryMetadata,
					UnanalysedReasons: []decision.UnanalysedReason{
						decision.UnanalysedReason(graph.UnanalysedOccurrences[0].Reason),
					},
				})
				if verdict.State != decision.StateUnknown {
					t.Fatalf("empty occurrence decision = %+v, want unknown", verdict)
				}
			}
		})
	}
}

func TestProduceEmptyRepositoryCannotHideBehindCleanRepository(t *testing.T) {
	empty := fixtureOccurrence()
	empty.RepositoryID = "repo-empty"
	empty.Occurrence.OccurrenceID = "occ-empty"
	graph, err := Produce([]RepositoryInput{
		analyseUsageFixture(t, "component2-usage-reachable"),
		{RepositoryID: "repo-empty"},
	}, []OccurrenceInput{fixtureOccurrence(), empty}, ProduceOptions{
		ScanID: "scan-mixed", Ecosystem: "npm", AnalyzerID: AnalyzerID,
		ReachabilityAnalysed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if graph.Analysis.Status != AnalysisPartial || graph.Coverage.FilesParsed == 0 {
		t.Fatalf("mixed scope coverage = %+v / %+v", graph.Analysis, graph.Coverage)
	}
	if len(graph.UnanalysedOccurrences) != 1 ||
		graph.UnanalysedOccurrences[0].OccurrenceID != "occ-empty" ||
		graph.UnanalysedOccurrences[0].Reason != "no_source_files" {
		t.Fatalf("empty repository hidden by clean repository: %+v", graph.UnanalysedOccurrences)
	}
	observation := requireObservationForSymbol(t, graph, "merge")
	if len(observation.CallSites) != 1 || observation.CallSites[0].Reachability != Reachable {
		t.Fatalf("positive evidence lost in mixed scope: %+v", observation)
	}
}

func TestProduceCleanSourceWithoutImportRetainsNegativeReason(t *testing.T) {
	graph, err := Produce([]RepositoryInput{{
		RepositoryID: "repo-app",
		Result: sourceanalysis.RepositoryResult{
			Files: []sourceanalysis.AnalyzedSource{cleanSource("src/app.js")},
		},
	}}, []OccurrenceInput{fixtureOccurrence()}, ProduceOptions{
		ScanID: "scan-clean", Ecosystem: "npm", AnalyzerID: AnalyzerID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if graph.Analysis.Status != AnalysisComplete || graph.Analysis.ReasonCode != "" ||
		len(graph.UnanalysedOccurrences) != 1 ||
		graph.UnanalysedOccurrences[0].Reason != "not_imported_by_analysed_source" {
		t.Fatalf("clean no-import scan changed: %+v", graph)
	}
}
