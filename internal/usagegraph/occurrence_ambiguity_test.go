package usagegraph

import "testing"

func TestDuplicateDirectOccurrencesAreNotNegative(t *testing.T) {
	first := fixtureOccurrence()
	second := fixtureOccurrence()
	second.Occurrence.OccurrenceID = "occ-lodash-other"
	second.Occurrence.ComponentPurl = "pkg:npm/lodash@4.17.20"

	graph, err := Produce(
		[]RepositoryInput{analyseUsageFixture(t, "component2-usage-reachable")},
		[]OccurrenceInput{second, first},
		ProduceOptions{
			ScanID:               "scan-ambiguous",
			Ecosystem:            "npm",
			AnalyzerID:           AnalyzerID,
			ReachabilityAnalysed: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Observations) != 1 ||
		graph.Observations[0].Resolution != ImportUnresolved ||
		graph.Observations[0].UnresolvedReason != "ambiguous_occurrence" {
		t.Fatalf("ambiguous import = %+v", graph.Observations)
	}
	if len(graph.UnanalysedOccurrences) != 2 {
		t.Fatalf("unanalysed occurrences = %+v", graph.UnanalysedOccurrences)
	}
	for _, occurrence := range graph.UnanalysedOccurrences {
		if occurrence.Reason != "ambiguous_occurrence" {
			t.Fatalf("ambiguous occurrence claimed no import: %+v", occurrence)
		}
	}
}

func TestImportSelectsUniqueWorkspaceOccurrence(t *testing.T) {
	repository := analyseUsageFixture(t, "component2-usage-reachable")
	for index := range repository.Result.Files {
		repository.Result.Files[index].Path =
			"packages/app/" + repository.Result.Files[index].Path
	}

	root := fixtureOccurrence()
	workspace := fixtureOccurrence()
	workspace.Occurrence.OccurrenceID = "occ-lodash-workspace"
	workspace.Occurrence.Workspace = "packages/app"
	workspace.Occurrence.ManifestPath = "packages/app/package.json"

	graph, err := Produce(
		[]RepositoryInput{repository},
		[]OccurrenceInput{root, workspace},
		ProduceOptions{
			ScanID:               "scan-workspace",
			Ecosystem:            "npm",
			AnalyzerID:           AnalyzerID,
			ReachabilityAnalysed: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Observations) != 1 ||
		graph.Observations[0].OccurrenceID != workspace.Occurrence.OccurrenceID ||
		graph.Observations[0].Resolution != ImportResolved {
		t.Fatalf("workspace import = %+v", graph.Observations)
	}
	if len(graph.UnanalysedOccurrences) != 1 ||
		graph.UnanalysedOccurrences[0].OccurrenceID != root.Occurrence.OccurrenceID {
		t.Fatalf("other occurrence = %+v", graph.UnanalysedOccurrences)
	}
}
