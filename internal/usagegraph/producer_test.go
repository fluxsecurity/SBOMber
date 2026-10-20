package usagegraph

import (
	"reflect"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/canonicalscan"
)

func fixtureOccurrence() OccurrenceInput {
	return OccurrenceInput{
		RepositoryID: "repo-app",
		Occurrence: canonicalscan.Occurrence{
			OccurrenceID:   "occ-lodash",
			ComponentPurl:  "pkg:npm/lodash@4.17.21",
			Workspace:      ".",
			ManifestPath:   "package.json",
			DependencyPath: []string{},
			Scope:          "direct",
			BuildScope:     "runtime",
		},
	}
}

func produceFixtureGraph(
	t *testing.T,
	fixture string,
) Graph {
	t.Helper()

	graph, err := Produce(
		[]RepositoryInput{analyseUsageFixture(t, fixture)},
		[]OccurrenceInput{fixtureOccurrence()},
		ProduceOptions{
			ScanID:               "scan-test",
			Ecosystem:            "npm",
			AnalyzerID:           AnalyzerID,
			ReachabilityAnalysed: true,
		},
	)
	if err != nil {
		t.Fatalf("Produce: %v", err)
	}

	return graph
}

func TestProduceFrozenReachableGraph(t *testing.T) {
	graph := produceFixtureGraph(
		t,
		"component2-usage-reachable",
	)

	if graph.SchemaVersion != SchemaVersion || graph.ScanID != "scan-test" {
		t.Fatalf("unexpected graph identity: %+v", graph)
	}
	if graph.Analysis.Status != AnalysisComplete ||
		!graph.Analyser.ReachabilityAnalysed {
		t.Fatalf("unexpected analysis metadata: %+v, %+v", graph.Analysis, graph.Analyser)
	}
	if len(graph.EntryPoints) != 1 || len(graph.Observations) != 1 {
		t.Fatalf("unexpected graph cardinality: %+v", graph)
	}

	entryPoint := graph.EntryPoints[0]
	if entryPoint.Function != "postWelcome" ||
		entryPoint.Kind != EntryPointExportedModule ||
		entryPoint.File != "src/index.js" ||
		entryPoint.Line != 3 {
		t.Fatalf("unexpected entry point: %+v", entryPoint)
	}

	observation := graph.Observations[0]
	if observation.OccurrenceID != "occ-lodash" ||
		observation.PURL != "pkg:npm/lodash@4.17.21" ||
		observation.ImportedSpecifier != "lodash" ||
		observation.ImportedSymbol != "merge" ||
		observation.LocalAlias != "merge" ||
		observation.Resolution != ImportResolved ||
		observation.EvidenceLevel != 3 ||
		len(observation.CallSites) != 1 {
		t.Fatalf("unexpected observation: %+v", observation)
	}

	callSite := observation.CallSites[0]
	if callSite.CalledSymbol != "merge" ||
		callSite.EnclosingFunction != "handleRequest" ||
		callSite.Resolution != CallResolved ||
		callSite.Reachability != Reachable ||
		callSite.EntryPointID != entryPoint.EntryPointID {
		t.Fatalf("unexpected call site: %+v", callSite)
	}
	wantPath := []CallPathStep{
		{Function: "postWelcome", File: "src/index.js", Line: 3},
		{Function: "handleRequest", File: "src/service.js", Line: 3},
	}
	if !reflect.DeepEqual(callSite.CallPath, wantPath) {
		t.Fatalf("call path = %+v, want %+v", callSite.CallPath, wantPath)
	}

	if graph.Coverage.EntryPointsDetected != 1 ||
		graph.Coverage.CallPathsResolved != 1 ||
		graph.Coverage.CallPathsUnresolved != 0 {
		t.Fatalf("unexpected reachability coverage: %+v", graph.Coverage)
	}
	if len(graph.UnanalysedOccurrences) != 0 || len(graph.ParseFailures) != 0 {
		t.Fatalf("unexpected incomplete-analysis records: %+v", graph)
	}
}

func TestProduceFrozenUnknownGraph(t *testing.T) {
	graph := produceFixtureGraph(
		t,
		"component2-usage-unknown",
	)

	if len(graph.EntryPoints) != 1 || len(graph.Observations) != 1 {
		t.Fatalf("unexpected graph cardinality: %+v", graph)
	}
	observation := graph.Observations[0]
	if observation.EvidenceLevel != 2 || len(observation.CallSites) != 1 {
		t.Fatalf("unexpected observation: %+v", observation)
	}

	callSite := observation.CallSites[0]
	if callSite.CalledSymbol != "merge" ||
		callSite.EnclosingFunction != "orphanHelper" ||
		callSite.Resolution != CallResolved ||
		callSite.Reachability != ReachUnknown {
		t.Fatalf("unexpected call site: %+v", callSite)
	}
	if callSite.EntryPointID != "" || len(callSite.CallPath) != 0 {
		t.Fatalf("unknown call carried path evidence: %+v", callSite)
	}

	if graph.Coverage.EntryPointsDetected != 1 ||
		graph.Coverage.CallPathsResolved != 0 ||
		graph.Coverage.CallPathsUnresolved != 1 {
		t.Fatalf("unexpected reachability coverage: %+v", graph.Coverage)
	}
}
