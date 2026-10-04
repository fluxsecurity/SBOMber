package usagegraph

import "testing"

func requireObservationForSymbol(
	t *testing.T,
	graph Graph,
	symbol string,
) Observation {
	t.Helper()

	for _, observation := range graph.Observations {
		if observation.ImportedSymbol == symbol {
			return observation
		}
	}

	t.Fatalf(
		"observation for imported symbol %q not found: %+v",
		symbol,
		graph.Observations,
	)
	return Observation{}
}

func TestProduceCallbackReferenceRemainsUnknown(t *testing.T) {
	graph := produceFixtureGraph(
		t,
		"component2-usage-callback",
	)

	if len(graph.EntryPoints) != 1 ||
		len(graph.Observations) != 2 {
		t.Fatalf("unexpected graph cardinality: %+v", graph)
	}

	forEach := requireObservationForSymbol(t, graph, "forEach")
	if forEach.EvidenceLevel != 3 || len(forEach.CallSites) != 1 {
		t.Fatalf("unexpected forEach observation: %+v", forEach)
	}
	forEachCall := forEach.CallSites[0]
	if forEachCall.EnclosingFunction != "postWelcome" ||
		forEachCall.Reachability != Reachable ||
		forEachCall.EntryPointID != graph.EntryPoints[0].EntryPointID ||
		len(forEachCall.CallPath) != 1 ||
		forEachCall.CallPath[0].Function != "postWelcome" {
		t.Fatalf("unexpected reachable forEach call: %+v", forEachCall)
	}

	merge := requireObservationForSymbol(t, graph, "merge")
	if merge.EvidenceLevel != 2 || len(merge.CallSites) != 1 {
		t.Fatalf("unexpected merge observation: %+v", merge)
	}
	mergeCall := merge.CallSites[0]
	if mergeCall.EnclosingFunction != "applyDefaults" ||
		mergeCall.Resolution != CallResolved ||
		mergeCall.Reachability != ReachUnknown ||
		mergeCall.EntryPointID != "" ||
		len(mergeCall.CallPath) != 0 {
		t.Fatalf(
			"callback-only function received reachability evidence: %+v",
			mergeCall,
		)
	}

	if graph.Coverage.EntryPointsDetected != 1 ||
		graph.Coverage.CallPathsResolved != 1 ||
		graph.Coverage.CallPathsUnresolved != 1 {
		t.Fatalf("unexpected callback coverage: %+v", graph.Coverage)
	}
}
