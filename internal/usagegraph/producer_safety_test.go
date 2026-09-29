package usagegraph

import (
	"testing"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

func TestProduceWithoutReachabilityUsesNotAnalysed(t *testing.T) {
	graph, err := Produce(
		[]RepositoryInput{
			analyseUsageFixture(t, "component2-usage-reachable"),
		},
		[]OccurrenceInput{fixtureOccurrence()},
		ProduceOptions{
			ScanID:               "scan-test",
			Ecosystem:            "npm",
			AnalyzerID:           AnalyzerID,
			ReachabilityAnalysed: false,
		},
	)
	if err != nil {
		t.Fatalf("Produce: %v", err)
	}

	if graph.Analyser.ReachabilityAnalysed || len(graph.EntryPoints) != 0 {
		t.Fatalf("reachability unexpectedly ran: %+v", graph)
	}
	if len(graph.Observations) != 1 ||
		len(graph.Observations[0].CallSites) != 1 {
		t.Fatalf("unexpected observations: %+v", graph.Observations)
	}
	callSite := graph.Observations[0].CallSites[0]
	if callSite.Reachability != NotAnalysed ||
		callSite.EntryPointID != "" ||
		len(callSite.CallPath) != 0 {
		t.Fatalf("disabled pass emitted path evidence: %+v", callSite)
	}
	if graph.Coverage.CallPathsResolved != 0 ||
		graph.Coverage.CallPathsUnresolved != 0 {
		t.Fatalf("disabled pass changed path coverage: %+v", graph.Coverage)
	}
}

func TestAmbiguousOccurrenceCannotBeReachable(t *testing.T) {
	first := fixtureOccurrence()
	second := fixtureOccurrence()
	second.Occurrence.OccurrenceID = "occ-lodash-other"
	second.Occurrence.ComponentPurl = "pkg:npm/lodash@4.17.20"

	graph, err := Produce(
		[]RepositoryInput{
			analyseUsageFixture(t, "component2-usage-reachable"),
		},
		[]OccurrenceInput{second, first},
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

	if len(graph.Observations) != 1 {
		t.Fatalf("unexpected observations: %+v", graph.Observations)
	}
	observation := graph.Observations[0]
	if observation.Resolution != ImportUnresolved ||
		observation.UnresolvedReason != "ambiguous_occurrence" ||
		observation.OccurrenceID != "" || observation.PURL != "" {
		t.Fatalf("ambiguous occurrence was resolved: %+v", observation)
	}
	if len(observation.CallSites) != 1 {
		t.Fatalf("ambiguous observation lost its call site: %+v", observation)
	}
	callSite := observation.CallSites[0]
	if callSite.Reachability != ReachUnknown ||
		callSite.EntryPointID != "" || len(callSite.CallPath) != 0 {
		t.Fatalf("ambiguous occurrence received path evidence: %+v", callSite)
	}
	if graph.Coverage.CallPathsResolved != 0 ||
		graph.Coverage.CallPathsUnresolved != 1 {
		t.Fatalf("unexpected path coverage: %+v", graph.Coverage)
	}
}

func TestWholeModuleCalledSymbolConvention(t *testing.T) {
	local := "lodashBinding"
	member := "merge"
	imported := sourceanalysis.Import{
		Specifier: "lodash",
		Kind:      "esm_default",
		Local:     local,
	}

	calledSymbol, resolution, reason, matched := thirdPartyCall(
		imported,
		sourceanalysis.Call{Callee: &local},
	)
	if !matched || resolution != CallResolved ||
		calledSymbol != "default" || reason != "" {
		t.Fatalf(
			"direct whole-module call = %q, %q, %q, %v",
			calledSymbol,
			resolution,
			reason,
			matched,
		)
	}

	calledSymbol, resolution, reason, matched = thirdPartyCall(
		imported,
		sourceanalysis.Call{
			Callee:   &member,
			Receiver: &local,
		},
	)
	if !matched || resolution != CallResolved ||
		calledSymbol != "merge" || reason != "" {
		t.Fatalf(
			"whole-module member call = %q, %q, %q, %v",
			calledSymbol,
			resolution,
			reason,
			matched,
		)
	}
}
