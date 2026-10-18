package usagegraph

import "testing"

// TestS6ESMNamedParameterShadowing verifies that a function
// parameter shadowing an imported name is not attributed
// to the third-party package.
func TestS6ESMNamedParameterShadowing(t *testing.T) {
	graph := produceFixtureGraph(
		t,
		"component2-s6-esm-named",
	)

	if len(graph.Observations) != 1 {
		t.Fatalf(
			"expected one import observation, got %d",
			len(graph.Observations),
		)
	}

	obs := graph.Observations[0]

	if obs.ImportedSpecifier != "lodash" ||
		obs.ImportedSymbol != "merge" ||
		obs.ImportKind != "esm_named" {
		t.Fatalf("unexpected import observation: %+v", obs)
	}

	// Only the call on line 4 belongs to Lodash.
	// Line 8 calls a shadowing function parameter.
	if len(obs.CallSites) != 1 {
		t.Fatalf(
			"expected one genuine Lodash call, got %d: %+v",
			len(obs.CallSites),
			obs.CallSites,
		)
	}

	call := obs.CallSites[0]

	if call.File != "src/index.js" ||
		call.Line != 4 ||
		call.CalledSymbol != "merge" ||
		call.Resolution != CallResolved {
		t.Fatalf("unexpected Lodash call: %+v", call)
	}
}
