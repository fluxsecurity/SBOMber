package usagegraph

import (
	"os"
	"testing"
)

// TestS6ExportUsageGraph exports the prelabelled Sprint 6 fixture.
// It only runs when S6_GRAPH_OUT is explicitly provided.
func TestS6ExportUsageGraph(t *testing.T) {
	output := os.Getenv("S6_GRAPH_OUT")
	if output == "" {
		t.Skip("set S6_GRAPH_OUT to export evaluation evidence")
	}

	fixture := os.Getenv("S6_FIXTURE")
	if fixture == "" {
		fixture = "component2-s6-esm-named"
	}

	switch fixture {
	case "component2-s6-esm-named", "component2-s6-esm-default", "component2-s6-esm-namespace", "component2-s6-cjs-require", "component2-s6-cjs-destructured", "component2-s6-package-subpath":
	default:
		t.Fatalf("unsupported evaluation fixture %q", fixture)
	}

	graph := produceFixtureGraph(t, fixture)

	if err := WriteGraph(output, graph); err != nil {
		t.Fatalf("write evaluation graph: %v", err)
	}

	t.Logf(
		"schema=%s observations=%d status=%s",
		graph.SchemaVersion,
		len(graph.Observations),
		graph.Analysis.Status,
	)
}
