package usagegraph

import (
	"os"
	"path/filepath"
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
	case "component2-s6-esm-named", "component2-s6-esm-default", "component2-s6-esm-namespace", "component2-s6-cjs-require", "component2-s6-cjs-destructured", "component2-s6-package-subpath", "component2-s6-import-type", "component2-s6-import-type-alias", "component2-s6-dynamic-static", "component2-s6-dynamic-computed", "component2-s6-reexport", "component2-s6-side-effect", "component2-s6-ts-path-alias":
	default:
		t.Fatalf("unsupported evaluation fixture %q", fixture)
	}

	var graph Graph
	if fixture == "component2-s6-ts-path-alias" {
		graph = produceS6AliasedFixtureGraph(t, fixture)
	} else {
		graph = produceFixtureGraph(t, fixture)
	}

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

// produceS6AliasedFixtureGraph uses the production alias parser and
// passes the root tsconfig mapping to the normal graph producer.
func produceS6AliasedFixtureGraph(t *testing.T, fixture string) Graph {
	t.Helper()

	root := filepath.Join("..", "..", "testdata", "fixtures", fixture)
	repository := analyseUsageFixture(t, fixture)

	tsconfig, err := os.ReadFile(filepath.Join(root, "tsconfig.json"))
	if err != nil {
		t.Fatalf("read tsconfig: %v", err)
	}

	aliases, err := ParseTSConfigPaths(tsconfig)
	if err != nil {
		t.Fatalf("parse path aliases: %v", err)
	}
	repository.PathAliases = aliases

	packageJSON, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		t.Fatalf("read package.json: %v", err)
	}
	repository.PackageJSON = packageJSON

	graph, err := Produce(
		[]RepositoryInput{repository},
		[]OccurrenceInput{fixtureOccurrence()},
		ProduceOptions{
			ScanID:               "scan-test",
			Ecosystem:            "npm",
			AnalyzerID:           AnalyzerID,
			ReachabilityAnalysed: true,
		},
	)
	if err != nil {
		t.Fatalf("Produce aliased fixture: %v", err)
	}

	return graph
}
