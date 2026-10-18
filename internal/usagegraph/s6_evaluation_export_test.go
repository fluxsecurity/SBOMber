package usagegraph

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

	paths, err := filepath.Glob(filepath.Join("..", "..", "testdata", "fixtures", "usage-ground-truth", "component2-s6-*", "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, path := range paths {
		if filepath.Base(filepath.Dir(path)) == fixture {
			found = true
		}
	}
	if !found {
		t.Fatalf("unsupported evaluation fixture %q", fixture)
	}
	graph := produceS6FixtureGraph(t, fixture)

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

// produceS6FixtureGraph supplies the fixture inventory and optional root aliases
// to the production producer. All fixtures use exact dependency versions.
func produceS6FixtureGraph(t *testing.T, fixture string) Graph {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "fixtures", fixture)
	repository := analyseUsageFixture(t, fixture)
	tsconfig, err := os.ReadFile(filepath.Join(root, "tsconfig.json"))
	if err == nil {
		repository.PathAliases, err = ParseTSConfigPaths(tsconfig)
		if err != nil {
			t.Fatal(err)
		}
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	packageJSON, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	repository.PackageJSON = packageJSON
	var manifest struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(packageJSON, &manifest); err != nil {
		t.Fatal(err)
	}
	var occurrences []OccurrenceInput
	for name, version := range manifest.Dependencies {
		occurrence := fixtureOccurrence()
		occurrence.Occurrence.ComponentPurl = "pkg:npm/" + strings.ReplaceAll(name, "@", "%40") + "@" + version
		occurrences = append(occurrences, occurrence)
	}
	graph, err := Produce([]RepositoryInput{repository}, occurrences, ProduceOptions{
		ScanID: "scan-test", Ecosystem: "npm", AnalyzerID: AnalyzerID, ReachabilityAnalysed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return graph
}
