package usagegraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

func TestComputedImportBlocksNegativeOccurrence(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "app.js")
	if err := os.WriteFile(sourcePath,
		[]byte("const name = process.env.PKG;\nimport(name);\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	result, err := sourceanalysis.AnalyzeRepository(
		root, sourceanalysis.RepositoryOptions{})
	if err != nil {
		t.Fatal(err)
	}

	lodash := fixtureOccurrence()
	other := fixtureOccurrence()
	other.Occurrence.OccurrenceID = "occ-other"
	other.Occurrence.ComponentPurl = "pkg:npm/other@1.0.0"

	graph, err := Produce(
		[]RepositoryInput{{RepositoryID: "repo-app", Result: result}},
		[]OccurrenceInput{lodash, other},
		ProduceOptions{
			ScanID:               "scan-computed",
			Ecosystem:            "npm",
			AnalyzerID:           AnalyzerID,
			ReachabilityAnalysed: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Observations) != 1 ||
		!graph.Observations[0].ComputedSpecifier ||
		graph.Observations[0].Resolution != ImportUnresolved {
		t.Fatalf("computed import = %+v", graph.Observations)
	}
	if len(graph.UnanalysedOccurrences) != 2 {
		t.Fatalf("unanalysed = %+v", graph.UnanalysedOccurrences)
	}
	for _, occurrence := range graph.UnanalysedOccurrences {
		if occurrence.Reason != "computed_specifier" {
			t.Fatalf("computed import allowed a negative: %+v", occurrence)
		}
	}
}
