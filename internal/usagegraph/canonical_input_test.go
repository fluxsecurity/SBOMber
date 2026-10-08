package usagegraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/canonicalscan"
)

// The published contract fixture must decode with the contract field names
// and map relationship onto the producer's direct/transitive flag.
func TestReadCanonicalScanContractFixture(t *testing.T) {
	file, err := os.Open(filepath.Join("..", "..", "contracts", "fixtures", "canonical-scan.sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()

	scan, err := ReadCanonicalScan(file, 0)
	if err != nil {
		t.Fatalf("ReadCanonicalScan: %v", err)
	}
	if scan.Scan.ScanID == "" || len(scan.Scan.Repositories) == 0 || len(scan.Occurrences) == 0 {
		t.Fatalf("scan = %+v", scan)
	}
	for index, input := range scan.OccurrenceInputs() {
		source := scan.Occurrences[index]
		if input.RepositoryID != source.RepositoryID ||
			input.Occurrence.ComponentPurl != source.PURL ||
			input.Occurrence.ManifestPath != source.Manifest ||
			input.Occurrence.Scope != source.Relationship ||
			input.Occurrence.DependencyPath == nil {
			t.Fatalf("occurrence %d mapped to %+v from %+v", index, input, source)
		}
	}
}

func TestReadCanonicalScanRejectsInvalidDocuments(t *testing.T) {
	cases := map[string]string{
		"missing scan id":  `{"schemaVersion":"1.0.0","scan":{"repositories":[]},"occurrences":[]}`,
		"wrong version":    `{"schemaVersion":"0.9.0","scan":{"scanId":"s","repositories":[]},"occurrences":[]}`,
		"bad relationship": `{"schemaVersion":"1.0.0","scan":{"scanId":"s","repositories":[{"repositoryId":"r"}]},"occurrences":[{"occurrenceId":"o","purl":"pkg:npm/a@1.0.0","repositoryId":"r","relationship":"peer"}]}`,
		"duplicate occurrence": `{"schemaVersion":"1.0.0","scan":{"scanId":"s","repositories":[{"repositoryId":"r"}]},"occurrences":[` +
			`{"occurrenceId":"o","purl":"pkg:npm/a@1.0.0","repositoryId":"r","relationship":"direct"},` +
			`{"occurrenceId":"o","purl":"pkg:npm/b@1.0.0","repositoryId":"r","relationship":"direct"}]}`,
		"internal Go field names": `{"schemaVersion":"1.0.0","scan":{"scanId":"s","repositories":[{"repositoryId":"r"}]},"occurrences":[{"occurrenceId":"o","componentPurl":"pkg:npm/a@1.0.0","repositoryId":"r","relationship":"direct"}]}`,
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadCanonicalScan(strings.NewReader(document), 0); err == nil {
				t.Fatalf("accepted invalid document")
			}
		})
	}

	t.Run("oversized input is rejected, not truncated", func(t *testing.T) {
		_, err := ReadCanonicalScan(strings.NewReader(strings.Repeat(" ", 100)), 50)
		if err == nil || !strings.Contains(err.Error(), "larger than 50 bytes") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestParseDeclaredEntryPoint(t *testing.T) {
	valid := map[string]DeclaredEntryPoint{
		"src/app.js:main":           {RepositoryID: "repo", File: "src/app.js", Function: "main"},
		"src/app.js:main:12":        {RepositoryID: "repo", File: "src/app.js", Function: "main", Line: 12},
		"other=src/app.js:<module>": {RepositoryID: "other", File: "src/app.js", Function: "<module>"},
		"src/a=b.js:main":           {RepositoryID: "repo", File: "src/a=b.js", Function: "main"},
	}
	for spec, want := range valid {
		got, err := ParseDeclaredEntryPoint(spec, "repo")
		if err != nil || got != want {
			t.Fatalf("%q = %+v, %v; want %+v", spec, got, err, want)
		}
	}
	for _, spec := range []string{"src/app.js", ":main", "src/app.js:", "a.js:main:0", "a.js:main:x", "a:b:c:d"} {
		if _, err := ParseDeclaredEntryPoint(spec, "repo"); err == nil {
			t.Fatalf("%q accepted", spec)
		}
	}
	if _, err := ParseDeclaredEntryPoint("src/app.js:main", ""); err == nil {
		t.Fatalf("missing repository accepted")
	}
}

// Safety: packages Component 2 never looked at cannot be reported as
// not imported, which is the only reason that may support no_usage_detected.
func TestUnanalysedReasonsForUnsupportedAndUnanalysedSource(t *testing.T) {
	repository := analyseUsageFixture(t, "component2-usage-reachable")
	python := OccurrenceInput{RepositoryID: "repo-app", Occurrence: canonicalscan.Occurrence{
		OccurrenceID: "occ-python", ComponentPurl: "pkg:pypi/requests@2.31.0", Scope: "direct"}}
	elsewhere := OccurrenceInput{RepositoryID: "repo-not-analysed", Occurrence: canonicalscan.Occurrence{
		OccurrenceID: "occ-elsewhere", ComponentPurl: "pkg:npm/axios@1.7.0", Scope: "direct"}}
	unused := OccurrenceInput{RepositoryID: "repo-app", Occurrence: canonicalscan.Occurrence{
		OccurrenceID: "occ-unused", ComponentPurl: "pkg:npm/chalk@5.3.0", Scope: "direct"}}

	graph, err := Produce(
		[]RepositoryInput{repository},
		[]OccurrenceInput{fixtureOccurrence(), python, elsewhere, unused},
		ProduceOptions{ScanID: "scan-reasons", Ecosystem: "npm", AnalyzerID: AnalyzerID, ReachabilityAnalysed: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"occ-python":    "ecosystem_unsupported",
		"occ-elsewhere": "excluded_by_limits",
		"occ-unused":    "not_imported_by_analysed_source",
	}
	for _, occurrence := range graph.UnanalysedOccurrences {
		if want[occurrence.OccurrenceID] != occurrence.Reason {
			t.Fatalf("%s reason = %q, want %q", occurrence.OccurrenceID, occurrence.Reason, want[occurrence.OccurrenceID])
		}
		delete(want, occurrence.OccurrenceID)
	}
	if len(want) != 0 {
		t.Fatalf("missing unanalysed occurrences: %v", want)
	}
}

func TestProduceUnavailableAccountsForEveryOccurrence(t *testing.T) {
	graph, err := ProduceUnavailable("scan-remote", AnalysisUnsupported, "no_local_source",
		[]OccurrenceInput{fixtureOccurrence(), {RepositoryID: "repo-app", Occurrence: canonicalscan.Occurrence{
			OccurrenceID: "occ-python", ComponentPurl: "pkg:pypi/requests@2.31.0", Scope: "direct"}}})
	if err != nil {
		t.Fatal(err)
	}
	if graph.Analysis.Status != AnalysisUnsupported || graph.Analysis.ReasonCode != "no_local_source" ||
		len(graph.Observations) != 0 || len(graph.UnanalysedOccurrences) != 2 {
		t.Fatalf("graph = %+v", graph)
	}
	for _, occurrence := range graph.UnanalysedOccurrences {
		if occurrence.Reason == "not_imported_by_analysed_source" {
			t.Fatalf("unavailable graph allowed a negative: %+v", occurrence)
		}
	}
	if _, err := ProduceUnavailable("scan", AnalysisComplete, "x", nil); err == nil {
		t.Fatal("complete status accepted for an unavailable graph")
	}
}
