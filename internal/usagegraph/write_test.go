package usagegraph

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestWriteGraphProducesDeterministicRoundTrippableJSON(t *testing.T) {
	graph := produceFixtureGraph(
		t,
		"component2-usage-reachable",
	)
	root := t.TempDir()
	firstPath := filepath.Join(root, "first.json")
	secondPath := filepath.Join(root, "second.json")

	if err := WriteGraph(firstPath, graph); err != nil {
		t.Fatalf("WriteGraph first: %v", err)
	}
	if err := WriteGraph(secondPath, graph); err != nil {
		t.Fatalf("WriteGraph second: %v", err)
	}

	first, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatalf("read first graph: %v", err)
	}
	second, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatalf("read second graph: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("identical graphs produced different JSON")
	}
	if !bytes.HasSuffix(first, []byte{'\n'}) {
		t.Fatal("usage graph JSON has no trailing newline")
	}
	if !json.Valid(first) {
		t.Fatalf("usage graph is not valid JSON: %s", first)
	}

	var decoded Graph
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatalf("unmarshal written graph: %v", err)
	}
	if !reflect.DeepEqual(decoded, graph) {
		t.Fatalf(
			"round trip changed graph\nwant: %+v\ngot:  %+v",
			graph,
			decoded,
		)
	}
}

func TestWriteGraphReportsOutputPath(t *testing.T) {
	outputPath := filepath.Join(
		t.TempDir(),
		"missing",
		"usage-graph.json",
	)
	err := WriteGraph(outputPath, Graph{})
	if err == nil {
		t.Fatal("expected write failure")
	}
	if !strings.Contains(err.Error(), outputPath) {
		t.Fatalf("write error does not name output path: %v", err)
	}
}
