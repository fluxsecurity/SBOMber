package usagegraph

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type frozenGroundTruth struct {
	Fixture     string         `json:"fixture"`
	LabelMethod string         `json:"labelMethod"`
	Language    string         `json:"language"`
	Expected    frozenExpected `json:"expected"`
}

type frozenExpected struct {
	EntryPoints       []frozenEntryPoint `json:"entryPoints"`
	ThirdPartyImports []frozenImport     `json:"thirdPartyImports"`
	ThirdPartyCalls   []frozenCall       `json:"thirdPartyCalls"`
	Coverage          frozenCoverage     `json:"coverage"`
}

type frozenEntryPoint struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	File string `json:"file"`
	Line int    `json:"line"`
}

type frozenImport struct {
	Specifier string `json:"specifier"`
	Imported  string `json:"imported"`
	Local     string `json:"local"`
	Kind      string `json:"kind"`
	File      string `json:"file"`
	Line      int    `json:"line"`
}

type frozenCall struct {
	Symbol        string   `json:"symbol"`
	File          string   `json:"file"`
	Line          int      `json:"line"`
	Resolution    string   `json:"resolution"`
	Reachability  string   `json:"reachability"`
	EntryPoint    string   `json:"entryPoint,omitempty"`
	CallPath      []string `json:"callPath,omitempty"`
	EvidenceLevel int      `json:"evidenceLevel"`
}

type frozenCoverage struct {
	EntryPointsDetected int `json:"entryPointsDetected"`
	CallPathsResolved   int `json:"callPathsResolved"`
	CallPathsUnresolved int `json:"callPathsUnresolved"`
}

func freezeGraphSemantics(graph Graph) frozenExpected {
	entryPointNames := make(map[string]string, len(graph.EntryPoints))
	entryPoints := make([]frozenEntryPoint, 0, len(graph.EntryPoints))
	for _, entryPoint := range graph.EntryPoints {
		entryPointNames[entryPoint.EntryPointID] = entryPoint.Function
		entryPoints = append(entryPoints, frozenEntryPoint{
			Name: entryPoint.Function,
			Kind: entryPoint.Kind,
			File: entryPoint.File,
			Line: entryPoint.Line,
		})
	}

	imports := make([]frozenImport, 0, len(graph.Observations))
	calls := make([]frozenCall, 0)
	for _, observation := range graph.Observations {
		imports = append(imports, frozenImport{
			Specifier: observation.ImportedSpecifier,
			Imported:  observation.ImportedSymbol,
			Local:     observation.LocalAlias,
			Kind:      observation.ImportKind,
			File:      observation.Location.File,
			Line:      observation.Location.Line,
		})

		for _, callSite := range observation.CallSites {
			var callPath []string
			if len(callSite.CallPath) != 0 {
				callPath = make([]string, 0, len(callSite.CallPath))
				for _, step := range callSite.CallPath {
					callPath = append(callPath, step.Function)
				}
			}

			calls = append(calls, frozenCall{
				Symbol:        callSite.CalledSymbol,
				File:          callSite.File,
				Line:          callSite.Line,
				Resolution:    callSite.Resolution,
				Reachability:  callSite.Reachability,
				EntryPoint:    entryPointNames[callSite.EntryPointID],
				CallPath:      callPath,
				EvidenceLevel: observation.EvidenceLevel,
			})
		}
	}

	return frozenExpected{
		EntryPoints:       entryPoints,
		ThirdPartyImports: imports,
		ThirdPartyCalls:   calls,
		Coverage: frozenCoverage{
			EntryPointsDetected: graph.Coverage.EntryPointsDetected,
			CallPathsResolved:   graph.Coverage.CallPathsResolved,
			CallPathsUnresolved: graph.Coverage.CallPathsUnresolved,
		},
	}
}

func TestFrozenUsageGroundTruth(t *testing.T) {
	fixtures := []string{
		"component2-usage-reachable",
		"component2-usage-unknown",
		"component2-usage-callback",
	}

	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			expectedPath := filepath.Join(
				"..",
				"..",
				"testdata",
				"fixtures",
				"usage-ground-truth",
				fixture,
				"expected.json",
			)
			data, err := os.ReadFile(expectedPath)
			if err != nil {
				t.Fatalf("read frozen expectation: %v", err)
			}

			var frozen frozenGroundTruth
			if err := json.Unmarshal(data, &frozen); err != nil {
				t.Fatalf("decode frozen expectation: %v", err)
			}
			if frozen.Fixture != fixture ||
				frozen.LabelMethod != "hand-authored before analyser execution" ||
				frozen.Language != "javascript" {
				t.Fatalf("invalid frozen-fixture metadata: %+v", frozen)
			}

			got := freezeGraphSemantics(
				produceFixtureGraph(t, fixture),
			)
			if !reflect.DeepEqual(got, frozen.Expected) {
				gotJSON, _ := json.MarshalIndent(got, "", "  ")
				wantJSON, _ := json.MarshalIndent(
					frozen.Expected,
					"",
					"  ",
				)
				t.Fatalf(
					"generated semantics differ from frozen ground truth\n"+
						"--- want ---\n%s\n"+
						"--- got ---\n%s",
					wantJSON,
					gotJSON,
				)
			}
		})
	}
}
