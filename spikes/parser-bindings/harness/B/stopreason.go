package main

import (
	"encoding/json"
	"fmt"
	"os"

	gotreesitter "github.com/odvcencio/gotreesitter"
)

type stopReasonReport struct {
	Fixture       string                       `json:"fixture"`
	SourceBytes   int                          `json:"sourceBytes"`
	StrictError   string                       `json:"strictError,omitempty"`
	StoppedEarly  bool                         `json:"stoppedEarly"`
	StopReason    gotreesitter.ParseStopReason `json:"stopReason"`
	Runtime       string                       `json:"runtime"`
	RootType      string                       `json:"rootType,omitempty"`
	RootHasError  bool                         `json:"rootHasError"`
	RootStartByte uint32                       `json:"rootStartByte"`
	RootEndByte   uint32                       `json:"rootEndByte"`
}

func runStopReason(fixturePath string) error {
	source, err := os.ReadFile(fixturePath)
	if err != nil {
		return fmt.Errorf("read fixture: %w", err)
	}

	language, err := languageForFixture(fixturePath)
	if err != nil {
		return err
	}

	parser := gotreesitter.NewParser(language)
	if parser == nil {
		return fmt.Errorf("parser creation returned nil")
	}

	tree, strictErr := parser.ParseStrict(source)
	if tree == nil {
		if strictErr != nil {
			return fmt.Errorf("strict parse returned no tree: %w", strictErr)
		}

		return fmt.Errorf("strict parse returned nil tree")
	}
	defer tree.Release()

	report := stopReasonReport{
		Fixture:      fixturePath,
		SourceBytes:  len(source),
		StoppedEarly: tree.ParseStoppedEarly(),
		StopReason:   tree.ParseStopReason(),
		Runtime:      tree.ParseRuntime().Summary(),
	}

	if strictErr != nil {
		report.StrictError = strictErr.Error()
	}

	root := tree.RootNode()
	if root != nil {
		report.RootType = root.Type(language)
		report.RootHasError = root.HasError()
		report.RootStartByte = root.StartByte()
		report.RootEndByte = root.EndByte()
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encode stop-reason report: %w", err)
	}

	return nil
}
