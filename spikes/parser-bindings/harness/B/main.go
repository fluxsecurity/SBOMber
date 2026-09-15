package main

import (
	"encoding/json"
	"fmt"
	"os"

	gotreesitter "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

type languageResult struct {
	Language     string `json:"language"`
	Instantiated bool   `json:"instantiated"`
	TreeCreated  bool   `json:"treeCreated"`
	HasError     bool   `json:"hasError"`
	Pass         bool   `json:"pass"`
	Error        string `json:"error,omitempty"`
}

type gateReport struct {
	Candidate string           `json:"candidate"`
	Test      string           `json:"test"`
	Fixture   string           `json:"fixture"`
	Languages []languageResult `json:"languages"`
	Pass      bool             `json:"pass"`
}

type languageCase struct {
	name     string
	language *gotreesitter.Language
	source   []byte
}

func runLanguage(item languageCase) languageResult {
	result := languageResult{
		Language:     item.name,
		Instantiated: item.language != nil,
	}

	if item.language == nil {
		result.Error = "language factory returned nil"
		return result
	}

	parser := gotreesitter.NewParser(item.language)
	if parser == nil {
		result.Error = "parser creation returned nil"
		return result
	}

	tree, err := parser.Parse(item.source)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	if tree == nil {
		result.Error = "parser returned nil tree"
		return result
	}
	defer tree.Release()

	root := tree.RootNode()
	if root == nil {
		result.Error = "tree returned nil root node"
		return result
	}

	result.TreeCreated = true
	result.HasError = root.HasError()
	result.Pass = !result.HasError

	if result.HasError {
		result.Error = "valid source produced parser error nodes"
	}

	return result
}

func runGates(fixturePath string) error {
	javascriptSource, err := os.ReadFile(fixturePath)
	if err != nil {
		return fmt.Errorf("read JavaScript fixture: %w", err)
	}

	cases := []languageCase{
		{
			name:     "javascript",
			language: grammars.JavascriptLanguage(),
			source:   javascriptSource,
		},
		{
			name:     "typescript",
			language: grammars.TypescriptLanguage(),
			source: []byte(
				`import type { DebouncedFunc } from "lodash";` +
					`const value: string = "hello";`,
			),
		},
		{
			name:     "tsx",
			language: grammars.TsxLanguage(),
			source: []byte(
				`import * as React from "react";` +
					`export const Badge = () => <span>hello</span>;`,
			),
		},
	}

	report := gateReport{
		Candidate: "B",
		Test:      "T1-language-availability",
		Fixture:   fixturePath,
		Languages: make([]languageResult, 0, len(cases)),
		Pass:      true,
	}

	for _, item := range cases {
		result := runLanguage(item)
		report.Languages = append(report.Languages, result)

		if !result.Pass {
			report.Pass = false
		}
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encode report: %w", err)
	}

	if !report.Pass {
		return fmt.Errorf("one or more required languages failed T1")
	}

	return nil
}

func printUsage() {
	fmt.Fprintln(
		os.Stderr,
		"usage: harness-B <gates|sexp|nodes|captures|extract|stopreason> <fixture>",
	)
}

func main() {
	if len(os.Args) != 3 {
		printUsage()
		os.Exit(2)
	}

	command := os.Args[1]
	fixturePath := os.Args[2]

	var err error

	switch command {
	case "gates":
		err = runGates(fixturePath)
	case "sexp":
		err = runSExpression(fixturePath)
	case "nodes":
		err = runNodeDump(fixturePath)
	case "captures":
		err = runCaptureDump(fixturePath)
	case "extract":
		err = runExtract(fixturePath)
	case "stopreason":
		err = runStopReason(fixturePath)
	default:
		fmt.Fprintf(
			os.Stderr,
			"unknown command %q\n",
			command,
		)
		printUsage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}
