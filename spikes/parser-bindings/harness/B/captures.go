package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

func captureLanguageForPath(path string) (*sitter.Language, error) {
	lowerPath := strings.ToLower(path)

	switch {
	case strings.HasSuffix(lowerPath, ".tsx"):
		return grammars.TsxLanguage(), nil
	case strings.HasSuffix(lowerPath, ".ts"):
		return grammars.TypescriptLanguage(), nil
	case strings.HasSuffix(lowerPath, ".js"),
		strings.HasSuffix(lowerPath, ".mjs"),
		strings.HasSuffix(lowerPath, ".cjs"):
		return grammars.JavascriptLanguage(), nil
	default:
		return nil, fmt.Errorf(
			"unsupported fixture extension %q",
			filepath.Ext(path),
		)
	}
}

func runCaptureDump(fixturePath string) error {
	source, err := os.ReadFile(fixturePath)
	if err != nil {
		return fmt.Errorf("read fixture: %w", err)
	}

	querySource, err := os.ReadFile("queries/usage.scm")
	if err != nil {
		return fmt.Errorf("read query: %w", err)
	}

	language, err := captureLanguageForPath(fixturePath)
	if err != nil {
		return err
	}

	if language == nil {
		return fmt.Errorf("language factory returned nil")
	}

	parser := sitter.NewParser(language)
	if parser == nil {
		return fmt.Errorf("parser creation returned nil")
	}

	tree, err := parser.Parse(source)
	if err != nil {
		return fmt.Errorf("parse fixture: %w", err)
	}

	if tree == nil {
		return fmt.Errorf("parser returned nil tree")
	}
	defer tree.Release()

	root := tree.RootNode()
	if root == nil {
		return fmt.Errorf("tree returned nil root node")
	}

	query, err := sitter.NewQuery(string(querySource), language)
	if err != nil {
		return fmt.Errorf("compile query: %w", err)
	}

	cursor := query.Exec(root, language, source)
	if cursor == nil {
		return fmt.Errorf("query returned nil cursor")
	}

	matchNumber := 0

	for {
		match, ok := cursor.NextMatch()
		if !ok {
			break
		}

		matchNumber++

		fmt.Printf(
			"match=%d pattern=%d captures=%d\n",
			matchNumber,
			match.PatternIndex,
			len(match.Captures),
		)

		for _, capture := range match.Captures {
			node := capture.Node
			if node == nil {
				fmt.Printf(
					"  capture=%q node=nil\n",
					capture.Name,
				)
				continue
			}

			start := node.StartPoint()
			end := node.EndPoint()

			fmt.Printf(
				"  capture=%q type=%q bytes=%d-%d start=%d:%d end=%d:%d text=%q\n",
				capture.Name,
				node.Type(language),
				node.StartByte(),
				node.EndByte(),
				start.Row,
				start.Column,
				end.Row,
				end.Column,
				capture.Text(source),
			)
		}
	}

	fmt.Printf("matches=%d\n", matchNumber)
	return nil
}
