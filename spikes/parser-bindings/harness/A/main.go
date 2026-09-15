package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	treesitter "github.com/tree-sitter/go-tree-sitter"
	javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	typescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"
)

var fieldLabelPattern = regexp.MustCompile(
	`\b[A-Za-z_][A-Za-z0-9_]*:\s+`,
)

func languageForFixture(
	fixturePath string,
) (*treesitter.Language, error) {
	lowerPath := strings.ToLower(fixturePath)

	switch {
	case strings.HasSuffix(lowerPath, ".tsx"):
		return treesitter.NewLanguage(
			typescript.LanguageTSX(),
		), nil

	case strings.HasSuffix(lowerPath, ".ts"):
		return treesitter.NewLanguage(
			typescript.LanguageTypescript(),
		), nil

	case strings.HasSuffix(lowerPath, ".js"),
		strings.HasSuffix(lowerPath, ".mjs"),
		strings.HasSuffix(lowerPath, ".cjs"):
		return treesitter.NewLanguage(
			javascript.Language(),
		), nil

	default:
		return nil, fmt.Errorf(
			"unsupported fixture extension %q",
			filepath.Ext(fixturePath),
		)
	}
}

func normalizeSExpression(value string) string {
	return fieldLabelPattern.ReplaceAllString(value, "")
}

func runSExpression(fixturePath string) error {
	source, err := os.ReadFile(fixturePath)
	if err != nil {
		return fmt.Errorf("read fixture: %w", err)
	}

	language, err := languageForFixture(fixturePath)
	if err != nil {
		return err
	}

	if language == nil {
		return fmt.Errorf("language factory returned nil")
	}

	parser := treesitter.NewParser()
	if parser == nil {
		return fmt.Errorf("parser creation returned nil")
	}
	defer parser.Close()

	if err := parser.SetLanguage(language); err != nil {
		return fmt.Errorf("set parser language: %w", err)
	}

	tree := parser.Parse(source, nil)
	if tree == nil {
		return fmt.Errorf("parser returned nil tree")
	}
	defer tree.Close()

	root := tree.RootNode()

	fmt.Println(normalizeSExpression(root.ToSexp()))
	return nil
}

func printUsage() {
	fmt.Fprintln(
		os.Stderr,
		"usage: harness-A <sexp|extract> <fixture>",
	)
}

func main() {
	if len(os.Args) != 3 {
		printUsage()
		os.Exit(2)
	}

	var err error

	switch os.Args[1] {
	case "sexp":
		err = runSExpression(os.Args[2])
	case "extract":
		err = runExtract(os.Args[2])
	default:
		fmt.Fprintf(
			os.Stderr,
			"unknown command %q\n",
			os.Args[1],
		)
		printUsage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}
