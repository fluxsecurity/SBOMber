package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	gotreesitter "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

func languageForFixture(path string) (*gotreesitter.Language, error) {
	extension := strings.ToLower(filepath.Ext(path))

	switch extension {
	case ".js", ".mjs", ".cjs":
		return grammars.JavascriptLanguage(), nil
	case ".ts":
		return grammars.TypescriptLanguage(), nil
	case ".tsx":
		return grammars.TsxLanguage(), nil
	default:
		return nil, fmt.Errorf(
			"unsupported fixture extension %q",
			extension,
		)
	}
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

	parser := gotreesitter.NewParser(language)
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
		fmt.Println("<nil>")
		return nil
	}

	fmt.Println(root.SExpr(language))
	return nil
}
