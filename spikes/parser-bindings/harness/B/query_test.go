package main

import (
	"os"
	"testing"

	gotreesitter "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

func TestUsageQueryCompilesForRequiredLanguages(t *testing.T) {
	querySource, err := os.ReadFile("../../queries/usage.scm")
	if err != nil {
		t.Fatalf("read shared query: %v", err)
	}

	tests := []struct {
		name     string
		language *gotreesitter.Language
	}{
		{
			name:     "javascript",
			language: grammars.JavascriptLanguage(),
		},
		{
			name:     "typescript",
			language: grammars.TypescriptLanguage(),
		},
		{
			name:     "tsx",
			language: grammars.TsxLanguage(),
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.language == nil {
				t.Fatal("language factory returned nil")
			}

			query, err := gotreesitter.NewQuery(
				string(querySource),
				testCase.language,
			)
			if err != nil {
				t.Fatalf("compile shared query: %v", err)
			}

			if query == nil {
				t.Fatal("query compiler returned nil query")
			}

			t.Logf(
				"shared usage query compiled for %s",
				testCase.name,
			)
		})
	}
}
