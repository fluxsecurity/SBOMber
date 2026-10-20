package usagegraph

import (
	"path/filepath"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

func TestDetectExportedModuleEntryPointsFromFrozenFixtures(t *testing.T) {
	tests := []struct {
		fixture string
		line    int
	}{
		{fixture: "component2-usage-reachable", line: 3},
		{fixture: "component2-usage-unknown", line: 1},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			root := filepath.Join(
				"..",
				"..",
				"testdata",
				"fixtures",
				test.fixture,
			)
			repository, err := sourceanalysis.AnalyzeRepository(
				root,
				sourceanalysis.RepositoryOptions{},
			)
			if err != nil {
				t.Fatalf("AnalyzeRepository: %v", err)
			}

			entryPoints := detectExportedModuleEntryPoints(
				[]RepositoryInput{
					{
						RepositoryID: "repo-app",
						Result:       repository,
					},
				},
			)

			if len(entryPoints) != 1 {
				t.Fatalf("entry points = %+v, want one", entryPoints)
			}

			entryPoint := entryPoints[0]
			if entryPoint.Kind != "exported_module" ||
				entryPoint.Function != "postWelcome" ||
				entryPoint.File != "src/index.js" ||
				entryPoint.Line != test.line ||
				entryPoint.RepositoryID != "repo-app" ||
				entryPoint.EntryPointID == "" {
				t.Fatalf("unexpected entry point: %+v", entryPoint)
			}

			again := detectExportedModuleEntryPoints(
				[]RepositoryInput{
					{
						RepositoryID: "repo-app",
						Result:       repository,
					},
				},
			)
			if len(again) != 1 ||
				again[0].EntryPointID != entryPoint.EntryPointID {
				t.Fatalf(
					"entry-point ID changed between runs: %q != %+v",
					entryPoint.EntryPointID,
					again,
				)
			}
		})
	}
}
