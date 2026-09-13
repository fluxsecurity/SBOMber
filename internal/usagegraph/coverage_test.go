package usagegraph

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

func TestRepositoryScanFlowsIntoCoverage(t *testing.T) {
	root := t.TempDir()
	for path, source := range map[string]string{
		"src/app.js":                   `import lodash from "lodash"; lodash({});`,
		"node_modules/lodash/index.js": `module.exports = {};`,
	} {
		absolute := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(absolute, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	repository, err := sourceanalysis.AnalyzeRepository(root, sourceanalysis.RepositoryOptions{})
	if err != nil {
		t.Fatalf("AnalyzeRepository: %v", err)
	}
	result, err := Build(
		[]RepositoryInput{{RepositoryID: "repo-app", Result: repository}},
		nil,
		Options{Ecosystem: "npm", AnalyzerID: AnalyzerID},
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if result.Analysis.Status != AnalysisComplete || result.Coverage.FilesDiscovered != 1 {
		t.Fatalf("unexpected integrated coverage: %+v", result)
	}
	if len(result.ScopeExclusions) != 1 || result.ScopeExclusions[0].Path != "node_modules" {
		t.Fatalf("excluded tree entered coverage: %+v", result.ScopeExclusions)
	}
}

func cleanSource(path string) sourceanalysis.AnalyzedSource {
	return sourceanalysis.AnalyzedSource{
		Path: path,
		Result: sourceanalysis.Result{
			Language: "javascript",
		},
	}
}

func TestBuildCompleteCoverageFromMeasuredInputs(t *testing.T) {
	result, err := Build(
		[]RepositoryInput{
			{
				RepositoryID: "repo-b",
				Result: sourceanalysis.RepositoryResult{
					Files: []sourceanalysis.AnalyzedSource{cleanSource("src/b.js")},
				},
			},
			{
				RepositoryID: "repo-a",
				Result: sourceanalysis.RepositoryResult{
					Files: []sourceanalysis.AnalyzedSource{cleanSource("src/a.ts")},
					Skipped: []sourceanalysis.SkippedSource{
						{
							Path:        "node_modules",
							Reason:      sourceanalysis.SkipExcludedDirectory,
							IsDirectory: true,
						},
					},
				},
			},
		},
		[]ObservationInput{
			{
				Resolution: ImportResolved,
				CallSites: []CallSiteInput{
					{Resolution: CallResolved, Reachability: NotAnalysed},
				},
			},
			{Resolution: ImportTypeOnly},
			{Resolution: ImportUnresolved},
		},
		Options{
			Ecosystem:  "npm",
			AnalyzerID: AnalyzerID,
		},
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if result.Analysis.Status != AnalysisComplete {
		t.Fatalf("status = %q, want complete", result.Analysis.Status)
	}
	if result.Coverage.FilesDiscovered != 2 || result.Coverage.FilesParsed != 2 {
		t.Fatalf("unexpected file coverage: %+v", result.Coverage)
	}
	if result.Coverage.FilesSkipped != 0 {
		t.Fatalf("excluded directory entered file denominator: %+v", result.Coverage)
	}
	if len(result.ScopeExclusions) != 1 || result.ScopeExclusions[0].Path != "node_modules" {
		t.Fatalf("scope exclusion was not retained internally: %+v", result.ScopeExclusions)
	}
	if got := []int{
		result.Coverage.ThirdPartyImportsResolved,
		result.Coverage.ThirdPartyImportsTypeOnly,
		result.Coverage.ThirdPartyImportsUnresolved,
		result.Coverage.ThirdPartyCallSitesResolved,
		result.Coverage.ThirdPartyCallSitesUnresolved,
	}; !reflect.DeepEqual(got, []int{1, 1, 1, 1, 0}) {
		t.Fatalf("unexpected observation counters: %v", got)
	}
	if got := []string{
		result.Coverage.PerRepository[0].RepositoryID,
		result.Coverage.PerRepository[1].RepositoryID,
	}; !reflect.DeepEqual(got, []string{"repo-a", "repo-b"}) {
		t.Fatalf("repositories not sorted: %v", got)
	}
	if result.Coverage.ParseCoveragePercent() != 100 {
		t.Fatalf("parse coverage = %v, want 100", result.Coverage.ParseCoveragePercent())
	}
}

func TestBuildPartialCoverageCountsOnlyInScopeFiles(t *testing.T) {
	withErrors := cleanSource("src/recoverable.js")
	withErrors.Result.HasError = true

	result, err := Build(
		[]RepositoryInput{
			{
				RepositoryID: "repo-app",
				Result: sourceanalysis.RepositoryResult{
					Files: []sourceanalysis.AnalyzedSource{
						cleanSource("src/clean.js"),
						withErrors,
					},
					Skipped: []sourceanalysis.SkippedSource{
						{Path: "dist", Reason: sourceanalysis.SkipExcludedDirectory, IsDirectory: true},
						{Path: "src/app.min.js", Reason: sourceanalysis.SkipMinifiedBundle},
					},
					Failed: []sourceanalysis.FailedSource{
						{Path: "src/broken.ts", Reason: "parser unavailable"},
						{Path: "private", Reason: "permission denied", IsDirectory: true},
					},
					LimitsHit: []string{
						sourceanalysis.LimitMaxFileSize,
						sourceanalysis.LimitMaxFileSize,
					},
				},
			},
		},
		[]ObservationInput{
			{
				Resolution: ImportResolved,
				CallSites: []CallSiteInput{
					{Resolution: CallUnresolved, Reachability: NotAnalysed},
				},
			},
		},
		Options{Ecosystem: "npm", AnalyzerID: AnalyzerID},
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if result.Analysis.Status != AnalysisPartial {
		t.Fatalf("status = %q, want partial", result.Analysis.Status)
	}
	wantFiles := []int{4, 1, 1, 1, 1}
	gotFiles := []int{
		result.Coverage.FilesDiscovered,
		result.Coverage.FilesParsed,
		result.Coverage.FilesParsedWithErrors,
		result.Coverage.FilesFailed,
		result.Coverage.FilesSkipped,
	}
	if !reflect.DeepEqual(gotFiles, wantFiles) {
		t.Fatalf("file counters = %v, want %v", gotFiles, wantFiles)
	}
	if got, want := result.Coverage.ParseCoveragePercent(), 25.0; got != want {
		t.Fatalf("parse coverage = %v, want %v", got, want)
	}
	if len(result.ParseFailures) != 1 || result.ParseFailures[0].File != "src/broken.ts" {
		t.Fatalf("unexpected parse failures: %+v", result.ParseFailures)
	}
	if got, want := result.Coverage.LimitsHit, []string{
		sourceanalysis.LimitMaxFileSize,
		LimitRepositoryTraversal,
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("limits = %v, want %v", got, want)
	}
	if len(result.ScopeExclusions) != 1 || result.ScopeExclusions[0].Path != "dist" {
		t.Fatalf("unexpected scope exclusions: %+v", result.ScopeExclusions)
	}
	if result.Coverage.ThirdPartyCallSitesUnresolved != 1 {
		t.Fatalf("unresolved call not counted: %+v", result.Coverage)
	}
}

func TestBuildReachabilityCoverage(t *testing.T) {
	result, err := Build(
		nil,
		[]ObservationInput{
			{
				Resolution: ImportResolved,
				CallSites: []CallSiteInput{
					{Resolution: CallResolved, Reachability: Reachable},
					{Resolution: CallResolved, Reachability: ReachUnknown},
				},
			},
		},
		Options{
			Ecosystem:            "npm",
			AnalyzerID:           AnalyzerID,
			ReachabilityAnalysed: true,
			EntryPointsDetected:  1,
		},
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if result.Coverage.CallPathsResolved != 1 || result.Coverage.CallPathsUnresolved != 1 {
		t.Fatalf("unexpected reachability coverage: %+v", result.Coverage)
	}
	if !result.Analyser.ReachabilityAnalysed {
		t.Fatal("analyser metadata did not record reachability pass")
	}
}

func TestBuildRejectsInconsistentInputs(t *testing.T) {
	tests := []struct {
		name         string
		repositories []RepositoryInput
		observations []ObservationInput
		options      Options
	}{
		{
			name: "duplicate repository",
			repositories: []RepositoryInput{
				{RepositoryID: "same"},
				{RepositoryID: "same"},
			},
			options: Options{Ecosystem: "npm", AnalyzerID: AnalyzerID},
		},
		{
			name: "type-only runtime call",
			observations: []ObservationInput{
				{
					Resolution: ImportTypeOnly,
					CallSites:  []CallSiteInput{{Resolution: CallResolved, Reachability: NotAnalysed}},
				},
			},
			options: Options{Ecosystem: "npm", AnalyzerID: AnalyzerID},
		},
		{
			name: "reachability without pass",
			observations: []ObservationInput{
				{
					Resolution: ImportResolved,
					CallSites:  []CallSiteInput{{Resolution: CallResolved, Reachability: ReachUnknown}},
				},
			},
			options: Options{Ecosystem: "npm", AnalyzerID: AnalyzerID},
		},
		{
			name: "reachable unresolved call",
			observations: []ObservationInput{
				{
					Resolution: ImportResolved,
					CallSites:  []CallSiteInput{{Resolution: CallUnresolved, Reachability: Reachable}},
				},
			},
			options: Options{
				Ecosystem:            "npm",
				AnalyzerID:           AnalyzerID,
				ReachabilityAnalysed: true,
				EntryPointsDetected:  1,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Build(test.repositories, test.observations, test.options); err == nil {
				t.Fatal("expected inconsistent coverage input to fail")
			}
		})
	}
}

func TestUnavailableAlwaysCarriesCoverage(t *testing.T) {
	for _, status := range []string{AnalysisFailed, AnalysisUnsupported} {
		t.Run(status, func(t *testing.T) {
			result, err := Unavailable(status, "npm", "analysis_unavailable")
			if err != nil {
				t.Fatalf("Unavailable: %v", err)
			}
			if result.Analysis.Status != status || result.Analysis.ReasonCode == "" {
				t.Fatalf("unexpected analysis envelope: %+v", result.Analysis)
			}
			if result.Coverage.LimitsHit == nil || result.Coverage.PerRepository == nil || result.ParseFailures == nil {
				t.Fatalf("mandatory empty coverage arrays are nil: %+v", result)
			}
		})
	}

	if _, err := Unavailable(AnalysisComplete, "npm", "wrong"); err == nil {
		t.Fatal("expected complete status to be rejected by Unavailable")
	}
}

func TestParseCoveragePercentZeroDenominator(t *testing.T) {
	if got := (Coverage{}).ParseCoveragePercent(); got != 0 {
		t.Fatalf("zero-denominator coverage = %v, want 0", got)
	}
}
