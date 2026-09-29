package usagegraph

import (
	"fmt"
	"sort"

	"github.com/Xsamsx/SBOMber/internal/canonicalscan"
	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

// OccurrenceInput associates a canonical occurrence with the repository whose
// application source is being analysed. The canonical occurrence model does
// not itself carry Component 2's stable repository ID.
type OccurrenceInput struct {
	RepositoryID string
	Occurrence   canonicalscan.Occurrence
}

// DeclaredEntryPoint identifies a configured application entry.
// Line is optional for a uniquely named function; <module> uses line 1.
type DeclaredEntryPoint struct {
	RepositoryID string
	File         string
	Function     string
	Line         int
}

// ProduceOptions controls construction of a complete usage-graph document.
type ProduceOptions struct {
	ScanID               string
	Ecosystem            string
	AnalyzerID           string
	ReachabilityAnalysed bool
	DeclaredEntryPoints  []DeclaredEntryPoint
}

// Produce converts parser-independent repository results into a complete
// usage-graph document. Reachability is derived from emitted call sites.
func Produce(
	repositories []RepositoryInput,
	occurrences []OccurrenceInput,
	options ProduceOptions,
) (Graph, error) {
	if options.ScanID == "" {
		return Graph{}, fmt.Errorf("usage graph scan ID is required")
	}

	entryPoints := []EntryPoint{}
	graph := applicationCallGraph{
		functions: make(map[sourceanalysis.FunctionID]struct{}),
		edges: make(
			map[sourceanalysis.FunctionID][]sourceanalysis.FunctionID,
		),
	}
	if options.ReachabilityAnalysed {
		entryPoints = detectEntryPoints(repositories, options.DeclaredEntryPoints)

		built, err := buildApplicationCallGraph(repositories)
		if err != nil {
			return Graph{}, fmt.Errorf("build application call graph: %w", err)
		}
		graph = built
	}

	observations, matchedOccurrences, ambiguousOccurrences, err := buildObservations(
		repositories,
		occurrences,
		graph.pathsFrom(entryPoints),
		options.ReachabilityAnalysed,
	)
	if err != nil {
		return Graph{}, err
	}

	coverageInputs := make([]ObservationInput, 0, len(observations))
	for _, observation := range observations {
		input := ObservationInput{
			Resolution: observation.Resolution,
			CallSites:  make([]CallSiteInput, 0, len(observation.CallSites)),
		}
		for _, callSite := range observation.CallSites {
			input.CallSites = append(input.CallSites, CallSiteInput{
				Resolution:   callSite.Resolution,
				Reachability: callSite.Reachability,
			})
		}
		coverageInputs = append(coverageInputs, input)
	}

	coverageResult, err := Build(
		repositories,
		coverageInputs,
		Options{
			Ecosystem:            options.Ecosystem,
			AnalyzerID:           options.AnalyzerID,
			ReachabilityAnalysed: options.ReachabilityAnalysed,
			EntryPointsDetected:  len(entryPoints),
		},
	)
	if err != nil {
		return Graph{}, fmt.Errorf("build usage graph coverage: %w", err)
	}

	analysed := make(map[string]struct{}, len(repositories))
	for _, repository := range repositories {
		analysed[repository.RepositoryID] = struct{}{}
	}
	unanalysed := buildUnanalysedOccurrences(
		repositories,
		analysed,
		occurrences,
		matchedOccurrences,
		ambiguousOccurrences,
		observations,
		coverageResult,
	)

	return Graph{
		SchemaVersion:         SchemaVersion,
		ScanID:                options.ScanID,
		Analysis:              coverageResult.Analysis,
		Analyser:              coverageResult.Analyser,
		EntryPoints:           entryPoints,
		Coverage:              coverageResult.Coverage,
		Observations:          observations,
		UnanalysedOccurrences: unanalysed,
		ParseFailures:         coverageResult.ParseFailures,
	}, nil
}

func buildUnanalysedOccurrences(
	repositories []RepositoryInput,
	analysedRepositories map[string]struct{},
	occurrences []OccurrenceInput,
	matched map[string]struct{},
	ambiguous map[string]struct{},
	observations []Observation,
	coverage Result,
) []UnanalysedOccurrence {
	result := []UnanalysedOccurrence{}
	unresolvedAliases := unresolvedPathAliasRepositories(repositories)
	emptyRepositories := make(map[string]struct{})
	for _, repository := range coverage.Coverage.PerRepository {
		if repository.FilesDiscovered == 0 {
			emptyRepositories[repository.RepositoryID] = struct{}{}
		}
	}
	// The first computed import per repository (observations are sorted by
	// location) is named in the detail, so a reviewer can see which line
	// keeps every unmatched package from reading as unused.
	computedRepositories := make(map[string]string)
	for _, observation := range observations {
		if !observation.ComputedSpecifier {
			continue
		}
		if _, seen := computedRepositories[observation.Location.RepositoryID]; !seen {
			computedRepositories[observation.Location.RepositoryID] = fmt.Sprintf(
				"computed import at %s:%d could load this package",
				observation.Location.File, observation.Location.Line)
		}
	}
	for _, input := range occurrences {
		occurrence := input.Occurrence
		if _, ok := matched[occurrence.OccurrenceID]; ok {
			continue
		}

		reason := "not_imported_by_analysed_source"
		detail := ""
		_, isNPM := npmPackageFromPURL(occurrence.ComponentPurl)
		_, repositoryAnalysed := analysedRepositories[input.RepositoryID]
		if !isNPM {
			// Only npm packages are joined to JS/TS imports. Any other
			// ecosystem was never looked at, so it cannot read as unused.
			reason = "ecosystem_unsupported"
		} else if !repositoryAnalysed {
			reason = "excluded_by_limits"
			detail = "repository source was not analysed in this run"
		} else if _, empty := emptyRepositories[input.RepositoryID]; empty {
			// Nothing was parsed, so "no import found" would rest on no
			// evidence at all (#121 acceptance case 6).
			reason = "excluded_by_limits"
			detail = "no JavaScript or TypeScript source files were found in the repository"
		} else if _, couldBeImported := ambiguous[occurrence.OccurrenceID]; couldBeImported {
			reason = "ambiguous_occurrence"
		} else if occurrence.Scope == "transitive" ||
			len(occurrence.DependencyPath) != 0 ||
			occurrence.Depth > 0 {
			reason = "nested_under_dependency"
		} else if where, unresolved := unresolvedAliases[input.RepositoryID]; unresolved {
			reason = "excluded_by_limits"
			detail = where
		} else if where, computed := computedRepositories[input.RepositoryID]; computed {
			reason = "computed_specifier"
			detail = where
		} else if coverage.Analysis.Status == AnalysisPartial {
			if coverage.Coverage.FilesFailed != 0 ||
				coverage.Coverage.FilesParsedWithErrors != 0 {
				reason = "import_site_parse_failed"
			} else {
				reason = "excluded_by_limits"
			}
		}

		result = append(result, UnanalysedOccurrence{
			OccurrenceID: occurrence.OccurrenceID,
			PURL:         occurrence.ComponentPurl,
			Reason:       reason,
			Detail:       detail,
		})
	}

	sort.Slice(result, func(left, right int) bool {
		return result[left].OccurrenceID < result[right].OccurrenceID
	})
	return result
}

// ProduceUnavailable builds a graph for a scan whose application source could
// not be analysed at all, for example when every repository is remote
// (manifest-only). Every occurrence is listed as unanalysed, so none can
// support a negative finding, and the analysis status says why.
func ProduceUnavailable(
	scanID string,
	status string,
	reasonCode string,
	occurrences []OccurrenceInput,
) (Graph, error) {
	if scanID == "" {
		return Graph{}, fmt.Errorf("usage graph scan ID is required")
	}
	result, err := Unavailable(status, "npm", reasonCode)
	if err != nil {
		return Graph{}, err
	}
	unanalysed := buildUnanalysedOccurrences(
		nil,
		map[string]struct{}{},
		occurrences,
		map[string]struct{}{},
		map[string]struct{}{},
		nil,
		result,
	)
	return Graph{
		SchemaVersion:         SchemaVersion,
		ScanID:                scanID,
		Analysis:              result.Analysis,
		Analyser:              result.Analyser,
		EntryPoints:           []EntryPoint{},
		Coverage:              result.Coverage,
		Observations:          []Observation{},
		UnanalysedOccurrences: unanalysed,
		ParseFailures:         result.ParseFailures,
	}, nil
}
