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

	unanalysed := buildUnanalysedOccurrences(
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
	occurrences []OccurrenceInput,
	matched map[string]struct{},
	ambiguous map[string]struct{},
	observations []Observation,
	coverage Result,
) []UnanalysedOccurrence {
	result := []UnanalysedOccurrence{}
	computedRepositories := make(map[string]struct{})
	for _, observation := range observations {
		if observation.ComputedSpecifier {
			computedRepositories[observation.Location.RepositoryID] = struct{}{}
		}
	}
	for _, input := range occurrences {
		occurrence := input.Occurrence
		if _, ok := matched[occurrence.OccurrenceID]; ok {
			continue
		}

		reason := "not_imported_by_analysed_source"
		if _, couldBeImported := ambiguous[occurrence.OccurrenceID]; couldBeImported {
			reason = "ambiguous_occurrence"
		} else if occurrence.Scope == "transitive" ||
			len(occurrence.DependencyPath) != 0 ||
			occurrence.Depth > 0 {
			reason = "nested_under_dependency"
		} else if _, computed := computedRepositories[input.RepositoryID]; computed {
			reason = "computed_specifier"
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
		})
	}

	sort.Slice(result, func(left, right int) bool {
		return result[left].OccurrenceID < result[right].OccurrenceID
	})
	return result
}
