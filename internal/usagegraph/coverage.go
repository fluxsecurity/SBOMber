// Package usagegraph converts parser-independent source-analysis results into
// the public usage-graph contract. Parser-specific Tree-sitter details must not
// cross this boundary.
package usagegraph

import (
	"fmt"
	"sort"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

const (
	AnalysisComplete    = "complete"
	AnalysisPartial     = "partial"
	AnalysisUnsupported = "unsupported"
	AnalysisFailed      = "failed"

	ImportResolved   = "resolved"
	ImportUnresolved = "unresolved"
	ImportTypeOnly   = "type_only"

	CallResolved   = "resolved"
	CallUnresolved = "unresolved"

	Reachable    = "reachable"
	ReachUnknown = "unknown"
	NotAnalysed  = "not_analysed"

	LimitRepositoryTraversal = "repository_traversal"
)

// Analysis is the public analysis envelope from usage-graph.json.
type Analysis struct {
	Status     string `json:"status"`
	Ecosystem  string `json:"ecosystem"`
	AnalyzerID string `json:"analyzerId,omitempty"`
	ReasonCode string `json:"reasonCode,omitempty"`
}

// Coverage contains the mandatory public coverage counters. Import and call
// counters only accept observations already classified as third-party by the
// usage-graph producer; raw parser imports must not be passed here.
type Coverage struct {
	FilesDiscovered               int                  `json:"filesDiscovered"`
	FilesParsed                   int                  `json:"filesParsed"`
	FilesParsedWithErrors         int                  `json:"filesParsedWithErrors"`
	FilesFailed                   int                  `json:"filesFailed"`
	FilesSkipped                  int                  `json:"filesSkipped"`
	ThirdPartyImportsResolved     int                  `json:"thirdPartyImportsResolved"`
	ThirdPartyImportsTypeOnly     int                  `json:"thirdPartyImportsTypeOnly"`
	ThirdPartyImportsUnresolved   int                  `json:"thirdPartyImportsUnresolved"`
	ThirdPartyCallSitesResolved   int                  `json:"thirdPartyCallSitesResolved"`
	ThirdPartyCallSitesUnresolved int                  `json:"thirdPartyCallSitesUnresolved"`
	LimitsHit                     []string             `json:"limitsHit"`
	PerRepository                 []RepositoryCoverage `json:"perRepository"`
	EntryPointsDetected           int                  `json:"entryPointsDetected"`
	CallPathsResolved             int                  `json:"callPathsResolved"`
	CallPathsUnresolved           int                  `json:"callPathsUnresolved"`
}

// RepositoryCoverage is the per-repository file subset of Coverage.
type RepositoryCoverage struct {
	RepositoryID          string `json:"repositoryId"`
	FilesDiscovered       int    `json:"filesDiscovered"`
	FilesParsed           int    `json:"filesParsed"`
	FilesParsedWithErrors int    `json:"filesParsedWithErrors"`
	FilesFailed           int    `json:"filesFailed"`
	FilesSkipped          int    `json:"filesSkipped"`
}

// ParseFailure is emitted for a source file that produced no usable tree.
type ParseFailure struct {
	RepositoryID string `json:"repositoryId,omitempty"`
	File         string `json:"file"`
	Reason       string `json:"reason"`
}

// ScopeExclusion records a pruned directory internally. Excluded directory
// contents are outside the declared source scope and public file denominator.
type ScopeExclusion struct {
	RepositoryID string
	Path         string
	Reason       string
}

// RepositoryInput ties an internal scan to its stable public repository ID.
type RepositoryInput struct {
	RepositoryID string
	Result       sourceanalysis.RepositoryResult
}

// ObservationInput is the coverage-relevant subset of a normalised public
// third-party import observation.
type ObservationInput struct {
	Resolution string
	CallSites  []CallSiteInput
}

// CallSiteInput is the coverage-relevant subset of a normalised call site.
type CallSiteInput struct {
	Resolution   string
	Reachability string
}

// Options supplies scan-wide information that is not derivable from the
// repository lists. ReachabilityAnalysed is false until #122 runs the level-3
// pass.
type Options struct {
	Ecosystem            string
	AnalyzerID           string
	ReachabilityAnalysed bool
	EntryPointsDetected  int
}

// Result is the portion of usage-graph.json built by coverage reporting.
// ScopeExclusions remains internal because the v1.2.0 public contract has no
// directory-exclusion array.
type Result struct {
	Analysis        Analysis         `json:"analysis"`
	Analyser        Analyser         `json:"analyser"`
	Coverage        Coverage         `json:"coverage"`
	ParseFailures   []ParseFailure   `json:"parseFailures"`
	ScopeExclusions []ScopeExclusion `json:"-"`
}

// Build derives coverage and status from measured repository and observation
// results. It never accepts caller-supplied file totals, preventing drift
// between the scan and the public contract.
func Build(repositories []RepositoryInput, observations []ObservationInput, options Options) (Result, error) {
	if options.Ecosystem == "" {
		return Result{}, fmt.Errorf("coverage ecosystem is required")
	}
	if options.AnalyzerID == "" {
		return Result{}, fmt.Errorf("coverage analyzer ID is required")
	}
	if options.EntryPointsDetected < 0 {
		return Result{}, fmt.Errorf("entry-point count cannot be negative")
	}

	result := Result{
		Analysis: Analysis{
			Status:     AnalysisComplete,
			Ecosystem:  options.Ecosystem,
			AnalyzerID: options.AnalyzerID,
		},
		Analyser: CurrentAnalyser(options.ReachabilityAnalysed),
		Coverage: Coverage{
			LimitsHit:           []string{},
			PerRepository:       []RepositoryCoverage{},
			EntryPointsDetected: options.EntryPointsDetected,
		},
		ParseFailures:   []ParseFailure{},
		ScopeExclusions: []ScopeExclusion{},
	}

	seenRepositories := make(map[string]struct{}, len(repositories))
	limitSet := make(map[string]struct{})
	partial := false

	for _, repository := range repositories {
		if repository.RepositoryID == "" {
			return Result{}, fmt.Errorf("repository ID is required")
		}
		if _, exists := seenRepositories[repository.RepositoryID]; exists {
			return Result{}, fmt.Errorf("duplicate repository ID %q", repository.RepositoryID)
		}
		seenRepositories[repository.RepositoryID] = struct{}{}

		perRepository := RepositoryCoverage{RepositoryID: repository.RepositoryID}
		for _, file := range repository.Result.Files {
			if file.Result.HasError {
				perRepository.FilesParsedWithErrors++
				partial = true
			} else {
				perRepository.FilesParsed++
			}
		}

		for _, skipped := range repository.Result.Skipped {
			if skipped.IsDirectory || skipped.Reason == sourceanalysis.SkipExcludedDirectory {
				result.ScopeExclusions = append(result.ScopeExclusions, ScopeExclusion{
					RepositoryID: repository.RepositoryID,
					Path:         skipped.Path,
					Reason:       skipped.Reason,
				})
				continue
			}
			perRepository.FilesSkipped++
			partial = true
		}

		for _, failed := range repository.Result.Failed {
			if failed.IsDirectory {
				limitSet[LimitRepositoryTraversal] = struct{}{}
				partial = true
				continue
			}
			perRepository.FilesFailed++
			partial = true
			result.ParseFailures = append(result.ParseFailures, ParseFailure{
				RepositoryID: repository.RepositoryID,
				File:         failed.Path,
				Reason:       failed.Reason,
			})
		}

		for _, limit := range repository.Result.LimitsHit {
			if limit == "" {
				return Result{}, fmt.Errorf("repository %q reported an empty limit", repository.RepositoryID)
			}
			limitSet[limit] = struct{}{}
			partial = true
		}

		perRepository.FilesDiscovered = perRepository.FilesParsed +
			perRepository.FilesParsedWithErrors +
			perRepository.FilesFailed +
			perRepository.FilesSkipped

		result.Coverage.FilesDiscovered += perRepository.FilesDiscovered
		result.Coverage.FilesParsed += perRepository.FilesParsed
		result.Coverage.FilesParsedWithErrors += perRepository.FilesParsedWithErrors
		result.Coverage.FilesFailed += perRepository.FilesFailed
		result.Coverage.FilesSkipped += perRepository.FilesSkipped
		result.Coverage.PerRepository = append(result.Coverage.PerRepository, perRepository)
	}

	for index, observation := range observations {
		switch observation.Resolution {
		case ImportResolved:
			result.Coverage.ThirdPartyImportsResolved++
		case ImportTypeOnly:
			result.Coverage.ThirdPartyImportsTypeOnly++
			if len(observation.CallSites) != 0 {
				return Result{}, fmt.Errorf("type-only observation %d contains runtime call sites", index)
			}
		case ImportUnresolved:
			result.Coverage.ThirdPartyImportsUnresolved++
		default:
			return Result{}, fmt.Errorf("observation %d has invalid resolution %q", index, observation.Resolution)
		}

		for callIndex, callSite := range observation.CallSites {
			switch callSite.Resolution {
			case CallResolved:
				result.Coverage.ThirdPartyCallSitesResolved++
			case CallUnresolved:
				result.Coverage.ThirdPartyCallSitesUnresolved++
			default:
				return Result{}, fmt.Errorf("observation %d call site %d has invalid resolution %q", index, callIndex, callSite.Resolution)
			}

			switch callSite.Reachability {
			case Reachable:
				if !options.ReachabilityAnalysed {
					return Result{}, fmt.Errorf("observation %d call site %d is reachable but reachability was not analysed", index, callIndex)
				}
				if callSite.Resolution != CallResolved {
					return Result{}, fmt.Errorf("observation %d call site %d is reachable but unresolved", index, callIndex)
				}
				result.Coverage.CallPathsResolved++
			case ReachUnknown:
				if !options.ReachabilityAnalysed {
					return Result{}, fmt.Errorf("observation %d call site %d has unknown reachability but the pass did not run", index, callIndex)
				}
				result.Coverage.CallPathsUnresolved++
			case NotAnalysed:
			default:
				return Result{}, fmt.Errorf("observation %d call site %d has invalid reachability %q", index, callIndex, callSite.Reachability)
			}
		}
	}

	if result.Coverage.CallPathsResolved > 0 && options.EntryPointsDetected == 0 {
		return Result{}, fmt.Errorf("resolved call paths require at least one entry point")
	}

	for limit := range limitSet {
		result.Coverage.LimitsHit = append(result.Coverage.LimitsHit, limit)
	}
	sort.Strings(result.Coverage.LimitsHit)
	sort.Slice(result.Coverage.PerRepository, func(i, j int) bool {
		return result.Coverage.PerRepository[i].RepositoryID < result.Coverage.PerRepository[j].RepositoryID
	})
	sort.Slice(result.ParseFailures, func(i, j int) bool {
		if result.ParseFailures[i].RepositoryID == result.ParseFailures[j].RepositoryID {
			return result.ParseFailures[i].File < result.ParseFailures[j].File
		}
		return result.ParseFailures[i].RepositoryID < result.ParseFailures[j].RepositoryID
	})
	sort.Slice(result.ScopeExclusions, func(i, j int) bool {
		if result.ScopeExclusions[i].RepositoryID == result.ScopeExclusions[j].RepositoryID {
			return result.ScopeExclusions[i].Path < result.ScopeExclusions[j].Path
		}
		return result.ScopeExclusions[i].RepositoryID < result.ScopeExclusions[j].RepositoryID
	})

	if partial {
		result.Analysis.Status = AnalysisPartial
	}

	return result, nil
}

// Unavailable creates the mandatory zero-valued coverage envelope for a scan
// that failed before usable analysis or targeted an unsupported ecosystem.
// Empty coverage is explicit and cannot be confused with a completed scan.
func Unavailable(status, ecosystem, reasonCode string) (Result, error) {
	if status != AnalysisFailed && status != AnalysisUnsupported {
		return Result{}, fmt.Errorf("unavailable coverage requires failed or unsupported status, got %q", status)
	}
	if ecosystem == "" {
		return Result{}, fmt.Errorf("coverage ecosystem is required")
	}
	if reasonCode == "" {
		return Result{}, fmt.Errorf("unavailable coverage reason code is required")
	}

	analyser := CurrentAnalyser(false)
	analyser.Ecosystems = []string{}
	return Result{
		Analysis: Analysis{
			Status:     status,
			Ecosystem:  ecosystem,
			ReasonCode: reasonCode,
		},
		Analyser: analyser,
		Coverage: Coverage{
			LimitsHit:     []string{},
			PerRepository: []RepositoryCoverage{},
		},
		ParseFailures:   []ParseFailure{},
		ScopeExclusions: []ScopeExclusion{},
	}, nil
}

// ParseCoveragePercent is the clean-file percentage consumed by Component 4.
// A zero denominator reports zero and must not support a negative decision.
func (coverage Coverage) ParseCoveragePercent() float64 {
	if coverage.FilesDiscovered == 0 {
		return 0
	}
	return float64(coverage.FilesParsed) / float64(coverage.FilesDiscovered) * 100
}
