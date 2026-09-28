package usagegraph

import (
	"fmt"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

type occurrenceKey struct {
	repositoryID string
	packageName  string
}

func buildObservations(
	repositories []RepositoryInput,
	occurrences []OccurrenceInput,
	entryPoints []EntryPoint,
	graph applicationCallGraph,
	reachabilityAnalysed bool,
) ([]Observation, map[string]struct{}, error) {
	occurrenceIndex, err := indexOccurrences(occurrences)
	if err != nil {
		return nil, nil, err
	}

	observations := []Observation{}
	matchedOccurrences := make(map[string]struct{})

	for _, repository := range repositories {
		for _, file := range repository.Result.Files {
			for _, imported := range file.Result.Imports {
				if !isThirdPartyImport(imported) {
					continue
				}

				observation := newObservation(
					repository.RepositoryID,
					file.Path,
					imported,
				)
				packageName, subpath, packageKnown := npmImportParts(
					imported.Specifier,
				)
				observation.Subpath = subpath

				var occurrenceID string
				if imported.Kind == "dynamic_computed" || !packageKnown {
					observation.Resolution = ImportUnresolved
					observation.UnresolvedReason = "computed_specifier"
					observation.ComputedSpecifier = true
				} else {
					candidates := occurrenceIndex[occurrenceKey{
						repositoryID: repository.RepositoryID,
						packageName:  packageName,
					}]
					if len(candidates) == 1 {
						occurrence := candidates[0].Occurrence
						occurrenceID = occurrence.OccurrenceID
						observation.OccurrenceID = occurrenceID
						observation.PURL = occurrence.ComponentPurl
						matchedOccurrences[occurrenceID] = struct{}{}
						if imported.TypeOnly {
							observation.Resolution = ImportTypeOnly
						} else {
							observation.Resolution = ImportResolved
						}
					} else {
						observation.Resolution = ImportUnresolved
						observation.UnresolvedReason = "not_in_inventory"
					}
				}

				if observation.Resolution != ImportTypeOnly {
					observation.CallSites = observationCallSites(
						repository.RepositoryID,
						file.Path,
						file.Result,
						imported,
						observation.Resolution,
						entryPoints,
						graph,
						reachabilityAnalysed,
					)
				}
				observation.EvidenceLevel = evidenceLevel(
					observation.CallSites,
				)
				identity := occurrenceID
				if identity == "" {
					identity = imported.Specifier
				}
				observation.ObservationID = stableID(
					"obs",
					identity,
					repository.RepositoryID,
					file.Path,
					strconv.Itoa(imported.Line),
					imported.Imported,
					imported.Local,
					imported.Kind,
				)
				observations = append(observations, observation)
			}
		}
	}

	sortObservations(observations)
	return observations, matchedOccurrences, nil
}

func indexOccurrences(
	occurrences []OccurrenceInput,
) (map[occurrenceKey][]OccurrenceInput, error) {
	index := make(map[occurrenceKey][]OccurrenceInput)
	seenIDs := make(map[string]struct{})

	for _, input := range occurrences {
		if input.RepositoryID == "" {
			return nil, fmt.Errorf("occurrence repository ID is required")
		}
		occurrence := input.Occurrence
		if occurrence.OccurrenceID == "" || occurrence.ComponentPurl == "" {
			return nil, fmt.Errorf("canonical occurrence identity is required")
		}
		if _, exists := seenIDs[occurrence.OccurrenceID]; exists {
			return nil, fmt.Errorf(
				"duplicate occurrence ID %q",
				occurrence.OccurrenceID,
			)
		}
		seenIDs[occurrence.OccurrenceID] = struct{}{}

		packageName, ok := npmPackageFromPURL(occurrence.ComponentPurl)
		if !ok {
			continue
		}
		if occurrence.Scope == "transitive" ||
			len(occurrence.DependencyPath) != 0 ||
			occurrence.Depth > 0 {
			continue
		}

		key := occurrenceKey{
			repositoryID: input.RepositoryID,
			packageName:  packageName,
		}
		index[key] = append(index[key], input)
	}

	for key := range index {
		sort.Slice(index[key], func(left, right int) bool {
			return index[key][left].Occurrence.OccurrenceID <
				index[key][right].Occurrence.OccurrenceID
		})
	}
	return index, nil
}

func newObservation(
	repositoryID string,
	file string,
	imported sourceanalysis.Import,
) Observation {
	return Observation{
		ImportedSpecifier: imported.Specifier,
		LocalAlias:        imported.Local,
		ImportedSymbol:    imported.Imported,
		ImportKind:        imported.Kind,
		Location: Location{
			RepositoryID: repositoryID,
			File:         file,
			Line:         imported.Line,
			Column:       imported.Column,
		},
		EvidenceLevel: 1,
		CallSites:     []CallSite{},
	}
}

func observationCallSites(
	repositoryID string,
	file string,
	result sourceanalysis.Result,
	imported sourceanalysis.Import,
	importResolution string,
	entryPoints []EntryPoint,
	graph applicationCallGraph,
	reachabilityAnalysed bool,
) []CallSite {
	callSites := []CallSite{}
	for _, call := range result.Calls {
		calledSymbol, resolution, unresolvedReason, matches :=
			thirdPartyCall(imported, call)
		if !matches {
			continue
		}

		callSite := CallSite{
			File:             file,
			Line:             call.Line,
			Column:           call.Column,
			CalledSymbol:     calledSymbol,
			Resolution:       resolution,
			UnresolvedReason: unresolvedReason,
			Reachability:     NotAnalysed,
		}

		owner, hasOwner := sourceanalysis.EnclosingFunction(
			result.Functions,
			call,
		)
		if hasOwner {
			callSite.EnclosingFunction = owner.Name
		}

		if reachabilityAnalysed {
			callSite.Reachability = ReachUnknown
			if importResolution == ImportResolved &&
				resolution == CallResolved && hasOwner {
				target := sourceanalysis.FunctionID{
					RepositoryID: repositoryID,
					File:         file,
					Name:         owner.Name,
					StartLine:    owner.Line,
				}
				entryPoint, callPath, reachable := graph.pathTo(
					entryPoints,
					target,
				)
				if reachable && len(callPath) != 0 {
					callSite.Reachability = Reachable
					callSite.EntryPointID = entryPoint.EntryPointID
					callSite.CallPath = callPath
				}
			}
		}
		callSites = append(callSites, callSite)
	}

	sort.Slice(callSites, func(left, right int) bool {
		a := callSites[left]
		b := callSites[right]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		return a.CalledSymbol < b.CalledSymbol
	})
	return callSites
}

func thirdPartyCall(
	imported sourceanalysis.Import,
	call sourceanalysis.Call,
) (string, string, string, bool) {
	if imported.Local == "" {
		return "", "", "", false
	}
	if call.Receiver != nil && *call.Receiver == imported.Local {
		if call.Callee == nil {
			return "", CallUnresolved, "computed_member_access", true
		}
		return *call.Callee, CallResolved, "", true
	}
	if call.Receiver != nil || call.Callee == nil ||
		*call.Callee != imported.Local {
		return "", "", "", false
	}

	switch imported.Kind {
	case "esm_named", "cjs_destructured":
		if imported.Imported == "" {
			return "", CallUnresolved, "outside_supported_syntax", true
		}
		return imported.Imported, CallResolved, "", true
	case "esm_default", "cjs_require", "dynamic_static_literal":
		_, subpath, _ := npmImportParts(imported.Specifier)
		if subpath != "" {
			return path.Base(subpath), CallResolved, "", true
		}
		return "default", CallResolved, "", true
	default:
		return "", CallUnresolved, "outside_supported_syntax", true
	}
}

func evidenceLevel(callSites []CallSite) int {
	level := 1
	for _, callSite := range callSites {
		if callSite.Resolution == CallResolved && level < 2 {
			level = 2
		}
		if callSite.Reachability == Reachable {
			return 3
		}
	}
	return level
}

func sortObservations(observations []Observation) {
	sort.Slice(observations, func(left, right int) bool {
		a := observations[left]
		b := observations[right]
		if a.Location.RepositoryID != b.Location.RepositoryID {
			return a.Location.RepositoryID < b.Location.RepositoryID
		}
		if a.Location.File != b.Location.File {
			return a.Location.File < b.Location.File
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		if a.Location.Column != b.Location.Column {
			return a.Location.Column < b.Location.Column
		}
		if a.ImportedSpecifier != b.ImportedSpecifier {
			return a.ImportedSpecifier < b.ImportedSpecifier
		}
		if a.ImportedSymbol != b.ImportedSymbol {
			return a.ImportedSymbol < b.ImportedSymbol
		}
		return a.ObservationID < b.ObservationID
	})
}

func isThirdPartyImport(imported sourceanalysis.Import) bool {
	if imported.Kind == "dynamic_computed" {
		return true
	}
	specifier := imported.Specifier
	if specifier == "" || isRelativeSpecifier(specifier) ||
		strings.HasPrefix(specifier, "/") ||
		strings.HasPrefix(specifier, "node:") {
		return false
	}
	return !isNodeBuiltin(specifier)
}

func npmImportParts(specifier string) (string, string, bool) {
	if specifier == "" || isRelativeSpecifier(specifier) ||
		strings.HasPrefix(specifier, "/") {
		return "", "", false
	}
	parts := strings.Split(specifier, "/")
	if strings.HasPrefix(specifier, "@") {
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return "", "", false
		}
		packageName := parts[0] + "/" + parts[1]
		return packageName, strings.Join(parts[2:], "/"), true
	}
	if parts[0] == "" {
		return "", "", false
	}
	return parts[0], strings.Join(parts[1:], "/"), true
}

func npmPackageFromPURL(purl string) (string, bool) {
	const prefix = "pkg:npm/"
	if !strings.HasPrefix(purl, prefix) {
		return "", false
	}
	value := strings.TrimPrefix(purl, prefix)
	if index := strings.IndexAny(value, "?#"); index >= 0 {
		value = value[:index]
	}
	versionAt := strings.LastIndex(value, "@")
	if versionAt <= 0 {
		return "", false
	}
	name, err := url.PathUnescape(value[:versionAt])
	if err != nil || name == "" {
		return "", false
	}
	return name, true
}

func isNodeBuiltin(specifier string) bool {
	packageName, _, ok := npmImportParts(specifier)
	if !ok {
		return false
	}
	_, builtin := nodeBuiltins[packageName]
	return builtin
}

var nodeBuiltins = map[string]struct{}{
	"assert": {}, "async_hooks": {}, "buffer": {}, "child_process": {},
	"cluster": {}, "console": {}, "constants": {}, "crypto": {},
	"dgram": {}, "diagnostics_channel": {}, "dns": {}, "domain": {},
	"events": {}, "fs": {}, "http": {}, "http2": {}, "https": {},
	"module": {}, "net": {}, "os": {}, "path": {}, "perf_hooks": {},
	"process": {}, "punycode": {}, "querystring": {}, "readline": {},
	"repl": {}, "stream": {}, "string_decoder": {}, "sys": {},
	"timers": {}, "tls": {}, "trace_events": {}, "tty": {}, "url": {},
	"util": {}, "v8": {}, "vm": {}, "wasi": {}, "worker_threads": {},
	"zlib": {},
}
