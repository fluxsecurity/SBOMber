package decision

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// ---- Candidate set (#139) ---------------------------------------------------
//
// The rule agreed in #139 and signed off by Component 4: a name match can
// prove usage; only a CLOSED candidate set can support a negative.
//
// Join keys for one localisation result:
//   - a candidate whose visibility is "public" joins on its own symbol;
//   - an "internal" candidate joins on each name in its exposedVia;
//   - a candidate with no visibility (localisation 1.0.0) or "unknown"
//     visibility joins on its own symbol, positive-only, and leaves the
//     set open;
//   - every key from an advisory_text localisation, or from an exposedVia
//     whose source is advisory_text, is prose-derived: it can prove usage
//     but caps confidence at medium (sign-off condition 3).
//
// The set is closed only when every candidate is public, or internal with
// exposedViaSource "export_resolution" AND exposedViaComplete true
// (sign-off condition 1: a partial caller walk must not close a set).
// advisory_text and llm_suggested localisations never close a set: prose
// can add keys but cannot prove the key set complete, and an LLM answer
// can never support a negative (R4).

// Localisation 1.1.0 candidate vocabulary (#139).
const (
	VisibilityPublic   = "public"
	VisibilityInternal = "internal"

	ExposedViaExportResolution = "export_resolution"
	ExposedViaAdvisoryText     = "advisory_text"
)

// candidateSet is the join-ready view of one localisation result.
type candidateSet struct {
	// keys maps join key -> true when at least one code-derived source
	// supplied it, false when it is prose-derived only.
	keys       map[string]bool
	closed     bool
	openDetail string
}

func buildCandidateSet(r LocalisationResult, found bool, schemaVersion string) candidateSet {
	set := candidateSet{keys: map[string]bool{}}
	method := LocalisationMethod(r.Method)
	if !found || method == LocalisationUnknown {
		set.openDetail = "localisation named no candidate function"
		return set
	}
	if len(r.CandidateSymbols) == 0 {
		set.openDetail = "localisation returned an empty candidate set"
		return set
	}

	proseMethod := method == LocalisationAdvisoryText
	addKey := func(name string, codeDerived bool) {
		if name == "" {
			return
		}
		set.keys[name] = set.keys[name] || codeDerived
	}

	set.closed = true
	var noVisibility, unknownVisibility, internalOpen []string
	for _, c := range r.CandidateSymbols {
		switch c.Visibility {
		case VisibilityPublic:
			addKey(c.Symbol, !proseMethod)
		case VisibilityInternal:
			codeDerived := c.ExposedViaSource == ExposedViaExportResolution && !proseMethod
			for _, name := range c.ExposedVia {
				addKey(name, codeDerived)
			}
			// An empty exposedVia is treated as open even when resolution
			// claims to be complete: "no public route found" is not the
			// same as "the function is never called by the package".
			if !codeDerived || !c.ExposedViaComplete || len(c.ExposedVia) == 0 {
				set.closed = false
				internalOpen = append(internalOpen, c.Symbol)
			}
		case "":
			addKey(c.Symbol, !proseMethod)
			set.closed = false
			noVisibility = append(noVisibility, c.Symbol)
		default: // "unknown" or an unrecognised value from untrusted input
			addKey(c.Symbol, !proseMethod)
			set.closed = false
			unknownVisibility = append(unknownVisibility, c.Symbol)
		}
	}

	var why []string
	if len(noVisibility) > 0 {
		v := schemaVersion
		if v == "" {
			v = "this localisation document"
		} else {
			v = "localisation " + v
		}
		why = append(why, v+" does not record whether "+joinQuoted(dedupe(noVisibility))+" is public or internal")
	}
	if len(unknownVisibility) > 0 {
		why = append(why, "visibility of "+joinQuoted(dedupe(unknownVisibility))+" is unknown")
	}
	if len(internalOpen) > 0 {
		why = append(why, joinQuoted(dedupe(internalOpen))+" has no complete, code-derived list of public entry points")
	}
	if proseMethod {
		set.closed = false
		why = append(why, "candidates came from advisory text, which cannot show the set is complete")
	}
	if method == LocalisationLLMSuggested {
		set.closed = false
		why = append(why, "candidates were LLM-suggested, which can never support a negative")
	}
	set.openDetail = strings.Join(why, "; ")
	return set
}

// ---- Relevance of observations to a finding --------------------------------

// findingScope is what identifies one finding's package in Component 2's
// output.
type findingScope struct {
	purl        string
	packageName string
	occurrences map[string]bool
}

func newFindingScope(f ScanFinding) findingScope {
	s := findingScope{purl: f.PURL, packageName: npmPackageFromPURL(f.PURL), occurrences: map[string]bool{}}
	for _, o := range f.OccurrenceIDs {
		s.occurrences[o] = true
	}
	return s
}

// tied reports whether an observation or unanalysed entry is attributed to
// this finding's package occurrence, by occurrenceId or by PURL.
func (s findingScope) tied(occurrenceID, purl string) bool {
	if occurrenceID != "" && s.occurrences[occurrenceID] {
		return true
	}
	return purl != "" && purl == s.purl
}

// unresolvedImportRelevant decides #119 rules 4 and 5 for an unresolved
// import binding that Component 2 could not tie to a package occurrence.
//
//   - A literal specifier naming this package (e.g. a not_in_inventory or
//     reexport_chain import of "lodash") is relevant.
//   - A literal specifier naming a different package is not (rule 5).
//   - A computed specifier could be anything. usage-graph 1.3.0 reports it
//     per occurrence as unanalysed reason computed_specifier, which the
//     state guard already handles, so on 1.3.0+ it is left to that entry.
//     Older graphs have no such attribution, so it is treated as relevant
//     to every finding: the conservative reading.
//   - A computed specifier whose source text starts with ./ or ../ (e.g.
//     import(`./plugins/${name}`)) loads application code, not a package,
//     and is not relevant to any finding.
func (s findingScope) unresolvedImportRelevant(o UsageObservation, graphSchema string) bool {
	if o.ComputedSpecifier || o.UnresolvedReason == "computed_specifier" {
		if isRelativeExpression(o.ImportedSpecifier) {
			return false
		}
		return !schemaAtLeast(graphSchema, 1, 3)
	}
	name := npmPackageFromSpecifier(o.ImportedSpecifier)
	return name != "" && name == s.packageName
}

// isRelativeExpression reports whether the source text of a computed
// specifier is a string or template literal starting with a relative path.
func isRelativeExpression(src string) bool {
	t := strings.TrimLeft(strings.TrimSpace(src), "`'\"")
	return strings.HasPrefix(t, "./") || strings.HasPrefix(t, "../")
}

// npmPackageFromPURL returns the npm package name from a purl such as
// pkg:npm/lodash@4.17.20 or pkg:npm/%40scope/name@1.0.0.
func npmPackageFromPURL(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:npm/")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i > 0 {
		rest = rest[:i]
	}
	if decoded, err := url.PathUnescape(rest); err == nil {
		rest = decoded
	}
	return rest
}

// npmPackageFromSpecifier returns the package part of an import specifier:
// "lodash/merge" -> "lodash", "@scope/pkg/sub" -> "@scope/pkg". Relative,
// absolute and node: built-in specifiers return "".
func npmPackageFromSpecifier(spec string) string {
	if spec == "" || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "node:") {
		return ""
	}
	parts := strings.Split(spec, "/")
	if strings.HasPrefix(spec, "@") {
		if len(parts) < 2 {
			return ""
		}
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

// schemaAtLeast reports whether a "MAJOR.MINOR.PATCH" version is at least
// major.minor. An unparseable or missing version is treated as older, which
// selects the conservative path.
func schemaAtLeast(v string, major, minor int) bool {
	var ma, mi, pa int
	if _, err := fmt.Sscanf(v, "%d.%d.%d", &ma, &mi, &pa); err != nil {
		return false
	}
	return ma > major || (ma == major && mi >= minor)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func location(file string, line int) string {
	if file == "" {
		return "an unknown location"
	}
	if line > 0 {
		return fmt.Sprintf("%s:%d", file, line)
	}
	return file
}

// ---- Join ------------------------------------------------------------------

// FindingInputs bundles one finding's StateInputs and ConfidenceInputs,
// ready to hand to Decide, plus the evidence the decision rests on so
// decision-results.json can carry it (basedOn).
type FindingInputs struct {
	FindingID  string
	State      StateInputs
	Confidence ConfidenceInputs
	Evidence   Evidence
}

// Evidence is what basedOn in decision-results.json records.
type Evidence struct {
	ObservationIDs           []string
	LocalisationMethod       LocalisationMethod
	LocalisationConfidence   LocalisationConfidence
	MatchedSymbols           []string
	EvidenceLevel            int // 0 = no observation of this package
	ParseCoveragePercent     float64
	UnresolvedImportsInScope int
	ScanStatus               AnalysisStatus
}

// BuildFindingInputs joins a canonical scan, a usage graph, and a
// localisation report into one FindingInputs per scan finding.
//
// Known limitations (documented when discovered, per S4-12):
//
//   - AnalysisStatus and coverage are read once from the top-level
//     usage-graph and applied to every finding. Correct for a single
//     ecosystem (npm); a multi-ecosystem scan will need a per-ecosystem
//     lookup.
//   - HasResolvedUsageEvidence is derived from call-site resolution and
//     the #139 join keys, not from usage-graph's evidenceLevel. The
//     evidenceLevel reported in basedOn is Component 2's own value for
//     this package's observations, not a claim about the vulnerable
//     function.
//   - A call site is joined on calledSymbol only. Component 2 (#135)
//     already emits "default" for a direct call on a whole-module binding
//     and the property name for member access (#119 rule 8), so no
//     importedSymbol fallback is needed.
func BuildFindingInputs(scan CanonicalScan, graph UsageGraph, loc LocalisationReport) []FindingInputs {
	locByFinding := make(map[string]LocalisationResult, len(loc.Results))
	for _, r := range loc.Results {
		locByFinding[r.FindingID] = r
	}

	coverage := 0.0
	if graph.Coverage.FilesDiscovered > 0 {
		coverage = float64(graph.Coverage.FilesParsed) / float64(graph.Coverage.FilesDiscovered) * 100
	}
	status := AnalysisStatus(graph.Analysis.Status)

	out := make([]FindingInputs, 0, len(scan.Findings))
	for _, f := range scan.Findings {
		scope := newFindingScope(f)

		method := LocalisationUnknown
		locConf := LocalisationConfidenceNone
		r, found := locByFinding[f.FindingID]
		if found {
			method = LocalisationMethod(r.Method)
			locConf = LocalisationConfidence(r.Confidence)
		}
		// A finding missing from the localisation report entirely falls back
		// to LocalisationUnknown, which DetermineState treats the same as an
		// explicit unknown.
		set := buildCandidateSet(r, found, loc.SchemaVersion)

		var reasons []UnanalysedReason
		for _, u := range graph.Unanalysed {
			if scope.tied(u.OccurrenceID, u.PURL) {
				reasons = append(reasons, UnanalysedReason(u.Reason))
			}
		}

		var (
			observationIDs     []string
			matched            = map[string]bool{}
			matchedCodeDerived bool
			agree              bool
			level              int
			relevant           []string
			unresolvedImports  int
			unresolvedCalls    int
		)

		for _, obs := range graph.Observations {
			tied := scope.tied(obs.OccurrenceID, obs.PURL)

			if obs.Resolution == "unresolved" {
				if tied || scope.unresolvedImportRelevant(obs, graph.SchemaVersion) {
					unresolvedImports++
					relevant = append(relevant, unresolvedImportText(obs))
					if tied && obs.ObservationID != "" {
						observationIDs = append(observationIDs, obs.ObservationID)
					}
				}
				continue
			}
			if !tied {
				continue
			}
			if obs.ObservationID != "" {
				observationIDs = append(observationIDs, obs.ObservationID)
			}
			if obs.EvidenceLevel > level {
				level = obs.EvidenceLevel
			}
			// type_only imports are erased at compile time: never runtime
			// evidence, positive or otherwise.
			if obs.Resolution != "resolved" {
				continue
			}
			for _, cs := range obs.CallSites {
				if cs.Resolution != "resolved" {
					unresolvedCalls++
					relevant = append(relevant, unresolvedCallText(cs))
					continue
				}
				codeDerived, isKey := set.keys[cs.CalledSymbol]
				if !isKey {
					continue
				}
				matched[cs.CalledSymbol] = true
				if codeDerived {
					matchedCodeDerived = true
				}
				if cs.Reachability != "" && cs.Reachability != "not_analysed" {
					agree = true
				}
			}
		}

		matchedSymbols := make([]string, 0, len(matched))
		for s := range matched {
			matchedSymbols = append(matchedSymbols, s)
		}
		sort.Strings(matchedSymbols)
		sort.Strings(observationIDs)
		sort.Strings(relevant)
		relevant = dedupe(relevant)

		hasUsage := len(matchedSymbols) > 0
		proseOnly := hasUsage && !matchedCodeDerived

		out = append(out, FindingInputs{
			FindingID: f.FindingID,
			State: StateInputs{
				AnalysisStatus:            status,
				LocalisationMethod:        method,
				HasResolvedUsageEvidence:  hasUsage,
				UnanalysedReasons:         reasons,
				MatchedSymbols:            matchedSymbols,
				MatchFromAdvisoryTextOnly: proseOnly,
				FilesDiscovered:           graph.Coverage.FilesDiscovered,
				RelevantUnresolved:        relevant,
				CandidateSetClosed:        set.closed,
				CandidateSetOpenDetail:    set.openDetail,
			},
			Confidence: ConfidenceInputs{
				LocalisationMethod:            method,
				LocalisationConfidence:        locConf,
				ParseCoveragePercent:          coverage,
				UnresolvedImportsForPackage:   unresolvedImports,
				UnresolvedCallSitesForPackage: unresolvedCalls,
				DeterministicMethodsAgree:     agree && !proseOnly,
				MatchFromAdvisoryTextOnly:     proseOnly,
			},
			Evidence: Evidence{
				ObservationIDs:           observationIDs,
				LocalisationMethod:       method,
				LocalisationConfidence:   locConf,
				MatchedSymbols:           matchedSymbols,
				EvidenceLevel:            level,
				ParseCoveragePercent:     clampPercent(coverage),
				UnresolvedImportsInScope: unresolvedImports,
				ScanStatus:               status,
			},
		})
	}
	return out
}

func unresolvedImportText(o UsageObservation) string {
	reason := o.UnresolvedReason
	if reason == "" {
		reason = "no reason given"
	}
	what := "an import"
	if o.ComputedSpecifier || o.UnresolvedReason == "computed_specifier" {
		what = "a dynamic import with a computed module name"
	} else if o.ImportedSpecifier != "" {
		what = "an import of " + o.ImportedSpecifier
	}
	return fmt.Sprintf("%s at %s could not be resolved (%s) and could refer to this package", what, location(o.Location.File, o.Location.Line), reason)
}

func unresolvedCallText(cs CallSite) string {
	reason := cs.UnresolvedReason
	if reason == "" {
		reason = "no reason given"
	}
	return fmt.Sprintf("a call on this package at %s could not be resolved (%s) and could reach a candidate function", location(cs.File, cs.Line), reason)
}
