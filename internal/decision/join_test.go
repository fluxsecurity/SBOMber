package decision

import (
	"strings"
	"testing"
)

// These tests drive the real join (BuildFindingInputs / BuildResults) from
// in-memory contract documents, so they exercise the same path a live
// `sbomber decide` run takes. They cover the nine tests #119 requires and
// the four #140 asks for.

const (
	lodashPURL  = "pkg:npm/lodash@4.17.4"
	lodashOcc   = "occ-lodash"
	findingID   = "find-c02"
	graphSchema = "1.3.0"
)

type joinCase struct {
	status          AnalysisStatus
	filesDiscovered int
	method          LocalisationMethod
	locConfidence   LocalisationConfidence
	candidates      []CandidateSymbol
	observations    []UsageObservation
	unanalysed      []UnanalysedOccurrence
	graphSchema     string
	locSchema       string
	kev             bool
}

func baseCase() joinCase {
	return joinCase{
		status:          AnalysisComplete,
		filesDiscovered: 40,
		method:          LocalisationPatchReference,
		locConfidence:   LocalisationConfidenceHigh,
		graphSchema:     graphSchema,
		locSchema:       "1.1.0",
	}
}

func (c joinCase) docs() (CanonicalScan, UsageGraph, LocalisationReport) {
	kev := c.kev
	scan := CanonicalScan{
		Scan:        ScanMeta{ScanID: "scan-test"},
		Occurrences: []ScanOccurrence{{OccurrenceID: lodashOcc, PURL: lodashPURL, Relationship: "direct"}},
		Findings: []ScanFinding{{
			FindingID:       findingID,
			VulnerabilityID: "CVE-2018-16487",
			PURL:            lodashPURL,
			OccurrenceIDs:   []string{lodashOcc},
			Severity:        "high",
			FixedVersion:    "4.17.11",
			CISAKev:         &kev,
		}},
	}
	graph := UsageGraph{
		SchemaVersion: c.graphSchema,
		Analysis:      UsageAnalysis{Status: string(c.status)},
		Coverage:      UsageCoverage{FilesDiscovered: c.filesDiscovered, FilesParsed: c.filesDiscovered},
		Observations:  c.observations,
		Unanalysed:    c.unanalysed,
	}
	loc := LocalisationReport{
		SchemaVersion: c.locSchema,
		Results: []LocalisationResult{{
			FindingID:        findingID,
			PURL:             lodashPURL,
			Method:           string(c.method),
			Confidence:       string(c.locConfidence),
			CandidateSymbols: c.candidates,
		}},
	}
	return scan, graph, loc
}

func (c joinCase) decide(t *testing.T) (FindingInputs, Decision, ResultDecision) {
	t.Helper()
	scan, graph, loc := c.docs()
	inputs := BuildFindingInputs(scan, graph, loc)
	if len(inputs) != 1 {
		t.Fatalf("got %d inputs, want 1", len(inputs))
	}
	in := inputs[0]
	dec := Decide(in.FindingID, in.State, in.Confidence)
	res, err := BuildResults(scan, graph, loc)
	if err != nil {
		t.Fatalf("BuildResults: %v", err)
	}
	return in, dec, res.Decisions[0]
}

// lodashCall is a resolved lodash observation whose call sites call the
// given symbols, e.g. _.merge(...) -> calledSymbol "merge".
func lodashCall(symbols ...string) UsageObservation {
	o := UsageObservation{
		ObservationID: "obs-lodash", OccurrenceID: lodashOcc, PURL: lodashPURL,
		ImportedSpecifier: "lodash", ImportKind: "cjs_require", Resolution: "resolved",
		Location: UsageLocation{File: "src/app.js", Line: 1}, EvidenceLevel: 2,
	}
	for i, s := range symbols {
		o.CallSites = append(o.CallSites, CallSite{
			File: "src/app.js", Line: 10 + i, CalledSymbol: s, Resolution: "resolved", Reachability: "reachable",
		})
	}
	return o
}

// publicCandidate is a localisation 1.1.0 public candidate.
func publicCandidate(sym string) CandidateSymbol {
	return CandidateSymbol{Symbol: sym, Visibility: VisibilityPublic}
}

// c02 helper: lodash's private safeGet, as localisation 1.0.0 reports it.
func safeGetV100() CandidateSymbol {
	return CandidateSymbol{Symbol: "safeGet", ModulePath: "lodash.js"}
}

func wantState(t *testing.T, got Decision, want State) {
	t.Helper()
	if got.State != want {
		t.Fatalf("state = %q, want %q\njustification: %s", got.State, want, got.Justification)
	}
}

// ---- #119 required tests ----------------------------------------------------

// 1. Complete negative: every guard satisfied, closed set, the app calls
// lodash but never a join key. The only legal negative, and it must be
// written with the agreed display text and pass validate.py's guards.
func TestJoin119_CompleteNegative(t *testing.T) {
	c := baseCase()
	c.candidates = []CandidateSymbol{publicCandidate("template")}
	c.observations = []UsageObservation{lodashCall("get")}

	_, dec, rd := c.decide(t)
	wantState(t, dec, StateNoUsageDetected)

	if !strings.HasPrefix(dec.Justification, "No usage evidence found within the analysed scope") {
		t.Errorf("justification must open with the R3 display text, got %q", dec.Justification)
	}
	if StateNoUsageDetected.Display() != "no usage evidence found within the analysed scope" {
		t.Errorf("Display() = %q", StateNoUsageDetected.Display())
	}
	if rd.BasedOn.CoverageSummary.ScanStatus != "complete" || rd.BasedOn.CoverageSummary.UnresolvedImportsInScope != 0 {
		t.Errorf("validate.py negative guards not met: %+v", rd.BasedOn.CoverageSummary)
	}
	if rd.VEXMapping == nil || rd.VEXMapping.Statement != VEXUnderInvestigation {
		t.Errorf("no_usage_detected must map to under_investigation, got %+v", rd.VEXMapping)
	}
	if rd.RiskPriority.Band != BandLowerPriority {
		t.Errorf("band = %q, want lower_priority", rd.RiskPriority.Band)
	}
}

// 2. Partial positive: a resolved match on a partial scan is real evidence
// (#119 rule 1), and the justification warns that the scan was partial.
func TestJoin119_PartialPositive(t *testing.T) {
	c := baseCase()
	c.status = AnalysisPartial
	c.candidates = []CandidateSymbol{publicCandidate("template")}
	c.observations = []UsageObservation{lodashCall("template")}

	_, dec, rd := c.decide(t)
	wantState(t, dec, StateUsageDetected)
	if !strings.Contains(dec.Justification, "partial") {
		t.Errorf("partial-scan warning missing: %q", dec.Justification)
	}
	if rd.BasedOn.CoverageSummary.ScanStatus != "partial" {
		t.Errorf("scanStatus = %q, want partial", rd.BasedOn.CoverageSummary.ScanStatus)
	}
}

// 3. Partial without evidence: never a negative, even with a closed set
// (#119 rule 2).
func TestJoin119_PartialWithoutEvidence(t *testing.T) {
	for _, status := range []AnalysisStatus{AnalysisPartial, AnalysisFailed} {
		c := baseCase()
		c.status = status
		c.candidates = []CandidateSymbol{publicCandidate("template")}
		c.observations = []UsageObservation{lodashCall("get")}

		_, dec, _ := c.decide(t)
		wantState(t, dec, StateUnknown)
		if !strings.Contains(dec.Justification, string(status)) {
			t.Errorf("%s: justification does not name the status: %q", status, dec.Justification)
		}
	}
}

// 4. Relevant unresolved observation: an unresolved call on this package,
// or an unresolved import naming this package, blocks the negative
// (#119 rule 4).
func TestJoin119_RelevantUnresolvedObservation(t *testing.T) {
	t.Run("computed member access on lodash", func(t *testing.T) {
		c := baseCase()
		c.candidates = []CandidateSymbol{publicCandidate("template")}
		obs := lodashCall("get")
		obs.CallSites = append(obs.CallSites, CallSite{
			File: "src/app.js", Line: 30, Resolution: "unresolved",
			UnresolvedReason: "computed_member_access", Reachability: "not_analysed",
		})
		c.observations = []UsageObservation{obs}

		in, dec, _ := c.decide(t)
		wantState(t, dec, StateUnknown)
		if in.Confidence.UnresolvedCallSitesForPackage != 1 {
			t.Errorf("unresolved call count = %d, want 1", in.Confidence.UnresolvedCallSitesForPackage)
		}
		if !strings.Contains(dec.Justification, "src/app.js:30") {
			t.Errorf("justification should locate the unresolved call: %q", dec.Justification)
		}
	})

	t.Run("unresolved import naming lodash", func(t *testing.T) {
		c := baseCase()
		c.candidates = []CandidateSymbol{publicCandidate("template")}
		c.observations = []UsageObservation{lodashCall("get"), {
			ObservationID: "obs-re", ImportedSpecifier: "lodash/fp", ImportKind: "esm_named",
			Resolution: "unresolved", UnresolvedReason: "reexport_chain",
			Location: UsageLocation{File: "src/re.js", Line: 2},
		}}

		_, dec, rd := c.decide(t)
		wantState(t, dec, StateUnknown)
		if rd.BasedOn.CoverageSummary.UnresolvedImportsInScope != 1 {
			t.Errorf("unresolvedImportsInScope = %d, want 1", rd.BasedOn.CoverageSummary.UnresolvedImportsInScope)
		}
	})
}

// 5. Unrelated unresolved observation: an unresolved import of another
// package, an unresolved call on another package, and a relative computed
// import do not make this finding unknown (#119 rule 5).
func TestJoin119_UnrelatedUnresolvedObservation(t *testing.T) {
	c := baseCase()
	c.candidates = []CandidateSymbol{publicCandidate("template")}
	c.observations = []UsageObservation{
		lodashCall("get"),
		{
			ObservationID: "obs-leftpad", ImportedSpecifier: "left-pad", ImportKind: "cjs_require",
			Resolution: "unresolved", UnresolvedReason: "not_in_inventory",
			Location: UsageLocation{File: "src/pad.js", Line: 1},
		},
		{
			ObservationID: "obs-axios", OccurrenceID: "occ-axios", PURL: "pkg:npm/axios@0.21.0",
			ImportedSpecifier: "axios", ImportKind: "cjs_require", Resolution: "resolved",
			Location: UsageLocation{File: "src/api.js", Line: 1}, EvidenceLevel: 1,
			CallSites: []CallSite{{File: "src/api.js", Line: 9, Resolution: "unresolved", UnresolvedReason: "computed_member_access", Reachability: "not_analysed"}},
		},
		{
			ObservationID: "obs-plugins", ImportedSpecifier: "`./plugins/${name}`", ComputedSpecifier: true,
			ImportKind: "dynamic_computed", Resolution: "unresolved", UnresolvedReason: "computed_specifier",
			Location: UsageLocation{File: "src/load.js", Line: 4},
		},
	}
	c.graphSchema = "1.2.0" // even on a pre-1.3.0 graph the relative import is not a package

	in, dec, _ := c.decide(t)
	wantState(t, dec, StateNoUsageDetected)
	if len(in.State.RelevantUnresolved) != 0 {
		t.Errorf("unrelated observations leaked into this finding: %v", in.State.RelevantUnresolved)
	}
}

// 6. Zero source files: a complete analysis of nothing is not evidence
// (#119 rule 3; validate.py "negative needs discovered source").
func TestJoin119_ZeroSourceFiles(t *testing.T) {
	c := baseCase()
	c.filesDiscovered = 0
	c.candidates = []CandidateSymbol{publicCandidate("template")}

	_, dec, _ := c.decide(t)
	wantState(t, dec, StateUnknown)
	if !strings.Contains(dec.Justification, "no application source files") {
		t.Errorf("justification should say no source was found: %q", dec.Justification)
	}
}

// 7. Private-helper mismatch: localisation names an internal helper the
// application cannot call by name. Symbol mismatch alone must not produce
// no_usage_detected (#119 rule 6), with or without the 1.1.0 fields.
func TestJoin119_PrivateHelperMismatch(t *testing.T) {
	t.Run("1.1.0 internal, no exposedVia", func(t *testing.T) {
		c := baseCase()
		c.candidates = []CandidateSymbol{{Symbol: "safeGet", Visibility: VisibilityInternal}}
		c.observations = []UsageObservation{lodashCall("merge")}
		_, dec, _ := c.decide(t)
		wantState(t, dec, StateUnknown)
		if !strings.Contains(strings.ToLower(dec.Justification), OpenSetCriterion) {
			t.Errorf("missing #139 criterion: %q", dec.Justification)
		}
	})

	t.Run("partial caller walk does not close the set", func(t *testing.T) {
		c := baseCase()
		c.candidates = []CandidateSymbol{{
			Symbol: "safeGet", Visibility: VisibilityInternal,
			ExposedVia: []string{"mergeWith"}, ExposedViaSource: ExposedViaExportResolution,
			ExposedViaComplete: false,
		}}
		c.observations = []UsageObservation{lodashCall("merge")}
		_, dec, _ := c.decide(t)
		wantState(t, dec, StateUnknown)
	})
}

// 8. Aliases: a candidate set is matched on any member, not only the first
// (#119 rule 7), including every name in exposedVia.
func TestJoin119_Aliases(t *testing.T) {
	t.Run("second public alias", func(t *testing.T) {
		c := baseCase()
		c.candidates = []CandidateSymbol{publicCandidate("decode"), publicCandidate("parse")}
		c.observations = []UsageObservation{lodashCall("parse")}
		in, dec, _ := c.decide(t)
		wantState(t, dec, StateUsageDetected)
		if got := strings.Join(in.State.MatchedSymbols, ","); got != "parse" {
			t.Errorf("matched = %q, want parse", got)
		}
	})

	t.Run("last exposedVia name", func(t *testing.T) {
		c := baseCase()
		c.candidates = []CandidateSymbol{{
			Symbol: "safeGet", Visibility: VisibilityInternal,
			ExposedVia: []string{"merge", "mergeWith", "defaultsDeep"}, ExposedViaSource: ExposedViaExportResolution,
			ExposedViaComplete: true,
		}}
		c.observations = []UsageObservation{lodashCall("defaultsDeep")}
		_, dec, _ := c.decide(t)
		wantState(t, dec, StateUsageDetected)
	})
}

// 9. Whole-module default calls: minimist(argv) is a direct call on a
// whole-module binding and joins on calledSymbol "default"; member access
// joins on the property name (#119 rule 8).
func TestJoin119_WholeModuleDefaultCall(t *testing.T) {
	t.Run("direct call joins on default", func(t *testing.T) {
		c := baseCase()
		c.candidates = []CandidateSymbol{publicCandidate("default")}
		c.observations = []UsageObservation{lodashCall("default")}
		_, dec, _ := c.decide(t)
		wantState(t, dec, StateUsageDetected)
	})

	t.Run("member access does not join on default", func(t *testing.T) {
		c := baseCase()
		c.candidates = []CandidateSymbol{publicCandidate("default")}
		c.observations = []UsageObservation{lodashCall("parse")}
		_, dec, _ := c.decide(t)
		wantState(t, dec, StateNoUsageDetected)
	})
}

// ---- #140 tests -------------------------------------------------------------

// c02 as it really arrives today: localisation 1.0.0 names only the private
// safeGet, the application calls _.merge, the analysis is complete. Before
// S5-08 this was no_usage_detected: a false negative on a real CVE.
func TestJoin140_C02PrivateHelperIsUnknown(t *testing.T) {
	c := baseCase()
	c.locSchema = "1.0.0"
	c.candidates = []CandidateSymbol{safeGetV100()}
	c.observations = []UsageObservation{lodashCall("merge")}

	in, dec, rd := c.decide(t)
	wantState(t, dec, StateUnknown)
	if in.State.CandidateSetClosed {
		t.Error("a 1.0.0 candidate set must never be closed")
	}
	if !strings.Contains(strings.ToLower(dec.Justification), OpenSetCriterion) {
		t.Errorf("missing #139 criterion: %q", dec.Justification)
	}
	if rd.RiskPriority.Band != BandInsufficientInformation {
		t.Errorf("band = %q, want insufficient_information", rd.RiskPriority.Band)
	}
}

// The same case once Component 3 ships 1.1.0 with code-derived exposedVia.
func TestJoin140_C02ExposedViaMergeIsUsage(t *testing.T) {
	c := baseCase()
	c.candidates = []CandidateSymbol{{
		Symbol: "safeGet", Visibility: VisibilityInternal,
		ExposedVia: []string{"merge"}, ExposedViaSource: ExposedViaExportResolution, ExposedViaComplete: true,
	}}
	c.observations = []UsageObservation{lodashCall("merge")}

	_, dec, rd := c.decide(t)
	wantState(t, dec, StateUsageDetected)
	if dec.Confidence != ConfidenceHigh {
		t.Errorf("code-derived match should be able to reach high, got %q %v", dec.Confidence, dec.Criteria)
	}
	if rd.VEXMapping == nil || rd.VEXMapping.Statement != VEXAffected || rd.VEXMapping.ActionStatement == "" {
		t.Errorf("vexMapping = %+v, want affected with action", rd.VEXMapping)
	}
}

// A prose-only match proves usage but never rates above medium, and the
// justification says the name came from advisory text (sign-off condition 3).
func TestJoin140_ProseOnlyMatchCapsAtMedium(t *testing.T) {
	cases := map[string][]CandidateSymbol{
		"exposedVia from advisory text": {{
			Symbol: "safeGet", Visibility: VisibilityInternal,
			ExposedVia: []string{"merge"}, ExposedViaSource: ExposedViaAdvisoryText, ExposedViaComplete: true,
		}},
		"1.0.0 advisory_text method": {{Symbol: "merge"}},
	}
	for name, cands := range cases {
		t.Run(name, func(t *testing.T) {
			c := baseCase()
			if name == "1.0.0 advisory_text method" {
				c.method = LocalisationAdvisoryText
				c.locSchema = "1.0.0"
			}
			c.candidates = cands
			c.observations = []UsageObservation{lodashCall("merge")}

			_, dec, _ := c.decide(t)
			wantState(t, dec, StateUsageDetected)
			if dec.Confidence == ConfidenceHigh {
				t.Errorf("prose-only match rated high: %v", dec.Criteria)
			}
			if !strings.Contains(strings.Join(dec.Criteria, "|"), "advisory text") {
				t.Errorf("criteria do not say the match came from advisory text: %v", dec.Criteria)
			}
			if !strings.Contains(dec.Justification, "advisory text") {
				t.Errorf("justification does not say the match came from advisory text: %q", dec.Justification)
			}
		})
	}
}

// Closed set, no match, all other guards satisfied -> no_usage_detected.
// A prose-derived key can never close the set, so the same case with
// advisory-text exposedVia stays unknown.
func TestJoin140_ClosedSetNegative(t *testing.T) {
	c := baseCase()
	c.candidates = []CandidateSymbol{{
		Symbol: "safeGet", Visibility: VisibilityInternal,
		ExposedVia: []string{"merge", "mergeWith"}, ExposedViaSource: ExposedViaExportResolution, ExposedViaComplete: true,
	}}
	c.observations = []UsageObservation{lodashCall("get", "pick")}
	_, dec, _ := c.decide(t)
	wantState(t, dec, StateNoUsageDetected)

	c.candidates[0].ExposedViaSource = ExposedViaAdvisoryText
	_, dec, _ = c.decide(t)
	wantState(t, dec, StateUnknown)
}

// ---- Further boundaries -----------------------------------------------------

// On usage-graph 1.2.0 a non-relative computed import could load any
// package, so it blocks the negative. On 1.3.0 Component 2 attributes it
// per occurrence via unanalysedOccurrences instead.
func TestJoin_ComputedSpecifierBySchemaVersion(t *testing.T) {
	computed := UsageObservation{
		ObservationID: "obs-dyn", ImportedSpecifier: "name", ComputedSpecifier: true,
		ImportKind: "dynamic_computed", Resolution: "unresolved", UnresolvedReason: "computed_specifier",
		Location: UsageLocation{File: "src/dyn.js", Line: 3},
	}

	c := baseCase()
	c.candidates = []CandidateSymbol{publicCandidate("template")}
	c.observations = []UsageObservation{lodashCall("get"), computed}

	c.graphSchema = "1.2.0"
	_, dec, _ := c.decide(t)
	wantState(t, dec, StateUnknown)

	c.graphSchema = "1.3.0"
	_, dec, _ = c.decide(t)
	wantState(t, dec, StateNoUsageDetected)

	c.unanalysed = []UnanalysedOccurrence{{OccurrenceID: lodashOcc, Reason: string(ReasonComputedSpecifier)}}
	_, dec, _ = c.decide(t)
	wantState(t, dec, StateUnknown)
}

// A type-only import is erased at compile time and is never evidence.
func TestJoin_TypeOnlyImportIsNotEvidence(t *testing.T) {
	c := baseCase()
	c.candidates = []CandidateSymbol{publicCandidate("template")}
	obs := lodashCall("template")
	obs.Resolution = "type_only"
	c.observations = []UsageObservation{obs}
	_, dec, _ := c.decide(t)
	if dec.State == StateUsageDetected {
		t.Fatal("type-only import produced usage_detected")
	}
}

// A KEV-listed vulnerability stays act_now even with no usage evidence.
func TestJoin_KEVNegativeStaysActNow(t *testing.T) {
	c := baseCase()
	c.kev = true
	c.candidates = []CandidateSymbol{publicCandidate("template")}
	c.observations = []UsageObservation{lodashCall("get")}
	_, dec, rd := c.decide(t)
	wantState(t, dec, StateNoUsageDetected)
	if rd.RiskPriority.Band != BandActNow {
		t.Errorf("band = %q, want act_now for KEV", rd.RiskPriority.Band)
	}
}

// Every decision carries all five #119 fields.
func TestJoin_EveryDecisionCarriesAllFive(t *testing.T) {
	scan, err := LoadCanonicalScan(fixtureCanonicalScan)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := LoadUsageGraph(fixtureUsageGraph)
	if err != nil {
		t.Fatal(err)
	}
	loc, err := LoadLocalisationReport(fixtureLocalisation)
	if err != nil {
		t.Fatal(err)
	}
	res, err := BuildResults(scan, graph, loc)
	if err != nil {
		t.Fatal(err)
	}
	if res.ScanID == "" || res.SchemaVersion != ResultsSchemaVersion {
		t.Fatalf("header: %q %q", res.ScanID, res.SchemaVersion)
	}
	for _, d := range res.Decisions {
		if d.State == "" || d.AnalysisConfidence == "" || d.RiskPriority.Band == "" || d.Justification == "" {
			t.Errorf("%s: missing a required field: %+v", d.FindingID, d)
		}
		if d.BasedOn.CoverageSummary.ScanStatus == "" {
			t.Errorf("%s: coverage summary has no scan status", d.FindingID)
		}
		if len(d.ConfidenceCriteria) == 0 {
			t.Errorf("%s: confidence shown without criteria", d.FindingID)
		}
	}
}

func TestNpmPackageNames(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:npm/lodash@4.17.20":        "lodash",
		"pkg:npm/%40babel/core@7.0.0":   "@babel/core",
		"pkg:npm/@babel/core@7.0.0?x=1": "@babel/core",
		"pkg:pypi/requests@2.0.0":       "",
	} {
		if got := npmPackageFromPURL(in); got != want {
			t.Errorf("npmPackageFromPURL(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"lodash/merge":   "lodash",
		"@scope/pkg/sub": "@scope/pkg",
		"./local":        "",
		"node:fs":        "",
		"@broken":        "",
	} {
		if got := npmPackageFromSpecifier(in); got != want {
			t.Errorf("npmPackageFromSpecifier(%q) = %q, want %q", in, got, want)
		}
	}
}
