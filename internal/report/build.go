package report

// Section is one of the named groupings a package can be filed under. A Go
// type rather than a bare string so render.go cannot be handed an arbitrary
// label and accidentally produce something other than the exact heading
// S4-13's Done-when criterion requires.
type Section string

const (
	// SectionUpdateFirst holds any package with at least one finding SBOMber
	// says needs acting on now.
	SectionUpdateFirst Section = "Update first"

	// SectionNoDirectUsage is S4-13's D1 acceptance criterion, verbatim:
	// "Wireframe includes the section named exactly 'No direct usage
	// evidence found within the analysed scope' (D1), distinct from the
	// insufficient-information section." Do not reword this string —
	// the Done-when check is on this literal text, not its meaning.
	SectionNoDirectUsage Section = "No direct usage evidence found within the analysed scope"

	// SectionInsufficientInfo is the D1-mandated distinct section: packages
	// where SBOMber's own analysis was incomplete, so nothing about them —
	// positive or negative — could be determined.
	SectionInsufficientInfo Section = "Insufficient information"

	// SectionLowerPriority holds packages with usable findings that are
	// simply not urgent (e.g. no_usage_detected only for genuinely
	// non-urgent CVEs is not distinguished further at this wireframe stage —
	// note that no_usage_detected findings are always filed under
	// SectionNoDirectUsage instead, per allNoUsage below).
	SectionLowerPriority Section = "Lower priority"
)

// sectionOrder fixes both the render order and classifyGroup's
// classification precedence. When a package's findings disagree (one
// finding says act now, another says unknown), the package is filed under
// the section EARLIEST in this list — the most urgent applicable
// classification wins, because "which package do I update first" only has
// one right answer per package, and silence about a second, worse finding
// on the same package is not acceptable.
var sectionOrder = []Section{
	SectionUpdateFirst,
	SectionInsufficientInfo,
	SectionNoDirectUsage,
	SectionLowerPriority,
}

// PackageFinding is one CVE row nested under a PackageGroup: everything the
// grouped report needs to show per finding without going back to
// decision-results.json.
type PackageFinding struct {
	FindingID       string
	VulnerabilityID string
	State           string
	Band            string
	Severity        string
	CVSSScore       float64
	EPSSScore       float64
	CISAKev         bool
	Relationship    string
	FixAvailable    bool
	Justification   string

	// Untrusted marks a finding this package could not confidently place:
	// either its findingId was absent from decisions.json entirely (a
	// broken join upstream), or its state/band value did not match any
	// value this package recognises. Set so a caller or a future test can
	// tell "genuinely low priority" apart from "we don't actually know",
	// which classifyGroup itself already treats as the latter.
	Untrusted bool
}

// PackageGroup is one package's remediation entry: installed version,
// upgrade target, and every nested CVE against it — grouped by package and
// installed version per S4-13's explicit acceptance criterion ("not a flat
// CVE list").
type PackageGroup struct {
	PURL                 string
	InstalledVersion     string
	ReportedFixedVersion string
	Relationship         string
	Section              Section
	Findings             []PackageFinding
}

// Report is the full rendered-ready wireframe: one scan's package groups,
// already classified and ordered into sections.
type Report struct {
	ScanID   string
	Sections []SectionGroup
}

// SectionGroup is one section heading plus the package groups filed under
// it, in the order BuildReport encountered their remediation groups.
type SectionGroup struct {
	Section Section
	Groups  []PackageGroup
}

// BuildReport groups a decision-results.json payload by package using its
// own remediationGroups (S4-13 does not re-derive package grouping from
// decisions — the schema already groups by package and installed version,
// which is the acceptance criterion), then classifies each package group
// into exactly one Section.
func BuildReport(dr DecisionResults) Report {
	decByID := make(map[string]Decision, len(dr.Decisions))
	for _, d := range dr.Decisions {
		decByID[d.FindingID] = d
	}

	groups := make([]PackageGroup, 0, len(dr.RemediationGroups))
	for _, rg := range dr.RemediationGroups {
		pg := PackageGroup{
			PURL:                 rg.PURL,
			InstalledVersion:     rg.InstalledVersion,
			ReportedFixedVersion: rg.ReportedFixedVersion,
			Relationship:         rg.Relationship,
		}
		for _, fid := range rg.FindingIDs {
			d, ok := decByID[fid]
			if !ok {
				// Boundary/untrusted-input case: a remediation group
				// references a finding ID that decisions.json doesn't
				// have. Dropping it would silently understate this
				// package's CVE count; inventing a reassuring state
				// would be worse. Record it as unknown and untrusted —
				// classifyGroup treats that the same as an incomplete
				// analysis, never as "fine".
				pg.Findings = append(pg.Findings, PackageFinding{
					FindingID:     fid,
					State:         StateUnknown,
					Band:          BandInsufficientInfo,
					Justification: "referenced by a remediation group but missing from decisions -- treated as unknown, never dropped",
					Untrusted:     true,
				})
				continue
			}
			pg.Findings = append(pg.Findings, PackageFinding{
				FindingID:       d.FindingID,
				VulnerabilityID: d.VulnerabilityID,
				State:           d.State,
				Band:            d.RiskPriority.Band,
				Severity:        d.RiskPriority.Severity,
				CVSSScore:       d.RiskPriority.CVSSScore,
				EPSSScore:       d.RiskPriority.EPSSScore,
				CISAKev:         d.RiskPriority.CISAKev,
				Relationship:    d.RiskPriority.Relationship,
				FixAvailable:    d.RiskPriority.FixAvailable,
				Justification:   d.Justification,
			})
		}
		pg.Section = classifyGroup(pg)
		groups = append(groups, pg)
	}

	bySection := make(map[Section][]PackageGroup, len(sectionOrder))
	for _, g := range groups {
		bySection[g.Section] = append(bySection[g.Section], g)
	}

	sections := make([]SectionGroup, 0, len(sectionOrder))
	for _, s := range sectionOrder {
		if gs, ok := bySection[s]; ok && len(gs) > 0 {
			sections = append(sections, SectionGroup{Section: s, Groups: gs})
		}
	}

	return Report{ScanID: dr.ScanID, Sections: sections}
}

// classifyGroup decides one package group's Section from its nested
// findings' state and risk-priority band. Precedence mirrors sectionOrder:
// the most urgent applicable classification wins when findings disagree.
//
// Untrusted input handling follows the same discipline as
// internal/decision's UnanalysedReason.blocksNegativeVerdict: an
// unrecognised band or state value is NEVER treated as reassuring
// (lower_priority or no-direct-usage). It is folded into
// SectionInsufficientInfo, the same place a genuinely incomplete analysis
// goes, because "we don't know what this value means" and "the analysis
// didn't finish" both forbid a confident answer.
func classifyGroup(pg PackageGroup) Section {
	anyActNow := false
	anyInsufficient := false
	anyUntrusted := false
	allNoUsage := len(pg.Findings) > 0

	for _, f := range pg.Findings {
		switch f.Band {
		case BandActNow:
			anyActNow = true
		case BandInsufficientInfo:
			anyInsufficient = true
		case BandLowerPriority:
			// recognised, non-urgent -- no flag set
		default:
			// Empty string (band omitted) or any unrecognised value.
			// Boundary case exercised by
			// TestBuildReport_UntrustedBandValue.
			anyUntrusted = true
		}

		switch f.State {
		case StateNoUsageDetected:
			// contributes to allNoUsage; no other flag
		case StateUsageDetected, StateUnknown, StateUnsupported:
			allNoUsage = false
		default:
			// Unrecognised state value: never let it pass as the
			// reassuring "no usage" case.
			allNoUsage = false
			anyUntrusted = true
		}

		if f.Untrusted {
			anyUntrusted = true
		}
	}

	switch {
	case anyActNow:
		return SectionUpdateFirst
	case anyInsufficient || anyUntrusted:
		return SectionInsufficientInfo
	case allNoUsage:
		return SectionNoDirectUsage
	default:
		return SectionLowerPriority
	}
}
