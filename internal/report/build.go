package report

import (
	"fmt"
	"strings"
)

// Section is one of the named groupings a package can be filed under. A Go
// type rather than a bare string so render.go cannot be handed an arbitrary
// label and accidentally produce something other than the exact heading
// S4-13's Done-when criterion requires.
type Section string

const (
	// SectionUpdateFirst holds any package with at least one finding SBOMber
	// says needs acting on now.
	SectionUpdateFirst Section = "Update first"

	// SectionNoDirectUsage is the D1 section, verbatim. Do not reword this
	// string: the Done-when check (S4-13, S5-09) is on this literal text,
	// not its meaning. Every no_usage_detected finding is listed here; it is
	// never removed from the report and the section is never presented as
	// low urgency, informational or safe.
	SectionNoDirectUsage Section = "No direct usage evidence found within the analysed scope"

	// SectionInsufficientInfo is the D1-mandated distinct section: packages
	// where SBOMber's own analysis was incomplete, so nothing about them —
	// positive or negative — could be determined.
	SectionInsufficientInfo Section = "Insufficient information"

	// SectionLowerPriority holds usable findings with no urgent signal.
	// no_usage_detected findings never land here; they are listed under
	// SectionNoDirectUsage.
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

// UngroupedPURL labels the entry holding decisions that no remediation
// group references (for example a decision without a purl). They are
// listed, never dropped.
const UngroupedPURL = "(no package identifier)"

// PackageFinding is one CVE row nested under a PackageGroup: everything the
// grouped report needs to show per finding without going back to
// decision-results.json.
type PackageFinding struct {
	FindingID            string
	VulnerabilityID      string
	State                string
	Band                 string
	Severity             string
	CVSSScore            float64
	EPSSScore            float64
	CISAKev              bool
	Relationship         string
	FixAvailable         bool
	ReportedFixedVersion string
	Justification        string
	// ScanStatus is basedOn.coverageSummary.scanStatus: complete, partial
	// or failed. Usage evidence from a partial or failed analysis is kept
	// and shown with a partial-analysis warning.
	ScanStatus string

	// Untrusted marks a finding this package could not confidently place:
	// either its findingId was absent from decisions.json entirely (a
	// broken join upstream), or its state/band value did not match any
	// value this package recognises. Set so a caller or a future test can
	// tell "genuinely low priority" apart from "we don't actually know",
	// which classifyGroup itself already treats as the latter.
	Untrusted bool
}

// PackageGroup is one package entry in one section: installed version,
// upgrade target, why it sits where it does, and the findings listed in
// this section. A package whose findings belong in two sections (its
// no_usage_detected findings under SectionNoDirectUsage, the rest under
// their own section) has one entry in each, cross-referenced, so every
// finding is listed exactly once and the upgrade still counts all of them.
type PackageGroup struct {
	PURL                 string
	InstalledVersion     string
	ReportedFixedVersion string
	Relationship         string
	Section              Section
	Findings             []PackageFinding

	// TotalFindings is every finding on this package, in any section.
	TotalFindings int
	// ResolvedByUpgrade counts findings on this package that have their
	// own reported fixed version, which the group's ReportedFixedVersion
	// (the highest reported) covers by version number. It is the
	// scanner's report, not verified.
	ResolvedByUpgrade int
	// ListedElsewhere is how many of this package's findings are listed
	// under ElsewhereSection instead of here.
	ListedElsewhere  int
	ElsewhereSection Section
	// Why states, in plain words, what placed this package here. Empty for
	// SectionNoDirectUsage entries, which carry no urgency statement.
	Why string
}

// Report is the full rendered-ready report: one scan's package entries,
// already classified and ordered into sections.
type Report struct {
	ScanID   string
	Sections []SectionGroup
	// Coverage is the usage-graph.json coverage the verdicts rest on, or
	// nil when the report was built without it (which the report says).
	Coverage *Coverage
}

// SectionGroup is one section heading plus the package entries filed under
// it, in update-first order (decision-results.json's remediationGroups
// order, which internal/decision sorts).
type SectionGroup struct {
	Section Section
	Groups  []PackageGroup
}

// BuildReport groups a decision-results.json payload by package using its
// own remediationGroups, then files each package's findings into sections:
//
//   - every no_usage_detected finding with a recognised band goes to
//     SectionNoDirectUsage (D1: findings move there, never removed);
//   - the package's other findings go to the most urgent applicable
//     section (classifyGroup);
//   - a package with findings in both gets one entry in each, each
//     pointing at the other.
//
// Decisions no remediation group references are collected into one
// UngroupedPURL entry and filed by the same rules.
func BuildReport(dr DecisionResults) Report {
	decByID := make(map[string]Decision, len(dr.Decisions))
	for _, d := range dr.Decisions {
		decByID[d.FindingID] = d
	}

	groups := dr.RemediationGroups
	referenced := make(map[string]bool)
	for _, rg := range groups {
		for _, id := range rg.FindingIDs {
			referenced[id] = true
		}
	}
	var ungrouped []string
	for _, d := range dr.Decisions {
		if !referenced[d.FindingID] {
			ungrouped = append(ungrouped, d.FindingID)
		}
	}
	if len(ungrouped) > 0 {
		groups = append(append([]RemediationGroup(nil), groups...), RemediationGroup{
			PURL:       UngroupedPURL,
			FindingIDs: ungrouped,
		})
	}

	bySection := make(map[Section][]PackageGroup, len(sectionOrder))
	for _, rg := range groups {
		for _, pg := range buildEntries(rg, decByID) {
			bySection[pg.Section] = append(bySection[pg.Section], pg)
		}
	}

	// The insufficient-information and no-direct-usage sections are always
	// present, even when empty, so their absence is never mistaken for a
	// missing section; the others appear only when they hold entries.
	sections := make([]SectionGroup, 0, len(sectionOrder))
	for _, s := range sectionOrder {
		gs := bySection[s]
		if len(gs) > 0 || s == SectionInsufficientInfo || s == SectionNoDirectUsage {
			sections = append(sections, SectionGroup{Section: s, Groups: gs})
		}
	}
	return Report{ScanID: dr.ScanID, Sections: sections}
}

// buildEntries turns one remediation group into one or two section entries.
func buildEntries(rg RemediationGroup, decByID map[string]Decision) []PackageGroup {
	all := make([]PackageFinding, 0, len(rg.FindingIDs))
	for _, fid := range rg.FindingIDs {
		d, ok := decByID[fid]
		if !ok {
			// Boundary/untrusted-input case: a remediation group
			// references a finding ID that decisions.json doesn't have.
			// Dropping it would silently understate this package's CVE
			// count; inventing a reassuring state would be worse. Record
			// it as unknown and untrusted — classifyGroup treats that the
			// same as an incomplete analysis, never as "fine".
			all = append(all, PackageFinding{
				FindingID:     fid,
				State:         StateUnknown,
				Band:          BandInsufficientInfo,
				Justification: "referenced by a remediation group but missing from decisions -- treated as unknown, never dropped",
				Untrusted:     true,
			})
			continue
		}
		all = append(all, PackageFinding{
			FindingID:            d.FindingID,
			VulnerabilityID:      d.VulnerabilityID,
			State:                d.State,
			Band:                 d.RiskPriority.Band,
			Severity:             d.RiskPriority.Severity,
			CVSSScore:            d.RiskPriority.CVSSScore,
			EPSSScore:            d.RiskPriority.EPSSScore,
			CISAKev:              d.RiskPriority.CISAKev,
			Relationship:         d.RiskPriority.Relationship,
			FixAvailable:         d.RiskPriority.FixAvailable,
			ReportedFixedVersion: d.Remediation.ReportedFixedVersion,
			Justification:        d.Justification,
			ScanStatus:           d.BasedOn.CoverageSummary.ScanStatus,
		})
	}

	var main, noUsage []PackageFinding
	resolved := 0
	for _, f := range all {
		if f.ReportedFixedVersion != "" {
			resolved++
		}
		if movesToNoDirectUsage(f) {
			noUsage = append(noUsage, f)
		} else {
			main = append(main, f)
		}
	}
	if rg.ReportedFixedVersion == "" {
		resolved = 0
	}

	// A no_usage_detected finding can still be act_now (CISA KEV-listed).
	// It is listed under SectionNoDirectUsage, but the package itself must
	// still appear under "Update first" so the urgency is not lost.
	kevElsewhere := 0
	for _, f := range noUsage {
		if f.Band == BandActNow {
			kevElsewhere++
		}
	}

	base := PackageGroup{
		PURL:                 rg.PURL,
		InstalledVersion:     rg.InstalledVersion,
		ReportedFixedVersion: rg.ReportedFixedVersion,
		Relationship:         rg.Relationship,
		TotalFindings:        len(all),
		ResolvedByUpgrade:    resolved,
	}

	var entries []PackageGroup
	var mainSection Section
	if len(main) > 0 || kevElsewhere > 0 {
		e := base
		e.Findings = main
		e.Section = classifyGroup(PackageGroup{Findings: main})
		if kevElsewhere > 0 {
			e.Section = SectionUpdateFirst
		}
		if len(noUsage) > 0 {
			e.ListedElsewhere = len(noUsage)
			e.ElsewhereSection = SectionNoDirectUsage
		}
		e.Why = whyText(e.Section, main, kevElsewhere)
		mainSection = e.Section
		entries = append(entries, e)
	}
	if len(noUsage) > 0 {
		e := base
		e.Findings = noUsage
		e.Section = SectionNoDirectUsage
		if len(main) > 0 || kevElsewhere > 0 {
			e.ListedElsewhere = len(main)
			e.ElsewhereSection = mainSection
		}
		entries = append(entries, e)
	}
	if len(entries) == 0 {
		// A remediation group with no findings at all: keep it visible.
		e := base
		e.Section = SectionInsufficientInfo
		e.Why = "This package entry references no findings; the input is incomplete."
		entries = append(entries, e)
	}
	return entries
}

// movesToNoDirectUsage reports whether a finding is listed under
// SectionNoDirectUsage: its state is no_usage_detected and its band is one
// this package recognises. An unrecognised band or an untrusted finding is
// never given the no-direct-usage placement; it stays with the package's
// other findings, where classifyGroup files it as insufficient information.
func movesToNoDirectUsage(f PackageFinding) bool {
	if f.Untrusted || f.State != StateNoUsageDetected {
		return false
	}
	switch f.Band {
	case BandActNow, BandLowerPriority, BandInsufficientInfo:
		return true
	default:
		return false
	}
}

// whyText says what placed a package entry in its section. It states the
// signals present; it never characterises absence of evidence.
func whyText(s Section, findings []PackageFinding, kevElsewhere int) string {
	var usage, undetermined int
	var kev bool
	var epss, cvss float64
	for _, f := range findings {
		switch f.State {
		case StateUsageDetected:
			usage++
		case StateNoUsageDetected:
		default:
			undetermined++
		}
		if f.CISAKev {
			kev = true
		}
		if f.EPSSScore > epss {
			epss = f.EPSSScore
		}
		if f.CVSSScore > cvss {
			cvss = f.CVSSScore
		}
	}

	var parts []string
	switch s {
	case SectionUpdateFirst:
		if usage > 0 {
			parts = append(parts, fmt.Sprintf("%s with usage detected in the application", plural(usage, "finding")))
		}
		if kev {
			parts = append(parts, "CISA KEV-listed (known exploited)")
		}
		if kevElsewhere > 0 {
			parts = append(parts, fmt.Sprintf("%s listed under %q CISA KEV-listed (known exploited)", plural(kevElsewhere, "finding"), string(SectionNoDirectUsage)))
		}
	case SectionInsufficientInfo:
		parts = append(parts, fmt.Sprintf("SBOMber could not determine usage for %s", plural(undetermined, "finding")))
	case SectionLowerPriority:
		parts = append(parts, fmt.Sprintf("%s with no urgent signal", plural(len(findings), "finding")))
	}
	if epss > 0 {
		parts = append(parts, fmt.Sprintf("highest EPSS %.4f", epss))
	}
	if cvss > 0 {
		parts = append(parts, fmt.Sprintf("highest CVSS %.1f", cvss))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "; ") + "."
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// classifyGroup decides one package entry's Section from its findings'
// state and risk-priority band. Precedence mirrors sectionOrder: the most
// urgent applicable classification wins when findings disagree.
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
