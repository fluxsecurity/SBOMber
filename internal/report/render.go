package report

import (
	"fmt"
	"strings"
)

// noDirectUsageNote is printed under the D1 heading in every format. It
// says what the section means and, deliberately, nothing about urgency or
// exploitability: the section is never presented as low urgency,
// informational or safe.
const noDirectUsageNote = "These findings had no direct usage evidence within the analysed scope. They are listed here, not removed. This records what the analysis found, not whether the vulnerability can be exploited."

// RenderText renders a Report as plain text for a terminal.
func RenderText(r Report) string {
	var b strings.Builder

	fmt.Fprintf(&b, "SBOMber Remediation Report — %s\n", r.ScanID)

	if len(r.Sections) == 0 {
		b.WriteString("\nNo findings to report.\n")
		return b.String()
	}

	for _, sg := range r.Sections {
		fmt.Fprintf(&b, "\n== %s ==\n", sg.Section)
		if sg.Section == SectionNoDirectUsage {
			fmt.Fprintf(&b, "%s\n", noDirectUsageNote)
		}
		for _, pg := range sg.Groups {
			renderPackageGroup(&b, pg)
		}
	}

	return b.String()
}

func renderPackageGroup(b *strings.Builder, pg PackageGroup) {
	b.WriteString("\n")
	fmt.Fprintf(b, "%s", pg.PURL)
	if pg.InstalledVersion != "" {
		fmt.Fprintf(b, " (installed %s)", pg.InstalledVersion)
	}
	if pg.Relationship != "" {
		fmt.Fprintf(b, " [%s]", pg.Relationship)
	}
	b.WriteString("\n")

	if pg.Why != "" {
		fmt.Fprintf(b, "  Why: %s\n", pg.Why)
	}
	fmt.Fprintf(b, "  %s\n", upgradeLine(pg))
	if pg.ListedElsewhere > 0 {
		fmt.Fprintf(b, "  %s\n", elsewhereLine(pg))
	}

	for _, f := range pg.Findings {
		renderFinding(b, f)
	}
}

// upgradeLine states the reported upgrade target and how many of the
// package's findings it covers by reported fixed version. Entries under
// SectionNoDirectUsage use neutral wording ("Reported fixed version")
// rather than an instruction, so the section carries no urgency.
func upgradeLine(pg PackageGroup) string {
	if pg.ReportedFixedVersion == "" {
		return "No single reported fixed version for this package; see each finding."
	}
	cover := fmt.Sprintf("covers %d of %d finding(s) on this package by reported fixed version (not verified)", pg.ResolvedByUpgrade, pg.TotalFindings)
	if pg.Section == SectionNoDirectUsage {
		return fmt.Sprintf("Reported fixed version: %s; %s.", pg.ReportedFixedVersion, cover)
	}
	return fmt.Sprintf("Update to %s (highest reported fixed version); %s.", pg.ReportedFixedVersion, cover)
}

func elsewhereLine(pg PackageGroup) string {
	return fmt.Sprintf("%s on this package listed under %q.", plural(pg.ListedElsewhere, "further finding"), string(pg.ElsewhereSection))
}

func renderFinding(b *strings.Builder, f PackageFinding) {
	label := f.VulnerabilityID
	if label == "" {
		label = f.FindingID
	}

	fmt.Fprintf(b, "  - %s [%s]\n", label, strings.Join(findingTags(f), ", "))
	if f.Justification != "" {
		fmt.Fprintf(b, "    %s\n", f.Justification)
	}
}

func findingTags(f PackageFinding) []string {
	tags := []string{f.State}
	if f.Severity != "" {
		tags = append(tags, f.Severity)
	}
	tags = append(tags, fmt.Sprintf("EPSS %.4f", f.EPSSScore))
	if f.CISAKev {
		tags = append(tags, "KEV")
	}
	if f.ReportedFixedVersion != "" {
		tags = append(tags, "reported fix "+f.ReportedFixedVersion)
	} else {
		tags = append(tags, "no reported fix")
	}
	if f.Untrusted {
		tags = append(tags, "UNVERIFIED INPUT")
	}
	return tags
}
