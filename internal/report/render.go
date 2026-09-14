package report

import (
	"fmt"
	"strings"
)

// RenderText renders a Report as a plain-text wireframe: the working
// prototype the Sprint 4 plan calls for, suitable for a terminal demo. HTML
// output is future work (Sprint 5's grouped remediation report task) — this
// is deliberately the smallest thing that actually answers "which package
// do I update first, why, and what will that upgrade fix?" from real
// grouped data.
func RenderText(r Report) string {
	var b strings.Builder

	fmt.Fprintf(&b, "SBOMber Remediation Report — %s\n", r.ScanID)

	if len(r.Sections) == 0 {
		b.WriteString("\nNo findings to report.\n")
		return b.String()
	}

	for _, sg := range r.Sections {
		fmt.Fprintf(&b, "\n== %s ==\n", sg.Section)
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

	if pg.ReportedFixedVersion != "" {
		fmt.Fprintf(b, "  Update to %s to resolve:\n", pg.ReportedFixedVersion)
	} else {
		b.WriteString("  No reported fix version available.\n")
	}

	for _, f := range pg.Findings {
		renderFinding(b, f)
	}
}

func renderFinding(b *strings.Builder, f PackageFinding) {
	label := f.VulnerabilityID
	if label == "" {
		label = f.FindingID
	}

	tags := []string{f.State}
	if f.Severity != "" {
		tags = append(tags, f.Severity)
	}
	tags = append(tags, fmt.Sprintf("EPSS %.4f", f.EPSSScore))
	if f.CISAKev {
		tags = append(tags, "KEV")
	}
	if f.Untrusted {
		tags = append(tags, "UNVERIFIED INPUT")
	}

	fmt.Fprintf(b, "  - %s [%s]\n", label, strings.Join(tags, ", "))
	if f.Justification != "" {
		fmt.Fprintf(b, "    %s\n", f.Justification)
	}
}
