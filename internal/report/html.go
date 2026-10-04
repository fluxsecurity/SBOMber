package report

import (
	"bytes"
	"html/template"
	"strings"
)

// RenderHTML renders a Report as one self-contained HTML page: inline CSS,
// no scripts, no external resources, so it can be opened offline or
// attached to a ticket. Every value is escaped by html/template.
//
// It uses the same wording helpers as RenderText (upgradeLine,
// elsewhereLine, findingTags, coverageLines and the section notes), so the
// two formats cannot drift apart on what a section means. The
// no-direct-usage section is styled neutrally: never green, never as
// resolved or low urgency.
func RenderHTML(r Report) (string, error) {
	view := htmlView{
		ScanID:       r.ScanID,
		Incomplete:   r.Coverage.Incomplete(),
		Banner:       incompleteBanner(r.Coverage),
		NoFindings:   findingCount(r) == 0,
		CoverageHead: "Analysis coverage",
		Coverage:     coverageLines(r.Coverage),
	}
	for _, sg := range r.Sections {
		sv := htmlSection{
			ID:      sectionID(sg.Section),
			Class:   sectionClass(sg.Section),
			Heading: string(sg.Section),
		}
		switch sg.Section {
		case SectionInsufficientInfo:
			sv.ShowCoverage = true
		case SectionNoDirectUsage:
			sv.Note = noDirectUsageNote
		}
		for _, pg := range sg.Groups {
			gv := htmlGroup{
				PURL:             pg.PURL,
				InstalledVersion: pg.InstalledVersion,
				Relationship:     pg.Relationship,
				Why:              pg.Why,
				Upgrade:          upgradeLine(pg),
			}
			if pg.ListedElsewhere > 0 {
				gv.Elsewhere = elsewhereLine(pg)
				gv.ElsewhereID = sectionID(pg.ElsewhereSection)
			}
			for _, f := range pg.Findings {
				label := f.VulnerabilityID
				if label == "" {
					label = f.FindingID
				}
				fv := htmlFinding{
					FindingID:     f.FindingID,
					Label:         label,
					Tags:          strings.Join(findingTags(f), ", "),
					Justification: f.Justification,
					Untrusted:     f.Untrusted,
				}
				if needsPartialWarning(f) {
					fv.Warning = partialWarning(f.ScanStatus)
				}
				gv.Findings = append(gv.Findings, fv)
			}
			sv.Groups = append(sv.Groups, gv)
		}
		view.Sections = append(view.Sections, sv)
	}

	var b bytes.Buffer
	if err := htmlTemplate.Execute(&b, view); err != nil {
		return "", err
	}
	return b.String(), nil
}

type htmlView struct {
	ScanID       string
	Incomplete   bool
	Banner       string
	NoFindings   bool
	CoverageHead string
	Coverage     []string
	Sections     []htmlSection
}

type htmlSection struct {
	ID           string
	Class        string
	Heading      string
	Note         string
	ShowCoverage bool
	Groups       []htmlGroup
}

type htmlGroup struct {
	PURL             string
	InstalledVersion string
	Relationship     string
	Why              string
	Upgrade          string
	Elsewhere        string
	ElsewhereID      string
	Findings         []htmlFinding
}

type htmlFinding struct {
	FindingID     string
	Label         string
	Tags          string
	Justification string
	Warning       string
	Untrusted     bool
}

// sectionID is the stable anchor for a section, used by cross-references.
func sectionID(s Section) string {
	switch s {
	case SectionUpdateFirst:
		return "update-first"
	case SectionInsufficientInfo:
		return "insufficient-information"
	case SectionNoDirectUsage:
		return "no-direct-usage"
	case SectionLowerPriority:
		return "lower-priority"
	default:
		return "section"
	}
}

// sectionClass picks the section's accent colour. The no-direct-usage
// section has its own neutral blue accent: deliberately not green (which
// would read as resolved) and not greyed out (which would read as low
// urgency).
func sectionClass(s Section) string {
	switch s {
	case SectionUpdateFirst:
		return "s-update"
	case SectionInsufficientInfo:
		return "s-insufficient"
	case SectionNoDirectUsage:
		return "s-nousage"
	default:
		return "s-lower"
	}
}

var htmlTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SBOMber remediation report — {{.ScanID}}</title>
<style>
:root {
  --bg: #ffffff; --fg: #1f2328; --muted: #57606a; --border: #d0d7de; --card: #f6f8fa;
  --update: #cf222e; --insufficient: #9a6700; --nousage: #0969da; --lower: #6e7781;
  --warn-bg: #fff8c5;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117; --fg: #e6edf3; --muted: #9198a1; --border: #30363d; --card: #161b22;
    --update: #ff7b72; --insufficient: #d29922; --nousage: #58a6ff; --lower: #9198a1;
    --warn-bg: #3b2e00;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }
main { max-width: 1000px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 1.5rem; margin: 0 0 4px; }
.scan { color: var(--muted); margin: 0 0 16px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.banner { background: var(--warn-bg); border: 1px solid var(--insufficient); border-radius: 6px; padding: 10px 14px; margin: 0 0 16px; }
a { color: var(--nousage); }
nav a { color: var(--fg); }
nav ul { list-style: none; padding: 0; margin: 0 0 24px; display: flex; flex-wrap: wrap; gap: 8px 16px; }
section { margin: 0 0 32px; }
section > h2 { font-size: 1.2rem; margin: 0 0 8px; padding-left: 10px; border-left: 4px solid var(--accent); }
.s-update { --accent: var(--update); }
.s-insufficient { --accent: var(--insufficient); }
.s-nousage { --accent: var(--nousage); }
.s-lower { --accent: var(--lower); }
.note { margin: 0 0 12px; }
.coverage { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; margin: 0 0 16px; }
.coverage h3 { font-size: 1rem; margin: 0 0 6px; }
.coverage ul { margin: 0; padding-left: 20px; }
.empty { color: var(--muted); font-style: italic; }
article { border: 1px solid var(--border); border-radius: 6px; padding: 12px 14px; margin: 0 0 12px; }
article h3 { font-size: 1rem; margin: 0 0 6px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap: anywhere; }
.meta { color: var(--muted); font-family: inherit; font-weight: normal; }
article p { margin: 4px 0; }
table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.92rem; }
th, td { text-align: left; vertical-align: top; padding: 6px 8px; border-top: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; }
td.id { white-space: nowrap; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.warn { background: var(--warn-bg); padding: 4px 6px; border-radius: 4px; margin-top: 4px; }
.untrusted { font-weight: 600; }
@media (max-width: 640px) {
  table, tbody, tr, td { display: block; width: 100%; }
  thead { display: none; }
  td { border-top: none; padding: 2px 0; }
  tr { border-top: 1px solid var(--border); padding: 6px 0; }
}
</style>
</head>
<body>
<main>
<h1>SBOMber remediation report</h1>
<p class="scan">{{.ScanID}}</p>
{{if .Incomplete}}<p class="banner">{{.Banner}}</p>{{end}}
{{if .NoFindings}}<p>No findings were listed in this decision-results file.</p>{{end}}
<nav aria-label="Sections"><ul>
{{range .Sections}}<li><a href="#{{.ID}}">{{.Heading}}</a></li>
{{end}}</ul></nav>
{{range .Sections}}
<section id="{{.ID}}" class="{{.Class}}">
<h2>{{.Heading}}</h2>
{{if .Note}}<p class="note">{{.Note}}</p>{{end}}
{{if .ShowCoverage}}<div class="coverage"><h3>{{$.CoverageHead}}</h3><ul>
{{range $.Coverage}}<li>{{.}}</li>
{{end}}</ul></div>{{end}}
{{if not .Groups}}<p class="empty">No findings in this section.</p>{{end}}
{{range .Groups}}
<article>
<h3>{{.PURL}}{{if .InstalledVersion}} <span class="meta">installed {{.InstalledVersion}}</span>{{end}}{{if .Relationship}} <span class="meta">[{{.Relationship}}]</span>{{end}}</h3>
{{if .Why}}<p><strong>Why:</strong> {{.Why}}</p>{{end}}
<p>{{.Upgrade}}</p>
{{if .Elsewhere}}<p><a href="#{{.ElsewhereID}}">{{.Elsewhere}}</a></p>{{end}}
{{if .Findings}}<table>
<thead><tr><th>Vulnerability</th><th>Details</th><th>Justification</th></tr></thead>
<tbody>
{{range .Findings}}<tr data-finding-id="{{.FindingID}}"{{if .Untrusted}} class="untrusted"{{end}}>
<td class="id">{{.Label}}</td>
<td>{{.Tags}}</td>
<td>{{.Justification}}{{if .Warning}}<div class="warn">{{.Warning}}</div>{{end}}</td>
</tr>
{{end}}</tbody>
</table>{{end}}
</article>
{{end}}
</section>
{{end}}
</main>
</body>
</html>
`))
