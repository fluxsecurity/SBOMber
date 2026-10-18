package report

import (
	"fmt"
	"sort"
	"strings"
)

// Filter narrows what a report shows. Empty fields match everything. A
// filter changes the view only: hidden findings are counted and the count is
// shown, so a filtered report is never mistaken for a scan with fewer
// findings.
type Filter struct {
	// Sections are section IDs: update-first, insufficient-information,
	// no-direct-usage, lower-priority.
	Sections []string
	// Bands are risk-priority bands: act_now, lower_priority,
	// insufficient_information.
	Bands []string
	// States are decision states: usage_detected, no_usage_detected,
	// unknown, unsupported.
	States []string
	// Packages are case-insensitive substrings of the package purl.
	Packages []string
}

// Active reports whether the filter narrows anything.
func (f Filter) Active() bool {
	return len(f.Sections)+len(f.Bands)+len(f.States)+len(f.Packages) > 0
}

// Validate rejects values the filter would silently never match.
func (f Filter) Validate() error {
	var bad []string
	check := func(kind string, got []string, allowed ...string) {
		ok := map[string]bool{}
		for _, a := range allowed {
			ok[a] = true
		}
		for _, g := range got {
			if !ok[g] {
				bad = append(bad, fmt.Sprintf("%s %q (want one of %s)", kind, g, strings.Join(allowed, ", ")))
			}
		}
	}
	check("section", f.Sections, "update-first", "insufficient-information", "no-direct-usage", "lower-priority")
	check("band", f.Bands, BandActNow, BandLowerPriority, BandInsufficientInfo)
	check("state", f.States, StateUsageDetected, StateNoUsageDetected, StateUnknown, StateUnsupported)
	for _, p := range f.Packages {
		if strings.TrimSpace(p) == "" {
			bad = append(bad, "empty package filter")
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("invalid filter: %s", strings.Join(bad, "; "))
	}
	return nil
}

// String describes the filter for the report header.
func (f Filter) String() string {
	var parts []string
	add := func(kind string, vs []string) {
		if len(vs) > 0 {
			parts = append(parts, kind+" "+strings.Join(vs, ", "))
		}
	}
	add("section", f.Sections)
	add("band", f.Bands)
	add("state", f.States)
	add("package", f.Packages)
	return strings.Join(parts, "; ")
}

// Apply returns the report narrowed by f. Every section that was present
// stays present, so the mandatory sections never disappear; each carries
// how many of its findings the filter hid.
func (r Report) Apply(f Filter) Report {
	if !f.Active() {
		return r
	}
	out := r
	out.Sections = nil
	out.FilterDescription = f.String()
	out.TotalBeforeFilter = findingCount(r)

	for _, sg := range r.Sections {
		nsg := SectionGroup{Section: sg.Section}
		sectionOK := matchAny(f.Sections, sectionID(sg.Section))
		for _, pg := range sg.Groups {
			packageOK := matchPackage(f.Packages, pg.PURL)
			var kept []PackageFinding
			for _, fd := range pg.Findings {
				if sectionOK && packageOK && matchAny(f.Bands, fd.Band) && matchAny(f.States, fd.State) {
					kept = append(kept, fd)
				} else {
					nsg.Hidden++
				}
			}
			// An entry with no findings of its own (a KEV pointer to the
			// no-direct-usage section) stays only when the section and
			// package match and no finding-level filter is set.
			keepEmpty := len(pg.Findings) == 0 && sectionOK && packageOK && len(f.Bands) == 0 && len(f.States) == 0
			if len(kept) > 0 || keepEmpty {
				npg := pg
				npg.Findings = kept
				nsg.Groups = append(nsg.Groups, npg)
			}
		}
		out.Sections = append(out.Sections, nsg)
	}
	return out
}

func matchAny(allowed []string, v string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == v {
			return true
		}
	}
	return false
}

func matchPackage(subs []string, purl string) bool {
	if len(subs) == 0 {
		return true
	}
	p := strings.ToLower(purl)
	for _, s := range subs {
		if strings.Contains(p, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// ParseList splits a comma-separated flag value, trimming spaces and
// dropping duplicates; it keeps empty items so Validate can reject them.
func ParseList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// filterLine is shown at the top of a filtered report.
func filterLine(r Report) string {
	return fmt.Sprintf("Filtered view (%s): showing %d of %d finding(s). Hidden findings are not removed from the analysis, only from this view.",
		r.FilterDescription, findingCount(r), r.TotalBeforeFilter)
}

// hiddenLine is shown under a section heading when the filter hid findings
// from it.
func hiddenLine(n int) string {
	return fmt.Sprintf("%s in this section hidden by the filter.", plural(n, "finding"))
}
