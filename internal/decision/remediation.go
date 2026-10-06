package decision

import (
	"sort"
	"strconv"
	"strings"
)

// ---- remediationGroups (S5-09, #120) ----------------------------------------
//
// remediationGroups answers the question the grouped report exists for:
// which package do I update first, why, and what will that upgrade fix?
// One group per package occurrence (purl, which carries the installed
// version). Every decision with a purl lands in exactly one group; nothing
// is dropped or merged away.

// RemediationGroup is one decision-results.json remediationGroups[] entry.
type RemediationGroup struct {
	PURL                 string   `json:"purl"`
	InstalledVersion     string   `json:"installedVersion,omitempty"`
	ReportedFixedVersion string   `json:"reportedFixedVersion,omitempty"`
	FindingIDs           []string `json:"findingIds"`
	HighestBand          RiskBand `json:"highestBand,omitempty"`
	Relationship         string   `json:"relationship,omitempty"`
}

// BuildRemediationGroups groups decisions by purl and orders the groups so
// the package to update first comes first.
//
// ReportedFixedVersion is the highest fixed version the scanner reported
// for any finding in the group. It is the scanner's report, not a verified
// upgrade target: a finding whose reported fix is higher than the installed
// line's real fix, or a fix on a different release line, is not detected
// here. When any reported fixed version cannot be ordered (it is not a
// dotted numeric version) or is not above the installed version, the
// group's ReportedFixedVersion is left empty rather than guessed, and each
// finding keeps its own decisions[].remediation.reportedFixedVersion.
//
// Decisions without a purl cannot be grouped (the schema requires one) and
// are left out of every group; the report lists them separately so they are
// never silently lost.
func BuildRemediationGroups(decisions []ResultDecision, findings []ScanFinding) []RemediationGroup {
	fixed := make(map[string]string, len(findings))
	for _, f := range findings {
		fixed[f.FindingID] = f.FixedVersion
	}

	type acc struct {
		group  RemediationGroup
		rank   int
		kev    bool
		epss   float64
		cvss   float64
		fixes  []string
		unsure bool
	}
	byPURL := make(map[string]*acc)
	var order []string

	for _, d := range decisions {
		if d.PURL == "" {
			continue
		}
		a, ok := byPURL[d.PURL]
		if !ok {
			a = &acc{group: RemediationGroup{
				PURL:             d.PURL,
				InstalledVersion: versionFromPURL(d.PURL),
			}}
			byPURL[d.PURL] = a
			order = append(order, d.PURL)
		}
		a.group.FindingIDs = append(a.group.FindingIDs, d.FindingID)

		// The tie-break signals come only from the findings in the group's
		// highest band, so a lower-priority finding listed in another
		// section cannot lift the package above one the report shows as
		// more urgent.
		if r := bandRank(d.RiskPriority.Band); r > a.rank {
			a.rank = r
			a.group.HighestBand = d.RiskPriority.Band
			a.kev, a.epss, a.cvss = false, 0, 0
		}
		switch d.RiskPriority.Relationship {
		case "direct":
			a.group.Relationship = "direct"
		case "transitive":
			if a.group.Relationship == "" {
				a.group.Relationship = "transitive"
			}
		}
		if bandRank(d.RiskPriority.Band) == a.rank {
			if d.RiskPriority.CISAKev != nil && *d.RiskPriority.CISAKev {
				a.kev = true
			}
			if d.RiskPriority.EPSSScore != nil && *d.RiskPriority.EPSSScore > a.epss {
				a.epss = *d.RiskPriority.EPSSScore
			}
			if d.RiskPriority.CVSSScore != nil && *d.RiskPriority.CVSSScore > a.cvss {
				a.cvss = *d.RiskPriority.CVSSScore
			}
		}
		if v := fixed[d.FindingID]; v != "" {
			// A reported fix at or below the installed version (a fix on
			// another release line) is not an upgrade target.
			installed := a.group.InstalledVersion
			if _, ok := parseVersion(v); !ok {
				a.unsure = true
			} else if _, ok := parseVersion(installed); ok && compareVersions(v, installed) <= 0 {
				a.unsure = true
			} else {
				a.fixes = append(a.fixes, v)
			}
		}
	}

	accs := make([]*acc, 0, len(order))
	for _, p := range order {
		a := byPURL[p]
		sort.Strings(a.group.FindingIDs)
		if !a.unsure && len(a.fixes) > 0 {
			best := a.fixes[0]
			for _, v := range a.fixes[1:] {
				if compareVersions(v, best) > 0 {
					best = v
				}
			}
			a.group.ReportedFixedVersion = best
		}
		accs = append(accs, a)
	}

	// Update-first order: most urgent band, then, among the findings in that
	// band, known exploitation (KEV), exploitation likelihood (EPSS) and
	// severity (CVSS), then how many findings the upgrade covers, then purl
	// for a stable order.
	sort.SliceStable(accs, func(i, j int) bool {
		a, b := accs[i], accs[j]
		if a.rank != b.rank {
			return a.rank > b.rank
		}
		if a.kev != b.kev {
			return a.kev
		}
		if a.epss != b.epss {
			return a.epss > b.epss
		}
		if a.cvss != b.cvss {
			return a.cvss > b.cvss
		}
		if len(a.group.FindingIDs) != len(b.group.FindingIDs) {
			return len(a.group.FindingIDs) > len(b.group.FindingIDs)
		}
		return a.group.PURL < b.group.PURL
	})

	groups := make([]RemediationGroup, 0, len(accs))
	for _, a := range accs {
		groups = append(groups, a.group)
	}
	return groups
}

// bandRank orders bands for "highest": act_now above
// insufficient_information above lower_priority. Insufficient information
// ranks above lower priority because an undetermined finding must never be
// presented as less urgent than one SBOMber could assess.
func bandRank(b RiskBand) int {
	switch b {
	case BandActNow:
		return 3
	case BandInsufficientInformation:
		return 2
	case BandLowerPriority:
		return 1
	default:
		return 0
	}
}

// versionFromPURL returns the version part of a purl ("pkg:npm/lodash@4.17.4"
// -> "4.17.4"), or "" when there is none.
func versionFromPURL(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	i := strings.LastIndex(rest, "@")
	if i <= 0 || i == len(rest)-1 {
		return ""
	}
	// An "@" inside the name segment of a scoped npm purl is percent-encoded
	// (%40), so the last "@" separates the version.
	if strings.Contains(rest[i+1:], "/") {
		return ""
	}
	return rest[i+1:]
}

// version is a dotted numeric version with an optional pre-release.
type version struct {
	nums []int
	pre  []string
}

// parseVersion accepts "1.2.3", "v1.2.3", "1.2", "1.2.3-beta.1" and
// "1.2.3+build". Anything else (ranges, words, empty) is not ordered.
func parseVersion(s string) (version, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var v version
	core := s
	if i := strings.IndexByte(s, '-'); i >= 0 {
		core = s[:i]
		if s[i+1:] == "" {
			return version{}, false
		}
		v.pre = strings.Split(s[i+1:], ".")
	}
	if core == "" {
		return version{}, false
	}
	for _, p := range strings.Split(core, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return version{}, false
		}
		v.nums = append(v.nums, n)
	}
	return v, true
}

// compareVersions returns -1, 0 or 1. Both must parse; callers check first.
// Missing numeric parts count as 0, and a release sorts above any
// pre-release of the same numbers (semver precedence).
func compareVersions(a, b string) int {
	va, _ := parseVersion(a)
	vb, _ := parseVersion(b)
	n := len(va.nums)
	if len(vb.nums) > n {
		n = len(vb.nums)
	}
	for i := 0; i < n; i++ {
		x, y := 0, 0
		if i < len(va.nums) {
			x = va.nums[i]
		}
		if i < len(vb.nums) {
			y = vb.nums[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(va.pre) == 0 && len(vb.pre) == 0:
		return 0
	case len(va.pre) == 0:
		return 1
	case len(vb.pre) == 0:
		return -1
	}
	for i := 0; i < len(va.pre) && i < len(vb.pre); i++ {
		if c := comparePreIdent(va.pre[i], vb.pre[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(va.pre) < len(vb.pre):
		return -1
	case len(va.pre) > len(vb.pre):
		return 1
	}
	return 0
}

// comparePreIdent compares one pre-release identifier: numeric identifiers
// compare numerically and sort below alphanumeric ones.
func comparePreIdent(a, b string) int {
	na, ea := strconv.Atoi(a)
	nb, eb := strconv.Atoi(b)
	switch {
	case ea == nil && eb == nil:
		switch {
		case na < nb:
			return -1
		case na > nb:
			return 1
		}
		return 0
	case ea == nil:
		return -1
	case eb == nil:
		return 1
	}
	return strings.Compare(a, b)
}
