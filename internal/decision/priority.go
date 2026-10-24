package decision

import (
	"math"
	"sort"
	"strings"
)

// Prioritisation order for decisions[] (S6-15, #156; client meeting,
// 5 October 2026). The rule, applied in this order:
//
//  1. Band: act_now, then insufficient_information, then lower_priority.
//     The same ranking as bandRank, so the report and decision-results
//     agree. An undetermined finding is never listed below one SBOMber
//     could assess.
//  2. Severity, as reported by the scanner: critical, high, medium (or
//     moderate), low, negligible. A missing or unrecognised severity sorts
//     last in its band, never first.
//  3. EPSS, highest first. A finding with no EPSS score sorts after every
//     finding that has one; it is shown as "EPSS not reported", not as 0.
//     A score that is NaN or outside [0, 1] is treated as not reported.
//  4. findingId, so the order is stable and reproducible run to run.
//
// What this order may and may not touch:
//
//   - It only reorders. The band is still set by state and CISA KEV alone
//     (riskPriority); EPSS and severity never move a finding between bands.
//   - EPSS never changes a state or a confidence rating. Neither
//     DetermineState nor Rate takes it as input; TestPriority_EPSSOrdersOnly
//     checks this end to end.
//   - A resolved call path is evidence for the state and the confidence
//     (DeterministicMethodsAgree), not an ordering key here.

// SortDecisions orders decisions in place by the rule above.
func SortDecisions(ds []ResultDecision) {
	sort.SliceStable(ds, func(i, j int) bool { return priorityLess(ds[i], ds[j]) })
}

// priorityLess reports whether a should be listed before b.
func priorityLess(a, b ResultDecision) bool {
	if ra, rb := bandRank(a.RiskPriority.Band), bandRank(b.RiskPriority.Band); ra != rb {
		return ra > rb
	}
	if sa, sb := severityRank(a.RiskPriority.Severity), severityRank(b.RiskPriority.Severity); sa != sb {
		return sa > sb
	}
	ea, okA := epssValue(a.RiskPriority.EPSSScore)
	eb, okB := epssValue(b.RiskPriority.EPSSScore)
	if okA != okB {
		return okA
	}
	if okA && ea != eb {
		return ea > eb
	}
	return a.FindingID < b.FindingID
}

// severityRank maps the scanner's severity label to an order. Grype
// reports Critical/High/Medium/Low/Negligible/Unknown; GHSA uses
// "moderate" for medium. Matching is case-insensitive.
func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium", "moderate":
		return 3
	case "low":
		return 2
	case "negligible":
		return 1
	default:
		return 0
	}
}

// epssValue returns a usable EPSS probability, or false when the score is
// absent or not a valid probability (untrusted scanner input). An invalid
// score is never allowed to break the sort or jump the queue.
func epssValue(p *float64) (float64, bool) {
	if p == nil || math.IsNaN(*p) || *p < 0 || *p > 1 {
		return 0, false
	}
	return *p, true
}
