package reachability

import (
	"math"
	"sort"
)

// RiskBand is the label for a 0–100% reachability risk score.
type RiskBand string

const (
	BandUndetermined RiskBand = "UNDETERMINED"
	// BandMinimal: 0–20%.
	BandMinimal RiskBand = "MINIMAL PRIORITY"
	// BandLow: 21–39%.
	BandLow RiskBand = "LOW RISK"
	// BandMedium: 40–69%.
	BandMedium RiskBand = "MEDIUM RISK"
	// BandHigh: 70–100%.
	BandHigh RiskBand = "HIGH RISK"
)

// The scoring chart. Each called vulnerable function is scored out of 100%
// from four parts, whose maximums add up to exactly 100:
//
//	Part             Formula                               Max
//	Severity         CVSS base score / 10 × 40             40
//	Exploit chance   EPSS probability × 25                 25
//	Known exploited  listed in CISA KEV                    20
//	Call proximity   app code calls it directly = 15       15
//	                 called via a dependency    = 8
//
// Only functions the call graph shows are actually called are scored;
// vulnerable code that is with no resolved call path is left out.
const (
	MaxSeverityPoints    = 40.0
	MaxExploitPoints     = 25.0
	KnownExploitedPoints = 20.0
	DirectCallPoints     = 15.0
	IndirectCallPoints   = 8.0
	// assumedCVSS is used when no CVSS score could be found for any of a
	// vulnerability's CVEs, so it is scored as a middling severity rather
	// than as harmless.
	assumedCVSS = 5.0
)

// BandFor maps a 0–100 percentage to its risk band.
func BandFor(percent int) RiskBand {
	switch {
	case percent >= 70:
		return BandHigh
	case percent >= 40:
		return BandMedium
	case percent > 20:
		return BandLow
	default:
		return BandMinimal
	}
}

// ExploitIntel is the severity and exploit data for one CVE.
type ExploitIntel struct {
	EPSSKnown bool
	KEVKnown  bool
	CVSS      float64
	EPSS      float64
	InKEV     bool
}

// RiskBreakdown is the points each part of the scoring chart contributed.
type RiskBreakdown struct {
	Severity       float64 `json:"severity"`
	ExploitChance  float64 `json:"exploitChance"`
	KnownExploited float64 `json:"knownExploited"`
	CallProximity  float64 `json:"callProximity"`
}

// CalledFunctionRisk is the risk score for one vulnerable function that the
// application actually calls.
type CalledFunctionRisk struct {
	EPSSKnown bool `json:"epssKnown"`
	KEVKnown  bool `json:"kevKnown"`
	Finding
	Percent   int           `json:"percent"`
	Band      RiskBand      `json:"band"`
	Breakdown RiskBreakdown `json:"breakdown"`
	CVSS      float64       `json:"cvss"`
	EPSS      float64       `json:"epss"`
	InKEV     bool          `json:"inCisaKev"`
	// SeverityAssumed is true when no CVSS score was found and the
	// severity part used a default of 5.0.
	SeverityAssumed bool `json:"severityAssumed"`
}

// ScoreCalledFunctions scores every reachable finding against the scoring
// chart, using intel keyed by CVE ID. Findings that are not reachable are
// skipped. When a vulnerability has several CVE aliases, the highest CVSS
// and EPSS among them are used, and it counts as known exploited if any of
// them is in CISA KEV. Results are sorted highest risk first.
func ScoreCalledFunctions(findings []Finding, intel map[string]ExploitIntel) []CalledFunctionRisk {
	results := make([]CalledFunctionRisk, 0, len(findings))
	for _, f := range findings {
		if !f.Reachable {
			continue
		}
		r := CalledFunctionRisk{Finding: f}
		for _, cve := range f.CVEs {
			in, ok := intel[cve]
			if !ok {
				continue
			}
			r.EPSSKnown = r.EPSSKnown || in.EPSSKnown
			r.KEVKnown = r.KEVKnown || in.KEVKnown
			r.CVSS = math.Max(r.CVSS, in.CVSS)
			r.EPSS = math.Max(r.EPSS, in.EPSS)
			r.InKEV = r.InKEV || in.InKEV
		}

		cvss := r.CVSS
		if cvss <= 0 {
			cvss = assumedCVSS
			r.SeverityAssumed = true
		}
		r.Breakdown.Severity = math.Min(cvss, 10) / 10 * MaxSeverityPoints
		r.Breakdown.ExploitChance = math.Min(r.EPSS, 1) * MaxExploitPoints
		if r.InKEV {
			r.Breakdown.KnownExploited = KnownExploitedPoints
		}
		if f.Tier == TierCritical {
			r.Breakdown.CallProximity = DirectCallPoints
		} else {
			r.Breakdown.CallProximity = IndirectCallPoints
		}

		total := r.Breakdown.Severity + r.Breakdown.ExploitChance + r.Breakdown.KnownExploited + r.Breakdown.CallProximity
		r.Percent = int(math.Round(math.Min(total, 100)))
		r.Band = BandFor(r.Percent)
		results = append(results, r)
	}

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Percent != results[j].Percent {
			return results[i].Percent > results[j].Percent
		}
		return results[i].OSV < results[j].OSV
	})
	return results
}

// OverallRisk is the project's risk: the score of its riskiest called
// vulnerable function, or 0 points when no call path is resolved when none are called.
func OverallRisk(results []CalledFunctionRisk) (int, RiskBand) {
	if len(results) == 0 {
		return 0, BandUndetermined
	}
	top := 0
	for _, r := range results {
		if r.Percent > top {
			top = r.Percent
		}
	}
	return top, BandFor(top)
}
