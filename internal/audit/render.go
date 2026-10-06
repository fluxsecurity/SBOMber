package audit

import (
	"fmt"
	"io"
	"strings"

	"github.com/Xsamsx/SBOMber/internal/decision"
)

// RenderText writes the per-case comparison, then every downgrade and every
// missed usage in full. Wording follows the decision package's rules: no
// verdict is ever described as safe, unaffected or clean.
func RenderText(w io.Writer, rep Report) error {
	p := &printer{w: w}

	p.f("SBOMber audit harness: %d case(s) under %s\n", len(rep.Cases), rep.CasesRoot)
	p.f("Labels are hand-made judgements. Counts are reported, not an accuracy rate: a handful of repositories cannot support one.\n\n")

	for _, c := range rep.Cases {
		p.f("== %s  (%s @ %s)\n", c.CaseID, c.Repository.URL, short(c.Repository.Commit))
		cov := c.Coverage
		p.f("   analysis %s; files discovered %d, parsed %d, parsed with errors %d, failed %d, skipped %d",
			orDash(cov.AnalysisStatus), cov.FilesDiscovered, cov.FilesParsed, cov.FilesParsedWithErrors, cov.FilesFailed, cov.FilesSkipped)
		if len(cov.LimitsHit) > 0 {
			p.f("; limits hit: %s", strings.Join(cov.LimitsHit, ", "))
		}
		p.f("\n")
		if cov.AnalysisStatus != "" && cov.AnalysisStatus != string(decision.AnalysisComplete) {
			p.f("   WARNING: usage analysis was %s for this case; its verdicts rest on partial evidence.\n", cov.AnalysisStatus)
		}
		p.f("\n   %-12s %-20s %-17s %-50s %-24s %s\n", "FINDING", "VULNERABILITY", "LABEL", "SBOMBER STATE", "BAND", "OUTCOME")
		for _, r := range c.Rows {
			state := "-"
			if r.State != "" {
				state = r.State.Display()
			}
			p.f("   %-12s %-20s %-17s %-50s %-24s %s\n",
				r.FindingID, orDash(r.VulnerabilityID), orDash(string(r.Label)), state, orDash(string(r.Band)), outcomeText(r))
		}
		p.f("   %s\n\n", totalsLine(c.Totals))
	}

	p.f("== All cases\n   %s\n", totalsLine(rep.Totals))

	var inspect []struct {
		caseID string
		row    Row
	}
	for _, c := range rep.Cases {
		for _, r := range c.Rows {
			if r.Downgrade || r.Outcome == OutcomeMissedUsage || r.Outcome == OutcomeLabelMismatch {
				inspect = append(inspect, struct {
					caseID string
					row    Row
				}{c.CaseID, r})
			}
		}
	}
	if len(inspect) == 0 {
		p.f("\nNo finding was moved into \"No direct usage evidence found within the analysed scope\" in this run.\n")
	} else {
		p.f("\n== Downgrades to inspect (%d)\n", len(inspect))
		for _, it := range inspect {
			renderDowngrade(p, it.caseID, it.row)
		}
	}

	if rep.Totals.Failed() {
		p.f("\nRESULT: FAIL")
		if rep.Totals.MissedUsage > 0 {
			p.f(" - %d finding(s) labelled genuine usage were moved out of usage detected", rep.Totals.MissedUsage)
		}
		if rep.Totals.Unlabelled > 0 || rep.Totals.NoDecision > 0 || rep.Totals.Mismatched > 0 {
			p.f(" - labels and decisions do not line up (%d unlabelled, %d without a decision, %d naming a different vulnerability or package); re-label the case",
				rep.Totals.Unlabelled, rep.Totals.NoDecision, rep.Totals.Mismatched)
		}
		p.f("\n")
	} else {
		p.f("\nRESULT: PASS - no labelled genuine usage was moved out of usage detected.\n")
	}
	return p.err
}

func renderDowngrade(p *printer, caseID string, r Row) {
	p.f("\n-- %s / %s  %s  %s\n", caseID, r.FindingID, orDash(r.VulnerabilityID), orDash(r.PURL))
	p.f("   outcome:       %s\n", outcomeText(r))
	p.f("   human label:   %s\n", orDash(string(r.Label)))
	if r.Outcome == OutcomeLabelMismatch {
		p.f("   label is for:  %s %s\n", orDash(r.LabelVulnID), orDash(r.LabelPURL))
	}
	if len(r.VulnerableSymbols) > 0 {
		p.f("   vulnerable:    %s\n", strings.Join(r.VulnerableSymbols, ", "))
	}
	p.f("   reasoning:     %s\n", orDash(r.LabelReasoning))
	for _, e := range r.LabelEvidence {
		p.f("   evidence:      %s\n", e)
	}
	p.f("   SBOMber state: %s (band %s, confidence %s)\n", r.State.Display(), orDash(string(r.Band)), orDash(string(r.AnalysisConfidence)))
	p.f("   justification: %s\n", orDash(r.Justification))
	for _, c := range r.ConfidenceCriteria {
		p.f("   criterion:     %s\n", c)
	}
	if b := r.BasedOn; b != nil {
		p.f("   based on:      localisation %s/%s; matched symbols [%s]; observations [%s]\n",
			b.LocalisationMethod, b.LocalisationConfidence, strings.Join(b.MatchedSymbols, ", "), strings.Join(b.UsageObservationIDs, ", "))
		p.f("   coverage:      parse %.1f%%, %d unresolved import(s) in scope, scan status %s\n",
			b.CoverageSummary.ParseCoveragePercent, b.CoverageSummary.UnresolvedImportsInScope, orDash(b.CoverageSummary.ScanStatus))
	}
}

func outcomeText(r Row) string {
	switch r.Outcome {
	case OutcomeAgreeUsage:
		return "agrees (usage)"
	case OutcomeAgreeNoUsage:
		return "agrees (no usage found)"
	case OutcomeMissedUsage:
		return "MISSED USAGE"
	case OutcomeOverReported:
		return "over-reported usage"
	case OutcomeAbstained:
		return "abstained (insufficient information)"
	case OutcomeUnlabelled:
		return "UNLABELLED"
	case OutcomeNoDecision:
		return "NO DECISION"
	case OutcomeLabelMismatch:
		return "LABEL MISMATCH"
	default:
		return string(r.Outcome)
	}
}

func totalsLine(t Totals) string {
	return fmt.Sprintf("%d finding(s): %d agree usage, %d agree no usage found, %d missed usage, %d over-reported, %d abstained, %d unlabelled, %d without decision, %d label mismatch; %d downgrade(s)",
		t.Findings, t.AgreeUsage, t.AgreeNoUsage, t.MissedUsage, t.OverReported, t.Abstained, t.Unlabelled, t.NoDecision, t.Mismatched, t.Downgrades)
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// printer keeps the first write error so RenderText can return it once.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) f(format string, a ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, format, a...)
}
