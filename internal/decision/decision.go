package decision

// Decision is one finding's verdict: the S4-11 scope only. It deliberately
// stops short of decision-results.schema.json's full "decisions[]" object —
// riskPriority, remediation, and vexMapping are other components' concerns
// (S4-13 grouped report, and the still-open question on issue #93 about
// whether Component 4 should emit VEX vocabulary directly or stay
// format-neutral). Wiring this into the full schema is S4-12's job.
type Decision struct {
	FindingID     string
	State         State
	Confidence    Confidence
	Criteria      []string
	Justification string
}

// Decide runs the full S4-11 pipeline for one finding: determine the state,
// rate the confidence, and build the justification — in that order, because
// confidence and justification both describe the SAME verdict the state
// guard produced, never a competing one.
func Decide(findingID string, stateIn StateInputs, confIn ConfidenceInputs) Decision {
	verdict := DetermineState(stateIn)
	rating := Rate(confIn)
	return Decision{
		FindingID:     findingID,
		State:         verdict.State,
		Confidence:    rating.Confidence,
		Criteria:      rating.Criteria,
		Justification: Justify(verdict),
	}
}

// Distribution is decision-results.json's "distribution" object: a
// prioritisation distribution, not "noise reduction" (S4-19's explicit
// framing requirement — reclassifying a finding is not proof it was a false
// positive, so this type counts states, nothing more).
type Distribution struct {
	TotalFindings   int
	UsageDetected   int
	NoUsageDetected int
	Unknown         int
	Unsupported     int
}

// Tally builds a Distribution from a set of decisions. Kept as a pure
// function over []Decision, separate from wherever decisions are actually
// produced, so it can be unit tested against hand-built slices without any
// fixture I/O (that belongs to S4-12).
func Tally(decisions []Decision) Distribution {
	d := Distribution{TotalFindings: len(decisions)}
	for _, dec := range decisions {
		switch dec.State {
		case StateUsageDetected:
			d.UsageDetected++
		case StateNoUsageDetected:
			d.NoUsageDetected++
		case StateUnknown:
			d.Unknown++
		case StateUnsupported:
			d.Unsupported++
		}
	}
	return d
}
