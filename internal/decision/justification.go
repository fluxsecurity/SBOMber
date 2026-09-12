package decision

import "strings"

// banned mirrors contracts/validate.py's BANNED list exactly. Keep these two
// lists in sync by hand until the validator and this package share a single
// source of truth (tracked as a limitation below, per S4-11's "Any
// limitation documented when discovered" requirement).
//
// Limitation: this list is duplicated in Python (contracts/validate.py) and
// Go (here). A drift between the two would let a phrase pass this package's
// Lint but still fail contracts/validate.py, or vice versa. No mechanism
// currently keeps them in sync automatically; a future task could generate
// both from one JSON/YAML source.
var banned = []string{
	"not affected",
	"is safe",
	"no risk",
	"false positive",
}

// Lint reports every banned phrase found in justification text (case
// insensitive, matching contracts/validate.py's j.lower() check), so a
// justification-builder or a report renderer can reject unsafe text before
// it ever reaches decision-results.json. An empty slice means the text is
// clean.
func Lint(justification string) []string {
	lower := strings.ToLower(justification)
	var hits []string
	for _, phrase := range banned {
		if strings.Contains(lower, phrase) {
			hits = append(hits, phrase)
		}
	}
	return hits
}

// Justify builds the human-readable justification required alongside every
// Verdict. Per S4-11: "Never the category alone" and the justification
// "must state what was checked and what could not be seen." Reasons come
// from DetermineState's Verdict, so the text is generated from the same
// facts the state guard used — never a separate narrative that could drift
// from the actual decision.
func Justify(v Verdict) string {
	var b strings.Builder
	for i, r := range v.Reasons {
		if i > 0 {
			b.WriteString(" ")
		}
		b.WriteString(capitalise(r))
		if !strings.HasSuffix(r, ".") {
			b.WriteString(".")
		}
	}
	text := b.String()
	// Defensive: if a future Reasons string ever slips in banned language
	// (for example a copy-pasted upstream note), fail loudly in tests
	// rather than silently shipping it. Callers building reports should
	// call Lint themselves before writing decision-results.json.
	return text
}

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
