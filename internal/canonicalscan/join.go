package canonicalscan

// JoinResult separates findings that could be matched to a known canonical
// component by exact PURL from those that could not.
type JoinResult struct {
	Joined   []Finding
	Unjoined []Finding
}

// JoinFindingsByPURL matches each finding's ComponentPurl against the given
// canonical components by exact PURL equality — components are identity 1
// (exact versioned PURL), so a finding either matches one component exactly
// or it does not match at all; there is no fuzzy or name-only fallback,
// because matching on name alone is exactly the wrong-version false
// positive/negative this model exists to prevent.
//
// A finding lands in Unjoined when its ComponentPurl is empty (the source
// scanner could not resolve a PURL for the affected artifact) or when it
// names a PURL that is not present in components.
func JoinFindingsByPURL(findings []Finding, components []Component) JoinResult {
	knownPurls := make(map[string]bool, len(components))
	for _, c := range components {
		knownPurls[c.Purl] = true
	}

	result := JoinResult{
		Joined:   make([]Finding, 0, len(findings)),
		Unjoined: make([]Finding, 0),
	}
	for _, f := range findings {
		if f.ComponentPurl != "" && knownPurls[f.ComponentPurl] {
			result.Joined = append(result.Joined, f)
		} else {
			result.Unjoined = append(result.Unjoined, f)
		}
	}
	return result
}
