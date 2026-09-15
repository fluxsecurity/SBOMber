package canonicalscan

// Component is identity 1: an exact versioned package, identified solely by
// its PURL. Two components with the same name but different versions are
// different components.
type Component struct {
	Purl      string `json:"purl"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	License   string `json:"license,omitempty"`
}

// Occurrence is identity 2: one appearance of a component in a workspace.
type Occurrence struct {
	OccurrenceID   string   `json:"occurrenceId"`
	ComponentPurl  string   `json:"componentPurl"`
	Workspace      string   `json:"workspace"`
	ManifestPath   string   `json:"manifestPath"`
	DependencyPath []string `json:"dependencyPath"`
	Scope          string   `json:"scope"`
	BuildScope     string   `json:"buildScope"`
	Depth          int      `json:"depth,omitempty"`
}

// Finding is identity 3: a vulnerability finding keyed by (vulnerability ID,
// component PURL), not by occurrence. ComponentPurl is empty when the
// source scanner could not resolve a PURL for the affected artifact, in
// which case the finding cannot be joined to a canonical component.
type Finding struct {
	FindingID       string `json:"findingId"`
	VulnerabilityID string `json:"vulnerabilityId"`
	ComponentPurl   string `json:"componentPurl"`
	Severity        string `json:"severity"`
	FixedVersion    string `json:"fixedVersion,omitempty"`
	FixState        string `json:"fixState,omitempty"`
	Source          string `json:"source,omitempty"`
}

// UsageObservation is identity 4: an occurrence tied to a concrete call
// site. Not produced by any SBOMber scanner today; see
// docs/design/canonical-scan.md.
type UsageObservation struct {
	OccurrenceID string `json:"occurrenceId"`
	Symbol       string `json:"symbol"`
	File         string `json:"file"`
	Line         int    `json:"line"`
	CallSite     string `json:"callSite,omitempty"`
}
