package usagegraph

// SchemaVersion is the public usage-graph contract version produced here.
const SchemaVersion = "1.3.0"

// Graph is the complete public usage-graph.json 1.3.0 document.
type Graph struct {
	SchemaVersion         string                 `json:"schemaVersion"`
	ScanID                string                 `json:"scanId"`
	Analysis              Analysis               `json:"analysis"`
	Analyser              Analyser               `json:"analyser"`
	EntryPoints           []EntryPoint           `json:"entryPoints"`
	Coverage              Coverage               `json:"coverage"`
	Observations          []Observation          `json:"observations"`
	UnanalysedOccurrences []UnanalysedOccurrence `json:"unanalysedOccurrences"`
	ParseFailures         []ParseFailure         `json:"parseFailures"`
}

// EntryPoint is a statically identified application entry function.
type EntryPoint struct {
	EntryPointID string `json:"entryPointId"`
	Kind         string `json:"kind"`
	Function     string `json:"function"`
	File         string `json:"file"`
	Line         int    `json:"line"`
	RepositoryID string `json:"repositoryId,omitempty"`
}

// Location records a repository-relative source location.
type Location struct {
	RepositoryID string `json:"repositoryId"`
	File         string `json:"file"`
	Line         int    `json:"line"`
	Column       int    `json:"column,omitempty"`
}

// CallPathStep is one named application function in a proven direct-call path.
type CallPathStep struct {
	Function string `json:"function"`
	File     string `json:"file"`
	Line     int    `json:"line"`
}

// CallSite records one use of an imported third-party binding.
type CallSite struct {
	File              string         `json:"file"`
	Line              int            `json:"line"`
	Column            int            `json:"column,omitempty"`
	CalledSymbol      string         `json:"calledSymbol,omitempty"`
	EnclosingFunction string         `json:"enclosingFunction,omitempty"`
	Resolution        string         `json:"resolution"`
	UnresolvedReason  string         `json:"unresolvedReason,omitempty"`
	Reachability      string         `json:"reachability"`
	EntryPointID      string         `json:"entryPointId,omitempty"`
	CallPath          []CallPathStep `json:"callPath,omitempty"`
}

// Observation represents one third-party import binding and its call sites.
type Observation struct {
	ObservationID     string     `json:"observationId"`
	OccurrenceID      string     `json:"occurrenceId,omitempty"`
	PURL              string     `json:"purl,omitempty"`
	ImportedSpecifier string     `json:"importedSpecifier"`
	ComputedSpecifier bool       `json:"computedSpecifier,omitempty"`
	Subpath           string     `json:"subpath,omitempty"`
	LocalAlias        string     `json:"localAlias,omitempty"`
	ImportedSymbol    string     `json:"importedSymbol,omitempty"`
	ImportKind        string     `json:"importKind"`
	Resolution        string     `json:"resolution"`
	UnresolvedReason  string     `json:"unresolvedReason,omitempty"`
	Location          Location   `json:"location"`
	EvidenceLevel     int        `json:"evidenceLevel"`
	CallSites         []CallSite `json:"callSites"`
}

// UnanalysedOccurrence explains why a canonical occurrence has no observation.
type UnanalysedOccurrence struct {
	OccurrenceID string `json:"occurrenceId"`
	PURL         string `json:"purl,omitempty"`
	Reason       string `json:"reason"`
	Detail       string `json:"detail,omitempty"`
}
