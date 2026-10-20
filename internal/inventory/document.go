// Package inventory writes canonical-scan.json (contract 1.0.0): Component
// 1's output, the shared identity model that usage, localise, decide and vex
// read. Field names follow contracts/canonical-scan.schema.json exactly, and
// every optional field is omitted rather than written empty, because the
// schema forbids properties it does not list.
package inventory

// SchemaVersion is the canonical-scan contract version this package writes.
const SchemaVersion = "1.0.0"

// Document is canonical-scan.json.
type Document struct {
	SchemaVersion       string               `json:"schemaVersion"`
	Scan                Scan                 `json:"scan"`
	Components          []Component          `json:"components"`
	Occurrences         []Occurrence         `json:"occurrences"`
	Findings            []Finding            `json:"findings"`
	SupplyChainWarnings []SupplyChainWarning `json:"supplyChainWarnings,omitempty"`
}

// Scan is the document's "scan" object.
type Scan struct {
	ScanID       string            `json:"scanId"`
	StartedAt    string            `json:"startedAt"`
	CompletedAt  string            `json:"completedAt,omitempty"`
	ToolVersions map[string]string `json:"toolVersions,omitempty"`
	Status       string            `json:"status"`
	StatusDetail *StatusDetail     `json:"statusDetail,omitempty"`
	Repositories []Repository      `json:"repositories"`
	Enrichment   []Enrichment      `json:"enrichment,omitempty"`
}

// Scan statuses. A partial scan must never be reported as a success.
const (
	StatusComplete = "complete"
	StatusPartial  = "partial"
	StatusFailed   = "failed"
)

// StatusDetail says what made a scan partial.
type StatusDetail struct {
	SkippedFiles  []string `json:"skippedFiles"`
	FailedFiles   []string `json:"failedFiles"`
	TruncatedTree bool     `json:"truncatedTree"`
	LimitsHit     []string `json:"limitsHit"`
}

func (d *StatusDetail) empty() bool {
	return len(d.SkippedFiles) == 0 && len(d.FailedFiles) == 0 && !d.TruncatedTree && len(d.LimitsHit) == 0
}

// Repository is one scanned repository. Path is relative to the directory
// canonical-scan.json is written to, so the file means the same thing on
// every machine.
type Repository struct {
	RepositoryID string `json:"repositoryId"`
	Path         string `json:"path"`
	Commit       string `json:"commit,omitempty"`
	Source       string `json:"source,omitempty"`
}

// Enrichment is one enrichment source's outcome.
type Enrichment struct {
	Source string `json:"source"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Component is one exact package version, identified by its PURL.
type Component struct {
	Purl               string `json:"purl"`
	Ecosystem          string `json:"ecosystem"`
	Name               string `json:"name"`
	Version            string `json:"version"`
	VersionKnown       *bool  `json:"versionKnown,omitempty"`
	DeclaredConstraint string `json:"declaredConstraint,omitempty"`
}

// Occurrence is one appearance of a component: PURL + workspace + manifest
// + install path.
type Occurrence struct {
	OccurrenceID   string   `json:"occurrenceId"`
	Purl           string   `json:"purl"`
	RepositoryID   string   `json:"repositoryId"`
	Workspace      string   `json:"workspace,omitempty"`
	Manifest       string   `json:"manifest"`
	Relationship   string   `json:"relationship"`
	DependencyPath []string `json:"dependencyPath"`
	InstallPath    string   `json:"installPath,omitempty"`
	Scope          string   `json:"scope,omitempty"`
}

// Finding is one vulnerability in one component: vulnerability ID + PURL.
type Finding struct {
	FindingID       string      `json:"findingId"`
	VulnerabilityID string      `json:"vulnerabilityId"`
	Aliases         []string    `json:"aliases,omitempty"`
	Purl            string      `json:"purl"`
	OccurrenceIDs   []string    `json:"occurrenceIds"`
	Severity        string      `json:"severity"`
	CVSSScore       *float64    `json:"cvssScore,omitempty"`
	FixedVersion    string      `json:"fixedVersion,omitempty"`
	EPSS            *EPSS       `json:"epss,omitempty"`
	CISAKev         *bool       `json:"cisaKev,omitempty"`
	Provenance      *Provenance `json:"provenance,omitempty"`
}

// EPSS is a finding's exploit prediction score.
type EPSS struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
}

// Provenance records which scanner reported a finding and which sources
// enriched it.
type Provenance struct {
	Scanner        string   `json:"scanner,omitempty"`
	ScannerVersion string   `json:"scannerVersion,omitempty"`
	EnrichedBy     []string `json:"enrichedBy,omitempty"`
}

// SupplyChainWarning is a signal with no CVE: deprecation, malware, health.
type SupplyChainWarning struct {
	WarningID string `json:"warningId"`
	Purl      string `json:"purl"`
	Kind      string `json:"kind"`
	Detail    string `json:"detail,omitempty"`
}
