package vex

// Context is the OpenVEX spec version selected in S4-09.
const Context = "https://openvex.dev/ns/v0.2.0"

// OpenVEX statuses. fixed is part of the spec but SBOMber never emits it.
const (
	StatusAffected           = "affected"
	StatusUnderInvestigation = "under_investigation"
	StatusNotAffected        = "not_affected"
)

// Decision states from decision-results.json.
const (
	StateUsageDetected   = "usage_detected"
	StateNoUsageDetected = "no_usage_detected"
	StateUnknown         = "unknown"
	StateUnsupported     = "unsupported"
)

// vexMapping.statement values that are not OpenVEX statuses.
const (
	mappingOmit     = "omit"
	mappingInTriage = "in_triage" // CycloneDX VEX vocabulary, rejected here
)

// Document is an OpenVEX 0.2.0 document.
type Document struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id"`
	Author     string      `json:"author"`
	Role       string      `json:"role,omitempty"`
	Timestamp  string      `json:"timestamp"`
	Version    int         `json:"version"`
	Tooling    string      `json:"tooling,omitempty"`
	Statements []Statement `json:"statements"`
}

// Statement is one OpenVEX statement.
type Statement struct {
	Vulnerability            Vulnerability `json:"vulnerability"`
	Products                 []Product     `json:"products"`
	Status                   string        `json:"status"`
	StatusNotes              string        `json:"status_notes,omitempty"`
	ImpactStatement          string        `json:"impact_statement,omitempty"`
	ActionStatement          string        `json:"action_statement,omitempty"`
	ActionStatementTimestamp string        `json:"action_statement_timestamp,omitempty"`
}

// Vulnerability names the advisory. Aliases carry every other ID, because
// Grype reports GHSA IDs and Trivy reports CVE IDs.
type Vulnerability struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

// Product is the statement's subject.
type Product struct {
	ID            string         `json:"@id"`
	Subcomponents []Subcomponent `json:"subcomponents,omitempty"`
}

// Subcomponent is the vulnerable package inside an application product.
type Subcomponent struct {
	ID string `json:"@id"`
}

// DecisionResults is the subset of decision-results.json the exporter reads.
type DecisionResults struct {
	SchemaVersion string     `json:"schemaVersion"`
	ScanID        string     `json:"scanId"`
	Decisions     []Decision `json:"decisions"`
}

// Decision is one component 4 verdict.
type Decision struct {
	FindingID       string      `json:"findingId"`
	VulnerabilityID string      `json:"vulnerabilityId"`
	PURL            string      `json:"purl"`
	State           string      `json:"state"`
	Justification   string      `json:"justification"`
	VEXMapping      *VEXMapping `json:"vexMapping,omitempty"`
}

// VEXMapping is component 4's statement for the decision.
type VEXMapping struct {
	Statement          string `json:"statement"`
	ActionStatement    string `json:"actionStatement,omitempty"`
	ManuallyReviewedBy string `json:"manuallyReviewedBy,omitempty"`
}

// CanonicalScan is the subset of canonical-scan.json the exporter reads: the
// repository identity for the application subject and the alias IDs.
type CanonicalScan struct {
	Scan struct {
		ScanID       string       `json:"scanId"`
		Repositories []Repository `json:"repositories"`
	} `json:"scan"`
	Occurrences []Occurrence `json:"occurrences"`
	Findings    []Finding    `json:"findings"`
}

// Repository is one scanned repository.
type Repository struct {
	RepositoryID string `json:"repositoryId"`
	Path         string `json:"path"`
	Commit       string `json:"commit"`
}

// Occurrence places a package in a repository.
type Occurrence struct {
	OccurrenceID string `json:"occurrenceId"`
	RepositoryID string `json:"repositoryId"`
}

// Finding is one scanner finding.
type Finding struct {
	FindingID       string   `json:"findingId"`
	VulnerabilityID string   `json:"vulnerabilityId"`
	Aliases         []string `json:"aliases"`
	PURL            string   `json:"purl"`
	OccurrenceIDs   []string `json:"occurrenceIds"`
}

// Summary counts what the document says, and what it leaves out.
type Summary struct {
	Decisions          int      `json:"decisions"`
	Affected           int      `json:"affected"`
	UnderInvestigation int      `json:"underInvestigation"`
	NotAffected        int      `json:"notAffected"`
	Omitted            int      `json:"omitted"`
	OmittedFindingIDs  []string `json:"omittedFindingIds,omitempty"`
}
