package localisation

// SchemaVersion is the localisation.json contract version this package emits.
const SchemaVersion = "1.0.0"

// Method is a localisation source, in the contract's fallback order.
type Method string

// Methods in the order they are tried. LLMSuggested is reserved by the
// contract and not implemented here.
const (
	MethodAdvisoryMetadata Method = "advisory_metadata"
	MethodPatchReference   Method = "patch_reference"
	MethodAdvisoryText     Method = "advisory_text"
	MethodVersionDiff      Method = "version_diff"
	MethodLLMSuggested     Method = "llm_suggested"
	MethodUnknown          Method = "unknown"
)

// Confidence is categorical with published criteria (see Result.Confidence).
type Confidence string

// Confidence levels.
const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
	ConfidenceNone   Confidence = "none"
)

// Document is the root of localisation.json.
type Document struct {
	SchemaVersion string   `json:"schemaVersion"`
	ScanID        string   `json:"scanId"`
	Summary       *Summary `json:"summary,omitempty"`
	Results       []Result `json:"results"`
}

// Summary holds per-method counts. The unknown rate is a reportable result.
type Summary struct {
	FindingsProcessed int            `json:"findingsProcessed"`
	ByMethod          map[string]int `json:"byMethod"`
	UnknownCount      int            `json:"unknownCount"`
}

// Result is one finding's localisation.
type Result struct {
	FindingID         string      `json:"findingId"`
	VulnerabilityID   string      `json:"vulnerabilityId"`
	PURL              string      `json:"purl"`
	Method            Method      `json:"method"`
	Confidence        Confidence  `json:"confidence"`
	CandidateSymbols  []Candidate `json:"candidateSymbols"`
	VulnerableVersion string      `json:"vulnerableVersion,omitempty"`
	FixedVersion      string      `json:"fixedVersion,omitempty"`
	Provenance        *Provenance `json:"provenance,omitempty"`
	ExcludedChanges   []string    `json:"excludedChanges,omitempty"`
	Notes             string      `json:"notes,omitempty"`
}

// Candidate is one implicated symbol. The set, not any single entry, is the
// answer.
type Candidate struct {
	Symbol     string `json:"symbol"`
	ModulePath string `json:"modulePath,omitempty"`
	ChangeKind string `json:"changeKind,omitempty"`
	Note       string `json:"note,omitempty"`
}

// Provenance traces every candidate back to its source artefact.
type Provenance struct {
	AdvisorySource string     `json:"advisorySource,omitempty"`
	AdvisoryURL    string     `json:"advisoryUrl,omitempty"`
	PatchCommit    string     `json:"patchCommit,omitempty"`
	PatchURL       string     `json:"patchUrl,omitempty"`
	Artefacts      []Artefact `json:"artefacts,omitempty"`
}

// Artefact is a downloaded file. Executed is always false and is serialised
// explicitly so the validator can check it.
type Artefact struct {
	URL       string `json:"url"`
	SHA256    string `json:"sha256,omitempty"`
	SizeBytes int64  `json:"sizeBytes,omitempty"`
	Verified  bool   `json:"verified"`
	Executed  bool   `json:"executed"`
}

// Finding is the input: one vulnerability against one versioned package,
// taken from canonical-scan.json.
type Finding struct {
	FindingID       string
	VulnerabilityID string
	Aliases         []string
	PURL            string
	FixedVersion    string
}

// Outcome classifies one method's attempt for the evaluation trace.
type Outcome string

// Outcomes of a single method attempt.
const (
	OutcomeHit       Outcome = "hit"       // produced at least one candidate
	OutcomeEmpty     Outcome = "empty"     // ran cleanly, found nothing
	OutcomeError     Outcome = "error"     // could not run (network, parse, limits)
	OutcomeSkipped   Outcome = "skipped"   // not attempted (disabled or no input)
	OutcomeNonCode   Outcome = "non_code"  // source existed but changed no code
	OutcomeUnbounded Outcome = "unbounded" // exceeded a size or count limit
)

// Attempt is one method's evidence, kept even when a cheaper method already
// answered so the spike can measure every source independently.
type Attempt struct {
	Method     Method      `json:"method"`
	Outcome    Outcome     `json:"outcome"`
	Candidates []Candidate `json:"candidates,omitempty"`
	// NonFunctionChanges lists module-level declarations touched by the fix
	// (regex constants, error strings). They are not callable and so are
	// not candidates, but they are part of the honest record.
	NonFunctionChanges []string    `json:"nonFunctionChanges,omitempty"`
	Provenance         *Provenance `json:"provenance,omitempty"`
	ExcludedChanges    []string    `json:"excludedChanges,omitempty"`
	Notes              []string    `json:"notes,omitempty"`
	// ClientMethod records the client's own suggested check: does the
	// vulnerability ID appear in a commit message of the package repository?
	ClientMethod *ClientMethodEvidence `json:"clientMethod,omitempty"`
}

// ClientMethodEvidence records the commit-message search the client
// described at the 21 August 2026 meeting.
type ClientMethodEvidence struct {
	Repository string `json:"repository"`
	Query      string `json:"query"`
	// CommitsMatched counts distinct commits whose message mentions any ID.
	CommitsMatched int      `json:"commitsMatched"`
	CommitSHAs     []string `json:"commitSHAs,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// Trace is the full record of one finding's localisation, for evaluation.
type Trace struct {
	FindingID       string    `json:"findingId"`
	VulnerabilityID string    `json:"vulnerabilityId"`
	PURL            string    `json:"purl"`
	Attempts        []Attempt `json:"attempts"`
	Selected        Method    `json:"selected"`
}
