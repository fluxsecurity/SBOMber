package localisation

// SchemaVersion is the localisation.json contract version this package emits.
// 1.1.0 adds per-candidate evidence, artefact identity and checksums, and
// release tag checks (S6-07). Every 1.1.0 field is optional, so a 1.0.0
// reader still accepts the document.
const SchemaVersion = "1.1.0"

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
	// Evidence lists the IDs of the artefacts in the result's provenance
	// that this candidate was read from.
	Evidence []string `json:"evidence,omitempty"`
	// Visibility and the ExposedVia fields are the localisation join rule
	// (docs/design/localisation-join-rule.md), resolved from the published
	// vulnerable tarball: public when the entry module exports the candidate
	// under this name and nothing else reaches it; internal with the public
	// names it is reached through otherwise; unknown when that cannot be
	// worked out. ExposedViaComplete is true only when every route was
	// resolved.
	Visibility         string   `json:"visibility,omitempty"`
	ExposedVia         []string `json:"exposedVia,omitempty"`
	ExposedViaSource   string   `json:"exposedViaSource,omitempty"`
	ExposedViaComplete *bool    `json:"exposedViaComplete,omitempty"`
}

// Provenance traces every candidate back to its source artefact.
type Provenance struct {
	AdvisorySource string     `json:"advisorySource,omitempty"`
	AdvisoryURL    string     `json:"advisoryUrl,omitempty"`
	PatchCommit    string     `json:"patchCommit,omitempty"`
	PatchURL       string     `json:"patchUrl,omitempty"`
	Artefacts      []Artefact `json:"artefacts,omitempty"`
	// TagChecks record whether the fix commit is in the release the npm
	// fixed version was published from, and absent from the vulnerable one.
	TagChecks []TagCheck `json:"tagChecks,omitempty"`
}

// ArtefactKind says what an artefact is and so how it was verified.
type ArtefactKind string

// Artefact kinds.
const (
	// ArtefactAdvisory is the OSV record, hashed in canonical JSON. Verified
	// means the record names the finding's vulnerability and this package.
	ArtefactAdvisory ArtefactKind = "advisory"
	// ArtefactSourceFile is one file at one commit. Verified means the git
	// blob hash of the bytes read matches the hash GitHub reports for that
	// path at that commit.
	ArtefactSourceFile ArtefactKind = "source_file"
	// ArtefactTarball is a published npm tarball. Verified means its bytes
	// match the registry's integrity value.
	ArtefactTarball ArtefactKind = "tarball"
)

// Artefact is a downloaded file. Executed is always false and is serialised
// explicitly so the validator can check it.
type Artefact struct {
	ID        string       `json:"id,omitempty"`
	Kind      ArtefactKind `json:"kind,omitempty"`
	URL       string       `json:"url"`
	SHA256    string       `json:"sha256,omitempty"`
	SizeBytes int64        `json:"sizeBytes,omitempty"`
	Verified  bool         `json:"verified"`
	Executed  bool         `json:"executed"`
	// Tarball identity.
	Version   string `json:"version,omitempty"`
	Integrity string `json:"integrity,omitempty"`
	// Source-file identity: the bytes are git blob GitBlobSHA, at Path in
	// Repo at Commit.
	Repo       string `json:"repo,omitempty"`
	Commit     string `json:"commit,omitempty"`
	Path       string `json:"path,omitempty"`
	GitBlobSHA string `json:"gitBlobSha,omitempty"`
	// Modified is the advisory record's own last-modified time. OSV records
	// change, so a later re-fetch may legitimately hash differently.
	Modified string `json:"modified,omitempty"`
	// Note says why an artefact is not verified.
	Note string `json:"note,omitempty"`
}

// TagRole is which side of the fix a release is on.
type TagRole string

// Tag roles.
const (
	TagRoleFixed      TagRole = "fixed"
	TagRoleVulnerable TagRole = "vulnerable"
)

// TagResult is the outcome of one tag check.
type TagResult string

// Tag check results.
const (
	// TagVerified: the fixed release contains the fix commit, or the
	// vulnerable release does not.
	TagVerified TagResult = "verified"
	// TagMismatch: the fixed release lacks the fix, or the vulnerable
	// release already has it.
	TagMismatch TagResult = "mismatch"
	// TagUnavailable: no release commit could be found or compared.
	TagUnavailable TagResult = "unavailable"
)

// TagBasis says how a tag check reached its result.
type TagBasis string

// Tag check bases.
const (
	// BasisAncestry: a linked fix commit is an ancestor of the release.
	BasisAncestry TagBasis = "ancestry"
	// BasisContent: no linked commit is an ancestor of the fixed release
	// (a backport or squash merge), but every line one of them adds is in
	// the release's copy of the file.
	BasisContent TagBasis = "content"
)

// ReleaseSource is where a tag check's release commit came from.
type ReleaseSource string

// Release sources.
const (
	ReleaseFromRegistryGitHead ReleaseSource = "registry_git_head"
	ReleaseFromGitTag          ReleaseSource = "git_tag"
)

// TagCheck is one release-to-fix check. ReleaseCommit is npm's gitHead when
// the registry records one, otherwise the git tag's commit.
type TagCheck struct {
	Version         string   `json:"version"`
	Role            TagRole  `json:"role"`
	Repo            string   `json:"repo"`
	FixCommits      []string `json:"fixCommits"`
	Tag             string   `json:"tag,omitempty"`
	TagCommit       string   `json:"tagCommit,omitempty"`
	RegistryGitHead string   `json:"registryGitHead,omitempty"`
	ReleaseCommit   string   `json:"releaseCommit,omitempty"`
	// ReleaseSource says where ReleaseCommit came from. A recorded gitHead
	// the repository does not have falls back to the git tag.
	ReleaseSource ReleaseSource `json:"releaseSource,omitempty"`
	// ByAncestry lists the fix commits that are ancestors of the release;
	// ByContent those that are not, but whose added lines are all in it.
	ByAncestry []string `json:"byAncestry,omitempty"`
	ByContent  []string `json:"byContent,omitempty"`
	// Content is the lines that were found for the ByContent commits, so
	// the check can be re-run.
	Content []FixContent `json:"content,omitempty"`
	Basis   TagBasis     `json:"basis,omitempty"`
	Result  TagResult    `json:"result"`
	Note    string       `json:"note,omitempty"`
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
	// fixCommits are the commits a patch_reference attempt attributed, and
	// fixContent the lines they add, for the release tag checks.
	fixCommits []gitHubCommit
	fixContent []FixContent
	// vulnerable is the vulnerable tarball a version_diff attempt already
	// read, reused for visibility.
	vulnerable *Tarball
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
