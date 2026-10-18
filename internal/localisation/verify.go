package localisation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Severity grades a verification issue. Errors mean a candidate cannot be
// traced to a verified artefact. Warnings are honest records that do not
// break the trace, such as a fix commit missing from a release tag.
type Severity string

// Severities.
const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// Issue is one verification problem.
type Issue struct {
	FindingID string   `json:"findingId"`
	Symbol    string   `json:"symbol,omitempty"`
	Artefact  string   `json:"artefact,omitempty"`
	Severity  Severity `json:"severity"`
	Message   string   `json:"message"`
}

// Verification is the outcome of checking a localisation document's
// provenance.
type Verification struct {
	SchemaVersion    string `json:"schemaVersion"`
	ScanID           string `json:"scanId"`
	Online           bool   `json:"online"`
	Results          int    `json:"results"`
	Candidates       int    `json:"candidates"`
	CandidatesTraced int    `json:"candidatesTraced"`
	Artefacts        int    `json:"artefacts"`
	Refetched        int    `json:"refetched"`
	// Unreachable counts artefacts that could not be re-fetched at all
	// (network, rate limit): the check is incomplete, not failed.
	Unreachable int               `json:"unreachable"`
	TagChecks   map[TagResult]int `json:"tagChecks"`
	Issues      []Issue           `json:"issues"`
}

// Errors counts error-severity issues.
func (v *Verification) Errors() int {
	n := 0
	for _, is := range v.Issues {
		if is.Severity == SeverityError {
			n++
		}
	}
	return n
}

func (v *Verification) add(sev Severity, finding, symbol, artefact, format string, args ...any) {
	v.Issues = append(v.Issues, Issue{FindingID: finding, Symbol: symbol, Artefact: artefact,
		Severity: sev, Message: fmt.Sprintf(format, args...)})
}

var reSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// VerifyDocument checks, without the network, that every candidate cites at
// least one artefact in its result's provenance, and that each cited
// artefact is complete, verified and was never executed. It reads the
// document as untrusted input.
func VerifyDocument(doc Document) Verification {
	v := Verification{SchemaVersion: doc.SchemaVersion, ScanID: doc.ScanID, Results: len(doc.Results),
		TagChecks: map[TagResult]int{}, Issues: []Issue{}}
	if doc.SchemaVersion != SchemaVersion {
		v.add(SeverityError, "", "", "", "schema %q records no per-candidate evidence; re-run sbomber localise to produce %s",
			doc.SchemaVersion, SchemaVersion)
	}
	if strings.TrimSpace(doc.ScanID) == "" {
		v.add(SeverityError, "", "", "", "document has no scanId")
	}
	if doc.Results == nil {
		v.add(SeverityError, "", "", "", "document has no results array")
	}
	seenFindings := map[string]bool{}
	for _, r := range doc.Results {
		if r.FindingID == "" || seenFindings[r.FindingID] {
			v.add(SeverityError, r.FindingID, "", "", "findingId is missing or repeated")
		}
		seenFindings[r.FindingID] = true
		strictIdentity := r.Method != MethodUnknown || len(r.CandidateSymbols) > 0
		if r.VulnerabilityID == "" || strictIdentity && !advisoryIDPattern.MatchString(r.VulnerabilityID) {
			v.add(SeverityError, r.FindingID, "", "", "invalid vulnerabilityId %q", r.VulnerabilityID)
		}
		_, installed, packageErr := ParsePURL(r.PURL)
		if !strings.HasPrefix(r.PURL, "pkg:") || len(r.PURL) <= 4 || strictIdentity && packageErr != nil {
			v.add(SeverityError, r.FindingID, "", "", "invalid package identity: %s", r.PURL)
		}
		if packageErr == nil && r.VulnerableVersion != "" && r.VulnerableVersion != installed {
			v.add(SeverityError, r.FindingID, "", "", "vulnerableVersion does not match the package URL")
		}
		switch r.Method {
		case MethodAdvisoryMetadata, MethodAdvisoryText, MethodPatchReference, MethodVersionDiff, MethodLLMSuggested, MethodUnknown:
		default:
			v.add(SeverityError, r.FindingID, "", "", "invalid localisation method %q", r.Method)
		}
		switch r.Confidence {
		case ConfidenceHigh, ConfidenceMedium, ConfidenceLow, ConfidenceNone:
		default:
			v.add(SeverityError, r.FindingID, "", "", "invalid confidence %q", r.Confidence)
		}
		if r.Method == MethodUnknown && (len(r.CandidateSymbols) > 0 || r.Confidence != ConfidenceNone) {
			v.add(SeverityError, r.FindingID, "", "", "unknown must have no candidates and no confidence")
		}

		var arts []Artefact
		if r.Provenance != nil {
			arts = r.Provenance.Artefacts
		}
		pkg, _, _ := ParsePURL(r.PURL)
		byID := map[string]Artefact{}
		for _, a := range arts {
			v.Artefacts++
			if a.Executed {
				v.add(SeverityError, r.FindingID, "", a.ID, "artefact records executed: true")
			}
			if a.ID == "" {
				v.add(SeverityError, r.FindingID, "", a.URL, "artefact has no id, so no candidate can cite it")
				continue
			}
			if _, dup := byID[a.ID]; dup {
				v.add(SeverityError, r.FindingID, "", a.ID, "artefact id is not unique within the result")
			}
			if want := expectedID(a, pkg); want != "" && a.ID != want {
				v.add(SeverityError, r.FindingID, "", a.ID, "artefact id does not match its fields (want %s)", want)
			}
			byID[a.ID] = a
		}
		allowed := evidenceKind(r.Method)
		if r.Method != MethodUnknown && r.Method != MethodLLMSuggested && len(r.CandidateSymbols) == 0 {
			v.add(SeverityError, r.FindingID, "", "", "method %s with no candidates", r.Method)
		}
		for _, c := range r.CandidateSymbols {
			v.Candidates++
			if strings.TrimSpace(c.Symbol) == "" {
				v.add(SeverityError, r.FindingID, "", "", "candidate has no symbol")
				continue
			}
			if len(c.Evidence) == 0 {
				v.add(SeverityError, r.FindingID, c.Symbol, "", "candidate cites no artefact")
				continue
			}
			traced := true
			for _, id := range c.Evidence {
				a, ok := byID[id]
				if !ok {
					v.add(SeverityError, r.FindingID, c.Symbol, id, "cited artefact is not in the result's provenance")
					traced = false
					continue
				}
				if msg := artefactIncomplete(a); msg != "" {
					v.add(SeverityError, r.FindingID, c.Symbol, id, "%s", msg)
					traced = false
				}
				if !a.Verified {
					note := a.Note
					if note == "" {
						note = "no reason recorded"
					}
					v.add(SeverityError, r.FindingID, c.Symbol, id, "cited artefact is not verified: %s", note)
					traced = false
				}
				if allowed != "" && a.Kind != allowed {
					v.add(SeverityError, r.FindingID, c.Symbol, id, "a %s candidate must cite a %s artefact, not %s", r.Method, allowed, a.Kind)
					traced = false
				}
				if a.Kind == ArtefactSourceFile && c.ModulePath != "" && a.Path != c.ModulePath {
					v.add(SeverityError, r.FindingID, c.Symbol, id, "candidate is in %s but cites %s", c.ModulePath, a.Path)
					traced = false
				}
			}
			if traced {
				v.CandidatesTraced++
			}
		}
		if r.Method == MethodPatchReference {
			verifyTagRecord(&v, r)
		}
	}
	return v
}

// evidenceKind is the artefact kind a method's candidates are read from.
func evidenceKind(m Method) ArtefactKind {
	switch m {
	case MethodPatchReference:
		return ArtefactSourceFile
	case MethodVersionDiff:
		return ArtefactTarball
	case MethodAdvisoryMetadata, MethodAdvisoryText:
		return ArtefactAdvisory
	}
	return ""
}

// expectedID is the id an artefact's own fields imply, or "" for a kind
// with no derived id.
func expectedID(a Artefact, pkg string) string {
	switch a.Kind {
	case ArtefactAdvisory:
		return AdvisoryArtefactID
	case ArtefactSourceFile:
		return SourceArtefactID(a.Repo, a.Commit, a.Path)
	case ArtefactTarball:
		if pkg != "" {
			return TarballArtefactID(pkg, a.Version)
		}
	}
	return ""
}

// artefactIncomplete names a missing identity field, or returns "".
func artefactIncomplete(a Artefact) string {
	if !reSHA256.MatchString(a.SHA256) {
		return "cited artefact has no SHA-256"
	}
	switch a.Kind {
	case ArtefactAdvisory:
		if a.URL == "" {
			return "advisory artefact has no URL"
		}
	case ArtefactSourceFile:
		if err := validateRepo(a.Repo); err != nil {
			return err.Error()
		}
		if err := validateRepoPath(a.Path); err != nil {
			return err.Error()
		}
		if a.Repo == "" || a.Path == "" || !reFullSHA.MatchString(a.Commit) || !reFullSHA.MatchString(a.GitBlobSHA) {
			return "source_file artefact needs repo, path, a full commit SHA and a git blob SHA"
		}
	case ArtefactTarball:
		if a.Version == "" || a.URL == "" {
			return "tarball artefact needs a version and a URL"
		}
	default:
		return fmt.Sprintf("artefact kind %q is not advisory, source_file or tarball", a.Kind)
	}
	return ""
}

// verifyTagRecord checks a patch_reference result's tag checks. A missing or
// failed tag check is a warning: the candidates are still traced by
// checksum, and a release that does not contain the linked commit is a
// finding about the advisory, not a broken trace.
func verifyTagRecord(v *Verification, r Result) {
	p := r.Provenance
	if p == nil {
		return
	}
	fixedChecked := false
	for _, tc := range p.TagChecks {
		v.TagChecks[tc.Result]++
		if msg := tagRecordInvalid(r, tc); msg != "" {
			v.add(SeverityError, r.FindingID, "", "", "invalid tag check: %s", msg)
		}
		if tc.Role == TagRoleFixed {
			fixedChecked = true
		}
		if tc.Result != TagVerified {
			v.add(SeverityWarning, r.FindingID, "", "", "tag check %s %s: %s (%s)", tc.Role, tc.Version, tc.Result, tc.Note)
		}
		if tc.RegistryGitHead != "" && tc.ReleaseSource == ReleaseFromGitTag {
			v.add(SeverityWarning, r.FindingID, "", "", "tag check %s %s: npm's gitHead %s could not be compared in %s, so the git tag %s was used",
				tc.Role, tc.Version, short(tc.RegistryGitHead), tc.Repo, tc.Tag)
		}
	}
	if !fixedChecked && r.FixedVersion != "" {
		v.add(SeverityWarning, r.FindingID, "", "", "no tag check against the fixed release %s", r.FixedVersion)
	}
	fixSide := false
	for _, a := range p.Artefacts {
		if a.Kind == ArtefactSourceFile && p.PatchCommit != "" && sameCommit(a.Commit, p.PatchCommit) {
			fixSide = true
		}
	}
	if p.PatchCommit != "" && !fixSide {
		v.add(SeverityWarning, r.FindingID, "", "", "no file at patch commit %s is recorded; candidates rest on the parent side only", short(p.PatchCommit))
	}
}

// Refetch re-downloads every artefact the document cites, rebuilding each
// request from validated identifiers rather than following URLs from the
// document, and compares the bytes with the recorded checksums. Each
// candidate's symbol must occur in the bytes of an artefact it cites, so a
// made-up candidate cannot borrow a real artefact. Recorded tag checks are
// re-run. It adds to a Verification from VerifyDocument.
func (l *Localiser) Refetch(ctx context.Context, doc Document, v *Verification) {
	v.Online = true
	// Keyed on every field the re-fetch uses, so two records that share an
	// id but differ in what they claim are each checked.
	done := map[string]*refetched{}
	type fixRead struct {
		content []FixContent
		err     error
	}
	fixesRead := map[string]fixRead{}
	for _, r := range doc.Results {
		if r.Provenance == nil {
			continue
		}
		name, _, err := ParsePURL(r.PURL)
		if err != nil {
			continue
		}
		got := map[string]*refetched{}
		for _, a := range r.Provenance.Artefacts {
			k := refetchKey(name, a)
			o, seen := done[k]
			if !seen {
				o = l.refetchOne(ctx, name, a)
				done[k] = o
				v.Refetched++
				if o.unreachable {
					v.Unreachable++
				}
			}
			got[a.ID] = o
			if o.msg != "" {
				v.add(o.sev, r.FindingID, "", a.ID, "%s", o.msg)
			}
			// Download caching is per artefact, but identity belongs to
			// each result. Never let a second finding borrow the first's
			// successful advisory identity check.
			if a.Kind == ArtefactAdvisory && len(o.body) > 0 && o.sev != SeverityError {
				var rec osvRecord
				if err := json.Unmarshal(o.body, &rec); err != nil {
					v.add(SeverityError, r.FindingID, "", a.ID, "advisory is not valid JSON: %v", err)
				} else {
					finding := Finding{VulnerabilityID: r.VulnerabilityID, PURL: r.PURL}
					checked := advisoryArtefact(a.URL, o.body, rec, finding, advisoryFromOSV(rec, r.PURL))
					if !checked.Verified {
						v.add(SeverityError, r.FindingID, "", a.ID, "%s", checked.Note)
					}
				}
			}
		}
		for _, c := range r.CandidateSymbols {
			found, checked := false, false
			for _, id := range c.Evidence {
				o := got[id]
				if o == nil || o.sev == SeverityError {
					continue
				}
				checked = true
				found = found || o.mentions(c.ModulePath, c.Symbol)
			}
			if checked && !found {
				v.add(SeverityError, r.FindingID, c.Symbol, "", "the symbol does not occur in any artefact it cites")
			}
		}
		for _, tc := range r.Provenance.TagChecks {
			if msg := tagRecordInvalid(r, tc); msg != "" {
				v.add(SeverityError, r.FindingID, "", "", "invalid tag check: %s", msg)
				continue
			}
			// Content evidence in the input is a claim, not a patch.
			// Rebuild it from the actual fix commit and checksummed files.
			var content []FixContent
			contentOK := true
			if tc.Basis == BasisContent || len(tc.ByContent) > 0 || len(tc.Content) > 0 {
				for _, fix := range tc.FixCommits {
					key := tc.Repo + "@" + fix
					read, seen := fixesRead[key]
					if !seen {
						read.content, read.err = l.readFixContent(ctx, tc.Repo, fix)
						fixesRead[key] = read
					}
					if read.err != nil {
						v.add(SeverityError, r.FindingID, "", "", "could not verify fix content: %v", read.err)
						contentOK = false
						break
					}
					content = append(content, read.content...)
				}
			}
			if !contentOK {
				continue
			}
			again := l.tagCheck(ctx, tc.Repo, tc.FixCommits, content, name, tc.Version, tc.Role)
			same := again.Result == tc.Result && again.ReleaseCommit == tc.ReleaseCommit && again.Basis == tc.Basis &&
				again.ReleaseSource == tc.ReleaseSource && again.RegistryGitHead == tc.RegistryGitHead &&
				again.Tag == tc.Tag && again.TagCommit == tc.TagCommit &&
				slices.Equal(again.ByAncestry, tc.ByAncestry) && slices.Equal(again.ByContent, tc.ByContent) &&
				slices.EqualFunc(again.Content, tc.Content, func(a, b FixContent) bool {
					return a.Commit == b.Commit && a.Parent == b.Parent && a.Path == b.Path && slices.Equal(a.Lines, b.Lines)
				})
			switch {
			case same:
			case again.Result == TagUnavailable:
				v.add(SeverityWarning, r.FindingID, "", "", "tag check %s %s could not be re-run: %s", tc.Role, tc.Version, again.Note)
			default:
				v.add(SeverityError, r.FindingID, "", "", "tag check %s %s was %s/%s (release %s), re-run gives %s/%s (release %s): %s",
					tc.Role, tc.Version, tc.Result, tc.Basis, short(tc.ReleaseCommit), again.Result, again.Basis, short(again.ReleaseCommit), again.Note)
			}
		}
	}
}

// refetched is the outcome of re-fetching one artefact, with the bytes kept
// so candidate symbols can be looked for in them.
type refetched struct {
	sev         Severity
	msg         string
	unreachable bool
	body        []byte            // source file or canonical advisory
	sourcePath  string            // set only for source files; needed to check default exports
	files       map[string][]byte // tarball sources by path
}

func (o *refetched) mentions(modulePath, symbol string) bool {
	if o.files == nil {
		return sourceMentions(o.sourcePath, o.body, symbol)
	}
	if src, ok := o.files[modulePath]; ok {
		return sourceMentions(modulePath, src, symbol)
	}
	if modulePath != "" {
		return false
	}
	for path, src := range o.files {
		if sourceMentions(path, src, symbol) {
			return true
		}
	}
	return false
}

// sourceMentions checks synthetic default names using the same parser that
// produced them. The spelling need not occur in module.exports = function...
// bytes, but a real callable/default export must exist. Advisories retain
// literal symbol checks because their prose is not JavaScript.
func sourceMentions(path string, body []byte, symbol string) bool {
	if symbol != "default" || path == "" {
		return bytes.Contains(body, []byte(symbol))
	}
	fs, err := ParseSymbols(path, body)
	if err != nil || fs.Minified {
		return false
	}
	for _, fn := range fs.Functions {
		if fn.Anonymous {
			continue
		}
		if fn.Name == "default" || slices.Contains(fn.Aliases, "default") || slices.Contains(fs.ExportedNames(fn.Name), "default") {
			return true
		}
	}
	return false
}

func tagRecordInvalid(r Result, tc TagCheck) string {
	switch tc.Result {
	case TagVerified, TagMismatch, TagUnavailable:
	default:
		return "invalid tag-check result"
	}
	switch tc.Basis {
	case "", BasisAncestry, BasisContent:
	default:
		return "invalid tag-check basis"
	}

	if err := validateRepo(tc.Repo); err != nil {
		return err.Error()
	}
	if !validVersion(tc.Version) {
		return "invalid version"
	}
	var expected string
	switch tc.Role {
	case TagRoleFixed:
		expected = r.FixedVersion
	case TagRoleVulnerable:
		expected = r.VulnerableVersion
		if expected == "" {
			_, expected, _ = ParsePURL(r.PURL)
		}
	default:
		return "invalid release role"
	}
	if expected == "" || tc.Version != expected {
		return "release version does not match its result"
	}
	if len(tc.FixCommits) == 0 {
		return "no fix commits"
	}
	for _, fix := range tc.FixCommits {
		if !reSHA.MatchString(fix) {
			return "invalid fix commit"
		}
	}
	return ""
}

// readFixContent rebuilds the complete supported-source additions for a fix.
// Saved parent SHAs, paths and lines are never used to construct requests.
func (l *Localiser) readFixContent(ctx context.Context, repo, fix string) ([]FixContent, error) {
	ci, err := l.c.Commit(ctx, repo, fix)
	if err != nil {
		return nil, err
	}
	if !reFullSHA.MatchString(ci.SHA) || !sameCommit(fix, ci.SHA) {
		return nil, fmt.Errorf("fix commit identity does not match %s", fix)
	}
	parent := ""
	if len(ci.Parents) > 0 {
		parent = ci.Parents[0].SHA
		if !reFullSHA.MatchString(parent) {
			return nil, fmt.Errorf("invalid fix parent")
		}
	}
	blobs := map[string]string{}
	for _, file := range ci.Files {
		blobs[file.Filename] = file.SHA
	}
	var out []FixContent
	for _, diff := range fileDiffsFromCommit(ci) {
		path := diff.Path()
		if classifyPath(path) != "" || !SupportedSourceFile(path) || diff.Binary || diff.Status == "removed" {
			continue
		}
		added, _ := diff.ChangedLines()
		if len(added) == 0 {
			continue
		}
		body, art, err := l.c.sourceArtefact(ctx, repo, path, ci.SHA, blobs[path])
		if err != nil {
			return nil, err
		}
		if !art.Verified {
			return nil, fmt.Errorf("unverified fix file %s: %s", path, art.Note)
		}
		if lines := distinctiveLines(body, added); len(lines) > 0 {
			out = append(out, FixContent{Commit: fix, Parent: parent, Path: path, Lines: lines})
		}
	}
	return out, nil
}

func refetchKey(pkg string, a Artefact) string {
	return strings.Join([]string{string(a.Kind), a.SHA256, a.URL, a.Repo, a.Commit, a.Path, a.GitBlobSHA, pkg, a.Version}, "|")
}

func unreachable(what string, err error) *refetched {
	return &refetched{sev: SeverityError, unreachable: true, msg: "could not re-fetch (" + what + "): " + errString(err)}
}

// refetchOne re-fetches one artefact; msg is empty when it still matches.
func (l *Localiser) refetchOne(ctx context.Context, pkg string, a Artefact) *refetched {
	fail := func(format string, args ...any) *refetched {
		return &refetched{sev: SeverityError, msg: fmt.Sprintf(format, args...)}
	}
	switch a.Kind {
	case ArtefactSourceFile:
		body, reported, err := l.c.FileBlobAt(ctx, a.Repo, a.Path, a.Commit)
		if err != nil {
			if strings.HasPrefix(err.Error(), "invalid ") {
				return fail("cannot re-fetch: %v", err)
			}
			return unreachable("file", err)
		}
		if got := gitBlobSHA(body); got != a.GitBlobSHA || reported != a.GitBlobSHA {
			return fail("file at %s is now blob %s, recorded %s", short(a.Commit), short(got), short(a.GitBlobSHA))
		}
		if sha256Hex(body) != a.SHA256 {
			return fail("SHA-256 of the re-fetched file differs from the record")
		}
		return &refetched{body: body, sourcePath: a.Path}
	case ArtefactTarball:
		pv, err := l.c.RegistryVersion(ctx, pkg, a.Version)
		if err != nil {
			if strings.HasPrefix(err.Error(), "invalid ") || strings.HasPrefix(err.Error(), "registry returned") {
				return fail("cannot re-fetch: %v", err)
			}
			return unreachable("registry", err)
		}
		if pv.Tarball != a.URL {
			return fail("registry now names tarball %s, recorded %s", pv.Tarball, a.URL)
		}
		tb, err := l.c.FetchTarball(ctx, pv, l.opts.MaxTarballBytes)
		if tb == nil {
			return unreachable("tarball", err)
		}
		if tb.Artefact.SHA256 != a.SHA256 {
			return fail("SHA-256 of the re-downloaded tarball differs from the record")
		}
		if !tb.Artefact.Verified {
			return fail("re-downloaded tarball no longer matches the registry integrity value")
		}
		return &refetched{files: tb.Files}
	case ArtefactAdvisory:
		i := strings.LastIndex(a.URL, "/v1/vulns/")
		if i < 0 {
			return fail("advisory URL does not name an OSV record")
		}
		id := a.URL[i+len("/v1/vulns/"):]
		if !advisoryIDPattern.MatchString(id) {
			return fail("advisory id %q is not a CVE or GHSA identifier", id)
		}
		body, _, err := l.c.get(ctx, l.c.OSVBaseURL+"/v1/vulns/"+id, "application/json", maxJSONResponseBytes)
		if err != nil {
			return unreachable("advisory", err)
		}
		canon, err := canonicalJSON(body)
		if err != nil {
			return fail("re-fetched advisory is not JSON: %v", err)
		}
		o := &refetched{body: canon}
		if sha256Hex(canon) != a.SHA256 {
			// OSV records are edited after publication, so this is not a
			// broken trace; the record's modified time says whether it moved.
			o.sev, o.msg = SeverityWarning, "advisory record has changed since it was read (recorded modified "+a.Modified+")"
		}
		return o
	}
	return fail("cannot re-fetch artefact kind %q", a.Kind)
}

// SortIssues orders issues errors first, then by finding.
func SortIssues(is []Issue) {
	sort.SliceStable(is, func(i, j int) bool {
		if is[i].Severity != is[j].Severity {
			return is[i].Severity == SeverityError
		}
		return is[i].FindingID < is[j].FindingID
	})
}
