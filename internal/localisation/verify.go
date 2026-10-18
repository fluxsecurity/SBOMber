package localisation

import (
	"context"
	"fmt"
	"regexp"
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
	SchemaVersion    string            `json:"schemaVersion"`
	ScanID           string            `json:"scanId"`
	Online           bool              `json:"online"`
	Results          int               `json:"results"`
	Candidates       int               `json:"candidates"`
	CandidatesTraced int               `json:"candidatesTraced"`
	Artefacts        int               `json:"artefacts"`
	Refetched        int               `json:"refetched"`
	TagChecks        map[TagResult]int `json:"tagChecks"`
	Issues           []Issue           `json:"issues"`
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
	for _, r := range doc.Results {
		var arts []Artefact
		if r.Provenance != nil {
			arts = r.Provenance.Artefacts
		}
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
			byID[a.ID] = a
		}
		if r.Method != MethodUnknown && r.Method != MethodLLMSuggested && len(r.CandidateSymbols) == 0 {
			v.add(SeverityError, r.FindingID, "", "", "method %s with no candidates", r.Method)
		}
		for _, c := range r.CandidateSymbols {
			v.Candidates++
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
		if tc.Role == TagRoleFixed {
			fixedChecked = true
		}
		if tc.Result != TagVerified {
			v.add(SeverityWarning, r.FindingID, "", "", "tag check %s %s: %s (%s)", tc.Role, tc.Version, tc.Result, tc.Note)
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
// document, and compares the bytes with the recorded checksums. Recorded tag
// checks are re-run. It adds to a Verification from VerifyDocument.
func (l *Localiser) Refetch(ctx context.Context, doc Document, v *Verification) {
	v.Online = true
	type outcome struct {
		sev Severity
		msg string
	}
	done := map[string]*outcome{}
	keys := func(r Result, a Artefact) string { return string(a.Kind) + "|" + a.ID + "|" + a.SHA256 + "|" + r.PURL }
	for _, r := range doc.Results {
		if r.Provenance == nil {
			continue
		}
		name, _, err := ParsePURL(r.PURL)
		if err != nil {
			continue
		}
		for _, a := range r.Provenance.Artefacts {
			k := keys(r, a)
			o, seen := done[k]
			if !seen {
				o = &outcome{}
				o.sev, o.msg = l.refetchOne(ctx, name, a)
				done[k] = o
				v.Refetched++
			}
			if o.msg != "" {
				v.add(o.sev, r.FindingID, "", a.ID, "%s", o.msg)
			}
		}
		for _, tc := range r.Provenance.TagChecks {
			valid := len(tc.FixCommits) > 0
			for _, f := range tc.FixCommits {
				valid = valid && reSHA.MatchString(f)
			}
			if !valid || !validVersion(tc.Version) {
				v.add(SeverityError, r.FindingID, "", "", "tag check has invalid fix commits %q or version %q", tc.FixCommits, tc.Version)
				continue
			}
			again := l.tagCheck(ctx, tc.Repo, tc.FixCommits, tc.Content, name, tc.Version, tc.Role)
			if again.Result != tc.Result || again.ReleaseCommit != tc.ReleaseCommit || again.Basis != tc.Basis ||
				len(again.ByAncestry) != len(tc.ByAncestry) || len(again.ByContent) != len(tc.ByContent) {
				v.add(SeverityWarning, r.FindingID, "", "", "tag check %s %s was %s/%s (release %s), now %s/%s (release %s): %s",
					tc.Role, tc.Version, tc.Result, tc.Basis, short(tc.ReleaseCommit), again.Result, again.Basis, short(again.ReleaseCommit), again.Note)
			}
		}
	}
}

// refetchOne returns ("", "") when the artefact still matches.
func (l *Localiser) refetchOne(ctx context.Context, pkg string, a Artefact) (Severity, string) {
	switch a.Kind {
	case ArtefactSourceFile:
		body, reported, err := l.c.FileBlobAt(ctx, a.Repo, a.Path, a.Commit)
		if err != nil {
			return SeverityError, "re-fetch failed: " + err.Error()
		}
		if got := gitBlobSHA(body); got != a.GitBlobSHA || reported != a.GitBlobSHA {
			return SeverityError, fmt.Sprintf("file at %s is now blob %s, recorded %s", short(a.Commit), short(got), short(a.GitBlobSHA))
		}
		if sha256Hex(body) != a.SHA256 {
			return SeverityError, "SHA-256 of the re-fetched file differs from the record"
		}
	case ArtefactTarball:
		pv, err := l.c.RegistryVersion(ctx, pkg, a.Version)
		if err != nil {
			return SeverityError, "registry lookup failed: " + err.Error()
		}
		if pv.Tarball != a.URL {
			return SeverityError, "registry now names tarball " + pv.Tarball + ", recorded " + a.URL
		}
		tb, err := l.c.FetchTarball(ctx, pv, l.opts.MaxTarballBytes)
		if tb == nil {
			return SeverityError, "re-download failed: " + errString(err)
		}
		if tb.Artefact.SHA256 != a.SHA256 {
			return SeverityError, "SHA-256 of the re-downloaded tarball differs from the record"
		}
		if !tb.Artefact.Verified {
			return SeverityError, "re-downloaded tarball no longer matches the registry integrity value"
		}
	case ArtefactAdvisory:
		i := strings.LastIndex(a.URL, "/v1/vulns/")
		if i < 0 {
			return SeverityError, "advisory URL does not name an OSV record"
		}
		id := a.URL[i+len("/v1/vulns/"):]
		if !advisoryIDPattern.MatchString(id) {
			return SeverityError, fmt.Sprintf("advisory id %q is not a CVE or GHSA identifier", id)
		}
		body, _, err := l.c.get(ctx, l.c.OSVBaseURL+"/v1/vulns/"+id, "application/json", maxJSONResponseBytes)
		if err != nil {
			return SeverityError, "re-fetch failed: " + err.Error()
		}
		canon, err := canonicalJSON(body)
		if err != nil {
			return SeverityError, "re-fetched advisory is not JSON: " + err.Error()
		}
		if sha256Hex(canon) != a.SHA256 {
			// OSV records are edited after publication, so this is not a
			// broken trace; the record's modified time says whether it moved.
			return SeverityWarning, "advisory record has changed since it was read (recorded modified " + a.Modified + ")"
		}
	default:
		return SeverityError, fmt.Sprintf("cannot re-fetch artefact kind %q", a.Kind)
	}
	return "", ""
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
