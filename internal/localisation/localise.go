package localisation

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Options configures a Localiser.
type Options struct {
	HTTPClient       *http.Client
	OSVBaseURL       string
	GitHubAPIBaseURL string
	RegistryBaseURL  string
	GitHubToken      string
	// MaxTarballBytes bounds each npm tarball download.
	MaxTarballBytes int64
	// AllMethods runs every method even after one has answered, so the
	// evaluation can measure each source independently. The selected result
	// still follows the fallback order.
	AllMethods bool
	// ClientMethodSearch enables the commit-message search the client asked
	// for. It costs one GitHub search request per finding.
	ClientMethodSearch bool
}

// Localiser produces localisation.json results.
type Localiser struct {
	c    *Client
	opts Options
}

// New builds a Localiser.
func New(opts Options) *Localiser {
	return &Localiser{c: newClient(opts), opts: opts}
}

// LocaliseAll runs every finding and assembles the contract document plus a
// per-finding trace.
func (l *Localiser) LocaliseAll(ctx context.Context, scanID string, findings []Finding) (Document, []Trace) {
	doc := Document{SchemaVersion: SchemaVersion, ScanID: scanID, Results: []Result{}, Summary: &Summary{ByMethod: map[string]int{}}}
	traces := make([]Trace, 0, len(findings))
	for _, f := range findings {
		r, t := l.Localise(ctx, f)
		doc.Results = append(doc.Results, r)
		traces = append(traces, t)
		doc.Summary.FindingsProcessed++
		doc.Summary.ByMethod[string(r.Method)]++
		if r.Method == MethodUnknown {
			doc.Summary.UnknownCount++
		}
	}
	return doc, traces
}

// Localise runs the methods for one finding in fallback order and returns
// the contract result and the evidence trace. It never returns an error: a
// finding that cannot be localised is an honest `unknown`.
func (l *Localiser) Localise(ctx context.Context, f Finding) (Result, Trace) {
	trace := Trace{FindingID: f.FindingID, VulnerabilityID: f.VulnerabilityID, PURL: f.PURL}
	res := Result{FindingID: f.FindingID, VulnerabilityID: f.VulnerabilityID, PURL: f.PURL,
		Method: MethodUnknown, Confidence: ConfidenceNone, CandidateSymbols: []Candidate{}}

	name, version, err := ParsePURL(f.PURL)
	if err != nil {
		trace.Attempts = append(trace.Attempts, Attempt{Method: MethodUnknown, Outcome: OutcomeError, Notes: []string{err.Error()}})
		res.Notes = "Not an npm package URL; only npm is supported in Sprint 4. " + err.Error()
		trace.Selected = MethodUnknown
		return res, trace
	}
	res.VulnerableVersion = version
	res.FixedVersion = f.FixedVersion

	// Advisory first: three of the four methods depend on it.
	adv, advErr := l.c.FetchAdvisory(ctx, f)
	var prov Provenance
	if adv != nil {
		prov.AdvisorySource = adv.Source
		prov.AdvisoryURL = adv.URL
		if res.FixedVersion == "" {
			res.FixedVersion = adv.FixedVersionFor(version)
		}
	}

	var attempts []Attempt
	stop := func() bool {
		if l.opts.AllMethods {
			return false
		}
		for _, a := range attempts {
			if a.Outcome == OutcomeHit {
				return true
			}
		}
		return false
	}

	// 1. advisory_metadata
	attempts = append(attempts, l.attemptMetadata(adv, advErr))

	// 2. patch_reference (includes the client's commit-message check)
	var patchCands []Candidate
	if !stop() {
		a := l.attemptPatch(ctx, adv, advErr, name, version, res.FixedVersion)
		attempts = append(attempts, a)
		patchCands = a.Candidates
	}

	// 3. advisory_text
	if !stop() {
		attempts = append(attempts, l.attemptText(adv, advErr, name))
	}

	// 4. version_diff
	if !stop() {
		attempts = append(attempts, l.attemptVersionDiff(ctx, name, version, res.FixedVersion))
	}
	trace.Attempts = attempts

	// Select the first hit in fallback order.
	var sel *Attempt
	for i := range attempts {
		if attempts[i].Outcome == OutcomeHit {
			sel = &attempts[i]
			break
		}
	}
	if sel == nil {
		trace.Selected = MethodUnknown
		res.Provenance = provenanceOrNil(prov)
		res.Notes = summariseFailure(attempts, adv, advErr)
		return res, trace
	}
	trace.Selected = sel.Method
	res.Method = sel.Method
	res.CandidateSymbols = sel.Candidates
	res.ExcludedChanges = sel.ExcludedChanges
	if sel.Provenance != nil {
		prov.PatchCommit = sel.Provenance.PatchCommit
		prov.PatchURL = sel.Provenance.PatchURL
		prov.Artefacts = sel.Provenance.Artefacts
	}
	res.Provenance = provenanceOrNil(prov)
	res.Confidence = confidenceFor(*sel, patchCands, attempts)
	res.Notes = summariseSelection(*sel, attempts)
	return res, trace
}

func provenanceOrNil(p Provenance) *Provenance {
	if p.AdvisorySource == "" && p.PatchCommit == "" && len(p.Artefacts) == 0 {
		return nil
	}
	return &p
}

// ---------------------------------------------------------------- methods

func (l *Localiser) attemptMetadata(adv *Advisory, advErr error) Attempt {
	a := Attempt{Method: MethodAdvisoryMetadata}
	if adv == nil {
		a.Outcome = OutcomeError
		a.Notes = []string{"advisory unavailable: " + errString(advErr)}
		return a
	}
	fns := adv.StructuredFunctions()
	if len(fns) == 0 {
		a.Outcome = OutcomeEmpty
		if len(adv.EcosystemSpecific) == 0 {
			a.Notes = []string{"OSV record has no ecosystem_specific block for this npm package; no structured function field exists"}
		} else {
			a.Notes = []string{"ecosystem_specific present but names no functions"}
		}
		return a
	}
	a.Outcome = OutcomeHit
	for _, fn := range fns {
		a.Candidates = append(a.Candidates, Candidate{Symbol: fn, Note: "named in structured advisory metadata"})
	}
	return a
}

func (l *Localiser) attemptText(adv *Advisory, advErr error, pkg string) Attempt {
	a := Attempt{Method: MethodAdvisoryText}
	if adv == nil {
		a.Outcome = OutcomeError
		a.Notes = []string{"advisory unavailable: " + errString(advErr)}
		return a
	}
	fns := adv.FunctionsFromText(pkg)
	if len(fns) == 0 {
		a.Outcome = OutcomeEmpty
		a.Notes = []string{"advisory prose names no function-like identifier"}
		return a
	}
	a.Outcome = OutcomeHit
	for _, fn := range fns {
		a.Candidates = append(a.Candidates, Candidate{Symbol: fn, Note: "named in advisory text"})
	}
	if len(fns) > 3 {
		a.Notes = append(a.Notes, fmt.Sprintf("%d identifiers extracted from prose; heuristic extraction is over-inclusive", len(fns)))
	}
	return a
}

// attemptPatch resolves the advisory's commit and pull-request links, fetches
// each commit, and attributes its changed lines. When the advisory links
// nothing, the client's commit-message search supplies candidates.
func (l *Localiser) attemptPatch(ctx context.Context, adv *Advisory, advErr error, pkg, version, fixed string) Attempt {
	a := Attempt{Method: MethodPatchReference}
	if adv == nil {
		a.Outcome = OutcomeError
		a.Notes = []string{"advisory unavailable: " + errString(advErr)}
		return a
	}
	commits, prs, repo := adv.PatchReferences()

	// Resolve pull requests to commits.
	for _, pr := range prs {
		shas, err := l.c.PullRequestCommits(ctx, pr.Repo, pr.Number)
		if err != nil {
			a.Notes = append(a.Notes, fmt.Sprintf("pull request %s#%s: %v", pr.Repo, pr.Number, err))
			continue
		}
		for _, sha := range shas {
			commits = append(commits, gitHubCommit{Repo: pr.Repo, SHA: sha})
		}
		a.Notes = append(a.Notes, fmt.Sprintf("pull request %s#%s resolved to %d commit(s)", pr.Repo, pr.Number, len(shas)))
	}

	// Client's method: search commit messages for the vulnerability ID.
	if repo == "" {
		if pv, err := l.c.RegistryVersion(ctx, pkg, version); err == nil {
			repo = RepoFromRegistryURL(pv.Repository)
		}
	}
	if l.opts.ClientMethodSearch && repo != "" {
		cm := &ClientMethodEvidence{Repository: repo}
		ids := []string{adv.ID}
		ids = append(ids, adv.Aliases...)
		seenSHA := map[string]bool{}
		for _, id := range ids {
			if !advisoryIDPattern.MatchString(id) {
				continue
			}
			_, shas, err := l.c.SearchCommits(ctx, repo, id)
			if err != nil {
				cm.Error = err.Error()
				break
			}
			cm.Query += id + " "
			for _, sha := range shas {
				if !seenSHA[sha] {
					seenSHA[sha] = true
					cm.CommitSHAs = append(cm.CommitSHAs, sha)
				}
			}
		}
		cm.CommitsMatched = len(cm.CommitSHAs)
		cm.Query = strings.TrimSpace(cm.Query)
		a.ClientMethod = cm
		if len(commits) == 0 && len(cm.CommitSHAs) > 0 {
			for _, sha := range cm.CommitSHAs {
				commits = append(commits, gitHubCommit{Repo: repo, SHA: sha})
			}
			a.Notes = append(a.Notes, "no fix link in the advisory; commits found by searching messages for the vulnerability ID")
		}
	}

	if len(commits) == 0 {
		a.Outcome = OutcomeEmpty
		a.Notes = append(a.Notes, "advisory links no commit or pull request")
		return a
	}

	// Prefer the commit the fixed release was published from, when npm knows it.
	preferred := ""
	if fixed != "" {
		if pv, err := l.c.RegistryVersion(ctx, pkg, fixed); err == nil && pv.GitHead != "" {
			for _, c := range commits {
				if strings.HasPrefix(pv.GitHead, c.SHA) || strings.HasPrefix(c.SHA, pv.GitHead) {
					preferred = c.SHA
					a.Notes = append(a.Notes, fmt.Sprintf("commit %s is the registry gitHead of %s@%s; other referenced commits ignored", short(c.SHA), pkg, fixed))
				}
			}
		}
	}

	var files []changedFile
	var used []string
	usedSet := map[string]bool{}
	nonCode := 0
	for _, c := range commits {
		if preferred != "" && c.SHA != preferred {
			continue
		}
		if usedSet[c.Repo+"@"+c.SHA] {
			continue
		}
		usedSet[c.Repo+"@"+c.SHA] = true
		ci, err := l.c.Commit(ctx, c.Repo, c.SHA)
		if err != nil {
			a.Notes = append(a.Notes, fmt.Sprintf("commit %s@%s: %v", c.Repo, short(c.SHA), err))
			continue
		}
		diffs := fileDiffsFromCommit(ci)
		codeFiles := 0
		parent := ""
		if len(ci.Parents) > 0 {
			parent = ci.Parents[0].SHA
		}
		for _, d := range diffs {
			p := d.Path()
			if classifyPath(p) != "" || !SupportedSourceFile(p) || d.Binary {
				if d.Binary && SupportedSourceFile(p) && classifyPath(p) == "" {
					a.Notes = append(a.Notes, p+": patch not inlined by the API (too large or binary)")
				}
				if classifyPath(p) != "" {
					files = append(files, changedFile{Path: p, Status: d.Status})
				}
				continue
			}
			codeFiles++
			cf := changedFile{Path: p, Status: d.Status}
			cf.Added, cf.Removed = d.ChangedLines()
			if len(cf.Added) > 0 && d.Status != "removed" {
				src, err := l.c.FileAt(ctx, c.Repo, p, ci.SHA)
				if err != nil {
					cf.FetchError = "could not fetch fixed file: " + err.Error()
				} else {
					cf.NewSource = src
				}
			}
			if len(cf.Removed) > 0 && parent != "" && d.Status != "added" {
				oldPath := d.OldPath
				if oldPath == "" {
					oldPath = p
				}
				src, err := l.c.FileAt(ctx, c.Repo, oldPath, parent)
				if err != nil {
					if cf.FetchError == "" {
						cf.FetchError = "could not fetch vulnerable file: " + err.Error()
					}
				} else {
					cf.OldSource = src
				}
			}
			files = append(files, cf)
		}
		if codeFiles == 0 {
			nonCode++
			a.Notes = append(a.Notes, fmt.Sprintf("commit %s changes no source code (release or docs commit)", short(c.SHA)))
			continue
		}
		used = append(used, c.Repo+"@"+c.SHA)
	}

	att := attributeChanges(files)
	a.Candidates = att.Candidates
	a.NonFunctionChanges = att.NonFunction
	a.ExcludedChanges = att.Excluded
	a.Notes = append(a.Notes, att.Notes...)
	if len(used) > 0 {
		a.Provenance = &Provenance{}
		first := strings.SplitN(used[0], "@", 2)
		a.Provenance.PatchCommit = first[1]
		a.Provenance.PatchURL = "https://github.com/" + first[0] + "/commit/" + first[1]
		if len(used) > 1 {
			a.Notes = append(a.Notes, fmt.Sprintf("%d commits attributed and merged: %s", len(used), strings.Join(shortAll(used), ", ")))
		}
	}
	switch {
	case len(a.Candidates) > 0:
		a.Outcome = OutcomeHit
	case len(used) == 0 && nonCode > 0:
		a.Outcome = OutcomeNonCode
	case len(used) == 0:
		a.Outcome = OutcomeError
	default:
		a.Outcome = OutcomeEmpty
		a.Notes = append(a.Notes, "fix commit changed code but no changed line fell inside a named function")
	}
	return a
}

// attemptVersionDiff downloads the vulnerable and fixed tarballs, verifies
// them, diffs their source files in memory and attributes the changes.
func (l *Localiser) attemptVersionDiff(ctx context.Context, pkg, version, fixed string) Attempt {
	a := Attempt{Method: MethodVersionDiff}
	if fixed == "" {
		a.Outcome = OutcomeSkipped
		a.Notes = []string{"no fixed version known; nothing to diff against"}
		return a
	}
	fetch := func(v string) (*Tarball, error) {
		pv, err := l.c.RegistryVersion(ctx, pkg, v)
		if err != nil {
			return nil, fmt.Errorf("registry %s@%s: %w", pkg, v, err)
		}
		tb, err := l.c.FetchTarball(ctx, pv, l.opts.MaxTarballBytes)
		if err != nil {
			return tb, fmt.Errorf("tarball %s@%s: %w", pkg, v, err)
		}
		return tb, nil
	}
	oldTb, err := fetch(version)
	if err != nil {
		a.Outcome = OutcomeError
		if strings.Contains(err.Error(), "exceeds") {
			a.Outcome = OutcomeUnbounded
		}
		a.Notes = []string{err.Error()}
		return a
	}
	newTb, err := fetch(fixed)
	if err != nil {
		a.Outcome = OutcomeError
		if strings.Contains(err.Error(), "exceeds") {
			a.Outcome = OutcomeUnbounded
		}
		a.Notes = []string{err.Error()}
		return a
	}
	a.Provenance = &Provenance{Artefacts: []Artefact{oldTb.Artefact, newTb.Artefact}}
	if !oldTb.Artefact.Verified || !newTb.Artefact.Verified {
		a.Notes = append(a.Notes, "a tarball did not match the registry integrity value; candidates from it are untrusted")
	}

	// Diff every source file present in either version.
	paths := map[string]bool{}
	for p := range oldTb.Files {
		paths[p] = true
	}
	for p := range newTb.Files {
		paths[p] = true
	}
	var files []changedFile
	changedCount := 0
	for p := range paths {
		oldSrc, inOld := oldTb.Files[p]
		newSrc, inNew := newTb.Files[p]
		switch {
		case inOld && inNew:
			if string(oldSrc) == string(newSrc) {
				continue
			}
			ed := DiffLines(splitLines(oldSrc), splitLines(newSrc))
			files = append(files, changedFile{Path: p, Status: "modified", NewSource: newSrc, OldSource: oldSrc,
				Added: ed.Added, Removed: ed.Removed, Approximate: ed.Approximate})
		case inNew:
			files = append(files, changedFile{Path: p, Status: "added", NewSource: newSrc, Added: allLines(newSrc)})
		default:
			files = append(files, changedFile{Path: p, Status: "removed", OldSource: oldSrc, Removed: allLines(oldSrc)})
		}
		changedCount++
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	a.Notes = append(a.Notes, fmt.Sprintf("%d source file(s) differ between %s and %s", changedCount, version, fixed))
	if len(oldTb.Skipped)+len(newTb.Skipped) > 0 {
		a.Notes = append(a.Notes, fmt.Sprintf("%d tarball entries skipped (non-source, links or over limit)", len(oldTb.Skipped)+len(newTb.Skipped)))
	}

	att := attributeChanges(files)
	a.Candidates = att.Candidates
	a.NonFunctionChanges = att.NonFunction
	a.ExcludedChanges = att.Excluded
	a.Notes = append(a.Notes, att.Notes...)
	if len(a.Candidates) > 0 {
		a.Outcome = OutcomeHit
	} else if changedCount == 0 {
		a.Outcome = OutcomeEmpty
		a.Notes = append(a.Notes, "no source file differs; the fix may live in a file type this tool does not read")
	} else {
		a.Outcome = OutcomeEmpty
	}
	return a
}

// ------------------------------------------------------------- confidence

// confidenceFor applies the published categorical criteria:
//
//	advisory_metadata  high   (structured field names the function)
//	patch_reference    high   (single fix commit, at most 3 candidates)
//	                   medium (at most 10 candidates)
//	                   low    (more, or attribution incomplete)
//	advisory_text      medium (at most 3 identifiers)
//	                   high   when a text candidate also appears in the patch diff
//	                   low    (more than 3 identifiers)
//	version_diff       medium (at most 5 candidates, exact alignment, verified tarballs)
//	                   low    otherwise
func confidenceFor(sel Attempt, patchCands []Candidate, all []Attempt) Confidence {
	n := len(sel.Candidates)
	switch sel.Method {
	case MethodAdvisoryMetadata:
		return ConfidenceHigh
	case MethodPatchReference:
		if hasNote(sel, "incomplete") || hasNote(sel, "could not fetch") {
			return ConfidenceLow
		}
		if n <= 3 {
			return ConfidenceHigh
		}
		if n <= 10 {
			return ConfidenceMedium
		}
		return ConfidenceLow
	case MethodAdvisoryText:
		if corroborated(sel.Candidates, patchCands) {
			return ConfidenceHigh
		}
		if n <= 3 {
			return ConfidenceMedium
		}
		return ConfidenceLow
	case MethodVersionDiff:
		verified := sel.Provenance != nil
		if verified {
			for _, art := range sel.Provenance.Artefacts {
				if !art.Verified {
					verified = false
				}
			}
		}
		if n <= 5 && verified && !hasNote(sel, "too large to align") {
			return ConfidenceMedium
		}
		return ConfidenceLow
	}
	return ConfidenceNone
}

func corroborated(text, patch []Candidate) bool {
	for _, t := range text {
		for _, p := range patch {
			if strings.EqualFold(t.Symbol, p.Symbol) {
				return true
			}
		}
	}
	return false
}

func hasNote(a Attempt, needle string) bool {
	for _, n := range a.Notes {
		if strings.Contains(n, needle) {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------ notes

func summariseSelection(sel Attempt, all []Attempt) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Selected %s with %d candidate symbol(s).", sel.Method, len(sel.Candidates))
	for _, a := range all {
		if a.Method == sel.Method {
			continue
		}
		fmt.Fprintf(&b, " %s: %s", a.Method, a.Outcome)
		if a.Outcome == OutcomeHit {
			fmt.Fprintf(&b, " (%d)", len(a.Candidates))
		}
		b.WriteString(".")
	}
	if len(sel.NonFunctionChanges) > 0 {
		fmt.Fprintf(&b, " Non-function changes: %s.", strings.Join(sel.NonFunctionChanges, ", "))
	}
	if sel.ClientMethod != nil {
		fmt.Fprintf(&b, " Commit-message search for the vulnerability ID in %s matched %d commit(s).", sel.ClientMethod.Repository, sel.ClientMethod.CommitsMatched)
	}
	return b.String()
}

func summariseFailure(all []Attempt, adv *Advisory, advErr error) string {
	var parts []string
	if adv == nil {
		parts = append(parts, "advisory unavailable: "+errString(advErr))
	}
	for _, a := range all {
		s := string(a.Method) + ": " + string(a.Outcome)
		if len(a.Notes) > 0 {
			s += " (" + a.Notes[len(a.Notes)-1] + ")"
		}
		parts = append(parts, s)
	}
	return "No method produced a candidate; falls back to package-level treatment. " + strings.Join(parts, "; ")
}

func errString(err error) string {
	if err == nil {
		return "no error recorded"
	}
	return err.Error()
}

func short(sha string) string {
	if len(sha) > 10 {
		return sha[:10]
	}
	return sha
}

func shortAll(refs []string) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		if i := strings.LastIndex(r, "@"); i >= 0 && len(r)-i > 11 {
			r = r[:i+11]
		}
		out = append(out, r)
	}
	return out
}

func splitLines(b []byte) []string {
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	lines := strings.Split(s, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func allLines(b []byte) []int {
	n := len(splitLines(b))
	out := make([]int, n)
	for i := range out {
		out[i] = i + 1
	}
	return out
}
