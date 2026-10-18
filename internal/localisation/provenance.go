package localisation

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // git names blobs by SHA-1; used only to compare with the hash GitHub reports
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// AdvisoryArtefactID is the artefact ID of the OSV record in every result.
const AdvisoryArtefactID = "advisory"

// TarballArtefactID names the npm tarball of name@version.
func TarballArtefactID(name, version string) string { return "npm:" + name + "@" + version }

// SourceArtefactID names one file at one commit. The full commit SHA keeps
// two commits that share a prefix apart.
func SourceArtefactID(repo, commit, path string) string {
	return "github:" + repo + "@" + commit + ":" + path
}

// gitBlobSHA is the hash git gives a file's bytes: SHA-1 over
// "blob <size>\x00<content>". It lets anyone check the bytes against a clone
// with `git rev-parse <commit>:<path>`.
func gitBlobSHA(b []byte) string {
	h := sha1.New() //nolint:gosec // see import comment
	_, _ = fmt.Fprintf(h, "blob %d\x00", len(b))
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// contentsDoc is the GitHub contents API's JSON form of one file.
type contentsDoc struct {
	Type     string `json:"type"`
	Encoding string `json:"encoding"`
	Size     int64  `json:"size"`
	SHA      string `json:"sha"`
	Content  string `json:"content"`
}

// FileBlobAt fetches a file at a commit together with the git blob hash
// GitHub reports for it. The JSON form carries the content for files up to
// 1 MB; larger files are fetched raw, and the reported hash still lets the
// caller verify the bytes.
func (c *Client) FileBlobAt(ctx context.Context, repo, path, ref string) ([]byte, string, error) {
	if err := validateRepo(repo); err != nil {
		return nil, "", err
	}
	if !reSHA.MatchString(ref) {
		return nil, "", fmt.Errorf("invalid ref %q", ref)
	}
	if err := validateRepoPath(path); err != nil {
		return nil, "", err
	}
	var doc contentsDoc
	if err := c.getJSON(ctx, c.GitHubAPI+"/repos/"+repo+"/contents/"+escapePath(path)+"?ref="+ref, "application/vnd.github+json", &doc); err != nil {
		return nil, "", err
	}
	if doc.Type != "" && doc.Type != "file" {
		return nil, "", fmt.Errorf("%s at %s is a %s, not a file", path, short(ref), doc.Type)
	}
	if !reFullSHA.MatchString(doc.SHA) {
		return nil, "", fmt.Errorf("contents API gave no blob hash for %s", path)
	}
	if doc.Size > maxSourceBytes {
		return nil, "", fmt.Errorf("%s is %d bytes, over the %d byte source limit", path, doc.Size, maxSourceBytes)
	}
	if doc.Encoding == "base64" {
		body, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(doc.Content, "\n", ""))
		if err != nil {
			return nil, "", fmt.Errorf("decode %s: %w", path, err)
		}
		return body, doc.SHA, nil
	}
	body, err := c.FileAt(ctx, repo, path, ref)
	if err != nil {
		return nil, "", err
	}
	return body, doc.SHA, nil
}

func escapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		segs[i] = url.PathEscape(seg)
	}
	return strings.Join(segs, "/")
}

// sourceArtefact fetches one file at one commit and records it. The file is
// verified when the git blob hash of the bytes read equals the hash GitHub
// reports for that path, and, for the fixed side, the hash in the commit's
// own file list (treeBlob) as well.
func (c *Client) sourceArtefact(ctx context.Context, repo, path, commit, treeBlob string) ([]byte, Artefact, error) {
	body, reported, err := c.FileBlobAt(ctx, repo, path, commit)
	if err != nil {
		return nil, Artefact{}, err
	}
	got := gitBlobSHA(body)
	art := Artefact{
		ID: SourceArtefactID(repo, commit, path), Kind: ArtefactSourceFile,
		URL:    "https://github.com/" + repo + "/blob/" + commit + "/" + escapePath(path),
		SHA256: sha256Hex(body), SizeBytes: int64(len(body)),
		Repo: repo, Commit: commit, Path: path, GitBlobSHA: got,
	}
	switch {
	case got != reported:
		art.Note = "bytes read hash to blob " + short(got) + " but GitHub reports " + short(reported)
	case treeBlob != "" && treeBlob != got:
		art.Note = "commit file list names blob " + short(treeBlob) + " but the file read is " + short(got)
	default:
		art.Verified = true
	}
	return body, art, nil
}

// ------------------------------------------------------------- tag checks

var (
	reFullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
	reTagName = regexp.MustCompile(`^[A-Za-z0-9@._+/-]{1,200}$`)
)

// tagNames lists the tag spellings npm packages commonly release under.
func tagNames(pkg, version string) []string {
	names := []string{"v" + version, version, pkg + "@" + version}
	if i := strings.LastIndex(pkg, "/"); i >= 0 {
		names = append(names, pkg[i+1:]+"@"+version)
	}
	out := names[:0]
	for _, n := range names {
		if reTagName.MatchString(n) && !strings.Contains(n, "..") {
			out = append(out, n)
		}
	}
	return out
}

type gitObject struct {
	Object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
	} `json:"object"`
}

// TagCommit resolves a release tag to its commit, following annotated tags.
// The second result is the tag name that matched. Not finding any spelling
// is reported as ("", "", nil).
func (c *Client) TagCommit(ctx context.Context, repo, pkg, version string) (string, string, error) {
	if err := validateRepo(repo); err != nil {
		return "", "", err
	}
	for _, tag := range tagNames(pkg, version) {
		var ref gitObject
		err := c.getJSON(ctx, c.GitHubAPI+"/repos/"+repo+"/git/ref/tags/"+escapePath(tag), "application/vnd.github+json", &ref)
		if isNotFound(err) {
			continue
		}
		if err != nil {
			return "", "", err
		}
		obj := ref.Object
		for hops := 0; obj.Type == "tag" && hops < 3; hops++ {
			if !reFullSHA.MatchString(obj.SHA) {
				return "", "", fmt.Errorf("tag %s points to an invalid object %q", tag, obj.SHA)
			}
			var annotated gitObject
			if err := c.getJSON(ctx, c.GitHubAPI+"/repos/"+repo+"/git/tags/"+obj.SHA, "application/vnd.github+json", &annotated); err != nil {
				return "", "", err
			}
			obj = annotated.Object
		}
		if obj.Type != "commit" || !reFullSHA.MatchString(obj.SHA) {
			return "", "", fmt.Errorf("tag %s does not resolve to a commit", tag)
		}
		return obj.SHA, tag, nil
	}
	return "", "", nil
}

// Contains reports whether commit is an ancestor of (or equal to) head.
func (c *Client) Contains(ctx context.Context, repo, commit, head string) (bool, string, error) {
	if err := validateRepo(repo); err != nil {
		return false, "", err
	}
	if !reSHA.MatchString(commit) || !reSHA.MatchString(head) {
		return false, "", fmt.Errorf("invalid commit pair %q...%q", commit, head)
	}
	var cmp struct {
		Status string `json:"status"`
	}
	if err := c.getJSON(ctx, c.GitHubAPI+"/repos/"+repo+"/compare/"+commit+"..."+head+"?per_page=1", "application/vnd.github+json", &cmp); err != nil {
		return false, "", err
	}
	switch cmp.Status {
	case "ahead", "identical":
		return true, cmp.Status, nil
	case "behind", "diverged":
		return false, cmp.Status, nil
	}
	return false, cmp.Status, fmt.Errorf("compare returned status %q", cmp.Status)
}

func sameCommit(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return strings.HasPrefix(a, b) || strings.HasPrefix(b, a)
}

// FixContent is the distinctive code lines one fix commit adds to one
// file. It lets a tag check recognise a backport or squash merge, where the
// fix commit itself is not an ancestor of the release but its change is in it.
type FixContent struct {
	Commit string `json:"commit"`
	// Parent is the fix commit's parent. A line the parent's copy of the
	// file already has is not evidence of the fix, so it is not looked for.
	Parent string   `json:"parent,omitempty"`
	Path   string   `json:"path"`
	Lines  []string `json:"lines"`
}

// minDistinctiveLine drops lines such as "}" or "return" that would match
// anywhere in a release.
const minDistinctiveLine = 8

func distinctiveLines(src []byte, lineNos []int) []string {
	lines := splitLines(src)
	var out []string
	for _, n := range lineNos {
		if n < 1 || n > len(lines) || !isCodeLine(lines[n-1]) {
			continue
		}
		if t := strings.TrimSpace(lines[n-1]); len(t) >= minDistinctiveLine {
			out = addEvidence(out, t)
		}
	}
	return out
}

func lineSet(src []byte) map[string]bool {
	set := map[string]bool{}
	for _, l := range splitLines(src) {
		set[strings.TrimSpace(l)] = true
	}
	return set
}

// releaseCommits lists the commits a version may have been published from,
// most authoritative first: npm's gitHead records the commit the tarball was
// published from; the git tag is a convention that usually agrees.
func (l *Localiser) releaseCommits(ctx context.Context, tc *TagCheck, pkg string) []string {
	if pv, err := l.c.RegistryVersion(ctx, pkg, tc.Version); err == nil && reSHA.MatchString(pv.GitHead) {
		tc.RegistryGitHead = pv.GitHead
	}
	commit, tag, err := l.c.TagCommit(ctx, tc.Repo, pkg, tc.Version)
	if err != nil {
		tc.Note = "tag lookup failed: " + err.Error() + ". "
	}
	tc.Tag, tc.TagCommit = tag, commit
	var out []string
	if tc.RegistryGitHead != "" {
		out = append(out, tc.RegistryGitHead)
	}
	if commit != "" && sameCommit(commit, tc.RegistryGitHead) {
		tc.Note += fmt.Sprintf("Tag %s and npm's gitHead agree. ", tag)
	}
	if commit != "" && !sameCommit(commit, tc.RegistryGitHead) {
		if tc.RegistryGitHead != "" {
			tc.Note += fmt.Sprintf("Tag %s is commit %s but npm says %s@%s was published from %s; npm's gitHead is checked first. ",
				tag, short(commit), pkg, tc.Version, short(tc.RegistryGitHead))
		}
		out = append(out, commit)
	}
	return out
}

// tagCheck checks one release against the linked fix commits. An advisory
// often links commits from several release lines, so each commit is placed:
// an ancestor of the release, or (a backport or squash merge) not an ancestor
// but every line it adds is in the release's copy of the file, or neither.
// The fixed release passes when it carries at least one linked commit; the
// vulnerable release passes when no linked commit is an ancestor of it.
func (l *Localiser) tagCheck(ctx context.Context, repo string, fixes []string, content []FixContent, pkg, version string, role TagRole) TagCheck {
	tc := TagCheck{Version: version, Role: role, Repo: repo, FixCommits: fixes, Result: TagUnavailable}
	candidates := l.releaseCommits(ctx, &tc, pkg)
	if len(candidates) == 0 {
		tc.Note += "No release tag (tried " + strings.Join(tagNames(pkg, version), ", ") + ") and npm records no gitHead."
		tc.Note = strings.TrimSpace(tc.Note)
		return tc
	}
	var outside []string
	for _, release := range candidates {
		tc.ByAncestry, outside = nil, nil
		var err error
		for _, fix := range fixes {
			var in bool
			in, _, err = l.c.Contains(ctx, repo, fix, release)
			if err != nil {
				break
			}
			if in {
				tc.ByAncestry = append(tc.ByAncestry, fix)
			} else {
				outside = append(outside, fix)
			}
		}
		if err == nil {
			tc.ReleaseCommit = release
			tc.ReleaseSource = ReleaseFromGitTag
			if release == tc.RegistryGitHead {
				tc.ReleaseSource = ReleaseFromRegistryGitHead
			}
			break
		}
		tc.Note += fmt.Sprintf("Compare against %s failed: %v. ", short(release), err)
	}
	if tc.ReleaseCommit == "" {
		tc.ByAncestry = nil
		tc.Note = strings.TrimSpace(tc.Note)
		return tc
	}

	if role == TagRoleVulnerable {
		tc.Basis = BasisAncestry
		if len(tc.ByAncestry) == 0 {
			tc.Result = TagVerified
		} else {
			tc.Result = TagMismatch
			tc.Note += fmt.Sprintf("Vulnerable release %s already contains linked commit %s, so that commit was a partial fix or the version range is wrong.",
				version, strings.Join(shortList(tc.ByAncestry), ", "))
		}
		tc.Note = strings.TrimSpace(tc.Note)
		return tc
	}

	var elsewhere []string
	for _, fix := range outside {
		found, why := l.contentPresent(ctx, repo, tc.ReleaseCommit, fix, content)
		if found {
			tc.ByContent = append(tc.ByContent, fix)
			tc.Content = append(tc.Content, contentOf(fix, content)...)
		} else {
			elsewhere = append(elsewhere, short(fix)+" ("+why+")")
		}
	}
	switch {
	case len(tc.ByAncestry) > 0:
		tc.Basis, tc.Result = BasisAncestry, TagVerified
	case len(tc.ByContent) > 0:
		tc.Basis, tc.Result = BasisContent, TagVerified
	default:
		tc.Result = TagMismatch
		tc.Note += fmt.Sprintf("Fixed release %s carries none of the linked commits. ", version)
	}
	if len(tc.ByContent) > 0 {
		tc.Note += fmt.Sprintf("Not ancestors but every line they add is present (backport or squash merge): %s. ", strings.Join(shortList(tc.ByContent), ", "))
	}
	if len(elsewhere) > 0 {
		tc.Note += "Not in this release, so another release line or superseded: " + strings.Join(elsewhere, "; ") + "."
	}
	tc.Note = strings.TrimSpace(tc.Note)
	return tc
}

func contentOf(fix string, content []FixContent) []FixContent {
	var out []FixContent
	for _, fc := range content {
		if fc.Commit == fix {
			out = append(out, fc)
		}
	}
	return out
}

// contentPresent reports whether every line one fix commit adds is in the
// release's copy of the same file. Lines the parent's copy already has are
// dropped first: a generic line such as "return out" proves nothing.
func (l *Localiser) contentPresent(ctx context.Context, repo, release, fix string, content []FixContent) (bool, string) {
	var mine []FixContent
	for _, fc := range contentOf(fix, content) {
		lines, err := l.newSinceParent(ctx, repo, fc)
		if err != nil {
			return false, fc.Path + " could not be read at the parent: " + err.Error()
		}
		if len(lines) > 0 {
			fc.Lines = lines
			mine = append(mine, fc)
		}
	}
	if len(mine) == 0 {
		return false, "adds no line its parent lacks"
	}
	for _, fc := range mine {
		body, _, err := l.c.FileBlobAt(ctx, repo, fc.Path, release)
		if isNotFound(err) {
			return false, fc.Path + " does not exist at the release"
		}
		if err != nil {
			return false, fc.Path + " could not be read: " + err.Error()
		}
		have := lineSet(body)
		missing := 0
		for _, line := range fc.Lines {
			if !have[line] {
				missing++
			}
		}
		if missing > 0 {
			return false, fmt.Sprintf("%d of %d added line(s) missing from %s", missing, len(fc.Lines), fc.Path)
		}
	}
	return true, ""
}

// newSinceParent drops the lines the parent's copy of the file already has.
// A file the parent does not have is new, so all its lines count.
func (l *Localiser) newSinceParent(ctx context.Context, repo string, fc FixContent) ([]string, error) {
	if fc.Parent == "" {
		return fc.Lines, nil
	}
	body, _, err := l.c.FileBlobAt(ctx, repo, fc.Path, fc.Parent)
	if isNotFound(err) {
		return fc.Lines, nil
	}
	if err != nil {
		return nil, err
	}
	had := lineSet(body)
	var out []string
	for _, line := range fc.Lines {
		if !had[line] {
			out = append(out, line)
		}
	}
	return out, nil
}

// tagChecks runs the fixed and vulnerable checks once per repository.
func (l *Localiser) tagChecks(ctx context.Context, fixes []gitHubCommit, content []FixContent, pkg, vulnerable, fixed string) []TagCheck {
	var repos []string
	byRepo := map[string][]string{}
	for _, f := range fixes {
		if _, ok := byRepo[f.Repo]; !ok {
			repos = append(repos, f.Repo)
		}
		byRepo[f.Repo] = addEvidence(byRepo[f.Repo], f.SHA)
	}
	var out []TagCheck
	for _, repo := range repos {
		if fixed != "" {
			out = append(out, l.tagCheck(ctx, repo, byRepo[repo], content, pkg, fixed, TagRoleFixed))
		}
		out = append(out, l.tagCheck(ctx, repo, byRepo[repo], content, pkg, vulnerable, TagRoleVulnerable))
	}
	return out
}

func shortList(shas []string) []string {
	out := make([]string, len(shas))
	for i, s := range shas {
		out[i] = short(s)
	}
	return out
}

// canonicalJSON re-encodes a JSON document with sorted keys, no whitespace,
// numbers kept as written and no HTML escaping. OSV serves the same record
// with keys in varying order, so a hash of the raw bytes would not be
// reproducible. For a record without fractional numbers the result equals
// `jq -S -c .` output without its trailing newline.
func canonicalJSON(body []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data after the JSON document")
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

// ------------------------------------------------------------ evidence

// addEvidence appends ids not already present.
func addEvidence(have []string, ids ...string) []string {
	for _, id := range ids {
		if id == "" {
			continue
		}
		dup := false
		for _, h := range have {
			if h == id {
				dup = true
				break
			}
		}
		if !dup {
			have = append(have, id)
		}
	}
	return have
}
