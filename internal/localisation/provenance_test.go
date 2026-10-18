package localisation

import (
	"context"
	"strings"
	"testing"
)

const (
	iniFix        = "56d2805e07ccd94e2ba0984ac9240ff02d44b6f1"
	iniParent     = "0000000000000000000000000000000000000001"
	iniFixedTag   = "1111111111111111111111111111111111111111" // annotated tag object
	iniFixedRel   = "2222222222222222222222222222222222222222"
	iniVulnRel    = "3333333333333333333333333333333333333333"
	iniFixedIDtag = "npm/ini/v1.3.6"
)

// seedIniReleases gives ini an annotated v1.3.6 tag that contains the fix and
// a lightweight v1.3.5 tag that does not.
func (w *fakeWorld) seedIniReleases() {
	w.tags[iniFixedIDtag] = map[string]string{"type": "tag", "sha": iniFixedTag}
	w.annotated[iniFixedTag] = iniFixedRel
	w.tags["npm/ini/v1.3.5"] = map[string]string{"type": "commit", "sha": iniVulnRel}
	w.compare[iniFix+"..."+iniFixedRel] = "ahead"
	w.compare[iniFix+"..."+iniVulnRel] = "behind"
}

func artefactByID(t *testing.T, r Result, id string) Artefact {
	t.Helper()
	for _, a := range r.Provenance.Artefacts {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("artefact %s not in %+v", id, r.Provenance.Artefacts)
	return Artefact{}
}

func TestGitBlobSHA_MatchesGit(t *testing.T) {
	// Values from `printf ... | git hash-object --stdin`.
	if got := gitBlobSHA([]byte("hello")); got != "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0" {
		t.Errorf("hello: %s", got)
	}
	if got := gitBlobSHA(nil); got != "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391" {
		t.Errorf("empty: %s", got)
	}
}

// Success path: every candidate cites the fixed file it was read from, the
// file's git blob hash matches what GitHub reports, both release tags agree
// with the fix commit, and the document verifies offline and online.
func TestProvenance_EveryCandidateTracedAndVerified(t *testing.T) {
	w := newFakeWorld(t)
	w.seedIni()
	w.seedIniReleases()
	l := w.localiser(false)
	doc, _ := l.LocaliseAll(context.Background(), "scan-1", []Finding{{FindingID: "f1",
		VulnerabilityID: "CVE-2020-7788", Aliases: []string{"GHSA-qqgx-2p2h-9c37"}, PURL: "pkg:npm/ini@1.3.5"}})
	r := doc.Results[0]
	if doc.SchemaVersion != "1.1.0" || r.Method != MethodPatchReference {
		t.Fatalf("schema %s method %s", doc.SchemaVersion, r.Method)
	}

	fixedID := SourceArtefactID("npm/ini", iniFix, "ini.js")
	for _, c := range r.CandidateSymbols {
		if len(c.Evidence) != 1 || c.Evidence[0] != fixedID {
			t.Errorf("%s cites %v, want [%s]", c.Symbol, c.Evidence, fixedID)
		}
	}
	src := artefactByID(t, r, fixedID)
	if !src.Verified || src.Kind != ArtefactSourceFile || src.Commit != iniFix || src.Path != "ini.js" ||
		src.GitBlobSHA != gitBlobSHA([]byte(iniFixed)) || src.SHA256 != sha256Hex([]byte(iniFixed)) || src.Executed {
		t.Errorf("fixed file artefact = %+v", src)
	}
	adv := artefactByID(t, r, AdvisoryArtefactID)
	if !adv.Verified || adv.Kind != ArtefactAdvisory || len(adv.SHA256) != 64 || !strings.HasSuffix(adv.URL, "/v1/vulns/GHSA-qqgx-2p2h-9c37") {
		t.Errorf("advisory artefact = %+v", adv)
	}

	got := map[TagRole]TagCheck{}
	for _, tc := range r.Provenance.TagChecks {
		got[tc.Role] = tc
	}
	if f := got[TagRoleFixed]; f.Result != TagVerified || f.Basis != BasisAncestry || f.Tag != "v1.3.6" ||
		f.TagCommit != iniFixedRel || f.ReleaseCommit != iniFixedRel || len(f.FixCommits) != 1 || f.FixCommits[0] != iniFix {
		t.Errorf("fixed tag check = %+v", f)
	}
	if v := got[TagRoleVulnerable]; v.Result != TagVerified || v.Tag != "v1.3.5" || v.ReleaseCommit != iniVulnRel {
		t.Errorf("vulnerable tag check = %+v", v)
	}
	if len(r.Provenance.TagChecks) != 2 {
		t.Errorf("want one check per release, got %+v", r.Provenance.TagChecks)
	}

	v := VerifyDocument(doc)
	if v.Errors() != 0 || len(v.Issues) != 0 || v.CandidatesTraced != v.Candidates || v.Candidates == 0 {
		t.Fatalf("offline verification = %+v", v)
	}
	l.Refetch(context.Background(), doc, &v)
	if len(v.Issues) != 0 || v.Refetched != len(r.Provenance.Artefacts) {
		t.Errorf("online verification = %+v", v)
	}
}

// Version-diff candidates cite the tarball they were attributed in, and the
// tarball artefact carries its version and the registry integrity value.
func TestProvenance_VersionDiffCitesTarballs(t *testing.T) {
	w := newFakeWorld(t)
	w.seedIni()
	w.tarballs["ini-1.3.5"] = buildTGZ(t, []tarEntry{{name: "package/ini.js", body: iniVulnerable}})
	w.tarballs["ini-1.3.6"] = buildTGZ(t, []tarEntry{{name: "package/ini.js", body: iniFixed}})
	_, trace := w.localiser(true).Localise(context.Background(), Finding{FindingID: "f1",
		VulnerabilityID: "CVE-2020-7788", Aliases: []string{"GHSA-qqgx-2p2h-9c37"}, PURL: "pkg:npm/ini@1.3.5"})
	var vd Attempt
	for _, a := range trace.Attempts {
		if a.Method == MethodVersionDiff {
			vd = a
		}
	}
	if vd.Outcome != OutcomeHit {
		t.Fatalf("version_diff = %+v", vd)
	}
	for _, c := range vd.Candidates {
		if len(c.Evidence) != 1 || c.Evidence[0] != TarballArtefactID("ini", "1.3.6") {
			t.Errorf("%s cites %v, want the fixed tarball (the change only adds lines)", c.Symbol, c.Evidence)
		}
	}
	for _, a := range vd.Provenance.Artefacts {
		if a.Kind != ArtefactTarball || a.Version == "" || !strings.HasPrefix(a.Integrity, "sha512-") || !a.Verified {
			t.Errorf("tarball artefact = %+v", a)
		}
	}
	// The text candidates cite the advisory.
	for _, a := range trace.Attempts {
		if a.Method == MethodAdvisoryText {
			for _, c := range a.Candidates {
				if len(c.Evidence) != 1 || c.Evidence[0] != AdvisoryArtefactID {
					t.Errorf("text candidate %s cites %v", c.Symbol, c.Evidence)
				}
			}
		}
	}
}

// A file over the contents API's JSON limit is fetched raw and still
// verified against the blob hash GitHub reports.
func TestProvenance_RawFallbackStillVerified(t *testing.T) {
	w := newFakeWorld(t)
	w.seedIni()
	w.rawOnly = true
	res, _ := w.localiser(false).Localise(context.Background(), Finding{FindingID: "f1",
		VulnerabilityID: "CVE-2020-7788", Aliases: []string{"GHSA-qqgx-2p2h-9c37"}, PURL: "pkg:npm/ini@1.3.5"})
	a := artefactByID(t, res, SourceArtefactID("npm/ini", iniFix, "ini.js"))
	if !a.Verified || a.GitBlobSHA != gitBlobSHA([]byte(iniFixed)) {
		t.Errorf("raw-fetched artefact = %+v", a)
	}
}

// Failure path: the commit's own file list names a different blob than the
// bytes served, so the artefact is unverified and every candidate citing it
// fails verification. The release tags do not contain the fix, which is an
// honest mismatch, and a version with no tag or gitHead is unavailable.
func TestProvenance_TamperedFileAndTagMismatch(t *testing.T) {
	w := newFakeWorld(t)
	w.seedIni()
	ci := w.commits[iniFix].(map[string]any)
	files := ci["files"].([]any)
	files[0].(map[string]any)["sha"] = "ffffffffffffffffffffffffffffffffffffffff"
	w.tags[iniFixedIDtag] = map[string]string{"type": "commit", "sha": iniFixedRel}
	w.compare[iniFix+"..."+iniFixedRel] = "diverged"
	w.files["npm/ini/"+iniFixedRel+"/ini.js"] = iniVulnerable // the release lacks the fix

	doc, _ := w.localiser(false).LocaliseAll(context.Background(), "scan-1", []Finding{{FindingID: "f1",
		VulnerabilityID: "CVE-2020-7788", Aliases: []string{"GHSA-qqgx-2p2h-9c37"}, PURL: "pkg:npm/ini@1.3.5"}})
	r := doc.Results[0]
	a := artefactByID(t, r, SourceArtefactID("npm/ini", iniFix, "ini.js"))
	if a.Verified || !strings.Contains(a.Note, "commit file list names blob ffffffffff") {
		t.Errorf("tampered artefact = %+v", a)
	}
	got := map[TagRole]TagCheck{}
	for _, tc := range r.Provenance.TagChecks {
		got[tc.Role] = tc
	}
	if f := got[TagRoleFixed]; f.Result != TagMismatch || f.Basis != "" ||
		!strings.Contains(f.Note, "carries none of the linked commits") ||
		!strings.Contains(f.Note, "56d2805e07 (1 of 1 added line(s) missing from ini.js)") {
		t.Errorf("fixed tag check = %+v", f)
	}
	if v := got[TagRoleVulnerable]; v.Result != TagUnavailable || !strings.Contains(v.Note, "No release tag") {
		t.Errorf("vulnerable tag check = %+v", v)
	}

	v := VerifyDocument(doc)
	if v.Errors() != len(r.CandidateSymbols) || v.CandidatesTraced != 0 {
		t.Errorf("want one error per candidate, got %d errors, %d traced: %+v", v.Errors(), v.CandidatesTraced, v.Issues)
	}
	warnings := 0
	for _, is := range v.Issues {
		if is.Severity == SeverityWarning {
			warnings++
		}
	}
	if warnings != 2 || v.TagChecks[TagMismatch] != 1 || v.TagChecks[TagUnavailable] != 1 {
		t.Errorf("tag warnings = %d, counts %v", warnings, v.TagChecks)
	}
}

// npm's gitHead is the commit the tarball was published from, so it is
// checked before the git tag, and a disagreement between them is recorded.
// A gitHead the repository does not have falls back to the tag.
func TestProvenance_RegistryGitHeadBeforeTag(t *testing.T) {
	w := newFakeWorld(t)
	w.seedIni()
	w.seedIniReleases()
	const head = "4444444444444444444444444444444444444444"
	w.gitHeads["ini-1.3.6"] = head
	w.compare[iniFix+"..."+head] = "ahead"
	w.gitHeads["ini-1.3.5"] = "5555555555555555555555555555555555555555" // unknown to the repository
	res, _ := w.localiser(false).Localise(context.Background(), Finding{FindingID: "f1",
		VulnerabilityID: "CVE-2020-7788", Aliases: []string{"GHSA-qqgx-2p2h-9c37"}, PURL: "pkg:npm/ini@1.3.5"})
	got := map[TagRole]TagCheck{}
	for _, tc := range res.Provenance.TagChecks {
		got[tc.Role] = tc
	}
	if f := got[TagRoleFixed]; f.Result != TagVerified || f.ReleaseCommit != head ||
		!strings.Contains(f.Note, "Tag v1.3.6 is commit 2222222222 but npm says ini@1.3.6 was published from 4444444444") {
		t.Errorf("fixed tag check = %+v", f)
	}
	if v := got[TagRoleVulnerable]; v.Result != TagVerified || v.ReleaseCommit != iniVulnRel ||
		!strings.Contains(v.Note, "Compare against 5555555555 failed") {
		t.Errorf("vulnerable tag check = %+v", v)
	}
}

// A backport: the fix commit is not an ancestor of the fixed release, but
// the line it adds is there, so the check passes on content. A vulnerable
// release that already contains the linked commit is a mismatch.
func TestProvenance_BackportVerifiedByContent(t *testing.T) {
	w := newFakeWorld(t)
	w.seedIni()
	w.seedIniReleases()
	w.compare[iniFix+"..."+iniFixedRel] = "diverged"
	w.files["npm/ini/"+iniFixedRel+"/ini.js"] = "// backported\n" + iniFixed
	w.compare[iniFix+"..."+iniVulnRel] = "ahead"
	l := w.localiser(false)
	doc, _ := l.LocaliseAll(context.Background(), "s", []Finding{{FindingID: "f1",
		VulnerabilityID: "CVE-2020-7788", Aliases: []string{"GHSA-qqgx-2p2h-9c37"}, PURL: "pkg:npm/ini@1.3.5"}})
	got := map[TagRole]TagCheck{}
	for _, tc := range doc.Results[0].Provenance.TagChecks {
		got[tc.Role] = tc
	}
	f := got[TagRoleFixed]
	if f.Result != TagVerified || f.Basis != BasisContent || len(f.ByContent) != 1 || len(f.Content) != 1 ||
		f.Content[0].Commit != iniFix || f.Content[0].Path != "ini.js" ||
		len(f.Content[0].Lines) != 1 || f.Content[0].Lines[0] != "if (line === '__proto__') return" {
		t.Errorf("fixed tag check = %+v", f)
	}
	if v := got[TagRoleVulnerable]; v.Result != TagMismatch || !strings.Contains(v.Note, "already contains linked commit 56d2805e07") {
		t.Errorf("vulnerable tag check = %+v", v)
	}
	// Online, the content check is re-run from the recorded lines.
	v := VerifyDocument(doc)
	l.Refetch(context.Background(), doc, &v)
	if v.Errors() != 0 {
		t.Errorf("issues = %+v", v.Issues)
	}
	for _, is := range v.Issues {
		if strings.Contains(is.Message, " now ") {
			t.Errorf("re-run disagreed: %s", is.Message)
		}
	}
}

// Advisory checksums are over canonical JSON, so key order does not matter.
func TestCanonicalJSON_KeyOrderAndNumbers(t *testing.T) {
	a, err1 := canonicalJSON([]byte(`{"b":1, "a":{"y":2.50,"x":[3,1]}}`))
	b, err2 := canonicalJSON([]byte(`{"a":{"x":[3,1],"y":2.50},"b":1}`))
	if err1 != nil || err2 != nil || string(a) != string(b) || string(a) != `{"a":{"x":[3,1],"y":2.50},"b":1}` {
		t.Errorf("%s / %s (%v %v)", a, b, err1, err2)
	}
	if _, err := canonicalJSON([]byte("{")); err == nil {
		t.Error("truncated JSON must fail")
	}
}

// Failure path online: a file or tarball that no longer matches its
// recorded checksum is an error.
func TestRefetch_DetectsChangedArtefacts(t *testing.T) {
	w := newFakeWorld(t)
	w.seedIni()
	w.tarballs["ini-1.3.5"] = buildTGZ(t, []tarEntry{{name: "package/ini.js", body: iniVulnerable}})
	w.tarballs["ini-1.3.6"] = buildTGZ(t, []tarEntry{{name: "package/ini.js", body: iniFixed}})
	l := w.localiser(false)
	doc, _ := l.LocaliseAll(context.Background(), "scan-1", []Finding{{FindingID: "f1",
		VulnerabilityID: "CVE-2020-7788", Aliases: []string{"GHSA-qqgx-2p2h-9c37"}, PURL: "pkg:npm/ini@1.3.5"}})
	// Add a tarball artefact by hand so both kinds are re-fetched.
	tb, err := l.c.FetchTarball(context.Background(), &PackageVersion{Name: "ini", Version: "1.3.6",
		Tarball: w.srv.URL + "/ini/-/ini-1.3.6.tgz", Integrity: integrityOf(w.tarballs["ini-1.3.6"])}, 0)
	if err != nil {
		t.Fatal(err)
	}
	doc.Results[0].Provenance.Artefacts = append(doc.Results[0].Provenance.Artefacts, tb.Artefact)

	w.files["npm/ini/"+iniFix+"/ini.js"] = iniFixed + "// changed\n"
	w.tarballs["ini-1.3.6"] = buildTGZ(t, []tarEntry{{name: "package/ini.js", body: iniFixed + "//x\n"}})
	v := VerifyDocument(doc)
	l.Refetch(context.Background(), doc, &v)
	var msgs []string
	for _, is := range v.Issues {
		if is.Severity == SeverityError {
			msgs = append(msgs, is.Message)
		}
	}
	joined := strings.Join(msgs, " | ")
	if !strings.Contains(joined, "file at "+short(iniFix)+" is now blob") || !strings.Contains(joined, "SHA-256 of the re-downloaded tarball differs") {
		t.Errorf("errors = %s", joined)
	}
}

// Boundary / untrusted input: a hand-edited document with broken references
// fails offline, and an online check never follows a URL or path the
// document supplies.
func TestVerify_HostileDocument(t *testing.T) {
	w := newFakeWorld(t)
	doc := Document{SchemaVersion: SchemaVersion, ScanID: "s", Results: []Result{{
		FindingID: "f1", VulnerabilityID: "CVE-2020-7788", PURL: "pkg:npm/ini@1.3.5", FixedVersion: "1.3.6",
		Method: MethodPatchReference, Confidence: ConfidenceHigh,
		CandidateSymbols: []Candidate{
			{Symbol: "none"},
			{Symbol: "dangling", Evidence: []string{"missing"}},
			{Symbol: "escape", ModulePath: "ini.js", Evidence: []string{"src"}},
			{Symbol: "evil", Evidence: []string{AdvisoryArtefactID}},
		},
		Provenance: &Provenance{Artefacts: []Artefact{
			{ID: "src", Kind: ArtefactSourceFile, URL: "https://evil.example/x", Repo: "../../etc", Path: "../passwd",
				Commit: iniFix, GitBlobSHA: iniFix, SHA256: strings.Repeat("a", 64), Verified: true},
			{ID: AdvisoryArtefactID, Kind: ArtefactAdvisory, URL: "https://evil.example/v1/vulns/../../admin",
				SHA256: strings.Repeat("b", 64), Verified: true},
			{ID: AdvisoryArtefactID, Kind: ArtefactAdvisory, URL: "x", SHA256: "short", Executed: true},
		}},
	}}}
	v := VerifyDocument(doc)
	want := []string{"candidate cites no artefact", "cited artefact is not in the result's provenance",
		"candidate is in ini.js but cites ../passwd", "artefact id is not unique", "artefact records executed: true",
		"no tag check against the fixed release"}
	all := ""
	for _, is := range v.Issues {
		all += is.Message + " | "
	}
	for _, s := range want {
		if !strings.Contains(all, s) {
			t.Errorf("missing %q in %s", s, all)
		}
	}
	w.localiser(false).Refetch(context.Background(), doc, &v)
	for _, p := range w.requests {
		if strings.Contains(p, "etc") || strings.Contains(p, "passwd") || strings.Contains(p, "admin") {
			t.Errorf("online verification followed untrusted input: %s", p)
		}
	}
	if len(w.requests) != 0 {
		t.Errorf("hostile identifiers must be rejected before any request, made %v", w.requests)
	}

	old := VerifyDocument(Document{SchemaVersion: "1.0.0"})
	if old.Errors() != 1 || !strings.Contains(old.Issues[0].Message, "records no per-candidate evidence") {
		t.Errorf("1.0.0 document: %+v", old.Issues)
	}
}

// Untrusted input: an advisory that does not name the finding, and a
// registry document for a different version, are both refused as evidence.
func TestProvenance_IdentityChecks(t *testing.T) {
	w := newFakeWorld(t)
	w.seedIni()
	w.osv["CVE-2020-7788"] = map[string]any{"id": "CVE-2099-9999",
		"affected": []any{map[string]any{"package": map[string]string{"ecosystem": "npm", "name": "ini"}}}}
	adv, err := w.localiser(false).c.FetchAdvisory(context.Background(), Finding{VulnerabilityID: "CVE-2020-7788", PURL: "pkg:npm/ini@1.3.5"})
	if err != nil {
		t.Fatal(err)
	}
	if adv.Artefact.Verified || !strings.Contains(adv.Artefact.Note, "does not name CVE-2020-7788") {
		t.Errorf("advisory artefact = %+v", adv.Artefact)
	}

	w.registryDocs["ini/9.9.9"] = map[string]any{"name": "ini", "version": "1.0.0"}
	if _, err := w.localiser(false).c.RegistryVersion(context.Background(), "ini", "9.9.9"); err == nil ||
		!strings.Contains(err.Error(), "registry returned ini@1.0.0 for ini@9.9.9") {
		t.Errorf("registry identity error = %v", err)
	}
}

// An advisory linking fixes on two release lines (c05, c06): the fixed
// release carries one of them, and the other is recorded as belonging to
// another line rather than failing the check.
func TestProvenance_FixesOnTwoReleaseLines(t *testing.T) {
	w := newFakeWorld(t)
	w.seedIni()
	w.seedIniReleases()
	const legacy = "7777777777777777777777777777777777777777"
	const legacyParent = "8888888888888888888888888888888888888888"
	rec := w.osv["GHSA-qqgx-2p2h-9c37"].(map[string]any)
	rec["references"] = append(rec["references"].([]any),
		map[string]string{"type": "WEB", "url": "https://github.com/npm/ini/commit/" + legacy})
	legacyFixed := strings.Replace(iniFixed, "if (line === '__proto__') return", "if (line == '__proto__') { return }", 1)
	w.commits[legacy] = map[string]any{"sha": legacy, "parents": []any{map[string]string{"sha": legacyParent}},
		"files": []any{map[string]any{"filename": "ini.js", "status": "modified", "sha": gitBlobSHA([]byte(legacyFixed)),
			"patch": "@@ -3,5 +3,6 @@ function decode (str) {\n   var out = {}\n   str.split('\\n').forEach(function (line) {\n+    if (line == '__proto__') { return }\n     out[line] = true\n   })\n   return out"}}}
	w.files["npm/ini/"+legacy+"/ini.js"] = legacyFixed
	w.files["npm/ini/"+iniFixedRel+"/ini.js"] = iniFixed
	w.compare[legacy+"..."+iniFixedRel] = "diverged"
	w.compare[legacy+"..."+iniVulnRel] = "diverged"

	res, _ := w.localiser(false).Localise(context.Background(), Finding{FindingID: "f1",
		VulnerabilityID: "CVE-2020-7788", Aliases: []string{"GHSA-qqgx-2p2h-9c37"}, PURL: "pkg:npm/ini@1.3.5"})
	for _, tc := range res.Provenance.TagChecks {
		if tc.Role != TagRoleFixed {
			continue
		}
		if tc.Result != TagVerified || tc.Basis != BasisAncestry || len(tc.FixCommits) != 2 ||
			len(tc.ByAncestry) != 1 || tc.ByAncestry[0] != iniFix ||
			!strings.Contains(tc.Note, "another release line or superseded: 7777777777 (1 of 1 added line(s) missing from ini.js)") {
			t.Errorf("fixed tag check = %+v", tc)
		}
		return
	}
	t.Fatal("no fixed tag check")
}
