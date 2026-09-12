package localisation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeWorld is one HTTP server standing in for OSV, the GitHub API and the
// npm registry. Tests point all three base URLs at it.
type fakeWorld struct {
	srv       *httptest.Server
	osv       map[string]any
	commits   map[string]any
	files     map[string]string // "repo/sha/path" -> content
	tarballs  map[string][]byte
	requests  []string
	prCommits map[string][]string
}

func newFakeWorld(t *testing.T) *fakeWorld {
	t.Helper()
	w := &fakeWorld{osv: map[string]any{}, commits: map[string]any{}, files: map[string]string{},
		tarballs: map[string][]byte{}, prCommits: map[string][]string{}}
	w.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.requests = append(w.requests, r.URL.Path)
		p := strings.Trim(r.URL.Path, "/")
		switch {
		case strings.HasPrefix(p, "v1/vulns/"):
			if rec, ok := w.osv[strings.TrimPrefix(p, "v1/vulns/")]; ok {
				_ = json.NewEncoder(rw).Encode(rec)
				return
			}
		case strings.HasPrefix(p, "repos/") && strings.Contains(p, "/commits/"):
			parts := strings.Split(p, "/")
			if ci, ok := w.commits[parts[len(parts)-1]]; ok {
				_ = json.NewEncoder(rw).Encode(ci)
				return
			}
		case strings.HasPrefix(p, "repos/") && strings.Contains(p, "/pulls/"):
			parts := strings.Split(p, "/")
			if shas, ok := w.prCommits[parts[4]]; ok {
				var out []map[string]string
				for _, s := range shas {
					out = append(out, map[string]string{"sha": s})
				}
				_ = json.NewEncoder(rw).Encode(out)
				return
			}
		case strings.HasPrefix(p, "repos/") && strings.Contains(p, "/contents/"):
			parts := strings.SplitN(p, "/contents/", 2)
			repo := strings.TrimPrefix(parts[0], "repos/")
			key := repo + "/" + r.URL.Query().Get("ref") + "/" + parts[1]
			if body, ok := w.files[key]; ok {
				_, _ = rw.Write([]byte(body))
				return
			}
		case strings.HasPrefix(p, "search/commits"):
			_ = json.NewEncoder(rw).Encode(map[string]any{"total_count": 1, "items": []map[string]string{{"sha": "feedfacefeedfacefeedfacefeedfacefeedface"}}})
			return
		default:
			// npm registry: <pkg>/<version> or <pkg>/-/<file>.tgz
			parts := strings.Split(p, "/")
			if len(parts) == 3 && parts[1] == "-" {
				if tb, ok := w.tarballs[strings.TrimSuffix(parts[2], ".tgz")]; ok {
					_, _ = rw.Write(tb)
					return
				}
			}
			if len(parts) == 2 {
				key := parts[0] + "-" + parts[1]
				if tb, ok := w.tarballs[key]; ok {
					_ = json.NewEncoder(rw).Encode(map[string]any{"name": parts[0], "version": parts[1],
						"dist":       map[string]any{"tarball": w.srv.URL + "/" + parts[0] + "/-/" + key + ".tgz", "integrity": integrityOf(tb)},
						"repository": "git+https://github.com/acme/" + parts[0] + ".git"})
					return
				}
			}
		}
		rw.WriteHeader(404)
	}))
	t.Cleanup(w.srv.Close)
	return w
}

func (w *fakeWorld) localiser(all bool) *Localiser {
	return New(Options{OSVBaseURL: w.srv.URL, GitHubAPIBaseURL: w.srv.URL, RegistryBaseURL: w.srv.URL,
		AllMethods: all, ClientMethodSearch: true})
}

const iniVulnerable = `exports.parse = exports.decode = decode
function decode (str) {
  var out = {}
  str.split('\n').forEach(function (line) {
    out[line] = true
  })
  return out
}
`

const iniFixed = `exports.parse = exports.decode = decode
function decode (str) {
  var out = {}
  str.split('\n').forEach(function (line) {
    if (line === '__proto__') return
    out[line] = true
  })
  return out
}
`

func (w *fakeWorld) seedIni() {
	w.osv["GHSA-qqgx-2p2h-9c37"] = map[string]any{
		"id": "GHSA-qqgx-2p2h-9c37", "aliases": []string{"CVE-2020-7788"},
		"summary": "ini before 1.3.6 vulnerable to Prototype Pollution via ini.parse",
		"details": "If an attacker submits a malicious INI file to an application that parses it with `ini.parse`, they will pollute the prototype.",
		"affected": []any{map[string]any{"package": map[string]string{"ecosystem": "npm", "name": "ini"},
			"ranges": []any{map[string]any{"type": "ECOSYSTEM", "events": []any{map[string]string{"introduced": "0"}, map[string]string{"fixed": "1.3.6"}}}}}},
		"references": []any{
			map[string]string{"type": "WEB", "url": "https://github.com/npm/ini/commit/56d2805e07ccd94e2ba0984ac9240ff02d44b6f1"},
			map[string]string{"type": "WEB", "url": "javascript:alert(1)"},
			map[string]string{"type": "WEB", "url": "https://github.com/npm/ini/commit/../../evil"},
			map[string]string{"type": "PACKAGE", "url": "https://github.com/npm/ini"},
		},
	}
	w.commits["56d2805e07ccd94e2ba0984ac9240ff02d44b6f1"] = map[string]any{
		"sha": "56d2805e07ccd94e2ba0984ac9240ff02d44b6f1", "parents": []any{map[string]string{"sha": "0000000000000000000000000000000000000001"}},
		"commit": map[string]string{"message": "fix: do not allow __proto__ keys"},
		"files": []any{
			map[string]any{"filename": "ini.js", "status": "modified", "patch": "@@ -3,5 +3,6 @@ function decode (str) {\n   var out = {}\n   str.split('\\n').forEach(function (line) {\n+    if (line === '__proto__') return\n     out[line] = true\n   })\n   return out"},
			map[string]any{"filename": "test/proto.js", "status": "added", "patch": "@@ -0,0 +1,1 @@\n+test"},
			map[string]any{"filename": "README.md", "status": "modified", "patch": "@@ -1,1 +1,1 @@\n-a\n+b"},
		},
	}
	w.files["npm/ini/56d2805e07ccd94e2ba0984ac9240ff02d44b6f1/ini.js"] = iniFixed
	w.files["npm/ini/0000000000000000000000000000000000000001/ini.js"] = iniVulnerable
}

// Success path: advisory text, the fix commit and the version diff all
// agree; patch_reference is selected, decode is found, and the export alias
// parse is added so Component 4 can join it to an ini.parse call.
func TestLocalise_PatchReferenceWithExportAlias(t *testing.T) {
	w := newFakeWorld(t)
	w.seedIni()
	res, trace := w.localiser(false).Localise(context.Background(), Finding{
		FindingID: "f1", VulnerabilityID: "CVE-2020-7788", Aliases: []string{"GHSA-qqgx-2p2h-9c37"},
		PURL: "pkg:npm/ini@1.3.5",
	})
	if res.Method != MethodPatchReference {
		t.Fatalf("method = %s, notes = %s", res.Method, res.Notes)
	}
	if res.Confidence != ConfidenceHigh {
		t.Errorf("confidence = %s", res.Confidence)
	}
	syms := map[string]bool{}
	for _, c := range res.CandidateSymbols {
		syms[c.Symbol] = true
	}
	if !syms["decode"] || !syms["parse"] {
		t.Errorf("candidates = %+v, want decode and its alias parse", res.CandidateSymbols)
	}
	if res.FixedVersion != "1.3.6" {
		t.Errorf("fixed version from advisory = %q", res.FixedVersion)
	}
	if res.Provenance == nil || res.Provenance.PatchCommit != "56d2805e07ccd94e2ba0984ac9240ff02d44b6f1" || res.Provenance.AdvisorySource != "osv" {
		t.Errorf("provenance = %+v", res.Provenance)
	}
	if len(res.ExcludedChanges) != 2 || res.ExcludedChanges[0] != "docs" || res.ExcludedChanges[1] != "tests" {
		t.Errorf("excluded = %v", res.ExcludedChanges)
	}
	// Fallback order stopped after the first hit.
	if len(trace.Attempts) != 2 || trace.Selected != MethodPatchReference {
		t.Errorf("trace = %+v", trace.Attempts)
	}
	// Untrusted reference URLs were never requested.
	for _, p := range w.requests {
		if strings.Contains(p, "evil") || strings.Contains(p, "javascript") {
			t.Errorf("untrusted reference was fetched: %s", p)
		}
	}
}

// All-methods mode records every source independently; text finds parse,
// metadata is honestly empty, version_diff attributes the tarball change.
func TestLocalise_AllMethodsRecordsEverySource(t *testing.T) {
	w := newFakeWorld(t)
	w.seedIni()
	w.tarballs["ini-1.3.5"] = buildTGZ(t, []tarEntry{{name: "package/ini.js", body: iniVulnerable}, {name: "package/package.json", body: "{}"}})
	w.tarballs["ini-1.3.6"] = buildTGZ(t, []tarEntry{{name: "package/ini.js", body: iniFixed}, {name: "package/package.json", body: "{}"}})

	_, trace := w.localiser(true).Localise(context.Background(), Finding{
		FindingID: "f1", VulnerabilityID: "CVE-2020-7788", Aliases: []string{"GHSA-qqgx-2p2h-9c37"}, PURL: "pkg:npm/ini@1.3.5",
	})
	got := map[Method]Attempt{}
	for _, a := range trace.Attempts {
		got[a.Method] = a
	}
	if got[MethodAdvisoryMetadata].Outcome != OutcomeEmpty {
		t.Errorf("metadata: %+v", got[MethodAdvisoryMetadata])
	}
	if a := got[MethodAdvisoryText]; a.Outcome != OutcomeHit || len(a.Candidates) != 1 || a.Candidates[0].Symbol != "parse" {
		t.Errorf("text: %+v", a)
	}
	vd := got[MethodVersionDiff]
	if vd.Outcome != OutcomeHit || vd.Provenance == nil || len(vd.Provenance.Artefacts) != 2 {
		t.Fatalf("version_diff: %+v", vd)
	}
	for _, art := range vd.Provenance.Artefacts {
		if art.Executed || !art.Verified {
			t.Errorf("artefact must be verified and never executed: %+v", art)
		}
	}
	if pr := got[MethodPatchReference]; pr.ClientMethod == nil || pr.ClientMethod.CommitsMatched != 1 {
		t.Errorf("client method evidence missing: %+v", pr.ClientMethod)
	}
}

// Failure / unknown path: no advisory anywhere and no fixed version means
// every method fails honestly and the result is unknown with no candidates.
func TestLocalise_UnknownWhenNothingIsAvailable(t *testing.T) {
	w := newFakeWorld(t)
	res, trace := w.localiser(false).Localise(context.Background(), Finding{
		FindingID: "f2", VulnerabilityID: "CVE-2099-0001", PURL: "pkg:npm/ghost@1.0.0",
	})
	if res.Method != MethodUnknown || res.Confidence != ConfidenceNone || len(res.CandidateSymbols) != 0 {
		t.Fatalf("expected honest unknown, got %+v", res)
	}
	if !strings.Contains(res.Notes, "package-level") {
		t.Errorf("notes should say it falls back to package level: %s", res.Notes)
	}
	if trace.Selected != MethodUnknown || len(trace.Attempts) != 4 {
		t.Errorf("trace = %+v", trace)
	}
	// A referenced release commit that changes no code is reported as such, not as a hit.
	w.osv["GHSA-2222-2222-2222"] = map[string]any{"id": "GHSA-2222-2222-2222", "summary": "x",
		"references": []any{map[string]string{"type": "WEB", "url": "https://github.com/acme/ghost/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}
	w.commits["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] = map[string]any{"sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"files": []any{map[string]any{"filename": "package.json", "status": "modified", "patch": "@@ -1,1 +1,1 @@\n-1\n+2"}}}
	res, trace = w.localiser(false).Localise(context.Background(), Finding{FindingID: "f3", VulnerabilityID: "GHSA-2222-2222-2222", PURL: "pkg:npm/ghost@1.0.0"})
	if res.Method != MethodUnknown {
		t.Errorf("release commit must not count as localisation: %+v", res)
	}
	var patch Attempt
	for _, a := range trace.Attempts {
		if a.Method == MethodPatchReference {
			patch = a
		}
	}
	if patch.Outcome != OutcomeNonCode {
		t.Errorf("patch outcome = %s, want non_code; notes %v", patch.Outcome, patch.Notes)
	}
}

// Boundary / untrusted input: a non-npm or malformed purl never reaches the
// network, and a hostile advisory cannot make the tool fetch arbitrary URLs.
func TestLocalise_RejectsBadPURLWithoutNetwork(t *testing.T) {
	w := newFakeWorld(t)
	for _, purl := range []string{"pkg:pypi/requests@2.0", "pkg:npm/../../etc@1", "not-a-purl", ""} {
		res, _ := w.localiser(true).Localise(context.Background(), Finding{FindingID: "b", VulnerabilityID: "CVE-2020-7788", PURL: purl})
		if res.Method != MethodUnknown || len(res.CandidateSymbols) != 0 {
			t.Errorf("%q: expected unknown, got %+v", purl, res)
		}
	}
	if len(w.requests) != 0 {
		t.Errorf("bad purls must make no requests, made %v", w.requests)
	}
}

// The contract's summary must agree with the results (validator rule
// "byMethod matches results").
func TestLocaliseAll_SummaryMatchesResults(t *testing.T) {
	w := newFakeWorld(t)
	w.seedIni()
	doc, traces := w.localiser(false).LocaliseAll(context.Background(), "scan-1", []Finding{
		{FindingID: "f1", VulnerabilityID: "CVE-2020-7788", Aliases: []string{"GHSA-qqgx-2p2h-9c37"}, PURL: "pkg:npm/ini@1.3.5"},
		{FindingID: "f2", VulnerabilityID: "CVE-2099-0001", PURL: "pkg:npm/ghost@1.0.0"},
	})
	if doc.SchemaVersion != SchemaVersion || doc.ScanID != "scan-1" || len(doc.Results) != 2 || len(traces) != 2 {
		t.Fatalf("doc = %+v", doc)
	}
	if doc.Summary.FindingsProcessed != 2 || doc.Summary.UnknownCount != 1 ||
		doc.Summary.ByMethod["patch_reference"] != 1 || doc.Summary.ByMethod["unknown"] != 1 {
		t.Errorf("summary = %+v", doc.Summary)
	}
	out, _ := json.Marshal(doc)
	if !strings.Contains(string(out), `"candidateSymbols":[]`) {
		t.Errorf("unknown result must serialise an empty candidate array: %s", out)
	}
}
