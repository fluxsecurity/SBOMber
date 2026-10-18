package localisation

import (
	"context"
	"strings"
	"testing"
)

func review168Document(t *testing.T) (*fakeWorld, *Localiser, Document) {
	t.Helper()
	w := newFakeWorld(t)
	w.seedIni()
	w.seedIniReleases()
	l := w.localiser(false)
	doc, _ := l.LocaliseAll(context.Background(), "review-168", []Finding{{FindingID: "f1", VulnerabilityID: "CVE-2020-7788", Aliases: []string{"GHSA-qqgx-2p2h-9c37"}, PURL: "pkg:npm/ini@1.3.5"}})
	return w, l, doc
}

func TestReview168RejectsInventedDefault(t *testing.T) {
	_, l, doc := review168Document(t)
	doc.Results[0].CandidateSymbols = []Candidate{{Symbol: "default", ModulePath: "ini.js", Evidence: []string{SourceArtefactID("npm/ini", iniFix, "ini.js")}}}
	v := VerifyDocument(doc)
	l.Refetch(context.Background(), doc, &v)
	if v.Errors() == 0 {
		t.Fatal("invented default candidate passed online verification")
	}
}

func TestReview168AdvisoryMustMatchEachResult(t *testing.T) {
	for _, which := range []string{"vulnerability", "package"} {
		t.Run(which, func(t *testing.T) {
			_, l, doc := review168Document(t)
			second := doc.Results[0]
			second.FindingID = "f2"
			if which == "vulnerability" {
				second.VulnerabilityID = "CVE-2099-9999"
			} else {
				second.PURL = "pkg:npm/other@1.3.5"
			}
			doc.Results = append(doc.Results, second)
			v := VerifyDocument(doc)
			l.Refetch(context.Background(), doc, &v)
			if !hasIssueFor(v, "f2", "does not") {
				t.Fatalf("foreign %s borrowed verified advisory: %+v", which, v.Issues)
			}
			if hasIssueFor(v, "f1", "does not") {
				t.Fatalf("valid first result incorrectly rejected: %+v", v.Issues)
			}
		})
	}
}

func TestReview168DoesNotTrustSavedBackportLines(t *testing.T) {
	w, l, doc := review168Document(t)
	w.compare[iniFix+"..."+iniFixedRel] = "diverged"
	w.files["npm/ini/"+iniFixedRel+"/ini.js"] = iniVulnerable
	for i := range doc.Results[0].Provenance.TagChecks {
		tc := &doc.Results[0].Provenance.TagChecks[i]
		if tc.Role != TagRoleFixed {
			continue
		}
		tc.Basis = BasisContent
		tc.ByAncestry = nil
		tc.ByContent = []string{iniFix}
		// A hand-edited record omits the real parent and substitutes an old,
		// generic line for the real newly added __proto__ guard.
		tc.Content = []FixContent{{Commit: iniFix, Path: "ini.js", Lines: []string{"function decode (str) {"}}}
	}
	v := VerifyDocument(doc)
	l.Refetch(context.Background(), doc, &v)
	if v.Errors() == 0 {
		t.Fatal("forged backport evidence verified a release without the fix")
	}
}

func TestReview168ComparesActualAncestryValues(t *testing.T) {
	_, l, doc := review168Document(t)
	for i := range doc.Results[0].Provenance.TagChecks {
		tc := &doc.Results[0].Provenance.TagChecks[i]
		if tc.Role == TagRoleFixed {
			tc.ByAncestry = []string{strings.Repeat("f", 40)}
		}
	}
	v := VerifyDocument(doc)
	l.Refetch(context.Background(), doc, &v)
	if v.Errors() == 0 {
		t.Fatal("altered ancestry commit accepted because the list length matches")
	}
}

func TestReview168RejectsMissingDocumentIdentity(t *testing.T) {
	if v := VerifyDocument(Document{SchemaVersion: SchemaVersion}); v.Errors() == 0 {
		t.Fatal("document without scanId or results passed")
	}
}

func TestReview168UnverifiedAdvisoryCannotProduceCandidates(t *testing.T) {
	for _, which := range []string{"vulnerability", "package"} {
		t.Run(which, func(t *testing.T) {
			w := newFakeWorld(t)
			w.seedIni()
			rec := w.osv["GHSA-qqgx-2p2h-9c37"].(map[string]any)
			if which == "vulnerability" {
				rec["id"] = "CVE-2099-9999"
				delete(rec, "aliases")
			} else {
				rec["affected"] = []any{map[string]any{"package": map[string]string{"ecosystem": "npm", "name": "other"}}}
			}
			res, _ := w.localiser(false).Localise(context.Background(), Finding{FindingID: "f1", VulnerabilityID: "CVE-2020-7788", Aliases: []string{"GHSA-qqgx-2p2h-9c37"}, PURL: "pkg:npm/ini@1.3.5"})
			if res.Method != MethodUnknown || len(res.CandidateSymbols) != 0 {
				t.Fatalf("unverified %s selected candidates: %+v", which, res)
			}
			if !strings.Contains(res.Notes, "identity verification failed") {
				t.Fatalf("unknown needs identity failure explanation: %+v", res)
			}
		})
	}
}

func TestReview168DefaultEvidenceUsesParsedSymbols(t *testing.T) {
	for _, src := range []string{
		"module.exports = function () {return 1}",
		"function run(){return 1}; module.exports=run;",
		"export default () => 1;",
		"export default function () { return 1 }",
		"export default function run(){return 1}",
	} {
		if !sourceMentions("index.js", []byte(src), "default") {
			t.Errorf("genuine default export rejected: %s", src)
		}
	}
	for _, src := range []string{"function run(){return 1}", "// export default () => 1;\nfunction run(){return 1}"} {
		if sourceMentions("index.js", []byte(src), "default") {
			t.Errorf("invented/comment-only default accepted: %s", src)
		}
	}
}

func TestReview168TagVersionMustMatchResult(t *testing.T) {
	_, _, doc := review168Document(t)
	doc.Results[0].Provenance.TagChecks[0].Version = "9.9.9"
	if v := VerifyDocument(doc); !hasIssue(v, SeverityError, "release version does not match its result") {
		t.Fatalf("unrelated release accepted: %+v", v)
	}
}

func TestReview168CanonicalJSONRejectsTrailingDelimiters(t *testing.T) {
	for _, raw := range []string{"{} ]", "{} }", "{} true", "[] false"} {
		if _, err := canonicalJSON([]byte(raw)); err == nil {
			t.Errorf("accepted trailing data: %s", raw)
		}
	}
}
