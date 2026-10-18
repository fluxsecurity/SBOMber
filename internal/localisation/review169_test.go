package localisation

import (
	"context"
	"testing"
)

func TestReview169_AllExportAliasesJoin(t *testing.T) {
	pm := mustModel(t, map[string]string{"package.json": `{}`, "index.js": "function decode(s) { return s }\nmodule.exports = { decode, parse: decode }\n"})
	got := pm.resolve("decode", "index.js")
	if got.Visibility != VisibilityInternal || !contains(got.ExposedVia, "parse") || !contains(got.ExposedVia, "decode") || !got.Complete {
		t.Fatalf("alias route lost: %+v", got)
	}
}
func TestReview169_ConditionalEntriesStayOpen(t *testing.T) {
	pm := mustModel(t, map[string]string{"package.json": `{"exports":{"require":"./index.js","import":"./other.mjs"}}`, "index.js": "function decode(s) { return s }\nmodule.exports = { decode }\n", "other.mjs": "export function parse(s) { return s }\n"})
	got := pm.resolve("decode", "index.js")
	if got.Complete {
		t.Fatalf("alternate condition was ignored: %+v", got)
	}
}
func TestReview169_SameLineCallerRetained(t *testing.T) {
	pm := mustModel(t, map[string]string{"package.json": `{}`, "index.js": "function decode(s) { return s }; function parse(s) { return decode(s) };\nmodule.exports = { decode, parse }\n"})
	got := pm.resolve("decode", "index.js")
	if got.Visibility != VisibilityInternal || !contains(got.ExposedVia, "parse") {
		t.Fatalf("same-line caller lost: %+v", got)
	}
}
func TestReview169_UnanalysedBundleStaysOpen(t *testing.T) {
	pm := mustModel(t, map[string]string{"package.json": `{}`, "index.js": "function decode(s) { return s }\nmodule.exports = { decode }\n", "dist/bundle.min.js": "function decode(s){return s};module.exports={parse:decode};"})
	if got := pm.resolve("decode", "index.js"); got.Complete {
		t.Fatalf("unanalysed package source ignored: %+v", got)
	}
}

func TestReview169_ModuleInitialisationStaysOpen(t *testing.T) {
	pm := mustModel(t, map[string]string{"package.json": `{}`, "index.js": "function decode(s) { return s }\ndecode('input');\nmodule.exports={decode};\n"})
	if got := pm.resolve("decode", "index.js"); got.Complete {
		t.Fatalf("load-time execution hidden: %+v", got)
	}
}

func TestReview169_OnlineVisibilityRejectsAlteredClosure(t *testing.T) {
	tb := &Tarball{Manifest: []byte(`{}`), Files: map[string][]byte{"index.js": []byte("function decode(s){return s}\nmodule.exports={decode,parse:decode}\n")}}
	complete := true
	r := Result{FindingID: "f1", PURL: "pkg:npm/pkg@1.0.0", CandidateSymbols: []Candidate{{Symbol: "decode", ModulePath: "index.js", Visibility: VisibilityPublic}}}
	got := map[string]*refetched{TarballArtefactID("pkg", "1.0.0"): {tarball: tb}}
	l := &Localiser{}
	v := Verification{}
	l.verifyVisibility(context.Background(), r, got, &v)
	if v.Errors() == 0 {
		t.Fatal("forged public visibility passed online verification")
	}
	r.CandidateSymbols[0].Visibility = VisibilityInternal
	r.CandidateSymbols[0].ExposedVia = []string{"decode", "parse"}
	r.CandidateSymbols[0].ExposedViaSource = ExposedViaExportResolution
	r.CandidateSymbols[0].ExposedViaComplete = &complete
	v = Verification{}
	l.verifyVisibility(context.Background(), r, got, &v)
	if v.Errors() != 0 {
		t.Fatalf("genuine visibility failed: %+v", v.Issues)
	}
	v = Verification{}
	l.verifyVisibility(context.Background(), r, nil, &v)
	if v.Errors() == 0 {
		t.Fatal("closure without the vulnerable tarball passed")
	}
}
