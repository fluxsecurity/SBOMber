package localisation

import "testing"

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
