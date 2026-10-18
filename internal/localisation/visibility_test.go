package localisation

import (
	"context"
	"strings"
	"testing"
)

// model builds the package model of a synthetic tarball.
func model(t *testing.T, files map[string]string) (*packageModel, error) {
	t.Helper()
	var entries []tarEntry
	for name, body := range files {
		entries = append(entries, tarEntry{name: "package/" + name, body: body})
	}
	tb := &Tarball{Files: map[string][]byte{}}
	if err := extractSources(buildTGZ(t, entries), tb); err != nil {
		t.Fatal(err)
	}
	return buildPackageModel(tb)
}

func mustModel(t *testing.T, files map[string]string) *packageModel {
	t.Helper()
	pm, err := model(t, files)
	if err != nil {
		t.Fatal(err)
	}
	return pm
}

func wantVis(t *testing.T, pm *packageModel, symbol, path, vis string, via []string, complete bool, why string) {
	t.Helper()
	got := pm.resolve(symbol, path)
	if got.Visibility != vis || strings.Join(got.ExposedVia, ",") != strings.Join(via, ",") || got.Complete != complete ||
		!strings.Contains(got.Why, why) {
		t.Errorf("%s in %s = %+v, want %s via %v complete=%v (%q)", symbol, path, got, vis, via, complete, why)
	}
}

// Success: the four shapes on the frozen set that steps 1-3 resolve.
func TestVisibility_ResolvedShapes(t *testing.T) {
	// ini: the entry exports the function under its own name and an alias.
	ini := mustModel(t, map[string]string{
		"package.json": `{"main": "ini.js"}`,
		"ini.js":       iniVulnerable,
	})
	wantVis(t, ini, "decode", "ini.js", VisibilityPublic, nil, true, "exported as decode, parse")
	wantVis(t, ini, "parse", "ini.js", VisibilityPublic, nil, true, "")

	// minimist: a helper nested in the anonymous module.exports function.
	minimist := mustModel(t, map[string]string{
		"package.json": `{"main": "index.js"}`,
		"index.js":     "module.exports = function (args) {\n  function setKey (o, k) { o[k] = 1 }\n  setKey({}, args)\n}\n",
	})
	wantVis(t, minimist, "setKey", "index.js", VisibilityInternal, []string{"default"}, true, "")

	// decode-uri-component: module-private helpers behind the default export.
	duc := mustModel(t, map[string]string{
		"package.json": `{}`,
		"index.js":     "function decode (s) { return s }\nfunction decodeComponents (s) { return decode(s) }\nmodule.exports = function (s) { return decodeComponents(s) }\n",
	})
	wantVis(t, duc, "decode", "index.js", VisibilityInternal, []string{"default"}, true, "decode is not exported")

	// qs: one hop. lib/index.js re-exports lib/parse.js as parse; without an
	// "exports" map lib/parse.js can also be required directly (default).
	qs := map[string]string{
		"package.json":     `{"main": "lib/index.js"}`,
		"lib/index.js":     "var parse = require('./parse');\nvar stringify = require('./stringify');\nmodule.exports = { parse: parse, stringify: stringify };\n",
		"lib/parse.js":     "var parseObject = function (c) { return c };\nmodule.exports = function (str) { return parseObject(str) };\n",
		"lib/stringify.js": "module.exports = function (o) { return '' + o };\n",
	}
	wantVis(t, mustModel(t, qs), "parseObject", "lib/parse.js", VisibilityInternal, []string{"default", "parse"}, true, "")
	// With an "exports" map only the entry is importable, so only parse.
	qs["package.json"] = `{"main": "lib/index.js", "exports": {".": {"require": "./lib/index.js"}, "./package.json": "./package.json"}}`
	wantVis(t, mustModel(t, qs), "parseObject", "lib/parse.js", VisibilityInternal, []string{"parse"}, true, "")
}

// ESM forms resolve the same way.
func TestVisibility_ESM(t *testing.T) {
	pm := mustModel(t, map[string]string{
		"package.json":   `{"exports": "./index.mjs"}`,
		"index.mjs":      "import helper from './lib/helper.mjs'\nexport default function ansiRegex () { return helper() }\nexport { tidy as clean } from './lib/tidy.mjs'\n",
		"lib/helper.mjs": "export default function helper () { return 1 }\n",
		"lib/tidy.mjs":   "function strip (s) { return s }\nexport function tidy (s) { return strip(s) }\n",
	})
	wantVis(t, pm, "ansiRegex", "index.mjs", VisibilityInternal, []string{"default"}, true, "")
	// The entry uses helper inside its own code, so any entry export may
	// reach it: the list is a superset, which is the safe direction.
	wantVis(t, pm, "helper", "lib/helper.mjs", VisibilityInternal, []string{"clean", "default"}, true, "")
	wantVis(t, pm, "strip", "lib/tidy.mjs", VisibilityInternal, []string{"clean"}, true, "strip is not exported")
}

// Failure / unknown paths: every reason a route may be missing leaves the
// set open (incomplete or unknown), never closed.
func TestVisibility_IncompleteOrUnknown(t *testing.T) {
	base := func() map[string]string {
		return map[string]string{
			"package.json": `{"main": "lib/index.js"}`,
			"lib/index.js": "var parse = require('./parse');\nmodule.exports = { parse: parse };\n",
			"lib/parse.js": "function helper (s) { return s }\nmodule.exports = function (s) { return helper(s) };\n",
		}
	}
	cases := []struct {
		name string
		edit func(map[string]string)
		why  string
	}{
		{"loaded by a second module (more than one hop)", func(f map[string]string) {
			f["lib/other.js"] = "var p = require('./parse');\nmodule.exports = function wrap (s) { return p(s) };\n"
		}, "is loaded by lib/other.js"},
		{"a computed require anywhere", func(f map[string]string) {
			f["lib/load.js"] = "module.exports = function (n) { return require('./' + n) };\n"
		}, "loads a module by a computed path"},
		{"a second copy in a bundle", func(f map[string]string) {
			f["dist/bundle.js"] = "function helper (s) { return s }\n"
		}, "another copy of helper is in dist/bundle.js"},
		{"computed exports in the module", func(f map[string]string) {
			f["lib/parse.js"] += "module.exports['x' + 1] = helper;\n"
		}, "computed export"},
		{"a separate bundler entry", func(f map[string]string) {
			f["package.json"] = `{"main": "lib/index.js", "module": "esm/index.js"}`
		}, "separate \"module\" entry"},
	}
	for _, c := range cases {
		files := base()
		c.edit(files)
		got := mustModel(t, files).resolve("helper", "lib/parse.js")
		if got.Visibility != VisibilityInternal || got.Complete || !strings.Contains(got.Why, c.why) {
			t.Errorf("%s: %+v, want incomplete because %q", c.name, got, c.why)
		}
	}

	pm := mustModel(t, base())
	wantVis(t, pm, "helper", "lib/missing.js", VisibilityUnknown, nil, false, "not in the published vulnerable package")
	wantVis(t, pm, "addedByTheFix", "lib/parse.js", VisibilityUnknown, nil, false, "not defined in lib/parse.js")

	// lodash's UMD export is not a plain module.exports assignment.
	umd := mustModel(t, map[string]string{
		"package.json": `{"main": "lodash.js"}`,
		"lodash.js":    ";(function () {\n  var runInContext = (function runInContext () {\n    function template () {}\n    return template\n  })\n  var freeModule = typeof module == 'object' && module\n  freeModule.exports = runInContext()\n}.call(this))\n",
	})
	wantVis(t, umd, "template", "lodash.js", VisibilityUnknown, nil, false, "could not be resolved statically")
}

// An exported function that other exports also call is not public: an
// application can reach it without calling it by name.
func TestVisibility_ExportedButUsedInternally(t *testing.T) {
	pm := mustModel(t, map[string]string{
		"package.json": `{}`,
		"index.js":     "function decode (s) { return s }\nfunction parseAll (l) { return l.map(decode) }\nmodule.exports = { decode, parseAll }\n",
	})
	wantVis(t, pm, "decode", "index.js", VisibilityInternal, []string{"decode", "parseAll"}, true, "also used by other code")
	wantVis(t, pm, "parseAll", "index.js", VisibilityPublic, nil, true, "")
}

// Boundary / untrusted input: the manifest and requires come from the
// package, so paths that leave it and malformed manifests resolve nothing.
func TestVisibility_HostilePackage(t *testing.T) {
	for name, manifest := range map[string]string{
		"main outside the package": `{"main": "../../etc/passwd"}`,
		"absolute main":            `{"main": "/etc/passwd"}`,
		"malformed":                `{"main": `,
		"exports to nowhere":       `{"exports": "./missing.js"}`,
	} {
		if _, err := model(t, map[string]string{"package.json": manifest, "index.js": "module.exports = 1\n"}); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := model(t, map[string]string{"index.js": "module.exports = 1\n"}); err == nil {
		t.Error("no package.json: want an error")
	}
	if got := resolveModule("lib/a.js", "../../../etc/passwd", map[string]bool{"etc/passwd": true}); got != "" {
		t.Errorf("escaping require resolved to %q", got)
	}
	// A pattern in "exports" makes every file importable by path.
	pm := mustModel(t, map[string]string{
		"package.json": `{"exports": {".": "./index.js", "./lib/*": "./lib/*.js"}}`,
		"index.js":     "module.exports = function () {}\n",
		"lib/x.js":     "function h () {}\nmodule.exports = { run: function () { return h() } }\n",
	})
	wantVis(t, pm, "h", "lib/x.js", VisibilityInternal, []string{"run"}, true, "")
}

// Through the localiser: the vulnerable tarball is fetched, verified and
// recorded, and the join-rule fields are filled.
func TestLocalise_FillsVisibility(t *testing.T) {
	w := newFakeWorld(t)
	w.seedIni()
	w.tarballs["ini-1.3.5"] = buildTGZ(t, []tarEntry{{name: "package/ini.js", body: iniVulnerable},
		{name: "package/package.json", body: `{"main": "ini.js"}`}})
	res, _ := w.localiser(false).Localise(context.Background(), Finding{FindingID: "f1",
		VulnerabilityID: "CVE-2020-7788", Aliases: []string{"GHSA-qqgx-2p2h-9c37"}, PURL: "pkg:npm/ini@1.3.5"})
	for _, c := range res.CandidateSymbols {
		if c.Visibility != VisibilityPublic || c.ExposedVia != nil || c.ExposedViaComplete != nil {
			t.Errorf("%s: %+v", c.Symbol, c)
		}
	}
	if !strings.Contains(res.Notes, "Visibility read from npm:ini@1.3.5: 2 of 2") {
		t.Errorf("notes = %s", res.Notes)
	}
	found := false
	for _, a := range res.Provenance.Artefacts {
		found = found || a.ID == "npm:ini@1.3.5" && a.Verified && a.Kind == ArtefactTarball
	}
	if !found {
		t.Errorf("vulnerable tarball not recorded: %+v", res.Provenance.Artefacts)
	}
	v := VerifyDocument(Document{SchemaVersion: SchemaVersion, Results: []Result{res}})
	if v.Errors() != 0 {
		t.Errorf("verification: %+v", v.Issues)
	}

	// A tarball that fails its integrity check resolves nothing.
	w2 := newFakeWorld(t)
	w2.seedIni()
	w2.tarballs["ini-1.3.5"] = buildTGZ(t, []tarEntry{{name: "package/ini.js", body: iniVulnerable}})
	w2.registryDocs["ini/1.3.5"] = map[string]any{"name": "ini", "version": "1.3.5",
		"dist": map[string]any{"tarball": w2.srv.URL + "/ini/-/ini-1.3.5.tgz", "integrity": "sha512-AAAA"}}
	res, _ = w2.localiser(false).Localise(context.Background(), Finding{FindingID: "f1",
		VulnerabilityID: "CVE-2020-7788", Aliases: []string{"GHSA-qqgx-2p2h-9c37"}, PURL: "pkg:npm/ini@1.3.5"})
	for _, c := range res.CandidateSymbols {
		if c.Visibility != VisibilityUnknown {
			t.Errorf("unverified tarball: %s = %s", c.Symbol, c.Visibility)
		}
	}
	if !strings.Contains(res.Notes, "does not match the registry integrity value") {
		t.Errorf("notes = %s", res.Notes)
	}
}
