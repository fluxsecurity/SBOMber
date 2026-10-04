package sourceanalysis

import (
	"path/filepath"
	"testing"
)

type wantImport struct {
	specifier     string
	kind          string
	local         string
	imported      string
	unresolvedUse string
	inlineCallee  string
}

func analyzeSnippet(t *testing.T, name, content string) Result {
	t.Helper()
	root := t.TempDir()
	writeTestSource(t, root, name, content)
	result, err := AnalyzeSource(filepath.Join(root, name))
	if err != nil {
		t.Fatalf("AnalyzeSource(%s): %v", name, err)
	}
	return result
}

// Every import form below used to be dropped or to fail the whole file.
// Each must now produce exactly the listed import records.
func TestImportFormsAreRecordedNotDropped(t *testing.T) {
	cases := []struct {
		name   string
		file   string
		source string
		want   []wantImport
	}{
		{
			name:   "computed require",
			file:   "a.js",
			source: "export function f(name) { const m = require(name); return m.x(); }\n",
			want:   []wantImport{{specifier: "name", kind: "dynamic_computed", local: "m", imported: "*"}},
		},
		{
			name:   "template require with substitution",
			file:   "a.js",
			source: "const m = require(`lod${suffix}`);\n",
			want:   []wantImport{{specifier: "`lod${suffix}`", kind: "dynamic_computed", local: "m", imported: "*"}},
		},
		{
			name:   "template require without substitution",
			file:   "a.js",
			source: "const m = require(`lodash`);\n",
			want:   []wantImport{{specifier: "lodash", kind: "cjs_require", local: "m", imported: "*"}},
		},
		{
			name:   "bare require statement",
			file:   "a.js",
			source: "require('lodash');\n",
			want:   []wantImport{{specifier: "lodash", kind: "cjs_require", imported: "*"}},
		},
		{
			name:   "chained require call",
			file:   "a.js",
			source: "export function f(x) { return require('lodash').merge({}, x); }\n",
			want:   []wantImport{{specifier: "lodash", kind: "cjs_require", imported: "*", inlineCallee: "merge"}},
		},
		{
			name:   "require called directly",
			file:   "a.js",
			source: "const log = require('debug')('app');\n",
			want:   []wantImport{{specifier: "debug", kind: "cjs_require", imported: "*", inlineCallee: "default"}},
		},
		{
			name:   "member of require bound to a name",
			file:   "a.js",
			source: "const merge = require('lodash').merge;\n",
			want:   []wantImport{{specifier: "lodash", kind: "cjs_destructured", local: "merge", imported: "merge"}},
		},
		{
			name:   "require passed as an argument",
			file:   "a.js",
			source: "wrap(require('lodash'));\n",
			want:   []wantImport{{specifier: "lodash", kind: "cjs_require", imported: "*", unresolvedUse: "outside_supported_syntax"}},
		},
		{
			name:   "require nested inside another call is not bound",
			file:   "a.js",
			source: "const wrapped = wrap(require('lodash'));\n",
			want:   []wantImport{{specifier: "lodash", kind: "cjs_require", imported: "*", unresolvedUse: "outside_supported_syntax"}},
		},
		{
			name:   "require assigned to an existing name",
			file:   "a.js",
			source: "let m;\nm = require('lodash');\n",
			want:   []wantImport{{specifier: "lodash", kind: "cjs_require", local: "m", imported: "*"}},
		},
		{
			name:   "require with array pattern",
			file:   "a.js",
			source: "const [first] = require('lodash');\n",
			want:   []wantImport{{specifier: "lodash", kind: "cjs_require", imported: "*", unresolvedUse: "outside_supported_syntax"}},
		},
		{
			name:   "require destructuring with a default",
			file:   "a.js",
			source: "const { merge, pick = null } = require('lodash');\n",
			want: []wantImport{
				{specifier: "lodash", kind: "cjs_destructured", local: "merge", imported: "merge"},
				{specifier: "lodash", kind: "cjs_require", imported: "*", unresolvedUse: "outside_supported_syntax"},
			},
		},
		{
			name:   "named re-export",
			file:   "a.js",
			source: "export { merge, template as t } from 'lodash';\n",
			want: []wantImport{
				{specifier: "lodash", kind: "esm_reexport", imported: "merge", unresolvedUse: "reexport_chain"},
				{specifier: "lodash", kind: "esm_reexport", imported: "template", unresolvedUse: "reexport_chain"},
			},
		},
		{
			name:   "star re-export",
			file:   "a.js",
			source: "export * from 'lodash';\n",
			want:   []wantImport{{specifier: "lodash", kind: "esm_reexport", imported: "*", unresolvedUse: "reexport_chain"}},
		},
		{
			name:   "namespace re-export",
			file:   "a.js",
			source: "export * as _ from 'lodash';\n",
			want:   []wantImport{{specifier: "lodash", kind: "esm_reexport", imported: "*", unresolvedUse: "reexport_chain"}},
		},
		{
			name:   "type-only re-export stays type-only",
			file:   "a.ts",
			source: "export type { Dictionary } from 'lodash';\n",
			want:   []wantImport{{specifier: "lodash", kind: "esm_type_only", imported: "Dictionary"}},
		},
		{
			name:   "side-effect import",
			file:   "a.js",
			source: "import 'lodash';\n",
			want:   []wantImport{{specifier: "lodash", kind: "esm_side_effect"}},
		},
		{
			name:   "TypeScript import-equals",
			file:   "a.ts",
			source: "import _ = require('lodash');\nexport function f() { return _.merge({}, {}); }\n",
			want:   []wantImport{{specifier: "lodash", kind: "cjs_require", local: "_", imported: "*"}},
		},
		{
			name:   "empty require loads nothing",
			file:   "a.js",
			source: "require();\n",
			want:   nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := analyzeSnippet(t, tc.file, tc.source)
			if len(result.Imports) != len(tc.want) {
				t.Fatalf("imports = %+v, want %d", result.Imports, len(tc.want))
			}
			for index, want := range tc.want {
				got := result.Imports[index]
				inline := ""
				if len(got.InlineCalls) == 1 && got.InlineCalls[0].Callee != nil {
					inline = *got.InlineCalls[0].Callee
				}
				if got.Specifier != want.specifier || got.Kind != want.kind ||
					got.Local != want.local || got.Imported != want.imported ||
					got.UnresolvedUse != want.unresolvedUse ||
					inline != want.inlineCallee {
					t.Fatalf("import %d = %+v, want %+v", index, got, want)
				}
			}
		})
	}
}

// Boundary: an unsupported component format must be counted, not ignored.
func TestAnalyzeRepositorySkipsUnsupportedSourceFormats(t *testing.T) {
	root := t.TempDir()
	writeTestSource(t, root, "src/main.js", "export function main() { return 1; }\n")
	writeTestSource(t, root, "src/App.vue", "<script>\nimport _ from 'lodash';\n</script>\n")
	writeTestSource(t, root, "src/Card.svelte", "<script>\nimport _ from 'lodash';\n</script>\n")
	writeTestSource(t, root, "README.md", "# not source\n")

	result, err := AnalyzeRepository(root, RepositoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 1 {
		t.Fatalf("parsed files = %+v", result.Files)
	}
	reasons := skippedReasons(result)
	if len(reasons) != 2 ||
		reasons["src/App.vue"] != SkipUnsupportedSource ||
		reasons["src/Card.svelte"] != SkipUnsupportedSource {
		t.Fatalf("skipped = %+v", reasons)
	}
}
