package sourceanalysis

import "testing"

func TestCopiedImportsRemainUnresolved(t *testing.T) {
	for name, source := range map[string]string{
		"returned":             "const api=require('pkg'); function get(){return api.parse} const p=get(); p();",
		"callback":             "const api=require('pkg'); consume(api.parse);",
		"arrow value":          "const api=require('pkg'); const get=()=>api.parse; const p=get(); p();",
		"member":               "const api=require('pkg'); const p=api.parse; p();",
		"whole module":         "const api=require('pkg'); const other=api; other.parse();",
		"named ESM":            "import {parse} from 'pkg'; const p=parse; p();",
		"destructured require": "const {parse}=require('pkg'); const p=parse; p();",
		"later assignment":     "const api=require('pkg'); let p; p=api.parse; p();",
		"container":            "const api=require('pkg'); const handlers=[api.parse]; handlers[0]();",
		"object":               "const api=require('pkg'); const handlers={parse:api.parse}; handlers.parse();",
		"destructuring":        "const api=require('pkg'); const {parse:p}=api; p();",
	} {
		t.Run(name, func(t *testing.T) {
			r := analyzeSnippet(t, "app.js", source)
			if len(r.Imports) != 1 || r.Imports[0].UnresolvedUse != "outside_supported_syntax" {
				t.Fatalf("copied value lost: %+v", r.Imports)
			}
		})
	}
}
func TestDirectCallResultIsNotCopiedImport(t *testing.T) {
	r := analyzeSnippet(t, "app.js", "const api=require('pkg'); const result=api.parse('x');")
	if len(r.Imports) != 1 || r.Imports[0].UnresolvedUse != "" {
		t.Fatalf("ordinary call changed: %+v", r.Imports)
	}
}
