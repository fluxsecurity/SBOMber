package usagegraph

import "testing"

func TestObservationLexicalShadows(t *testing.T) {
	const named = "import { merge } from 'lodash';\n"
	cases := []struct {
		name, source, extension string
		calls                   int
	}{
		{"function require", "function run(){ const lodash=require('lodash'); return lodash.merge({},{});}", "js", 1},
		{"function destructured require", "function run(){ const {merge}=require('lodash'); return merge({},{});}", "js", 1},
		{"default parameter expression", named + "export function run(opts=merge({},{})){return merge(opts,{})}", "js", 2},
		{"nested block does not shadow outer call", named + "export function run(){merge({},{}); {const merge=null;} }", "js", 1},
		{"nested callback does not shadow outer call", named + "export function run(){merge({},{}); [1].map(()=>{const merge=null;});}", "js", 1},
		{"type query is not a parameter", named + "export function run(x: Parameters<typeof merge>[0]){return merge(x,{})}", "ts", 1},
		{"destructured arrow parameter", named + "const run=({merge})=>merge({},{});", "js", 0},
		{"class method parameter", named + "class A{run(merge){return merge({},{});}}", "js", 0},
		{"local arrow", named + "function run(){ const merge=x=>x; return merge({});}", "js", 0},
		{"local let", named + "function run(){ let merge=x=>x; return merge({});}", "js", 0},
		{"local function", named + "function run(){function merge(x){return x;} return merge({});}", "js", 0},
		{"nested local and genuine call", named + "function run(){ {const merge=x=>x; merge({});} return merge({},{});}", "js", 1},
		{"require outside its scope", "function load(){const lodash=require('lodash');lodash.merge({},{});} function run(){lodash.merge({},{});}", "js", 1},
		{"catch binding", named + "function run(){try {} catch(merge){merge({});} return merge({},{});}", "js", 1},
		{"destructured default parameter", named + "function run({merge=()=>{}}={}){merge({});}", "js", 0},
		{"aliased destructured parameter", named + "function run({value:merge}){merge({});}", "js", 0},
		{"for of binding", named + "function run(xs){for(const merge of xs){merge({});} return merge({},{});}", "js", 1},
		{"hoisted var", named + "function run(){merge({});if(true){var merge=x=>x;}}", "js", 0},
		{"sibling callback parameter", named + "function run(){[1].map(merge=>merge({}));return merge({},{});}", "js", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			graph := produceSourceTree(t, map[string]string{"src/index." + tc.extension: tc.source + "\n"})
			if graph.Analysis.Status != AnalysisComplete {
				t.Fatalf("incomplete analysis: %+v", graph.Analysis)
			}
			count := 0
			for _, observation := range graph.Observations {
				if observation.PURL == "pkg:npm/lodash@4.17.21" {
					count += len(observation.CallSites)
				}
			}
			if count != tc.calls {
				t.Fatalf("dependency calls: got %d want %d; observations=%+v", count, tc.calls, graph.Observations)
			}
		})
	}
}
