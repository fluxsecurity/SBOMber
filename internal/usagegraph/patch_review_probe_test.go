package usagegraph

import "testing"

func TestReviewComparisonRegressions(t *testing.T) {
	cases := []struct {
		name, source      string
		resolved, unknown int
	}{
		{"require binding then a real nested local shadow", "function run(){const lodash=require('lodash');lodash.merge({},{});{const lodash={merge:x=>x};lodash.merge({});}}", 1, 0},
		{"require binding must not leak out of its block", "function run(){{const lodash=require('lodash');}return lodash.merge({},{});}", 0, 0},
		{"require binding must not leak into another function", "function load(){const lodash=require('lodash');}function run(){return lodash.merge({},{});}", 0, 0},
		{"nested declaration must not degrade genuine call", "import {merge} from 'lodash';function run(){merge({},{});{const merge=null;}}", 1, 0},
		{"body var must not shadow default initializer", "import {merge} from 'lodash';function run(opts=merge({},{})){var merge=x=>x;return merge(opts);}", 1, 0},
		{"require assignment to declared local", "function run(){let lodash;lodash=require('lodash');return lodash.merge({},{});}", 1, 0},
		{"module require assignment to declared local", "let lodash;lodash=require('lodash');lodash.merge({},{});", 1, 0},
		{"own require nested inside outer parameter scope", "function outer(lodash){function run(){const lodash=require('lodash');return lodash.merge({},{});}}", 1, 0},
		{"assigned require still respects inner shadow", "function run(){let lodash;lodash=require('lodash');{const lodash={merge:x=>x};lodash.merge({});}return lodash.merge({},{});}", 1, 0},
		{"assigned require does not leak local declaration", "function load(){let lodash;lodash=require('lodash');}function run(){lodash.merge({},{});}", 0, 0},
		{"assignment to parameter is an import use", "function run(lodash){lodash=require('lodash');return lodash.merge({},{});}", 1, 0},
		{"module assignment does not bypass a parameter shadow", "let lodash;lodash=require('lodash');function run(lodash){lodash.merge({},{});}", 0, 0},
		{"dynamic assignment to function let", "export async function run(){let lodash;lodash=await import('lodash');return lodash.merge({},{});}", 1, 0},
		{"dynamic assignment to function var", "export async function run(){var lodash;lodash=await import('lodash');return lodash.merge({},{});}", 1, 0},
		{"dynamic assignment to module let", "let lodash;lodash=await import('lodash');lodash.merge({},{});", 1, 0},
		{"assigned dynamic import respects inner shadow", "export async function run(){let lodash;lodash=await import('lodash');{const lodash={merge:x=>x};lodash.merge({});}return lodash.merge({},{});}", 1, 0},
		{"assigned dynamic import does not leak", "async function load(){let lodash;lodash=await import('lodash');}function run(){lodash.merge({},{});}", 0, 0},
		{"generator parameter shadow", "import {merge} from 'lodash';function* run(merge){yield merge({});}", 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			graph := produceSourceTree(t, map[string]string{"src/index.js": tc.source + "\n"})
			resolved, unknown := 0, 0
			for _, obs := range graph.Observations {
				for _, call := range obs.CallSites {
					if call.Resolution == CallResolved {
						resolved++
					} else {
						unknown++
					}
				}
			}
			if resolved != tc.resolved || unknown != tc.unknown {
				t.Errorf("got resolved=%d unknown=%d; want resolved=%d unknown=%d", resolved, unknown, tc.resolved, tc.unknown)
			}
		})
	}
}

func TestRepeatedVarImportsStayUnresolved(t *testing.T) {
	graph := produceSourceTree(t, map[string]string{"src/index.js": "var lib=require('lodash'); lib.merge({},{}); var lib=require('underscore'); lib.merge({},{});\n"})
	if len(graph.Observations) != 2 {
		t.Fatalf("expected two imports: %+v", graph.Observations)
	}
	for _, obs := range graph.Observations {
		if obs.ImportedSpecifier != "lodash" && obs.ImportedSpecifier != "underscore" {
			continue
		}
		if len(obs.CallSites) != 2 {
			t.Fatalf("possible uses deleted for %s: %+v", obs.ImportedSpecifier, obs)
		}
		for _, call := range obs.CallSites {
			if call.Resolution != CallUnresolved || call.Reachability != ReachUnknown || len(call.CallPath) != 0 {
				t.Fatalf("ambiguous owner treated as proven: %+v", call)
			}
		}
	}
}
