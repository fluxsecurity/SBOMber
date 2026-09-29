package usagegraph

import (
	"reflect"
	"strconv"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

func TestPrecomputedPathsMatchPerTargetSearch(t *testing.T) {
	id := func(name string, line int) sourceanalysis.FunctionID {
		return sourceanalysis.FunctionID{
			RepositoryID: "repo-app",
			File:         "src/app.js",
			Name:         name,
			StartLine:    line,
		}
	}
	startA := id("startA", 1)
	startB := id("startB", 2)
	viaA := id("viaA", 3)
	viaB := id("viaB", 4)
	target := id("target", 5)
	unreachable := id("unreachable", 6)

	graph := applicationCallGraph{
		functions: map[sourceanalysis.FunctionID]struct{}{
			startA: {}, startB: {}, viaA: {}, viaB: {},
			target: {}, unreachable: {},
		},
		edges: map[sourceanalysis.FunctionID][]sourceanalysis.FunctionID{
			startA: {viaA, viaB},
			startB: {viaB},
			viaA:   {target},
			viaB:   {target},
		},
	}
	entries := []EntryPoint{
		{
			EntryPointID: "ep-b", RepositoryID: "repo-app",
			File: "src/app.js", Function: "startB", Line: 2,
		},
		{
			EntryPointID: "ep-a", RepositoryID: "repo-app",
			File: "src/app.js", Function: "startA", Line: 1,
		},
	}

	for _, ordered := range [][]EntryPoint{entries, {entries[1], entries[0]}} {
		paths := graph.pathsFrom(ordered)
		for _, node := range []sourceanalysis.FunctionID{
			startA, startB, viaA, viaB, target, unreachable,
		} {
			wantEntry, wantPath, wantOK := graph.pathTo(ordered, node)
			gotEntry, gotPath, gotOK := paths.pathTo(node)
			if gotOK != wantOK ||
				gotEntry.EntryPointID != wantEntry.EntryPointID ||
				!reflect.DeepEqual(gotPath, wantPath) {
				t.Fatalf("%s: indexed path = %+v / %+v / %v; search = %+v / %+v / %v",
					node.Name, gotEntry, gotPath, gotOK,
					wantEntry, wantPath, wantOK)
			}
		}
	}
}

func BenchmarkPrecomputedPaths(b *testing.B) {
	for _, size := range []int{400, 1600} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			graph := applicationCallGraph{
				functions: make(map[sourceanalysis.FunctionID]struct{}, size*2),
				edges:     make(map[sourceanalysis.FunctionID][]sourceanalysis.FunctionID, size),
			}
			entries := make([]EntryPoint, 0, size)
			var lastTarget sourceanalysis.FunctionID
			for index := 0; index < size; index++ {
				start := sourceanalysis.FunctionID{
					RepositoryID: "repo-app", File: "src/app.js",
					Name: "start" + strconv.Itoa(index), StartLine: index*2 + 1,
				}
				target := sourceanalysis.FunctionID{
					RepositoryID: "repo-app", File: "src/app.js",
					Name: "target" + strconv.Itoa(index), StartLine: index*2 + 2,
				}
				graph.functions[start] = struct{}{}
				graph.functions[target] = struct{}{}
				graph.edges[start] = []sourceanalysis.FunctionID{target}
				entries = append(entries, EntryPoint{
					EntryPointID: "ep-" + strconv.Itoa(index),
					RepositoryID: "repo-app", File: "src/app.js",
					Function: start.Name, Line: start.StartLine,
				})
				lastTarget = target
			}
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				paths := graph.pathsFrom(entries)
				if _, path, ok := paths.pathTo(lastTarget); !ok || len(path) != 2 {
					b.Fatal("indexed path missing")
				}
			}
		})
	}
}
