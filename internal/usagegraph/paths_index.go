package usagegraph

import (
	"sort"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

type indexedPath struct {
	entry     EntryPoint
	parent    sourceanalysis.FunctionID
	hasParent bool
}

type graphPaths map[sourceanalysis.FunctionID]indexedPath

// pathsFrom searches once from all entry points. Entry-point ID breaks ties
// between paths of the same length; call-graph edges are already sorted.
func (graph applicationCallGraph) pathsFrom(entries []EntryPoint) graphPaths {
	ordered := append([]EntryPoint(nil), entries...)
	sort.Slice(ordered, func(left, right int) bool {
		a, b := ordered[left], ordered[right]
		if a.EntryPointID != b.EntryPointID {
			return a.EntryPointID < b.EntryPointID
		}
		aStart := sourceanalysis.FunctionID{
			RepositoryID: a.RepositoryID, File: a.File,
			Name: a.Function, StartLine: a.Line,
		}
		bStart := sourceanalysis.FunctionID{
			RepositoryID: b.RepositoryID, File: b.File,
			Name: b.Function, StartLine: b.Line,
		}
		return functionPathKey([]sourceanalysis.FunctionID{aStart}) <
			functionPathKey([]sourceanalysis.FunctionID{bStart})
	})

	paths := make(graphPaths)
	queue := make([]sourceanalysis.FunctionID, 0, len(graph.functions))
	for _, entry := range ordered {
		start := sourceanalysis.FunctionID{
			RepositoryID: entry.RepositoryID,
			File:         entry.File,
			Name:         entry.Function,
			StartLine:    entry.Line,
		}
		if _, valid := graph.functions[start]; !valid {
			continue
		}
		if _, seen := paths[start]; seen {
			continue
		}
		paths[start] = indexedPath{entry: entry}
		queue = append(queue, start)
	}

	for head := 0; head < len(queue); head++ {
		current := queue[head]
		for _, next := range graph.edges[current] {
			if _, seen := paths[next]; seen {
				continue
			}
			paths[next] = indexedPath{
				entry:     paths[current].entry,
				parent:    current,
				hasParent: true,
			}
			queue = append(queue, next)
		}
	}
	return paths
}

func (paths graphPaths) pathTo(
	target sourceanalysis.FunctionID,
) (EntryPoint, []CallPathStep, bool) {
	record, found := paths[target]
	if !found {
		return EntryPoint{}, nil, false
	}

	reversed := make([]CallPathStep, 0, 4)
	for current := target; ; {
		reversed = append(reversed, CallPathStep{
			Function: current.Name,
			File:     current.File,
			Line:     current.StartLine,
		})
		item := paths[current]
		if !item.hasParent {
			break
		}
		current = item.parent
	}
	path := make([]CallPathStep, len(reversed))
	for index := range reversed {
		path[len(reversed)-1-index] = reversed[index]
	}
	return record.entry, path, true
}
