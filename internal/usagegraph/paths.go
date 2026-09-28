package usagegraph

import (
	"sort"
	"strconv"
	"strings"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

func (graph applicationCallGraph) pathTo(
	entryPoints []EntryPoint,
	target sourceanalysis.FunctionID,
) (EntryPoint, []CallPathStep, bool) {
	if _, exists := graph.functions[target]; !exists {
		return EntryPoint{}, nil, false
	}

	orderedEntryPoints := append([]EntryPoint(nil), entryPoints...)
	sort.Slice(orderedEntryPoints, func(left, right int) bool {
		a := orderedEntryPoints[left]
		b := orderedEntryPoints[right]

		if a.RepositoryID != b.RepositoryID {
			return a.RepositoryID < b.RepositoryID
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Function != b.Function {
			return a.Function < b.Function
		}

		return a.EntryPointID < b.EntryPointID
	})

	var selectedEntryPoint EntryPoint
	var selectedPath []sourceanalysis.FunctionID
	selectedKey := ""

	for _, entryPoint := range orderedEntryPoints {
		start := sourceanalysis.FunctionID{
			RepositoryID: entryPoint.RepositoryID,
			File:         entryPoint.File,
			Name:         entryPoint.Function,
			StartLine:    entryPoint.Line,
		}
		candidate, ok := graph.shortestPath(start, target)
		if !ok {
			continue
		}

		candidateKey := entryPoint.EntryPointID + "\x00" +
			functionPathKey(candidate)
		if selectedPath == nil ||
			len(candidate) < len(selectedPath) ||
			(len(candidate) == len(selectedPath) &&
				candidateKey < selectedKey) {
			selectedEntryPoint = entryPoint
			selectedPath = candidate
			selectedKey = candidateKey
		}
	}

	if selectedPath == nil {
		return EntryPoint{}, nil, false
	}

	publicPath := make([]CallPathStep, 0, len(selectedPath))
	for _, function := range selectedPath {
		publicPath = append(publicPath, CallPathStep{
			Function: function.Name,
			File:     function.File,
			Line:     function.StartLine,
		})
	}

	return selectedEntryPoint, publicPath, true
}

func (graph applicationCallGraph) shortestPath(
	start sourceanalysis.FunctionID,
	target sourceanalysis.FunctionID,
) ([]sourceanalysis.FunctionID, bool) {
	if _, exists := graph.functions[start]; !exists {
		return nil, false
	}

	queue := []sourceanalysis.FunctionID{start}
	seen := map[sourceanalysis.FunctionID]bool{start: true}
	parents := make(map[sourceanalysis.FunctionID]sourceanalysis.FunctionID)

	for len(queue) != 0 {
		current := queue[0]
		queue = queue[1:]
		if current == target {
			return rebuildFunctionPath(start, target, parents), true
		}

		for _, next := range graph.edges[current] {
			if seen[next] {
				continue
			}
			seen[next] = true
			parents[next] = current
			queue = append(queue, next)
		}
	}

	return nil, false
}

func rebuildFunctionPath(
	start sourceanalysis.FunctionID,
	target sourceanalysis.FunctionID,
	parents map[sourceanalysis.FunctionID]sourceanalysis.FunctionID,
) []sourceanalysis.FunctionID {
	reversed := []sourceanalysis.FunctionID{target}
	for current := target; current != start; {
		current = parents[current]
		reversed = append(reversed, current)
	}

	path := make([]sourceanalysis.FunctionID, len(reversed))
	for index := range reversed {
		path[len(reversed)-1-index] = reversed[index]
	}

	return path
}

func functionPathKey(path []sourceanalysis.FunctionID) string {
	var key strings.Builder
	for _, function := range path {
		key.WriteString(function.RepositoryID)
		key.WriteByte(0)
		key.WriteString(function.File)
		key.WriteByte(0)
		key.WriteString(strconv.Itoa(function.StartLine))
		key.WriteByte(0)
		key.WriteString(function.Name)
		key.WriteByte(0)
	}

	return key.String()
}
