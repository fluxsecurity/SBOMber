package usagegraph

import (
	"path"
	"strings"
)

// A single direct occurrence retains the existing resolution behaviour.
// With several candidates, the longest matching workspace must be unique.
func selectDirectOccurrence(
	candidates []OccurrenceInput,
	file string,
) (OccurrenceInput, bool) {
	if len(candidates) == 1 {
		return candidates[0], true
	}

	bestLength := -1
	bestCount := 0
	var best OccurrenceInput
	for _, candidate := range candidates {
		workspace := candidate.Occurrence.Workspace
		if workspace == "." {
			workspace = ""
		} else if workspace != "" {
			if strings.HasPrefix(workspace, "/") ||
				strings.Contains(workspace, "\\") {
				continue
			}
			invalid := false
			for _, segment := range strings.Split(workspace, "/") {
				if segment == ".." {
					invalid = true
					break
				}
			}
			if invalid {
				continue
			}
			workspace = path.Clean(workspace)
			if file != workspace &&
				!strings.HasPrefix(file, workspace+"/") {
				continue
			}
		}

		length := len(workspace)
		if length > bestLength {
			best, bestLength, bestCount = candidate, length, 1
		} else if length == bestLength {
			bestCount++
		}
	}
	return best, bestLength >= 0 && bestCount == 1
}
