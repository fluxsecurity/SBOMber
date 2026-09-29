package usagegraph

import (
	"path"
	"strconv"
	"strings"
)

func detectDeclaredEntryPoints(
	repositories []RepositoryInput,
	declarations []DeclaredEntryPoint,
) []EntryPoint {
	entries := make([]EntryPoint, 0)
	for _, declared := range declarations {
		filePath, ok := cleanDeclaredFile(declared.File)
		if !ok || declared.RepositoryID == "" || declared.Function == "" {
			continue
		}
		for _, repository := range repositories {
			if repository.RepositoryID != declared.RepositoryID {
				continue
			}
			for _, file := range repository.Result.Files {
				if path.Clean(file.Path) != filePath {
					continue
				}

				line := 0
				if declared.Function == syntheticModuleName {
					if declared.Line == 0 || declared.Line == 1 {
						line = 1
					}
				} else {
					matches := 0
					for _, function := range file.Result.Functions {
						if function.Name != declared.Function ||
							(declared.Line != 0 && function.Line != declared.Line) {
							continue
						}
						matches++
						line = function.Line
					}
					if matches != 1 {
						line = 0
					}
				}
				if line == 0 {
					continue
				}

				id := stableID(
					"ep", repository.RepositoryID, filePath,
					declared.Function, strconv.Itoa(line), "declared",
				)
				duplicate := false
				for _, existing := range entries {
					if existing.EntryPointID == id {
						duplicate = true
						break
					}
				}
				if duplicate {
					continue
				}
				entries = append(entries, EntryPoint{
					EntryPointID: id,
					Kind:         "declared",
					Function:     declared.Function,
					File:         filePath,
					Line:         line,
					RepositoryID: repository.RepositoryID,
				})
			}
		}
	}
	return entries
}

func cleanDeclaredFile(file string) (string, bool) {
	if file == "" || strings.HasPrefix(file, "/") ||
		strings.Contains(file, "\\") {
		return "", false
	}
	for _, segment := range strings.Split(file, "/") {
		if segment == ".." {
			return "", false
		}
	}
	clean := path.Clean(strings.TrimPrefix(file, "./"))
	return clean, clean != "."
}
