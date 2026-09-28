package usagegraph

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// EntryPointExportedModule identifies an exported conventional entry module.
const EntryPointExportedModule = "exported_module"

func detectExportedModuleEntryPoints(
	repositories []RepositoryInput,
) []EntryPoint {
	entryPoints := make([]EntryPoint, 0)

	for _, repository := range repositories {
		for _, file := range repository.Result.Files {
			if !isConventionalExportedModule(file.Path) {
				continue
			}

			for _, function := range file.Result.Functions {
				if !function.Exported || len(function.ExportedNames) == 0 {
					continue
				}

				entryPoints = append(entryPoints, EntryPoint{
					EntryPointID: stableID(
						"ep",
						repository.RepositoryID,
						file.Path,
						function.Name,
						strconv.Itoa(function.Line),
						EntryPointExportedModule,
					),
					Kind:         EntryPointExportedModule,
					Function:     function.Name,
					File:         file.Path,
					Line:         function.Line,
					RepositoryID: repository.RepositoryID,
				})
			}
		}
	}

	sort.Slice(entryPoints, func(left, right int) bool {
		a := entryPoints[left]
		b := entryPoints[right]

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

	return entryPoints
}

func isConventionalExportedModule(path string) bool {
	path = filepath.ToSlash(filepath.Clean(path))
	extension := strings.ToLower(filepath.Ext(path))
	if extension != ".js" &&
		extension != ".mjs" &&
		extension != ".cjs" &&
		extension != ".ts" &&
		extension != ".tsx" {
		return false
	}

	base := strings.TrimSuffix(filepath.Base(path), extension)
	if base != "index" {
		return false
	}

	directory := filepath.ToSlash(filepath.Dir(path))
	return directory == "." || directory == "src"
}
