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

// detectEntryPoints combines supported entry sources in a stable order.
func detectEntryPoints(repositories []RepositoryInput, declarations []DeclaredEntryPoint) []EntryPoint {
	entries := detectExportedModuleEntryPoints(repositories)
	entries = append(entries, detectRouteEntryPoints(repositories)...)
	entries = append(entries, detectPackageEntryPoints(repositories)...)
	entries = append(entries, detectDeclaredEntryPoints(repositories, declarations)...)

	sort.Slice(entries, func(left, right int) bool {
		a, b := entries[left], entries[right]
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
	return entries
}

// A named route is an entry only when it identifies one local function.
// Inline handlers use the parser's synthetic name and source location.
func detectRouteEntryPoints(repositories []RepositoryInput) []EntryPoint {
	entries := make([]EntryPoint, 0)
	seen := make(map[string]struct{})
	for _, repository := range repositories {
		for _, file := range repository.Result.Files {
			syntheticByLine := make(map[int]int)
			for _, route := range file.Result.RouteHandlers {
				if route.Synthetic {
					syntheticByLine[route.Line]++
				}
			}

			for _, route := range file.Result.RouteHandlers {
				line := route.Line
				if route.Synthetic {
					if syntheticByLine[line] != 1 {
						continue
					}
				} else {
					matches := 0
					for _, function := range file.Result.Functions {
						if function.Name == route.Function {
							matches++
							line = function.Line
						}
					}
					if matches != 1 {
						continue
					}
				}

				id := stableID(
					"ep",
					repository.RepositoryID,
					file.Path,
					route.Function,
					strconv.Itoa(line),
					"route_handler",
				)
				if _, duplicate := seen[id]; duplicate {
					continue
				}
				seen[id] = struct{}{}
				entries = append(entries, EntryPoint{
					EntryPointID: id,
					Kind:         "route_handler",
					Function:     route.Function,
					File:         file.Path,
					Line:         line,
					RepositoryID: repository.RepositoryID,
				})
			}
		}
	}
	return entries
}

func isConventionalExportedModule(path string) bool {
	path = filepath.ToSlash(filepath.Clean(path))
	extension := strings.ToLower(filepath.Ext(path))
	if !isSupportedSourceExtension(extension) {
		return false
	}

	base := strings.TrimSuffix(filepath.Base(path), extension)
	if base != "index" {
		return false
	}

	directory := filepath.ToSlash(filepath.Dir(path))
	return directory == "." || directory == "src"
}
