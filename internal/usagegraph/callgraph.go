package usagegraph

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

type sourceFileID struct {
	repositoryID string
	file         string
}

type applicationCallGraph struct {
	functions map[sourceanalysis.FunctionID]struct{}
	edges     map[sourceanalysis.FunctionID][]sourceanalysis.FunctionID
}

func buildApplicationCallGraph(
	repositories []RepositoryInput,
) (applicationCallGraph, error) {
	graph := applicationCallGraph{
		functions: make(map[sourceanalysis.FunctionID]struct{}),
		edges:     make(map[sourceanalysis.FunctionID][]sourceanalysis.FunctionID),
	}
	files := make(map[sourceFileID]sourceanalysis.Result)
	functionsByName := make(
		map[sourceFileID]map[string][]sourceanalysis.FunctionID,
	)
	exportsByName := make(
		map[sourceFileID]map[string][]sourceanalysis.FunctionID,
	)
	seenRepositories := make(map[string]struct{})

	for _, repository := range repositories {
		if repository.RepositoryID == "" {
			return applicationCallGraph{}, fmt.Errorf(
				"repository ID is required",
			)
		}
		if _, exists := seenRepositories[repository.RepositoryID]; exists {
			return applicationCallGraph{}, fmt.Errorf(
				"duplicate repository ID %q",
				repository.RepositoryID,
			)
		}
		seenRepositories[repository.RepositoryID] = struct{}{}

		for _, file := range repository.Result.Files {
			filePath := path.Clean(file.Path)
			fileID := sourceFileID{
				repositoryID: repository.RepositoryID,
				file:         filePath,
			}
			if _, exists := files[fileID]; exists {
				return applicationCallGraph{}, fmt.Errorf(
					"duplicate analysed file %q in repository %q",
					filePath,
					repository.RepositoryID,
				)
			}
			files[fileID] = file.Result
			graph.functions[sourceanalysis.FunctionID{
				RepositoryID: repository.RepositoryID,
				File:         filePath,
				Name:         syntheticModuleName,
				StartLine:    1,
			}] = struct{}{}
			functionsByName[fileID] = make(
				map[string][]sourceanalysis.FunctionID,
			)
			exportsByName[fileID] = make(
				map[string][]sourceanalysis.FunctionID,
			)

			for _, function := range graphFunctions(file.Result) {
				functionID := sourceanalysis.FunctionID{
					RepositoryID: repository.RepositoryID,
					File:         filePath,
					Name:         function.Name,
					StartLine:    function.Line,
				}
				if _, exists := graph.functions[functionID]; exists {
					return applicationCallGraph{}, fmt.Errorf(
						"duplicate function identity %+v",
						functionID,
					)
				}
				graph.functions[functionID] = struct{}{}
				functionsByName[fileID][function.Name] = append(
					functionsByName[fileID][function.Name],
					functionID,
				)

				for _, exportedName := range function.ExportedNames {
					exportsByName[fileID][exportedName] = append(
						exportsByName[fileID][exportedName],
						functionID,
					)
				}
			}
		}
	}

	for fileID, result := range files {
		for _, call := range result.Calls {
			if call.Callee == nil {
				continue
			}

			owner, ok := graphCallOwner(result, call)
			if !ok || shadowedLocalCall(result, call) {
				continue
			}

			caller := sourceanalysis.FunctionID{
				RepositoryID: fileID.repositoryID,
				File:         fileID.file,
				Name:         owner.Name,
				StartLine:    owner.Line,
			}
			if _, exists := graph.functions[caller]; !exists {
				continue
			}

			targets := resolveApplicationCallTargets(
				fileID,
				result,
				call,
				files,
				functionsByName,
				exportsByName,
			)
			if len(targets) != 1 {
				continue
			}

			graph.edges[caller] = append(
				graph.edges[caller],
				targets[0],
			)
		}
	}

	for caller, targets := range graph.edges {
		sortFunctionIDs(targets)
		unique := targets[:0]
		for _, target := range targets {
			if len(unique) != 0 && unique[len(unique)-1] == target {
				continue
			}
			unique = append(unique, target)
		}
		graph.edges[caller] = unique
	}

	return graph, nil
}

func resolveApplicationCallTargets(
	fileID sourceFileID,
	result sourceanalysis.Result,
	call sourceanalysis.Call,
	files map[sourceFileID]sourceanalysis.Result,
	functionsByName map[sourceFileID]map[string][]sourceanalysis.FunctionID,
	exportsByName map[sourceFileID]map[string][]sourceanalysis.FunctionID,
) []sourceanalysis.FunctionID {
	candidates := make(map[sourceanalysis.FunctionID]struct{})
	callee := *call.Callee

	if call.Receiver == nil {
		for _, target := range functionsByName[fileID][callee] {
			candidates[target] = struct{}{}
		}
	}

	for _, imported := range result.Imports {
		exportedName, matches := importedApplicationCall(
			imported,
			call,
		)
		if !matches || !isRelativeSpecifier(imported.Specifier) {
			continue
		}

		targetFile, ok := resolveRelativeSourceFile(
			fileID,
			imported.Specifier,
			files,
		)
		if !ok {
			continue
		}

		for _, target := range exportsByName[targetFile][exportedName] {
			candidates[target] = struct{}{}
		}
	}

	if len(candidates) != 1 {
		return nil
	}

	for target := range candidates {
		return []sourceanalysis.FunctionID{target}
	}

	return nil
}

func importedApplicationCall(
	imported sourceanalysis.Import,
	call sourceanalysis.Call,
) (string, bool) {
	if imported.TypeOnly || imported.Local == "" || call.Callee == nil {
		return "", false
	}

	if call.Receiver == nil {
		if *call.Callee != imported.Local {
			return "", false
		}

		switch imported.Kind {
		case "esm_named", "cjs_destructured":
			if imported.Imported == "" {
				return "", false
			}
			return imported.Imported, true

		case "esm_default", "cjs_require", "dynamic_static_literal":
			return "default", true
		}

		return "", false
	}

	if *call.Receiver != imported.Local {
		return "", false
	}

	switch imported.Kind {
	case "esm_namespace", "cjs_require":
		return *call.Callee, true
	default:
		return "", false
	}
}

func isRelativeSpecifier(specifier string) bool {
	return strings.HasPrefix(specifier, "./") ||
		strings.HasPrefix(specifier, "../")
}

func resolveRelativeSourceFile(
	current sourceFileID,
	specifier string,
	files map[sourceFileID]sourceanalysis.Result,
) (sourceFileID, bool) {
	base := path.Clean(path.Join(path.Dir(current.file), specifier))
	if base == ".." || strings.HasPrefix(base, "../") {
		return sourceFileID{}, false
	}

	candidatePaths := make([]string, 0, 16)
	if isSupportedSourceExtension(path.Ext(base)) {
		candidatePaths = append(candidatePaths, base)
		// TypeScript NodeNext source commonly spells its runtime import
		// with .js even when the analysed source is .ts, .tsx or .mts.
		// Prefer an actual .js file; only fall back when it is absent.
		switch strings.ToLower(path.Ext(current.file)) {
		case ".ts", ".tsx", ".mts", ".cts":
			if path.Ext(base) == ".js" {
				exact := sourceFileID{
					repositoryID: current.repositoryID,
					file:         base,
				}
				if _, exists := files[exact]; !exists {
					stem := strings.TrimSuffix(base, ".js")
					for _, extension := range []string{".ts", ".tsx", ".mts"} {
						candidatePaths = append(candidatePaths, stem+extension)
					}
				}
			}
		}
	} else {
		for _, extension := range sourceExtensions {
			candidatePaths = append(
				candidatePaths,
				base+extension,
				path.Join(base, "index"+extension),
			)
		}
	}

	matched := sourceFileID{}
	matchCount := 0
	for _, candidatePath := range candidatePaths {
		candidate := sourceFileID{
			repositoryID: current.repositoryID,
			file:         candidatePath,
		}
		if _, exists := files[candidate]; !exists {
			continue
		}
		matched = candidate
		matchCount++
	}

	return matched, matchCount == 1
}

var sourceExtensions = [...]string{
	".js", ".jsx", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx",
}

func isSupportedSourceExtension(extension string) bool {
	for _, supported := range sourceExtensions {
		if strings.EqualFold(extension, supported) {
			return true
		}
	}
	return false
}

func sortFunctionIDs(ids []sourceanalysis.FunctionID) {
	sort.Slice(ids, func(left, right int) bool {
		a := ids[left]
		b := ids[right]

		if a.RepositoryID != b.RepositoryID {
			return a.RepositoryID < b.RepositoryID
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.StartLine != b.StartLine {
			return a.StartLine < b.StartLine
		}

		return a.Name < b.Name
	})
}
