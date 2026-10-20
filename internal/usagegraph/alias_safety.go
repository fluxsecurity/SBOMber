package usagegraph

import (
	"fmt"
	"path"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
)

// unresolvedPathAliasRepositories identifies imports whose tsconfig path
// mapping has no unique analysed target. Such a target may hide package use,
// so unmatched occurrences from that repository cannot support a negative.
func unresolvedPathAliasRepositories(repositories []RepositoryInput) map[string]string {
	unresolved := make(map[string]string)
	for _, repository := range repositories {
		if len(repository.PathAliases) == 0 {
			continue
		}
		files := make(map[sourceFileID]sourceanalysis.Result, len(repository.Result.Files))
		for _, file := range repository.Result.Files {
			files[sourceFileID{repositoryID: repository.RepositoryID, file: path.Clean(file.Path)}] = file.Result
		}
		for _, file := range repository.Result.Files {
			current := sourceFileID{repositoryID: repository.RepositoryID, file: path.Clean(file.Path)}
			for _, imported := range file.Result.Imports {
				if imported.TypeOnly || imported.Kind == "dynamic_computed" ||
					isRelativeSpecifier(imported.Specifier) {
					continue
				}
				bases, alias := matchPathAlias(repository.PathAliases, imported.Specifier)
				if !alias {
					continue
				}
				if _, ok := resolveAliasSourceFile(current, bases, files); ok {
					continue
				}
				if _, recorded := unresolved[repository.RepositoryID]; !recorded {
					unresolved[repository.RepositoryID] = fmt.Sprintf(
						"path alias %q at %s:%d has no unique analysed source target",
						imported.Specifier, file.Path, imported.Line)
				}
			}
		}
	}
	return unresolved
}
