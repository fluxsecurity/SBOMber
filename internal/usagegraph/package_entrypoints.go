package usagegraph

import (
	"encoding/json"
	"path"
	"strings"
)

// Package entries are accepted only when they uniquely identify an analysed
// application source file. Missing, ambiguous and unsupported paths add no entry.
func detectPackageEntryPoints(repositories []RepositoryInput) []EntryPoint {
	entries := make([]EntryPoint, 0)
	for _, repository := range repositories {
		if len(repository.PackageJSON) == 0 {
			continue
		}
		var manifest struct {
			Main json.RawMessage `json:"main"`
			Bin  json.RawMessage `json:"bin"`
		}
		if json.Unmarshal(repository.PackageJSON, &manifest) != nil {
			continue
		}

		add := func(kind, target string) {
			file, ok := resolvePackageEntryFile(repository, target)
			if !ok {
				return
			}
			for _, existing := range entries {
				if existing.RepositoryID == repository.RepositoryID &&
					existing.Kind == kind && existing.File == file {
					return
				}
			}
			entries = append(entries, EntryPoint{
				EntryPointID: stableID(
					"ep", repository.RepositoryID, file, "<module>", "1", kind,
				),
				Kind:         kind,
				Function:     "<module>",
				File:         file,
				Line:         1,
				RepositoryID: repository.RepositoryID,
			})
		}

		var main string
		if json.Unmarshal(manifest.Main, &main) == nil {
			add("package_main", main)
		}
		var binPath string
		if json.Unmarshal(manifest.Bin, &binPath) == nil {
			add("package_bin", binPath)
		} else {
			var bins map[string]string
			if json.Unmarshal(manifest.Bin, &bins) == nil {
				for _, target := range bins {
					add("package_bin", target)
				}
			}
		}
	}
	return entries
}

func resolvePackageEntryFile(
	repository RepositoryInput,
	target string,
) (string, bool) {
	if target == "" || strings.HasPrefix(target, "/") ||
		strings.Contains(target, "\\") {
		return "", false
	}
	for _, segment := range strings.Split(target, "/") {
		if segment == ".." {
			return "", false
		}
	}
	base := path.Clean(strings.TrimPrefix(target, "./"))
	if base == "." {
		return "", false
	}

	candidates := []string{}
	if isSupportedSourceExtension(path.Ext(base)) {
		candidates = append(candidates, base)
	} else {
		for _, extension := range sourceExtensions {
			candidates = append(candidates, base+extension, path.Join(base, "index"+extension))
		}
	}

	match := ""
	count := 0
	for _, file := range repository.Result.Files {
		for _, candidate := range candidates {
			if path.Clean(file.Path) == candidate {
				match = candidate
				count++
			}
		}
	}
	return match, count == 1
}
