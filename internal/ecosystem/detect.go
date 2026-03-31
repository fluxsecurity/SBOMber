package ecosystem

import (
	"os"
	"path/filepath"
	"sort"
)

// Name identifies a supported project ecosystem.
type Name string

const (
	NPM    Name = "npm"
	Python Name = "python"
	Maven  Name = "maven"
	Ruby   Name = "ruby"
	Go     Name = "go"
)

// Detection reports the ecosystems detected for a repository and the files that
// triggered each match.
type Detection struct {
	Names    []Name
	Evidence map[Name][]string
}

var markers = map[Name][]string{
	NPM: {
		"package.json",
		"package-lock.json",
		"yarn.lock",
		"pnpm-lock.yaml",
	},
	Python: {
		"pyproject.toml",
		"requirements.txt",
		"requirements-dev.txt",
		"Pipfile",
		"poetry.lock",
		"setup.py",
		"setup.cfg",
	},
	Maven: {
		"pom.xml",
	},
	Ruby: {
		"Gemfile",
		"Gemfile.lock",
	},
	Go: {
		"go.mod",
		"go.sum",
	},
}

// Detect inspects the repository root and reports which ecosystems are present
// based on well-known manifest and lockfile names.
func Detect(root string) (Detection, error) {
	dirEntries, err := os.ReadDir(root)
	if err != nil {
		return Detection{}, err
	}

	files := make(map[string]struct{}, len(dirEntries))
	for _, entry := range dirEntries {
		if entry.IsDir() {
			continue
		}

		files[entry.Name()] = struct{}{}
	}

	gemspecs, err := filepath.Glob(filepath.Join(root, "*.gemspec"))
	if err != nil {
		return Detection{}, err
	}

	for _, gemspec := range gemspecs {
		files[filepath.Base(gemspec)] = struct{}{}
	}

	detection := Detection{
		Names:    make([]Name, 0),
		Evidence: make(map[Name][]string),
	}

	for ecosystem, expectedFiles := range markers {
		for _, candidate := range expectedFiles {
			if _, ok := files[candidate]; !ok {
				continue
			}

			detection.Evidence[ecosystem] = append(detection.Evidence[ecosystem], candidate)
		}

		if len(detection.Evidence[ecosystem]) == 0 {
			continue
		}

		sort.Strings(detection.Evidence[ecosystem])
		detection.Names = append(detection.Names, ecosystem)
	}

	sort.Slice(detection.Names, func(i, j int) bool {
		return detection.Names[i] < detection.Names[j]
	})

	return detection, nil
}
