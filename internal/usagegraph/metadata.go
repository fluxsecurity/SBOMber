package usagegraph

import (
	"runtime/debug"
	"strings"
)

const (
	AnalyzerID = "component2-js-ts-tree-sitter"

	bindingModule    = "github.com/tree-sitter/go-tree-sitter"
	javascriptModule = "github.com/tree-sitter/tree-sitter-javascript"
	typescriptModule = "github.com/tree-sitter/tree-sitter-typescript"

	bindingVersion    = "0.25.0"
	javascriptVersion = "0.25.0"
	typescriptVersion = "0.23.2"
)

// Analyser records the parser and grammar versions used for a scan.
type Analyser struct {
	Parser               string            `json:"parser"`
	Binding              string            `json:"binding"`
	BindingVersion       string            `json:"bindingVersion"`
	CGOEnabled           bool              `json:"cgoEnabled"`
	GrammarVersions      map[string]string `json:"grammarVersions"`
	Ecosystems           []string          `json:"ecosystems"`
	ReachabilityAnalysed bool              `json:"reachabilityAnalysed"`
}

// CurrentAnalyser prefers dependency versions from Go build information. The
// compiled fallbacks match the versions pinned in go.mod because test binaries
// and stripped builds may omit otherwise-unused modules from ReadBuildInfo.
func CurrentAnalyser(reachabilityAnalysed bool) Analyser {
	versions := buildVersions()
	return Analyser{
		Parser:         "tree-sitter",
		Binding:        bindingModule,
		BindingVersion: versions[bindingModule],
		CGOEnabled:     true,
		GrammarVersions: map[string]string{
			"javascript": versions[javascriptModule],
			"typescript": versions[typescriptModule],
		},
		Ecosystems:           []string{"npm"},
		ReachabilityAnalysed: reachabilityAnalysed,
	}
}

func buildVersions() map[string]string {
	versions := map[string]string{
		bindingModule:    bindingVersion,
		javascriptModule: javascriptVersion,
		typescriptModule: typescriptVersion,
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return versions
	}
	for _, dependency := range info.Deps {
		version := dependency.Version
		if dependency.Replace != nil {
			version = dependency.Replace.Version
		}
		if _, wanted := versions[dependency.Path]; wanted {
			if version == "" || version == "(devel)" {
				continue
			}
			versions[dependency.Path] = strings.TrimPrefix(version, "v")
		}
	}

	return versions
}
