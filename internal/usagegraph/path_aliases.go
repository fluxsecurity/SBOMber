package usagegraph

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

// PathAlias is one TypeScript compilerOptions.paths entry, with its targets
// already joined to baseUrl and relative to the repository root.
type PathAlias struct {
	Pattern string
	Targets []string
}

// ParseTSConfigPaths reads compilerOptions.baseUrl and compilerOptions.paths
// from a root tsconfig.json. tsconfig allows comments and trailing commas,
// which are removed first. "extends" is not followed.
func ParseTSConfigPaths(data []byte) ([]PathAlias, error) {
	var config struct {
		CompilerOptions struct {
			BaseURL string              `json:"baseUrl"`
			Paths   map[string][]string `json:"paths"`
		} `json:"compilerOptions"`
	}
	if err := json.Unmarshal(stripJSONC(data), &config); err != nil {
		return nil, fmt.Errorf("parse tsconfig.json: %w", err)
	}

	base := path.Clean(strings.TrimPrefix(config.CompilerOptions.BaseURL, "./"))
	if base == "" || strings.HasPrefix(base, "/") || base == ".." || strings.HasPrefix(base, "../") {
		base = "."
	}

	aliases := make([]PathAlias, 0, len(config.CompilerOptions.Paths))
	for pattern, targets := range config.CompilerOptions.Paths {
		if pattern == "" || strings.Count(pattern, "*") > 1 {
			continue
		}
		alias := PathAlias{Pattern: pattern}
		for _, target := range targets {
			if strings.Count(target, "*") > 1 || strings.HasPrefix(target, "/") {
				continue
			}
			joined := path.Clean(path.Join(base, target))
			if joined == ".." || strings.HasPrefix(joined, "../") {
				continue
			}
			alias.Targets = append(alias.Targets, joined)
		}
		if len(alias.Targets) != 0 {
			aliases = append(aliases, alias)
		}
	}
	return aliases, nil
}

// matchPathAlias applies TypeScript's rule: an exact pattern wins, otherwise
// the wildcard pattern with the longest prefix. It returns the candidate
// repository-relative paths for the specifier.
func matchPathAlias(aliases []PathAlias, specifier string) ([]string, bool) {
	var best *PathAlias
	bestCapture := ""
	bestPrefix := -1
	for index := range aliases {
		alias := &aliases[index]
		star := strings.Index(alias.Pattern, "*")
		if star < 0 {
			if alias.Pattern == specifier {
				// An exact pattern always wins over a wildcard.
				best, bestCapture = alias, ""
				break
			}
			continue
		}
		prefix, suffix := alias.Pattern[:star], alias.Pattern[star+1:]
		if len(specifier) < len(prefix)+len(suffix) ||
			!strings.HasPrefix(specifier, prefix) ||
			!strings.HasSuffix(specifier, suffix) {
			continue
		}
		if len(prefix) > bestPrefix {
			best = alias
			bestCapture = specifier[len(prefix) : len(specifier)-len(suffix)]
			bestPrefix = len(prefix)
		}
	}
	if best == nil {
		return nil, false
	}
	paths := make([]string, 0, len(best.Targets))
	for _, target := range best.Targets {
		resolved := path.Clean(strings.Replace(target, "*", bestCapture, 1))
		if resolved == ".." || strings.HasPrefix(resolved, "../") || strings.HasPrefix(resolved, "/") {
			continue
		}
		paths = append(paths, resolved)
	}
	return paths, true
}

// stripJSONC removes // and /* */ comments outside strings and commas that
// directly precede a closing bracket or brace.
func stripJSONC(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString, escaped := false, false
	for index := 0; index < len(data); index++ {
		current := data[index]
		if inString {
			out = append(out, current)
			switch {
			case escaped:
				escaped = false
			case current == '\\':
				escaped = true
			case current == '"':
				inString = false
			}
			continue
		}
		switch {
		case current == '"':
			inString = true
			out = append(out, current)
		case current == '/' && index+1 < len(data) && data[index+1] == '/':
			for index < len(data) && data[index] != '\n' {
				index++
			}
			if index < len(data) {
				out = append(out, '\n')
			}
		case current == '/' && index+1 < len(data) && data[index+1] == '*':
			index += 2
			for index+1 < len(data) && (data[index] != '*' || data[index+1] != '/') {
				index++
			}
			index++
		default:
			out = append(out, current)
		}
	}

	// Drop trailing commas: a comma followed only by whitespace before } or ].
	cleaned := make([]byte, 0, len(out))
	inString, escaped = false, false
	for index := 0; index < len(out); index++ {
		current := out[index]
		if inString {
			cleaned = append(cleaned, current)
			switch {
			case escaped:
				escaped = false
			case current == '\\':
				escaped = true
			case current == '"':
				inString = false
			}
			continue
		}
		if current == '"' {
			inString = true
		}
		if current == ',' {
			next := index + 1
			for next < len(out) && (out[next] == ' ' || out[next] == '\t' || out[next] == '\n' || out[next] == '\r') {
				next++
			}
			if next < len(out) && (out[next] == '}' || out[next] == ']') {
				continue
			}
		}
		cleaned = append(cleaned, current)
	}
	return cleaned
}
