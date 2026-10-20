package inventory

import (
	"net/url"
	"regexp"
	"strings"
)

// Contract ecosystems. canonical-scan 1.0.0 has no value for cargo,
// composer or nuget, so their packages cannot be written; the scan says so
// in statusDetail.limitsHit instead of dropping them silently.
const (
	EcosystemNPM    = "npm"
	EcosystemPyPI   = "pypi"
	EcosystemMaven  = "maven"
	EcosystemGem    = "gem"
	EcosystemGolang = "golang"
)

// contractEcosystem maps a parser's ecosystem name onto the contract's, and
// reports false for one the contract cannot represent.
func contractEcosystem(parser string) (string, bool) {
	switch strings.ToLower(parser) {
	case "npm":
		return EcosystemNPM, true
	case "pypi", "python":
		return EcosystemPyPI, true
	case "maven":
		return EcosystemMaven, true
	case "gem", "rubygems", "ruby":
		return EcosystemGem, true
	case "golang", "go":
		return EcosystemGolang, true
	default:
		return "", false
	}
}

var pypiSeparators = regexp.MustCompile(`[-_.]+`)

// normalisedName is the package name as the contract and the PURL spec
// spell it: PyPI names are lower-cased with runs of - _ . collapsed to -.
func normalisedName(ecosystem, name string) string {
	if ecosystem == EcosystemPyPI {
		return pypiSeparators.ReplaceAllString(strings.ToLower(name), "-")
	}
	return name
}

// buildPurl returns the package URL for an exact version, or the versionless
// PURL when the version is unknown.
func buildPurl(ecosystem, name, version string) string {
	var path string
	switch ecosystem {
	case EcosystemNPM:
		// @scope/name -> %40scope/name
		if strings.HasPrefix(name, "@") {
			if slash := strings.Index(name, "/"); slash > 0 {
				path = "%40" + escape(name[1:slash]) + "/" + escape(name[slash+1:])
				break
			}
		}
		path = escape(name)
	case EcosystemMaven:
		// groupId:artifactId -> groupId/artifactId
		group, artifact, found := strings.Cut(name, ":")
		if found {
			path = escape(group) + "/" + escape(artifact)
		} else {
			path = escape(name)
		}
	case EcosystemGolang:
		// Module paths keep their slashes.
		parts := strings.Split(name, "/")
		for i := range parts {
			parts[i] = escape(parts[i])
		}
		path = strings.Join(parts, "/")
	default:
		path = escape(name)
	}
	purl := "pkg:" + ecosystem + "/" + path
	if version != "" {
		purl += "@" + escape(version)
	}
	return purl
}

func escape(part string) string {
	return strings.ReplaceAll(url.PathEscape(part), "%2F", "/")
}

// purlKey reduces a PURL to type, name and version, so the same package
// matches whether or not a scanner added qualifiers (?arch=...), a subpath,
// different percent-encoding or different case.
func purlKey(purl string) string {
	purl = strings.TrimPrefix(purl, "pkg:")
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		purl = purl[:i]
	}
	version := ""
	// The version's @ follows the last path segment's start; an earlier one
	// is an unencoded npm scope ("npm/@scope/name").
	if i := strings.LastIndex(purl, "@"); i > strings.LastIndex(purl, "/") {
		purl, version = purl[:i], purl[i+1:]
	}
	if decoded, err := url.PathUnescape(purl); err == nil {
		purl = decoded
	}
	if decoded, err := url.PathUnescape(version); err == nil {
		version = decoded
	}
	// A range is not a version: a scanner matching a declared range
	// ("@^0.4.0", from a manifest with no lockfile) is talking about the
	// component whose version is unknown.
	if !isExactVersion(version) {
		version = ""
	}
	kind, name, _ := strings.Cut(purl, "/")
	kind = strings.ToLower(kind)
	if ecosystem, ok := contractEcosystem(kind); ok {
		kind = ecosystem
	}
	if kind == EcosystemPyPI {
		name = normalisedName(EcosystemPyPI, name)
	}
	return kind + "/" + strings.ToLower(name) + "@" + version
}

// isExactVersion reports whether a version is a resolved version rather than
// a range, a wildcard or an operator.
func isExactVersion(version string) bool {
	if version == "" || version == "latest" {
		return false
	}
	return !strings.ContainsAny(version, "^~*><=| ") && !strings.EqualFold(version, "x")
}
