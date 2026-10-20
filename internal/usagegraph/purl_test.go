package usagegraph

import "testing"

// A version-unknown component (versionKnown: false) has a versionless PURL.
// It is still an npm package, so its occurrences can match an import
// instead of reading as an unsupported ecosystem (#121).
func TestNPMPackageFromPURL(t *testing.T) {
	for purl, want := range map[string]string{
		"pkg:npm/lodash@4.17.20":          "lodash",
		"pkg:npm/lodash":                  "lodash",
		"pkg:npm/%40babel/core@7.0.0":     "@babel/core",
		"pkg:npm/%40babel/core":           "@babel/core",
		"pkg:npm/@babel/core":             "@babel/core",
		"pkg:npm/@babel/core@7.0.0?x=1#y": "@babel/core",
	} {
		got, ok := npmPackageFromPURL(purl)
		if !ok || got != want {
			t.Errorf("npmPackageFromPURL(%q) = %q, %v; want %q", purl, got, ok, want)
		}
	}
	for _, purl := range []string{"pkg:pypi/requests@2.0.0", "pkg:npm/", "npm/lodash@1.0.0", "pkg:npm/%zz@1.0.0"} {
		if got, ok := npmPackageFromPURL(purl); ok {
			t.Errorf("npmPackageFromPURL(%q) = %q, want not npm", purl, got)
		}
	}
}
