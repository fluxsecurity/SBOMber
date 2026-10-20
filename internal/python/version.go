package python

import "strings"

// PinnedVersion returns the exact version a requirement specifier pins
// ("==1.2.3" or "===1.2.3" gives "1.2.3"), or "" when it only constrains a
// range (">=1.0", "~=2.1", "==1.*", "==1.2,!=1.3"). A range is not a
// version: putting it in an SBOM produces purls like pkg:pypi/x@==1.2.3
// that no vulnerability scanner can match.
func PinnedVersion(spec string) string {
	s := strings.TrimSpace(spec)
	if s == "" || strings.Contains(s, ",") {
		return ""
	}
	for _, op := range []string{"===", "=="} {
		if strings.HasPrefix(s, op) {
			v := strings.TrimSpace(s[len(op):])
			if v == "" || strings.ContainsAny(v, "*<>=!~ \t") {
				return ""
			}
			return v
		}
	}
	return ""
}
