package localisation

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Advisory is the subset of an OSV record the localiser uses.
type Advisory struct {
	ID         string
	Aliases    []string
	Summary    string
	Details    string
	Source     string // osv
	URL        string
	References []Reference
	Affected   []AffectedRange
	// Structured fields that might name functions. Recorded verbatim so the
	// evaluation can show they are absent for npm.
	EcosystemSpecific []json.RawMessage
	DatabaseSpecific  json.RawMessage
}

// Reference is one advisory link.
type Reference struct {
	Type string
	URL  string
}

// AffectedRange is one npm package range from the advisory.
type AffectedRange struct {
	Package    string
	Introduced string
	Fixed      string
}

type osvRecord struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific json.RawMessage `json:"ecosystem_specific"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

var advisoryIDPattern = regexp.MustCompile(`^(?i)(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$`)

// FetchAdvisory loads the OSV record for a finding. The GHSA alias is tried
// first because OSV mirrors GitHub advisories under that ID; the primary ID
// is the fallback.
func (c *Client) FetchAdvisory(ctx context.Context, f Finding) (*Advisory, error) {
	var ids []string
	for _, a := range f.Aliases {
		if strings.HasPrefix(strings.ToUpper(a), "GHSA-") {
			ids = append(ids, a)
		}
	}
	ids = append(ids, f.VulnerabilityID)
	for _, a := range f.Aliases {
		if !strings.HasPrefix(strings.ToUpper(a), "GHSA-") {
			ids = append(ids, a)
		}
	}
	var lastErr error
	for _, id := range ids {
		if !advisoryIDPattern.MatchString(id) {
			lastErr = fmt.Errorf("unsupported advisory identifier %q", id)
			continue
		}
		var rec osvRecord
		err := c.getJSON(ctx, c.OSVBaseURL+"/v1/vulns/"+id, "application/json", &rec)
		if err != nil {
			lastErr = err
			if isNotFound(err) {
				continue
			}
			return nil, err
		}
		return advisoryFromOSV(rec, f.PURL), nil
	}
	return nil, lastErr
}

func advisoryFromOSV(rec osvRecord, purl string) *Advisory {
	name, _, _ := ParsePURL(purl)
	adv := &Advisory{
		ID:               rec.ID,
		Aliases:          rec.Aliases,
		Summary:          rec.Summary,
		Details:          rec.Details,
		Source:           "osv",
		URL:              "https://osv.dev/vulnerability/" + rec.ID,
		DatabaseSpecific: rec.DatabaseSpecific,
	}
	for _, r := range rec.References {
		adv.References = append(adv.References, Reference{Type: r.Type, URL: r.URL})
	}
	for _, a := range rec.Affected {
		if !strings.EqualFold(a.Package.Ecosystem, "npm") {
			continue
		}
		if name != "" && a.Package.Name != name {
			continue
		}
		if len(a.EcosystemSpecific) > 0 && string(a.EcosystemSpecific) != "null" {
			adv.EcosystemSpecific = append(adv.EcosystemSpecific, a.EcosystemSpecific)
		}
		for _, rg := range a.Ranges {
			var intro string
			for _, ev := range rg.Events {
				if ev.Introduced != "" {
					intro = ev.Introduced
				}
				if ev.Fixed != "" {
					adv.Affected = append(adv.Affected, AffectedRange{Package: a.Package.Name, Introduced: intro, Fixed: ev.Fixed})
				}
			}
		}
	}
	return adv
}

// FixedVersionFor picks the smallest fixed version above the installed one
// from the advisory ranges, or "" when the advisory gives none.
func (a *Advisory) FixedVersionFor(installed string) string {
	best := ""
	for _, r := range a.Affected {
		if r.Fixed == "" || !semverLess(installed, r.Fixed) {
			continue
		}
		if r.Introduced != "" && r.Introduced != "0" && semverLess(installed, r.Introduced) {
			continue
		}
		if best == "" || semverLess(r.Fixed, best) {
			best = r.Fixed
		}
	}
	return best
}

// StructuredFunctions returns function names from structured advisory
// fields. OSV defines ecosystem_specific.imports[].symbols for Go; npm has
// no such field, and the evaluation records how often this is empty.
func (a *Advisory) StructuredFunctions() []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, raw := range a.EcosystemSpecific {
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		for _, key := range []string{"functions", "affected_functions", "symbols", "vulnerable_functions"} {
			if arr, ok := m[key].([]any); ok {
				for _, v := range arr {
					if s, ok := v.(string); ok {
						add(s)
					}
				}
			}
		}
		if imports, ok := m["imports"].([]any); ok {
			for _, imp := range imports {
				if im, ok := imp.(map[string]any); ok {
					if syms, ok := im["symbols"].([]any); ok {
						for _, v := range syms {
							if s, ok := v.(string); ok {
								add(s)
							}
						}
					}
				}
			}
		}
	}
	if len(a.DatabaseSpecific) > 0 {
		var m map[string]any
		if json.Unmarshal(a.DatabaseSpecific, &m) == nil {
			for _, key := range []string{"affected_functions", "functions", "vulnerable_functions"} {
				if arr, ok := m[key].([]any); ok {
					for _, v := range arr {
						if s, ok := v.(string); ok {
							add(s)
						}
					}
				}
			}
		}
	}
	return out
}

var (
	// `template`, `_.merge`, `ini.parse`, `new Range`, `setKey()`
	reBacktick = regexp.MustCompile("`([^`\\n]{1,80})`")
	// "the template function", "via the merge, mergeWith functions"
	reFunctionWord = regexp.MustCompile(`(?i)\b(?:function|method)s?\s+` + "`?" + `([A-Za-z_$][\w$.]*)`)
	reWordFunction = regexp.MustCompile(`(?i)\b([A-Za-z_$][\w$.]*)\(?\)?` + "`?" + `\s+(?:function|method)s?\b`)
	// 'defaultsDeep', "merge"
	reQuoted = regexp.MustCompile(`['"]([A-Za-z_$][\w$.]{1,60})['"]`)
	// bare call syntax: setKey(), _.merge(...)
	reCall = regexp.MustCompile(`\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\(\)`)
)

// textStopwords are tokens that look like identifiers but never name the
// implicated function: payload words from prototype-pollution advisories,
// language builtins, packaging vocabulary.
var textStopwords = map[string]bool{
	"object": true, "prototype": true, "constructor": true, "__proto__": true, "array": true,
	"string": true, "number": true, "function": true, "require": true, "import": true, "console": true,
	"console.log": true, "npm": true, "node": true, "node.js": true, "js": true, "javascript": true,
	"json": true, "http": true, "https": true, "url": true, "true": true, "false": true, "null": true,
	"undefined": true, "this": true, "new": true, "var": true, "const": true, "let": true, "e.g": true,
	"i.e": true, "eval": true, "regexp": true, "regex": true, "denial": true, "service": true, "redos": true,
	"the": true, "a": true, "an": true, "in": true, "of": true, "to": true, "and": true, "or": true,
	"cve": true, "ghsa": true, "nvd": true, "cvss": true, "package": true, "version": true, "versions": true,
	"index.js": true, "lib": true, "src": true, "dist": true, "process": true, "buffer": true, "math": true,
	"date": true, "error": true, "typeerror": true, "promise": true, "symbol": true, "map": true, "set": true,
}

// FunctionsFromText extracts function-like identifiers from the advisory
// prose. It is deliberately conservative: a false candidate costs Component
// 4 a wrong join, a missed one only costs a fall-through to the next method.
// The package name is removed as a receiver (ini.parse -> parse, _.merge ->
// merge) and "new Range" keeps Range.
func (a *Advisory) FunctionsFromText(packageName string) []string {
	text := a.Summary + "\n" + a.Details
	// Drop fenced code blocks: proofs of concept are full of calls that are
	// not the vulnerable function (require, console.log, the attacker's code).
	text = stripCodeFences(text)

	seen := map[string]bool{}
	var out []string
	add := func(raw string) {
		tok := normaliseSymbolToken(raw, packageName)
		if tok == "" || seen[tok] {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	for _, m := range reBacktick.FindAllStringSubmatch(text, -1) {
		if looksLikeIdentifier(m[1]) {
			add(m[1])
		}
	}
	for _, m := range reFunctionWord.FindAllStringSubmatch(text, -1) {
		add(m[1])
	}
	for _, m := range reWordFunction.FindAllStringSubmatch(text, -1) {
		add(m[1])
	}
	for _, m := range reCall.FindAllStringSubmatch(text, -1) {
		add(m[1])
	}
	for _, m := range reQuoted.FindAllStringSubmatch(text, -1) {
		if strings.ContainsAny(m[1], "._$") || hasInnerUpper(m[1]) {
			add(m[1]) // 'defaultsDeep', 'mergeWith': camelCase or dotted only
		}
	}
	sort.Strings(out)
	return out
}

func stripCodeFences(s string) string {
	var b strings.Builder
	in := false
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			in = !in
			continue
		}
		if !in {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func looksLikeIdentifier(s string) bool {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "new ")
	s = strings.TrimSuffix(s, "()")
	if s == "" || len(s) > 60 || strings.ContainsAny(s, " \t{}[]=;,:'\"<>/\\") {
		return false
	}
	for _, r := range s {
		if !isIdentifierRune(r) {
			return false
		}
	}
	return true
}

func isIdentifierRune(r rune) bool {
	return r == '_' || r == '$' || r == '.' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

func hasInnerUpper(s string) bool {
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			return true
		}
	}
	return false
}

// normaliseSymbolToken turns an extracted token into a bare symbol name.
func normaliseSymbolToken(raw, packageName string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "new ")
	s = strings.TrimSuffix(s, "()")
	s = strings.Trim(s, ".,;:")
	if !looksLikeIdentifier(s) {
		return ""
	}
	// Strip receivers: _.merge, ini.parse, jwt.verify, moment.locale, res.location
	if i := strings.LastIndex(s, "."); i >= 0 {
		recv := strings.ToLower(s[:i])
		s = s[i+1:]
		if recv == "" || textStopwords[recv] {
			return ""
		}
	}
	lower := strings.ToLower(s)
	if textStopwords[lower] || lower == strings.ToLower(packageName) || len(s) < 2 {
		return ""
	}
	// All-caps tokens are constants or acronyms (HTTP, URL, POC), not functions.
	if strings.ToUpper(s) == s && len(s) > 1 {
		return ""
	}
	// Must start like an identifier.
	if first := rune(s[0]); !isIdentifierRune(first) || first == '.' || first >= '0' && first <= '9' {
		return ""
	}
	return s
}

// gitHubCommit is a commit reference mined from an advisory link.
type gitHubCommit struct {
	Repo string // owner/name
	SHA  string
}

// gitHubPR is a pull request reference mined from an advisory link.
type gitHubPR struct {
	Repo   string
	Number string
}

var (
	reCommitURL = regexp.MustCompile(`^https?://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/(?:commit|pull/\d+/commits)/([0-9a-f]{7,40})(?:[#?].*)?$`)
	rePullURL   = regexp.MustCompile(`^https?://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/pull/(\d+)(?:[#?].*)?$`)
	reRepoURL   = regexp.MustCompile(`^(?:git\+)?(?:https?|git|ssh)://(?:[^@/]+@)?github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?$`)
)

// PatchReferences returns the commit and pull-request links in the
// advisory, and the repository if a PACKAGE reference names one. Only
// github.com links are accepted; anything else is untrusted input and is
// ignored, never fetched.
func (a *Advisory) PatchReferences() (commits []gitHubCommit, prs []gitHubPR, repo string) {
	seenC := map[string]bool{}
	seenP := map[string]bool{}
	for _, r := range a.References {
		u := strings.TrimSpace(r.URL)
		if m := reCommitURL.FindStringSubmatch(u); m != nil {
			key := m[1] + "@" + m[2]
			if !seenC[key] {
				seenC[key] = true
				commits = append(commits, gitHubCommit{Repo: m[1], SHA: m[2]})
			}
			continue
		}
		if m := rePullURL.FindStringSubmatch(u); m != nil {
			key := m[1] + "#" + m[2]
			if !seenP[key] {
				seenP[key] = true
				prs = append(prs, gitHubPR{Repo: m[1], Number: m[2]})
			}
			continue
		}
		if m := reRepoURL.FindStringSubmatch(u); m != nil && (r.Type == "PACKAGE" || repo == "") {
			repo = m[1]
		}
	}
	if repo == "" {
		if len(commits) > 0 {
			repo = commits[0].Repo
		} else if len(prs) > 0 {
			repo = prs[0].Repo
		}
	}
	return commits, prs, repo
}

// RepoFromRegistryURL normalises a package.json repository URL to owner/name.
func RepoFromRegistryURL(u string) string {
	if m := reRepoURL.FindStringSubmatch(strings.TrimSpace(u)); m != nil {
		return m[1]
	}
	return ""
}
