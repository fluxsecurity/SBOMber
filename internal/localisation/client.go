package localisation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Default endpoints. Every one is overridable so tests and mirrors can
// substitute a local server.
const (
	DefaultOSVBaseURL      = "https://api.osv.dev"
	DefaultGitHubAPIURL    = "https://api.github.com"
	DefaultRegistryBaseURL = "https://registry.npmjs.org"
	defaultUserAgent       = "SBOMber-localisation/0.1 (+https://github.com/fluxsecurity/SBOMber)"
	maxJSONResponseBytes   = 8 << 20
)

// Client performs the bounded HTTP fetches the localiser needs. It never
// follows a URL it did not construct itself from a validated identifier.
type Client struct {
	HTTP        *http.Client
	OSVBaseURL  string
	GitHubAPI   string
	RegistryURL string
	GitHubToken string
	UserAgent   string
}

func newClient(opts Options) *Client {
	c := &Client{
		HTTP:        opts.HTTPClient,
		OSVBaseURL:  opts.OSVBaseURL,
		GitHubAPI:   opts.GitHubAPIBaseURL,
		RegistryURL: opts.RegistryBaseURL,
		GitHubToken: opts.GitHubToken,
		UserAgent:   defaultUserAgent,
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 60 * time.Second}
	}
	if c.OSVBaseURL == "" {
		c.OSVBaseURL = DefaultOSVBaseURL
	}
	if c.GitHubAPI == "" {
		c.GitHubAPI = DefaultGitHubAPIURL
	}
	if c.RegistryURL == "" {
		c.RegistryURL = DefaultRegistryBaseURL
	}
	return c
}

// httpError carries the status so callers can distinguish "not found" from
// "could not ask".
type httpError struct {
	Status int
	URL    string
}

func (e *httpError) Error() string { return fmt.Sprintf("HTTP %d for %s", e.Status, e.URL) }

func isNotFound(err error) bool {
	he, ok := err.(*httpError)
	return ok && he.Status == http.StatusNotFound
}

func (c *Client) get(ctx context.Context, rawURL, accept string, limit int64) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if strings.HasPrefix(rawURL, c.GitHubAPI) {
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if c.GitHubToken != "" {
			req.Header.Set("Authorization", "Bearer "+c.GitHubToken)
		}
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.Header, &httpError{Status: resp.StatusCode, URL: rawURL}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, resp.Header, err
	}
	if int64(len(body)) > limit {
		return nil, resp.Header, fmt.Errorf("response for %s exceeds %d bytes", rawURL, limit)
	}
	return body, resp.Header, nil
}

func (c *Client) getJSON(ctx context.Context, rawURL, accept string, out any) error {
	body, _, err := c.get(ctx, rawURL, accept, maxJSONResponseBytes)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode %s: %w", rawURL, err)
	}
	return nil
}

// ParsePURL splits an npm package URL into name and version.
// Accepts pkg:npm/lodash@4.17.20 and pkg:npm/%40scope/name@1.0.0.
func ParsePURL(purl string) (name, version string, err error) {
	const prefix = "pkg:npm/"
	if !strings.HasPrefix(purl, prefix) {
		return "", "", fmt.Errorf("not an npm purl: %q", purl)
	}
	rest := purl[len(prefix):]
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	at := strings.LastIndex(rest, "@")
	if at <= 0 || at == len(rest)-1 {
		return "", "", fmt.Errorf("purl %q has no version", purl)
	}
	name, err = url.PathUnescape(rest[:at])
	if err != nil {
		return "", "", fmt.Errorf("purl %q: %w", purl, err)
	}
	version = rest[at+1:]
	if !validPackageName(name) || !validVersion(version) {
		return "", "", fmt.Errorf("purl %q has an invalid name or version", purl)
	}
	return name, version, nil
}

// validPackageName follows npm's rules closely enough to keep path
// traversal and URL tricks out of registry requests.
func validPackageName(name string) bool {
	if name == "" || len(name) > 214 || strings.Contains(name, "..") {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) > 2 {
		return false
	}
	for i, p := range parts {
		if p == "" {
			return false
		}
		if i == 0 && len(parts) == 2 && !strings.HasPrefix(p, "@") {
			return false
		}
		if len(parts) == 1 && strings.HasPrefix(p, "@") {
			return false // a scope with no package name
		}
		for _, r := range strings.TrimPrefix(p, "@") {
			if !isPackageNameRune(r) {
				return false
			}
		}
	}
	return true
}

func validVersion(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for _, r := range v {
		if !isVersionRune(r) {
			return false
		}
	}
	return true
}

func isPackageNameRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.'
}

func isVersionRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '+'
}

// semverLess compares two dotted versions numerically on major.minor.patch.
// Pre-release tags are ignored; that is enough to pick the smallest fixed
// version above the installed one.
func semverLess(a, b string) bool {
	pa, pb := semverParts(a), semverParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func semverParts(v string) [3]int {
	var out [3]int
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	for i, p := range strings.SplitN(v, ".", 3) {
		n, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		out[i] = n
	}
	return out
}
