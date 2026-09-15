package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultBaseURL = "https://api.github.com"
	defaultTimeout = 30 * time.Second

	// maxResponseBodyBytes bounds how much of any single API response we will
	// buffer in memory. Without this, a malicious or misbehaving endpoint
	// (or a very large file/tree response) can exhaust memory via a bare
	// io.ReadAll.
	maxResponseBodyBytes = 50 << 20 // 50 MiB
)

// Client provides access to GitHub API with rate limiting and caching.
type Client struct {
	httpClient    *http.Client
	token         string
	baseURL       string
	rateLimit     RateLimit
	rateLimitSeen bool // true once we have received at least one X-RateLimit header
	rateMu        sync.RWMutex
	cache         *cache
}

// cache stores API responses to avoid redundant requests.
type cache struct {
	mu      sync.RWMutex
	repos   map[string]*RepoInfo
	files   map[string]*FileContent
	metrics map[string]*HealthMetrics
}

func newCache() *cache {
	return &cache{
		repos:   make(map[string]*RepoInfo),
		files:   make(map[string]*FileContent),
		metrics: make(map[string]*HealthMetrics),
	}
}

// NewClient creates a GitHub API client.
// Token is read from GITHUB_TOKEN env var if not provided.
func NewClient(token string) *Client {
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	return &Client{
		httpClient: &http.Client{Timeout: defaultTimeout},
		token:      token,
		baseURL:    defaultBaseURL,
		cache:      newCache(),
	}
}

// NewClientWithBaseURL creates a GitHub API client pointed at a custom base
// URL. This exists so tests can point the client at an httptest server
// instead of the real GitHub API.
func NewClientWithBaseURL(token, base string) *Client {
	c := NewClient(token)
	c.baseURL = base
	return c
}

// HasToken returns true if the client has authentication configured.
func (c *Client) HasToken() bool {
	return c.token != ""
}

// GetRateLimit returns the current rate limit status.
func (c *Client) GetRateLimit() RateLimit {
	c.rateMu.RLock()
	defer c.rateMu.RUnlock()
	return c.rateLimit
}

// ParseRepoURL extracts owner and repo name from a GitHub URL.
func ParseRepoURL(rawURL string) (owner, repo string, err error) {
	rawURL = strings.TrimSuffix(rawURL, ".git")
	rawURL = strings.TrimSuffix(rawURL, "/")

	if strings.HasPrefix(rawURL, "git@github.com:") {
		parts := strings.TrimPrefix(rawURL, "git@github.com:")
		return splitOwnerRepo(parts)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", "", fmt.Errorf("invalid URL: %w", err)
	}

	if parsed.Host != "github.com" && parsed.Host != "www.github.com" {
		return "", "", fmt.Errorf("not a GitHub URL: %s", rawURL)
	}

	path := strings.TrimPrefix(parsed.Path, "/")
	return splitOwnerRepo(path)
}

func splitOwnerRepo(path string) (owner, repo string, err error) {
	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid repo path: %s", path)
	}
	return parts[0], parts[1], nil
}

// GetRepoInfo fetches repository metadata.
func (c *Client) GetRepoInfo(owner, repo string) (*RepoInfo, error) {
	key := owner + "/" + repo

	c.cache.mu.RLock()
	if cached, ok := c.cache.repos[key]; ok {
		c.cache.mu.RUnlock()
		return cached, nil
	}
	c.cache.mu.RUnlock()

	endpoint := fmt.Sprintf("%s/repos/%s/%s", c.baseURL, owner, repo)
	body, err := c.doRequest(context.Background(), "GET", endpoint)
	if err != nil {
		return nil, err
	}

	var resp apiRepoResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse repo info: %w", err)
	}

	info := &RepoInfo{
		Owner:       owner,
		Name:        repo,
		FullName:    resp.FullName,
		Description: resp.Description,
		Stars:       resp.Stars,
		Forks:       resp.Forks,
		OpenIssues:  resp.OpenIssues,
	}
	if resp.License != nil {
		info.License = resp.License.Name
	}

	if t, err := time.Parse(time.RFC3339, resp.CreatedAt); err == nil {
		info.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, resp.UpdatedAt); err == nil {
		info.UpdatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, resp.PushedAt); err == nil {
		info.PushedAt = t
	}

	c.cache.mu.Lock()
	c.cache.repos[key] = info
	c.cache.mu.Unlock()

	return info, nil
}

// GetRepoTree fetches the full file tree for a repository. The returned bool
// reports whether the GitHub API truncated the listing (see the "truncated"
// field in the tree API): when true, the returned entries are known to be
// incomplete and callers must not treat the listing as exhaustive.
func (c *Client) GetRepoTree(ctx context.Context, owner, repo, branch string) ([]TreeEntry, bool, error) {
	if branch == "" {
		branch = "HEAD"
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s/git/trees/%s?recursive=1", c.baseURL, owner, repo, branch)
	body, err := c.doRequest(ctx, "GET", endpoint)
	if err != nil {
		return nil, false, err
	}

	var resp apiTreeResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, false, fmt.Errorf("failed to parse tree: %w", err)
	}

	entries := make([]TreeEntry, 0, len(resp.Tree))
	for _, item := range resp.Tree {
		entries = append(entries, TreeEntry{
			Path: item.Path,
			Type: item.Type,
			SHA:  item.SHA,
			Size: item.Size,
		})
	}

	return entries, resp.Truncated, nil
}

// GetFileContent fetches the content of a single file.
func (c *Client) GetFileContent(ctx context.Context, owner, repo, path string) (*FileContent, error) {
	key := fmt.Sprintf("%s/%s/%s", owner, repo, path)

	c.cache.mu.RLock()
	if cached, ok := c.cache.files[key]; ok {
		c.cache.mu.RUnlock()
		return cached, nil
	}
	c.cache.mu.RUnlock()

	endpoint := fmt.Sprintf("%s/repos/%s/%s/contents/%s", c.baseURL, owner, repo, path)
	body, err := c.doRequest(ctx, "GET", endpoint)
	if err != nil {
		return nil, err
	}

	var resp apiContentResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse file content: %w", err)
	}

	if resp.Encoding != "base64" {
		return nil, fmt.Errorf("unexpected encoding: %s", resp.Encoding)
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(resp.Content, "\n", ""))
	if err != nil {
		return nil, fmt.Errorf("failed to decode content: %w", err)
	}

	content := &FileContent{
		Path:    resp.Path,
		Content: decoded,
		SHA:     resp.SHA,
	}

	c.cache.mu.Lock()
	c.cache.files[key] = content
	c.cache.mu.Unlock()

	return content, nil
}

// GetContributors fetches contributor stats for a repository.
func (c *Client) GetContributors(owner, repo string) (*ContributorStats, error) {
	// Fetch up to 100 contributors per page, use Link header for total if more
	endpoint := fmt.Sprintf("%s/repos/%s/%s/contributors?per_page=100&anon=1", c.baseURL, owner, repo)

	req, err := http.NewRequestWithContext(context.Background(), "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "SBOMber")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	c.updateRateLimit(resp.Header)

	if resp.StatusCode != 200 {
		return &ContributorStats{TotalContributors: 0}, nil
	}

	// Read the response body, bounded so a huge/misbehaving response cannot
	// exhaust memory.
	body, err := readLimitedBody(resp.Body)
	if err != nil {
		return &ContributorStats{TotalContributors: 0}, nil
	}

	var contributors []apiContributorResponse
	if err := json.Unmarshal(body, &contributors); err != nil {
		return &ContributorStats{TotalContributors: 0}, nil
	}

	totalContributors := len(contributors)

	// Check Link header for pagination - if there's a "last" page, calculate total
	linkHeader := resp.Header.Get("Link")
	if linkHeader != "" {
		if lastPage := extractLastPage(linkHeader); lastPage > 1 {
			// Total = (lastPage - 1) * 100 + current page count
			// But we only have first page, so estimate: lastPage * 100
			// More accurate: lastPage * per_page (but last page may have fewer)
			totalContributors = (lastPage-1)*100 + len(contributors)
		}
	}

	return &ContributorStats{
		TotalContributors: totalContributors,
	}, nil
}

func extractLastPage(linkHeader string) int {
	// Parse: <https://api.github.com/...?page=42>; rel="last"
	parts := strings.Split(linkHeader, ",")
	for _, part := range parts {
		if strings.Contains(part, `rel="last"`) {
			// Extract page number
			start := strings.Index(part, "page=")
			if start == -1 {
				continue
			}
			start += 5
			end := strings.Index(part[start:], ">")
			if end == -1 {
				end = strings.Index(part[start:], "&")
			}
			if end == -1 {
				end = len(part[start:])
			}
			pageStr := part[start : start+end]
			var page int
			fmt.Sscanf(pageStr, "%d", &page)
			return page
		}
	}
	return 0
}

// GetHealthMetrics calculates supply chain health metrics for a repository.
func (c *Client) GetHealthMetrics(owner, repo string) (*HealthMetrics, error) {
	key := owner + "/" + repo

	c.cache.mu.RLock()
	if cached, ok := c.cache.metrics[key]; ok {
		c.cache.mu.RUnlock()
		return cached, nil
	}
	c.cache.mu.RUnlock()

	info, err := c.GetRepoInfo(owner, repo)
	if err != nil {
		return nil, err
	}

	contribs, err := c.GetContributors(owner, repo)
	if err != nil {
		contribs = &ContributorStats{TotalContributors: 0}
	}

	metrics := &HealthMetrics{
		RepoInfo:       *info,
		Contributors:   contribs.TotalContributors,
		LastCommitDate: info.PushedAt,
	}

	daysSinceCommit := int(time.Since(info.PushedAt).Hours() / 24)
	switch {
	case daysSinceCommit < 30:
		metrics.CommitFrequency = "active"
	case daysSinceCommit < 180:
		metrics.CommitFrequency = "moderate"
	case daysSinceCommit < 365:
		metrics.CommitFrequency = "inactive"
	default:
		metrics.CommitFrequency = "abandoned"
	}

	metrics.RiskLevel = calculateRiskLevel(metrics)

	c.cache.mu.Lock()
	c.cache.metrics[key] = metrics
	c.cache.mu.Unlock()

	return metrics, nil
}

func calculateRiskLevel(m *HealthMetrics) string {
	score := 0

	if m.CommitFrequency == "abandoned" {
		score += 3
	} else if m.CommitFrequency == "inactive" {
		score += 2
	} else if m.CommitFrequency == "moderate" {
		score += 1
	}

	if m.Contributors <= 1 {
		score += 2
	} else if m.Contributors <= 3 {
		score += 1
	}

	if m.Stars < 10 {
		score += 1
	}

	switch {
	case score >= 4:
		return "high"
	case score >= 2:
		return "medium"
	default:
		return "low"
	}
}

func (c *Client) doRequest(ctx context.Context, method, endpoint string) ([]byte, error) {
	c.rateMu.RLock()
	if c.rateLimitSeen && c.rateLimit.Remaining == 0 && time.Now().Before(c.rateLimit.Reset) {
		c.rateMu.RUnlock()
		return nil, fmt.Errorf("rate limit exceeded, resets in %v", time.Until(c.rateLimit.Reset))
	}
	c.rateMu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "SBOMber")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	c.updateRateLimit(resp.Header)

	if resp.StatusCode == 401 {
		// Invalid/expired token — retry without auth so public repos still work.
		if c.token != "" {
			req2, err2 := http.NewRequestWithContext(ctx, method, endpoint, nil)
			if err2 != nil {
				return nil, fmt.Errorf("authentication failed (check GITHUB_TOKEN): %s", endpoint)
			}
			req2.Header.Set("Accept", "application/vnd.github.v3+json")
			req2.Header.Set("User-Agent", "SBOMber")
			resp2, err2 := c.httpClient.Do(req2)
			if err2 != nil {
				return nil, fmt.Errorf("authentication failed and unauthenticated retry failed: %w", err2)
			}
			defer resp2.Body.Close()
			c.updateRateLimit(resp2.Header)
			if resp2.StatusCode == 200 {
				return readLimitedBody(resp2.Body)
			}
		}
		return nil, fmt.Errorf("authentication failed (GITHUB_TOKEN is invalid or expired): %s", endpoint)
	}
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("not found: %s", endpoint)
	}
	if resp.StatusCode == 403 {
		return nil, fmt.Errorf("forbidden (rate limit or auth): %s", endpoint)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, endpoint)
	}

	return readLimitedBody(resp.Body)
}

// readLimitedBody reads r, refusing to buffer more than maxResponseBodyBytes.
// A bare io.ReadAll on an HTTP response body has no upper bound, so a large
// or misbehaving response can exhaust memory; this caps that risk.
func readLimitedBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxResponseBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBodyBytes {
		return nil, fmt.Errorf("response body exceeds %d byte limit", maxResponseBodyBytes)
	}
	return body, nil
}

func (c *Client) updateRateLimit(headers http.Header) {
	c.rateMu.Lock()
	defer c.rateMu.Unlock()

	if v := headers.Get("X-RateLimit-Limit"); v != "" {
		c.rateLimit.Limit, _ = strconv.Atoi(v)
		c.rateLimitSeen = true
	}
	if v := headers.Get("X-RateLimit-Remaining"); v != "" {
		c.rateLimit.Remaining, _ = strconv.Atoi(v)
	}
	if v := headers.Get("X-RateLimit-Reset"); v != "" {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			c.rateLimit.Reset = time.Unix(ts, 0)
		}
	}
}
