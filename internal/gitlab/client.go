package gitlab

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const defaultTimeout = 30 * time.Second

// Client provides access to the GitLab API.
type Client struct {
	httpClient *http.Client
	token      string
	baseURL    string
	rateLimit  RateLimit
}

// NewClient creates a GitLab API client.
// Supports both gitlab.com and self-hosted instances.
// Token is read from GITLAB_TOKEN env var if not provided.
func NewClient(token, instanceURL string) *Client {
	if token == "" {
		token = os.Getenv("GITLAB_TOKEN")
	}
	if instanceURL == "" {
		instanceURL = "https://gitlab.com"
	}
	instanceURL = strings.TrimSuffix(instanceURL, "/")
	return &Client{
		httpClient: &http.Client{Timeout: defaultTimeout},
		token:      token,
		baseURL:    instanceURL + "/api/v4",
	}
}

// HasToken returns true if the client has authentication configured.
func (c *Client) HasToken() bool {
	return c.token != ""
}

// GetRateLimit returns the last observed rate limit state.
func (c *Client) GetRateLimit() RateLimit {
	return c.rateLimit
}

// ParseRepoURL extracts the namespace/project path and optional instance URL
// from a GitLab repository URL.
func ParseRepoURL(rawURL string) (namespace, project, instanceURL string, err error) {
	rawURL = strings.TrimSuffix(rawURL, ".git")
	rawURL = strings.TrimSuffix(rawURL, "/")

	u, parseErr := url.Parse(rawURL)
	if parseErr != nil || u.Host == "" {
		return "", "", "", fmt.Errorf("invalid GitLab URL: %s", rawURL)
	}

	instanceURL = u.Scheme + "://" + u.Host
	parts := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 2)
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("URL must include namespace and project: %s", rawURL)
	}
	return parts[0], parts[1], instanceURL, nil
}

// GetRepoTree returns the recursive file tree for a project.
func (c *Client) GetRepoTree(namespace, project, ref string) ([]TreeEntry, error) {
	projectID := url.PathEscape(namespace + "/" + project)
	var all []TreeEntry

	// GitLab paginates with keyset pagination
	apiURL := fmt.Sprintf("%s/projects/%s/repository/tree?recursive=true&per_page=100&ref=%s",
		c.baseURL, projectID, url.QueryEscape(ref))

	for apiURL != "" {
		body, nextURL, err := c.getWithPagination(apiURL)
		if err != nil {
			return nil, err
		}

		var page []TreeEntry
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("parse tree response: %w", err)
		}
		all = append(all, page...)
		apiURL = nextURL
	}

	return all, nil
}

// GetFileContent fetches the raw content of a file.
func (c *Client) GetFileContent(namespace, project, path, ref string) (*FileContent, error) {
	projectID := url.PathEscape(namespace + "/" + project)
	encodedPath := url.PathEscape(path)

	apiURL := fmt.Sprintf("%s/projects/%s/repository/files/%s/raw?ref=%s",
		c.baseURL, projectID, encodedPath, url.QueryEscape(ref))

	resp, err := c.do(apiURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("file not found: %s", path)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitLab API error %d for %s", resp.StatusCode, path)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &FileContent{Content: data, Path: path}, nil
}

func (c *Client) do(apiURL string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	// Update rate limit from headers
	if remaining := resp.Header.Get("RateLimit-Remaining"); remaining != "" {
		c.rateLimit.Remaining, _ = strconv.Atoi(remaining)
	}
	if limit := resp.Header.Get("RateLimit-Limit"); limit != "" {
		c.rateLimit.Limit, _ = strconv.Atoi(limit)
	}

	return resp, nil
}

func (c *Client) getWithPagination(apiURL string) ([]byte, string, error) {
	resp, err := c.do(apiURL)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("GitLab API error %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	// Follow Link header for next page
	nextURL := parseLinkNext(resp.Header.Get("Link"))
	return body, nextURL, nil
}

// parseLinkNext extracts the next page URL from a Link header.
func parseLinkNext(link string) string {
	if link == "" {
		return ""
	}
	for _, part := range strings.Split(link, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, `rel="next"`) {
			start := strings.Index(part, "<")
			end := strings.Index(part, ">")
			if start != -1 && end != -1 && end > start {
				return part[start+1 : end]
			}
		}
	}
	return ""
}
