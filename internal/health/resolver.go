package health

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Xsamsx/SBOMber/internal/deps"
	"github.com/Xsamsx/SBOMber/internal/github"
)

// DependencyHealth combines dependency info with supply chain health metrics.
type DependencyHealth struct {
	deps.Dependency
	RepoURL        string
	RepoOwner      string
	RepoName       string
	Stars          int
	Forks          int
	Contributors   int
	LastCommit     time.Time
	CommitActivity string
	RiskLevel      string
	License        string
	Error          string
}

// Resolver fetches health metrics for dependencies.
type Resolver struct {
	ghClient   *github.Client
	httpClient *http.Client
	cache      map[string]*DependencyHealth
	cacheMu    sync.RWMutex
}

// NewResolver creates a new health resolver.
func NewResolver(ghClient *github.Client) *Resolver {
	return &Resolver{
		ghClient:   ghClient,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cache:      make(map[string]*DependencyHealth),
	}
}

// ResolveHealth fetches health metrics for a single dependency.
func (r *Resolver) ResolveHealth(dep deps.Dependency) *DependencyHealth {
	key := dep.Ecosystem + ":" + dep.Name

	r.cacheMu.RLock()
	if cached, ok := r.cache[key]; ok {
		r.cacheMu.RUnlock()
		return cached
	}
	r.cacheMu.RUnlock()

	health := &DependencyHealth{Dependency: dep}

	repoURL, err := r.resolveRepoURL(dep)
	if err != nil {
		health.Error = err.Error()
		r.cacheMu.Lock()
		r.cache[key] = health
		r.cacheMu.Unlock()
		return health
	}

	health.RepoURL = repoURL
	owner, repo, err := github.ParseRepoURL(repoURL)
	if err != nil {
		health.Error = "not a GitHub repo"
		r.cacheMu.Lock()
		r.cache[key] = health
		r.cacheMu.Unlock()
		return health
	}

	health.RepoOwner = owner
	health.RepoName = repo

	metrics, err := r.ghClient.GetHealthMetrics(owner, repo)
	if err != nil {
		health.Error = err.Error()
		r.cacheMu.Lock()
		r.cache[key] = health
		r.cacheMu.Unlock()
		return health
	}

	health.Stars = metrics.Stars
	health.Forks = metrics.Forks
	health.Contributors = metrics.Contributors
	health.LastCommit = metrics.LastCommitDate
	health.CommitActivity = metrics.CommitFrequency
	health.RiskLevel = metrics.RiskLevel
	health.License = metrics.License

	r.cacheMu.Lock()
	r.cache[key] = health
	r.cacheMu.Unlock()
	return health
}

// ProgressFunc is called with progress updates during resolution.
type ProgressFunc func(current, total int, depName string)

// ResolveAll fetches health metrics for all dependencies.
func (r *Resolver) ResolveAll(dependencies []deps.Dependency) []*DependencyHealth {
	return r.ResolveAllWithProgress(dependencies, nil)
}

// ResolveAllWithProgress fetches health metrics with progress callback (parallel).
func (r *Resolver) ResolveAllWithProgress(dependencies []deps.Dependency, progress ProgressFunc) []*DependencyHealth {
	results := make([]*DependencyHealth, len(dependencies))

	// Use worker pool for parallel fetching
	const maxWorkers = 10
	jobs := make(chan int, len(dependencies))
	done := make(chan struct{})

	var completed int
	var mu sync.Mutex

	// Start workers
	for w := 0; w < maxWorkers; w++ {
		go func() {
			for i := range jobs {
				dep := dependencies[i]
				result := r.ResolveHealth(dep)
				results[i] = result

				mu.Lock()
				completed++
				if progress != nil {
					progress(completed, len(dependencies), dep.Name)
				}
				mu.Unlock()
			}
			done <- struct{}{}
		}()
	}

	// Send jobs
	for i := range dependencies {
		jobs <- i
	}
	close(jobs)

	// Wait for workers
	for w := 0; w < maxWorkers; w++ {
		<-done
	}

	return results
}

func (r *Resolver) resolveRepoURL(dep deps.Dependency) (string, error) {
	switch dep.Ecosystem {
	case "npm":
		return r.resolveNpmRepo(dep.Name)
	case "pypi":
		return r.resolvePyPIRepo(dep.Name)
	case "go":
		return r.resolveGoRepo(dep.Name)
	case "rubygems":
		return r.resolveRubyRepo(dep.Name)
	case "maven":
		return r.resolveMavenRepo(dep.Name)
	default:
		return "", fmt.Errorf("unsupported ecosystem: %s", dep.Ecosystem)
	}
}

type npmPackageInfo struct {
	Repository struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"repository"`
}

func (r *Resolver) resolveNpmRepo(name string) (string, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s", name)
	resp, err := r.httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("npm registry returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var pkg npmPackageInfo
	if err := json.Unmarshal(body, &pkg); err != nil {
		return "", err
	}

	repoURL := pkg.Repository.URL
	if repoURL == "" {
		return "", fmt.Errorf("no repository URL found")
	}

	return normalizeGitURL(repoURL), nil
}

type pypiPackageInfo struct {
	Info struct {
		ProjectURLs map[string]string `json:"project_urls"`
		HomePage    string            `json:"home_page"`
	} `json:"info"`
}

func (r *Resolver) resolvePyPIRepo(name string) (string, error) {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", name)
	resp, err := r.httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("PyPI returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var pkg pypiPackageInfo
	if err := json.Unmarshal(body, &pkg); err != nil {
		return "", err
	}

	for key, url := range pkg.Info.ProjectURLs {
		keyLower := strings.ToLower(key)
		if strings.Contains(keyLower, "source") || strings.Contains(keyLower, "repository") || strings.Contains(keyLower, "github") {
			if strings.Contains(url, "github.com") {
				return normalizeGitURL(url), nil
			}
		}
	}

	if strings.Contains(pkg.Info.HomePage, "github.com") {
		return normalizeGitURL(pkg.Info.HomePage), nil
	}

	return "", fmt.Errorf("no GitHub repository found")
}

func (r *Resolver) resolveGoRepo(name string) (string, error) {
	if strings.HasPrefix(name, "github.com/") {
		parts := strings.Split(name, "/")
		if len(parts) >= 3 {
			return fmt.Sprintf("https://github.com/%s/%s", parts[1], parts[2]), nil
		}
	}
	return "", fmt.Errorf("cannot resolve non-GitHub Go module")
}

type rubyGemInfo struct {
	SourceCodeURI string `json:"source_code_uri"`
	HomepageURI   string `json:"homepage_uri"`
}

func (r *Resolver) resolveRubyRepo(name string) (string, error) {
	url := fmt.Sprintf("https://rubygems.org/api/v1/gems/%s.json", name)
	resp, err := r.httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("RubyGems returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var gem rubyGemInfo
	if err := json.Unmarshal(body, &gem); err != nil {
		return "", err
	}

	if gem.SourceCodeURI != "" && strings.Contains(gem.SourceCodeURI, "github.com") {
		return normalizeGitURL(gem.SourceCodeURI), nil
	}
	if gem.HomepageURI != "" && strings.Contains(gem.HomepageURI, "github.com") {
		return normalizeGitURL(gem.HomepageURI), nil
	}

	return "", fmt.Errorf("no GitHub repository found")
}

type mavenSearchResponse struct {
	Response struct {
		Docs []struct {
			LatestVersion string `json:"latestVersion"`
		} `json:"docs"`
	} `json:"response"`
}

func (r *Resolver) resolveMavenRepo(name string) (string, error) {
	// Maven dep names are "groupId:artifactId"
	parts := strings.SplitN(name, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("expected groupId:artifactId format, got: %s", name)
	}
	groupID, artifactID := parts[0], parts[1]

	// Find the latest version via Maven Central search
	searchURL := fmt.Sprintf(
		"https://search.maven.org/solrsearch/select?q=g:%s+AND+a:%s&rows=1&wt=json",
		url.QueryEscape(groupID), url.QueryEscape(artifactID),
	)
	resp, err := r.httpClient.Get(searchURL)
	if err != nil {
		return "", fmt.Errorf("maven search request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var searchResp mavenSearchResponse
	if err := json.Unmarshal(body, &searchResp); err != nil || len(searchResp.Response.Docs) == 0 {
		return "", fmt.Errorf("no Maven Central result for %s", name)
	}
	version := searchResp.Response.Docs[0].LatestVersion

	// Fetch POM and extract SCM URL
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	pomURL := fmt.Sprintf(
		"https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.pom",
		groupPath, artifactID, version, artifactID, version,
	)
	pomResp, err := r.httpClient.Get(pomURL)
	if err != nil {
		return "", fmt.Errorf("pom fetch failed: %w", err)
	}
	defer func() { _ = pomResp.Body.Close() }()

	pomBody, err := io.ReadAll(pomResp.Body)
	if err != nil {
		return "", err
	}

	scmURL := extractPOMScmURL(string(pomBody))
	if scmURL == "" {
		return "", fmt.Errorf("no SCM URL found in POM for %s", name)
	}
	return normalizeGitURL(scmURL), nil
}

var (
	scmURLPattern  = regexp.MustCompile(`(?s)<scm>.*?<url>([^<]+)</url>`)
	scmConnPattern = regexp.MustCompile(`(?s)<scm>.*?<connection>([^<]+)</connection>`)
)

func extractPOMScmURL(pom string) string {
	if m := scmURLPattern.FindStringSubmatch(pom); len(m) > 1 {
		u := strings.TrimSpace(m[1])
		if strings.Contains(u, "github.com") {
			return u
		}
	}
	if m := scmConnPattern.FindStringSubmatch(pom); len(m) > 1 {
		u := strings.TrimSpace(m[1])
		if strings.Contains(u, "github.com") {
			return u
		}
	}
	return ""
}

var gitURLPattern = regexp.MustCompile(`github\.com[:/]([^/]+)/([^/\.]+)`)

func normalizeGitURL(url string) string {
	url = strings.TrimPrefix(url, "git+")
	url = strings.TrimPrefix(url, "git://")
	url = strings.TrimSuffix(url, ".git")

	matches := gitURLPattern.FindStringSubmatch(url)
	if len(matches) >= 3 {
		return fmt.Sprintf("https://github.com/%s/%s", matches[1], matches[2])
	}

	return url
}
