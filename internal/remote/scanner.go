package remote

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Xsamsx/SBOMber/internal/deps"
	"github.com/Xsamsx/SBOMber/internal/github"
)

// KnownManifests maps manifest filenames to their ecosystems.
var KnownManifests = map[string]string{
	"package.json":       "npm",
	"package-lock.json":  "npm",
	"yarn.lock":          "npm",
	"requirements.txt":   "pypi",
	"Pipfile.lock":       "pypi",
	"go.mod":             "go",
	"go.sum":             "go",
	"pom.xml":            "maven",
	"Gemfile.lock":       "rubygems",
	"Cargo.lock":         "cargo",
	"composer.lock":      "composer",
	"packages.lock.json": "nuget",
}

// Scan status values. "complete" means every discovered manifest was fetched
// and parsed and the repo tree listing was not truncated. "partial" means
// the scan produced usable results but something was skipped — a truncated
// tree, a failed manifest fetch/parse, or the overall deadline being hit.
// "failed" means nothing could be scanned at all.
const (
	StatusComplete = "complete"
	StatusPartial  = "partial"
	StatusFailed   = "failed"
)

const (
	// defaultScanTimeout bounds the total wall-clock time a single ScanRepo
	// call may take, across the tree fetch and every manifest fetch/parse.
	defaultScanTimeout = 5 * time.Minute

	// defaultMaxConcurrency bounds how many manifest fetches run at once.
	// The previous implementation spawned one goroutine per manifest file
	// with no limit, so a repo with hundreds of manifests could open
	// hundreds of simultaneous GitHub API requests.
	defaultMaxConcurrency = 8
)

// ProgressFunc is called to report scanning progress.
type ProgressFunc func(message string)

// Scanner scans remote GitHub repositories for dependencies.
type Scanner struct {
	client         *github.Client
	progress       ProgressFunc
	timeout        time.Duration
	maxConcurrency int
}

// ScanResult contains the results from scanning a remote repository.
type ScanResult struct {
	RepoURL    string
	Owner      string
	Repo       string
	Summary    deps.Summary
	Manifests  []string
	RepoHealth *github.HealthMetrics
	Error      error

	// Status is one of StatusComplete, StatusPartial or StatusFailed.
	Status string
	// Skipped names, in plain language, everything the scan could not do:
	// a truncated tree, a manifest that failed to fetch or parse, or work
	// abandoned because the overall deadline was reached. An empty slice
	// with Status == StatusComplete means nothing was skipped.
	Skipped []string
	// Truncated is true when the GitHub tree API truncated the file
	// listing, meaning some manifest files may never have been discovered.
	Truncated bool
}

// NewScanner creates a new remote repository scanner.
func NewScanner(client *github.Client) *Scanner {
	return &Scanner{
		client:         client,
		timeout:        defaultScanTimeout,
		maxConcurrency: defaultMaxConcurrency,
	}
}

// SetProgress sets the progress callback function.
func (s *Scanner) SetProgress(fn ProgressFunc) {
	s.progress = fn
}

// SetTimeout overrides the overall deadline for a single ScanRepo call.
func (s *Scanner) SetTimeout(d time.Duration) {
	s.timeout = d
}

// SetMaxConcurrency overrides how many manifest fetches run at once.
func (s *Scanner) SetMaxConcurrency(n int) {
	s.maxConcurrency = n
}

func (s *Scanner) log(msg string) {
	if s.progress != nil {
		s.progress(msg)
	}
}

// ScanRepo scans a single GitHub repository and extracts dependencies. The
// scan is bounded by the Scanner's configured timeout (default 5 minutes);
// see ScanRepoContext to supply a caller-controlled context instead.
func (s *Scanner) ScanRepo(repoURL string) (*ScanResult, error) {
	return s.ScanRepoContext(context.Background(), repoURL)
}

// ScanRepoContext scans a single GitHub repository, bounding the whole
// operation (tree fetch plus every manifest fetch and parse) to the
// Scanner's configured timeout on top of the supplied context. Work skipped
// because of a truncated tree listing, a failed manifest, or the deadline
// being reached is recorded on the returned ScanResult rather than silently
// dropped.
func (s *Scanner) ScanRepoContext(ctx context.Context, repoURL string) (*ScanResult, error) {
	owner, repo, err := github.ParseRepoURL(repoURL)
	if err != nil {
		return nil, fmt.Errorf("invalid GitHub URL: %w", err)
	}

	timeout := s.timeout
	if timeout <= 0 {
		timeout = defaultScanTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	s.log(fmt.Sprintf("Parsing URL: %s/%s", owner, repo))

	result := &ScanResult{
		RepoURL:   repoURL,
		Owner:     owner,
		Repo:      repo,
		Manifests: make([]string, 0),
		Summary: deps.Summary{
			Direct:     make([]deps.Dependency, 0),
			Transitive: make([]deps.Dependency, 0),
		},
	}

	s.log("Fetching repository tree...")
	tree, truncated, err := s.client.GetRepoTree(ctx, owner, repo, "HEAD")
	if err != nil {
		result.Status = StatusFailed
		result.Error = err
		return result, fmt.Errorf("failed to get repo tree: %w", err)
	}
	s.log(fmt.Sprintf("Found %d files in repository", len(tree)))

	result.Truncated = truncated
	if truncated {
		result.Skipped = append(result.Skipped, "repository file tree was truncated by the GitHub API; some manifest files may not have been discovered")
		s.log("WARNING: repository tree was truncated by the GitHub API; results may be incomplete")
	}

	manifestFiles := findManifestFiles(tree)
	if len(manifestFiles) == 0 {
		s.log("No manifest files found")
		result.Status = finalStatus(result, 0, 0)
		return result, nil
	}

	s.log(fmt.Sprintf("Found %d manifest files", len(manifestFiles)))
	for _, mf := range manifestFiles {
		s.log(fmt.Sprintf("  - %s (%s)", mf.Path, mf.Ecosystem))
	}

	type fetchResult struct {
		manifest manifestFile
		parsed   *deps.Summary
		err      error
		fetchErr error
	}

	workerCount := s.maxConcurrency
	if workerCount <= 0 {
		workerCount = defaultMaxConcurrency
	}
	if workerCount > len(manifestFiles) {
		workerCount = len(manifestFiles)
	}

	jobs := make(chan manifestFile)
	results := make(chan fetchResult, len(manifestFiles))
	var wg sync.WaitGroup

	s.log(fmt.Sprintf("Fetching manifests with %d workers...", workerCount))
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for mf := range jobs {
				fr := fetchResult{manifest: mf}

				content, err := s.client.GetFileContent(ctx, owner, repo, mf.Path)
				if err != nil {
					fr.fetchErr = err
					results <- fr
					continue
				}

				parsed, err := parseManifestContent(mf.Path, content.Content)
				if err != nil {
					fr.err = err
					results <- fr
					continue
				}
				fr.parsed = &parsed
				results <- fr
			}
		}()
	}

	// Feed jobs, but stop handing out new work once the deadline is hit so
	// workers can drain and exit instead of blocking forever on a full
	// unbuffered channel nobody is reading from.
	go func() {
		defer close(jobs)
		for _, mf := range manifestFiles {
			select {
			case jobs <- mf:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	processed := make(map[string]bool, len(manifestFiles))
	for fr := range results {
		processed[fr.manifest.Path] = true

		if fr.fetchErr != nil {
			s.log(fmt.Sprintf("  Error fetching %s: %v", fr.manifest.Path, fr.fetchErr))
			result.Skipped = append(result.Skipped, fmt.Sprintf("manifest fetch failed: %s: %v", fr.manifest.Path, fr.fetchErr))
			continue
		}
		if fr.err != nil {
			s.log(fmt.Sprintf("  Error parsing %s: %v", fr.manifest.Path, fr.err))
			result.Skipped = append(result.Skipped, fmt.Sprintf("manifest parse failed: %s: %v", fr.manifest.Path, fr.err))
			continue
		}

		depCount := len(fr.parsed.Direct) + len(fr.parsed.Transitive)
		s.log(fmt.Sprintf("  %s: %d dependencies", fr.manifest.Path, depCount))

		result.Manifests = append(result.Manifests, fr.manifest.Path)
		result.Summary.Direct = append(result.Summary.Direct, fr.parsed.Direct...)
		result.Summary.Transitive = append(result.Summary.Transitive, fr.parsed.Transitive...)
	}

	// Manifests that were never picked up (or were dropped mid-flight by the
	// deadline) must still be named rather than silently missing from the
	// output.
	for _, mf := range manifestFiles {
		if !processed[mf.Path] {
			result.Skipped = append(result.Skipped, fmt.Sprintf("manifest skipped: %s: scan deadline exceeded before it could be processed", mf.Path))
		}
	}

	result.Summary.Direct = deduplicateDeps(result.Summary.Direct)
	s.log(fmt.Sprintf("Total: %d direct, %d transitive dependencies", len(result.Summary.Direct), len(result.Summary.Transitive)))

	if ctx.Err() != nil && !containsDeadlineNote(result.Skipped) {
		result.Skipped = append(result.Skipped, fmt.Sprintf("scan deadline exceeded: %v", ctx.Err()))
	}

	result.Status = finalStatus(result, len(result.Manifests), len(manifestFiles))
	return result, nil
}

func containsDeadlineNote(skipped []string) bool {
	for _, s := range skipped {
		if strings.Contains(s, "scan deadline exceeded") {
			return true
		}
	}
	return false
}

// finalStatus derives the overall scan status. discovered is the number of
// manifest files found in the tree; succeeded is how many were fetched and
// parsed successfully.
func finalStatus(result *ScanResult, succeeded, discovered int) string {
	switch {
	case discovered > 0 && succeeded == 0:
		return StatusFailed
	case len(result.Skipped) > 0:
		return StatusPartial
	default:
		return StatusComplete
	}
}

// ScanRepos scans multiple GitHub repositories concurrently.
func (s *Scanner) ScanRepos(repoURLs []string) []*ScanResult {
	results := make([]*ScanResult, len(repoURLs))

	for i, url := range repoURLs {
		result, err := s.ScanRepo(url)
		if err != nil {
			if result == nil {
				result = &ScanResult{RepoURL: url, Status: StatusFailed}
			}
			result.Error = err
			results[i] = result
		} else {
			results[i] = result
		}
	}

	return results
}

// FetchHealthMetrics fetches health metrics for a scan result.
func (s *Scanner) FetchHealthMetrics(result *ScanResult) error {
	metrics, err := s.client.GetHealthMetrics(result.Owner, result.Repo)
	if err != nil {
		return err
	}
	result.RepoHealth = metrics
	return nil
}

type manifestFile struct {
	Path      string
	Ecosystem string
}

func findManifestFiles(tree []github.TreeEntry) []manifestFile {
	var manifests []manifestFile

	for _, entry := range tree {
		if entry.Type != "blob" {
			continue
		}

		filename := getFilename(entry.Path)
		if ecosystem, ok := KnownManifests[filename]; ok {
			manifests = append(manifests, manifestFile{
				Path:      entry.Path,
				Ecosystem: ecosystem,
			})
		}
	}

	return manifests
}

func getFilename(path string) string {
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}

func deduplicateDeps(depsSlice []deps.Dependency) []deps.Dependency {
	seen := make(map[string]bool)
	unique := make([]deps.Dependency, 0, len(depsSlice))

	for _, dep := range depsSlice {
		key := dep.Ecosystem + ":" + dep.Name + ":" + dep.Version
		if !seen[key] {
			seen[key] = true
			unique = append(unique, dep)
		}
	}

	return unique
}
