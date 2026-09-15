package remote

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Xsamsx/SBOMber/internal/github"
)

const testPackageJSON = `{"dependencies":{"left-pad":"1.0.0"}}`

// treeEntryJSON mirrors the shape the GitHub tree API returns.
type treeEntryJSON struct {
	Path string `json:"path"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Size int    `json:"size"`
}

// fakeGitHub simulates just enough of the GitHub REST API for ScanRepo:
// the recursive tree endpoint and the file-contents endpoint.
type fakeGitHub struct {
	mu sync.Mutex

	manifestPaths []string
	truncated     bool

	// perFileDelay simulates network/API latency on each contents fetch.
	perFileDelay time.Duration
	// failPaths, when set, makes the contents fetch for that exact path
	// return a 500 instead of content.
	failPaths map[string]bool

	inFlight    int32
	maxInFlight int32
}

func (f *fakeGitHub) server() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/git/trees/"):
			f.serveTree(w, r)
		case strings.Contains(r.URL.Path, "/contents/"):
			f.serveContents(w, r)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	return httptest.NewServer(mux)
}

func (f *fakeGitHub) serveTree(w http.ResponseWriter, r *http.Request) {
	entries := make([]treeEntryJSON, 0, len(f.manifestPaths))
	for _, p := range f.manifestPaths {
		entries = append(entries, treeEntryJSON{Path: p, Type: "blob", SHA: "abc123", Size: len(testPackageJSON)})
	}

	resp := struct {
		SHA       string          `json:"sha"`
		Tree      []treeEntryJSON `json:"tree"`
		Truncated bool            `json:"truncated"`
	}{
		SHA:       "root",
		Tree:      entries,
		Truncated: f.truncated,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *fakeGitHub) serveContents(w http.ResponseWriter, r *http.Request) {
	idx := strings.Index(r.URL.Path, "/contents/")
	path := r.URL.Path[idx+len("/contents/"):]

	if f.failPaths[path] {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	cur := atomic.AddInt32(&f.inFlight, 1)
	defer atomic.AddInt32(&f.inFlight, -1)
	for {
		max := atomic.LoadInt32(&f.maxInFlight)
		if cur <= max || atomic.CompareAndSwapInt32(&f.maxInFlight, max, cur) {
			break
		}
	}

	if f.perFileDelay > 0 {
		select {
		case <-time.After(f.perFileDelay):
		case <-r.Context().Done():
			return
		}
	}

	resp := struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
		SHA      string `json:"sha"`
		Path     string `json:"path"`
	}{
		Content:  base64.StdEncoding.EncodeToString([]byte(testPackageJSON)),
		Encoding: "base64",
		SHA:      "filesha",
		Path:     path,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func manifestPaths(n int) []string {
	paths := make([]string, n)
	for i := 0; i < n; i++ {
		paths[i] = fmt.Sprintf("pkg%d/package.json", i)
	}
	return paths
}

// TestScanRepoBoundedConcurrency is the "synthetic large-repo" scenario from
// S5-01: a repo with many manifests must not spawn one goroutine per
// manifest. It asserts the number of simultaneously in-flight fetches never
// exceeds the configured worker count.
func TestScanRepoBoundedConcurrency(t *testing.T) {
	const manifestCount = 60
	const maxConcurrency = 4

	fake := &fakeGitHub{
		manifestPaths: manifestPaths(manifestCount),
		perFileDelay:  10 * time.Millisecond,
	}
	srv := fake.server()
	defer srv.Close()

	client := github.NewClientWithBaseURL("", srv.URL)
	scanner := NewScanner(client)
	scanner.SetMaxConcurrency(maxConcurrency)
	scanner.SetTimeout(30 * time.Second)

	result, err := scanner.ScanRepo("https://github.com/acme/widgets")
	if err != nil {
		t.Fatalf("ScanRepo returned error: %v", err)
	}

	if got := atomic.LoadInt32(&fake.maxInFlight); got > int32(maxConcurrency) {
		t.Errorf("observed %d concurrent manifest fetches, want <= %d", got, maxConcurrency)
	}

	if result.Status != StatusComplete {
		t.Errorf("Status = %q, want %q; skipped: %v", result.Status, StatusComplete, result.Skipped)
	}
	if len(result.Manifests) != manifestCount {
		t.Errorf("Manifests = %d, want %d", len(result.Manifests), manifestCount)
	}
}

// TestScanRepoDeadlineExceeded proves the scan "ends predictably" instead of
// hanging: with a deadline far shorter than the time needed to fetch every
// manifest, ScanRepo must still return promptly, and must name what it
// skipped rather than silently reporting success.
func TestScanRepoDeadlineExceeded(t *testing.T) {
	const manifestCount = 40

	fake := &fakeGitHub{
		manifestPaths: manifestPaths(manifestCount),
		perFileDelay:  200 * time.Millisecond,
	}
	srv := fake.server()
	defer srv.Close()

	client := github.NewClientWithBaseURL("", srv.URL)
	scanner := NewScanner(client)
	scanner.SetMaxConcurrency(2)
	timeout := 150 * time.Millisecond
	scanner.SetTimeout(timeout)

	start := time.Now()
	result, err := scanner.ScanRepo("https://github.com/acme/widgets")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("ScanRepo returned error: %v", err)
	}

	// Generous bound: the scan must not run anywhere close to the ~4s it
	// would take to serially fetch all 40 manifests at 200ms each.
	if elapsed > 2*time.Second {
		t.Errorf("ScanRepo took %v, expected it to end predictably near the %v deadline", elapsed, timeout)
	}

	if result.Status == StatusComplete {
		t.Errorf("Status = %q, want partial or failed when the deadline was exceeded", result.Status)
	}
	if len(result.Skipped) == 0 {
		t.Error("expected Skipped to name what was abandoned when the deadline was hit, got none")
	}
}

// TestScanRepoTruncatedTree proves a truncated GitHub tree listing is
// surfaced rather than silently treated as a complete, successful scan.
func TestScanRepoTruncatedTree(t *testing.T) {
	fake := &fakeGitHub{
		manifestPaths: manifestPaths(3),
		truncated:     true,
	}
	srv := fake.server()
	defer srv.Close()

	client := github.NewClientWithBaseURL("", srv.URL)
	scanner := NewScanner(client)

	result, err := scanner.ScanRepo("https://github.com/acme/widgets")
	if err != nil {
		t.Fatalf("ScanRepo returned error: %v", err)
	}

	if !result.Truncated {
		t.Error("Truncated = false, want true")
	}
	if result.Status != StatusPartial {
		t.Errorf("Status = %q, want %q", result.Status, StatusPartial)
	}
	found := false
	for _, s := range result.Skipped {
		if strings.Contains(s, "truncated") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Skipped to mention the truncated tree, got: %v", result.Skipped)
	}
}

// TestScanRepoPartialManifestFailure proves a manifest that fails to fetch
// is named in Skipped and downgrades Status to partial, instead of the scan
// silently reporting success with an incomplete dependency list.
func TestScanRepoPartialManifestFailure(t *testing.T) {
	paths := manifestPaths(5)
	fake := &fakeGitHub{
		manifestPaths: paths,
		failPaths:     map[string]bool{paths[2]: true},
	}
	srv := fake.server()
	defer srv.Close()

	client := github.NewClientWithBaseURL("", srv.URL)
	scanner := NewScanner(client)

	result, err := scanner.ScanRepo("https://github.com/acme/widgets")
	if err != nil {
		t.Fatalf("ScanRepo returned error: %v", err)
	}

	if result.Status != StatusPartial {
		t.Errorf("Status = %q, want %q", result.Status, StatusPartial)
	}
	if len(result.Manifests) != len(paths)-1 {
		t.Errorf("Manifests = %d, want %d", len(result.Manifests), len(paths)-1)
	}
	found := false
	for _, s := range result.Skipped {
		if strings.Contains(s, paths[2]) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Skipped to name the failed manifest %s, got: %v", paths[2], result.Skipped)
	}
}
