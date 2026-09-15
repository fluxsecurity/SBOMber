// Package supplychain enriches dependencies with signals from outside the
// scanned repository itself: registry metadata today, malware scanning as a
// tracked-but-not-yet-implemented source (see malware.go).
package supplychain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Xsamsx/SBOMber/internal/netstatus"
)

// npmRegistryBaseURL and npmDownloadsBaseURL are variables, not constants, so
// tests can point them at a local server.
var (
	npmRegistryBaseURL  = "https://registry.npmjs.org"
	npmDownloadsBaseURL = "https://api.npmjs.org/downloads/point/last-week"
)

var registryHTTPClient = &http.Client{Timeout: 15 * time.Second}

// RegistrySignals holds the npm registry signals used to gauge how
// maintained a package is: who maintains it, how much it's used, and
// whether the authors themselves have flagged it deprecated.
type RegistrySignals struct {
	PackageName     string
	MaintainerCount int
	WeeklyDownloads int
	Deprecated      bool
	DeprecatedNote  string
}

// npmPackageDoc is the subset of the npm registry's package document
// (GET /<name>) this package reads.
type npmPackageDoc struct {
	DistTags struct {
		Latest string `json:"latest"`
	} `json:"dist-tags"`
	Maintainers []struct {
		Name string `json:"name"`
	} `json:"maintainers"`
	Versions map[string]struct {
		Deprecated string `json:"deprecated"`
	} `json:"versions"`
}

// npmDownloadsDoc is the response shape of the npm downloads API.
type npmDownloadsDoc struct {
	Downloads int `json:"downloads"`
}

// FetchNpmRegistrySignals fetches maintainer count, weekly downloads, and
// the deprecated flag for an npm package from the public npm registry. When
// version is non-empty, the deprecated flag is read from that exact
// version; otherwise the dist-tags "latest" version is used.
//
// Both the package-metadata and downloads requests are attempted even if
// one fails, so a single unavailable endpoint does not hide data the other
// endpoint could still provide. The returned Status reflects the worse of
// the two outcomes.
func FetchNpmRegistrySignals(ctx context.Context, name, version string) (*RegistrySignals, netstatus.Status, error) {
	signals := &RegistrySignals{PackageName: name}

	metaStatus, metaErr := fetchNpmPackageMeta(ctx, name, version, signals)
	downloadsStatus, downloadsErr := fetchNpmWeeklyDownloads(ctx, name, signals)

	status := netstatus.Worse(metaStatus, downloadsStatus)
	if status == netstatus.Success {
		return signals, netstatus.Success, nil
	}

	err := metaErr
	if err == nil {
		err = downloadsErr
	}
	return signals, status, err
}

func fetchNpmPackageMeta(ctx context.Context, name, version string, signals *RegistrySignals) (netstatus.Status, error) {
	reqURL := npmRegistryBaseURL + "/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return netstatus.Unavailable, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := registryHTTPClient.Do(req)
	if err != nil {
		return netstatus.ClassifyErr(err), err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return netstatus.ClassifyHTTPStatus(resp.StatusCode), fmt.Errorf("npm registry lookup for %s: HTTP %d", name, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRegistryResponseBytes))
	if err != nil {
		return netstatus.Unavailable, err
	}

	var doc npmPackageDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return netstatus.Unavailable, err
	}

	signals.MaintainerCount = len(doc.Maintainers)

	target := version
	if target == "" {
		target = doc.DistTags.Latest
	}
	if v, ok := doc.Versions[target]; ok && v.Deprecated != "" {
		signals.Deprecated = true
		signals.DeprecatedNote = v.Deprecated
	}

	return netstatus.Success, nil
}

func fetchNpmWeeklyDownloads(ctx context.Context, name string, signals *RegistrySignals) (netstatus.Status, error) {
	reqURL := npmDownloadsBaseURL + "/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return netstatus.Unavailable, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := registryHTTPClient.Do(req)
	if err != nil {
		return netstatus.ClassifyErr(err), err
	}
	defer func() { _ = resp.Body.Close() }()

	// A brand-new or scoped-private package with no download history
	// returns 404; that is a real "zero downloads" answer, not a failure.
	if resp.StatusCode == http.StatusNotFound {
		signals.WeeklyDownloads = 0
		return netstatus.Success, nil
	}
	if resp.StatusCode != http.StatusOK {
		return netstatus.ClassifyHTTPStatus(resp.StatusCode), fmt.Errorf("npm downloads lookup for %s: HTTP %d", name, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRegistryResponseBytes))
	if err != nil {
		return netstatus.Unavailable, err
	}

	var doc npmDownloadsDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return netstatus.Unavailable, err
	}

	signals.WeeklyDownloads = doc.Downloads
	return netstatus.Success, nil
}

// maxRegistryResponseBytes bounds how much of a registry response is read.
const maxRegistryResponseBytes = 4 << 20
