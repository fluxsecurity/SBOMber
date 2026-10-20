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
	"strings"
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

// npmVersionDoc is the subset of one version's registry document
// (GET /<name>/<version>) this package reads. The full package document
// (GET /<name>) lists every version ever published and runs to tens of
// megabytes for popular packages, so it is never fetched.
type npmVersionDoc struct {
	Version     string `json:"version"`
	Deprecated  string `json:"deprecated"`
	Maintainers []struct {
		Name string `json:"name"`
	} `json:"maintainers"`
}

// npmDownloadsDoc is the response shape of the npm downloads API.
type npmDownloadsDoc struct {
	Downloads int `json:"downloads"`
}

// FetchNpmRegistrySignals fetches maintainer count, weekly downloads, and
// the deprecated flag for an npm package from the public npm registry. When
// version is non-empty, the maintainers and deprecated flag are read from
// that exact version's document; otherwise from the "latest" version's.
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
	target := version
	if target == "" {
		target = "latest"
	}
	reqURL := npmRegistryBaseURL + "/" + npmPathName(name) + "/" + url.PathEscape(target)
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
		return netstatus.ClassifyResponse(resp), fmt.Errorf("npm registry lookup for %s@%s: HTTP %d", name, target, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRegistryResponseBytes+1))
	if err != nil {
		return netstatus.Unavailable, err
	}
	if len(body) > maxRegistryResponseBytes {
		return netstatus.Unavailable, fmt.Errorf("npm registry lookup for %s@%s: response exceeds %d bytes", name, target, maxRegistryResponseBytes)
	}

	var doc npmVersionDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return netstatus.Unavailable, err
	}

	signals.MaintainerCount = len(doc.Maintainers)
	if doc.Deprecated != "" {
		signals.Deprecated = true
		signals.DeprecatedNote = doc.Deprecated
	}

	return netstatus.Success, nil
}

// npmPathName escapes a package name for a registry URL path, keeping the
// scope separator: "@babel/core" is requested as /@babel/core/<version>.
func npmPathName(name string) string {
	if scope, rest, ok := strings.Cut(name, "/"); ok && strings.HasPrefix(scope, "@") {
		return url.PathEscape(scope) + "/" + url.PathEscape(rest)
	}
	return url.PathEscape(name)
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
		return netstatus.ClassifyResponse(resp), fmt.Errorf("npm downloads lookup for %s: HTTP %d", name, resp.StatusCode)
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
const maxRegistryResponseBytes = 4 << 20 // a version document is a few KiB
