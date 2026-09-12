package localisation

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1" //nolint:gosec // npm's legacy shasum field is SHA-1; used only to confirm the registry's own checksum
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
)

// PackageVersion is the registry metadata for one published version.
type PackageVersion struct {
	Name         string
	Version      string
	Tarball      string
	Integrity    string
	Shasum       string
	GitHead      string
	Repository   string
	UnpackedSize int64
	FileCount    int
}

type registryVersionDoc struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	GitHead string `json:"gitHead"`
	Dist    struct {
		Tarball      string `json:"tarball"`
		Integrity    string `json:"integrity"`
		Shasum       string `json:"shasum"`
		UnpackedSize int64  `json:"unpackedSize"`
		FileCount    int    `json:"fileCount"`
	} `json:"dist"`
	Repository any `json:"repository"` // string or {type,url}
}

// RegistryVersion fetches the registry document for name@version.
func (c *Client) RegistryVersion(ctx context.Context, name, version string) (*PackageVersion, error) {
	if !validPackageName(name) || !validVersion(version) {
		return nil, fmt.Errorf("invalid package %s@%s", name, version)
	}
	escaped := name
	if strings.HasPrefix(name, "@") {
		escaped = url.PathEscape(name) // @scope/name -> %40scope%2Fname
	}
	var doc registryVersionDoc
	if err := c.getJSON(ctx, c.RegistryURL+"/"+escaped+"/"+version, "application/json", &doc); err != nil {
		return nil, err
	}
	pv := &PackageVersion{
		Name: doc.Name, Version: doc.Version, Tarball: doc.Dist.Tarball, Integrity: doc.Dist.Integrity,
		Shasum: doc.Dist.Shasum, GitHead: doc.GitHead, UnpackedSize: doc.Dist.UnpackedSize, FileCount: doc.Dist.FileCount,
	}
	switch r := doc.Repository.(type) {
	case string:
		pv.Repository = r
	case map[string]any:
		if u, ok := r["url"].(string); ok {
			pv.Repository = u
		}
	}
	return pv, nil
}

// Tarball is an npm package tarball read entirely in memory. Only text
// source files are kept; nothing is written to disk and nothing is run.
type Tarball struct {
	Artefact Artefact
	// Files maps package-relative paths (without the leading "package/") to
	// their bytes.
	Files map[string][]byte
	// Skipped records entries that were not kept and why, so a reviewer can
	// see what the diff did not look at.
	Skipped []string
}

// Extraction limits. Exceeding one is reported as an error, never silently
// truncated, because a partial diff would under-report candidates.
const (
	DefaultMaxTarballBytes = 30 << 20
	maxExtractedBytes      = 120 << 20
	maxTarEntries          = 6000
)

// FetchTarball downloads and verifies a package tarball, then extracts its
// source files in memory. Verified is true when the SHA-512 (or legacy
// SHA-1) matches the registry's published integrity value. Executed is
// always false.
func (c *Client) FetchTarball(ctx context.Context, pv *PackageVersion, maxBytes int64) (*Tarball, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxTarballBytes
	}
	if err := validateTarballURL(pv.Tarball, c.RegistryURL); err != nil {
		return nil, err
	}
	body, _, err := c.get(ctx, pv.Tarball, "application/octet-stream", maxBytes)
	if err != nil {
		return nil, err
	}
	sum256 := sha256.Sum256(body)
	tb := &Tarball{
		Artefact: Artefact{
			URL:       pv.Tarball,
			SHA256:    hex.EncodeToString(sum256[:]),
			SizeBytes: int64(len(body)),
			Verified:  verifyIntegrity(body, pv.Integrity, pv.Shasum),
			Executed:  false,
		},
		Files: map[string][]byte{},
	}
	if err := extractSources(body, tb); err != nil {
		return tb, err
	}
	return tb, nil
}

// validateTarballURL accepts only https tarball URLs on the registry host
// that served the metadata (or its configured mirror), so a poisoned
// registry document cannot redirect the download.
func validateTarballURL(raw, registryBase string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("tarball url: %w", err)
	}
	base, err := url.Parse(registryBase)
	if err != nil {
		return fmt.Errorf("registry base url: %w", err)
	}
	if u.Host != base.Host {
		return fmt.Errorf("tarball host %q does not match registry %q", u.Host, base.Host)
	}
	if u.Scheme != base.Scheme {
		return fmt.Errorf("tarball scheme %q does not match registry %q", u.Scheme, base.Scheme)
	}
	if !strings.HasSuffix(u.Path, ".tgz") {
		return fmt.Errorf("tarball url %q is not a .tgz", raw)
	}
	return nil
}

func verifyIntegrity(body []byte, integrity, shasum string) bool {
	if strings.HasPrefix(integrity, "sha512-") {
		sum := sha512.Sum512(body)
		return base64.StdEncoding.EncodeToString(sum[:]) == strings.TrimPrefix(integrity, "sha512-")
	}
	if strings.HasPrefix(integrity, "sha256-") {
		sum := sha256.Sum256(body)
		return base64.StdEncoding.EncodeToString(sum[:]) == strings.TrimPrefix(integrity, "sha256-")
	}
	if shasum != "" {
		sum := sha1.Sum(body) //nolint:gosec // registry legacy checksum, see import comment
		return hex.EncodeToString(sum[:]) == strings.ToLower(shasum)
	}
	return false
}

// extractSources walks the gzip'd tar in memory, keeping only regular
// JavaScript/TypeScript files under the package root. Entries that escape
// the root, are links, or exceed a limit are skipped and recorded.
func extractSources(body []byte, tb *Tarball) error {
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("gunzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	var total int64
	entries := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		entries++
		if entries > maxTarEntries {
			return fmt.Errorf("tarball has more than %d entries", maxTarEntries)
		}
		name := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		if hdr.Typeflag != tar.TypeReg {
			tb.Skipped = append(tb.Skipped, name+" (not a regular file)")
			continue
		}
		if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "..") || strings.Contains(name, "/../") {
			tb.Skipped = append(tb.Skipped, name+" (escapes package root)")
			continue
		}
		rel := name
		if i := strings.IndexByte(rel, '/'); i >= 0 {
			rel = rel[i+1:] // drop the top-level "package/" directory
		} else {
			tb.Skipped = append(tb.Skipped, name+" (outside package directory)")
			continue
		}
		if !SupportedSourceFile(rel) || strings.HasSuffix(rel, ".map") {
			continue
		}
		if hdr.Size > maxSourceBytes {
			tb.Skipped = append(tb.Skipped, rel+fmt.Sprintf(" (%d bytes exceeds source limit)", hdr.Size))
			continue
		}
		total += hdr.Size
		if total > maxExtractedBytes {
			return fmt.Errorf("extracted sources exceed %d bytes", maxExtractedBytes)
		}
		data, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		tb.Files[rel] = data
	}
	return nil
}
