package localisation

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type tarEntry struct {
	name string
	body string
	typ  byte
	link string
}

func buildTGZ(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: typ, Linkname: e.link}
		if typ != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func integrityOf(b []byte) string {
	sum := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

// registryServer serves /<pkg>/<version> metadata and /<pkg>/-/<file>.tgz.
func registryServer(t *testing.T, tarballs map[string][]byte, integrity map[string]string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) == 3 && parts[1] == "-" {
			file := strings.TrimSuffix(parts[2], ".tgz")
			if tb, ok := tarballs[file]; ok {
				_, _ = w.Write(tb)
				return
			}
			w.WriteHeader(404)
			return
		}
		if len(parts) == 2 {
			key := parts[0] + "-" + parts[1]
			if _, ok := tarballs[key]; !ok {
				w.WriteHeader(404)
				return
			}
			integ := integrity[key]
			if integ == "" {
				integ = integrityOf(tarballs[key])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name": parts[0], "version": parts[1], "gitHead": "abc",
				"dist":       map[string]any{"tarball": fmt.Sprintf("%s/%s/-/%s.tgz", srv.URL, parts[0], key), "integrity": integ},
				"repository": map[string]any{"type": "git", "url": "git+https://github.com/example/" + parts[0] + ".git"},
			})
			return
		}
		w.WriteHeader(404)
	}))
	return srv
}

// Success path: a normal tarball is verified and its source files extracted,
// with the leading package/ directory removed and executed recorded false.
func TestFetchTarball_VerifiedAndExtractedInMemory(t *testing.T) {
	tgz := buildTGZ(t, []tarEntry{
		{name: "package/package.json", body: `{"name":"demo"}`},
		{name: "package/index.js", body: "module.exports = () => 1;\n"},
		{name: "package/lib/util.mjs", body: "export const x = 1;\n"},
		{name: "package/README.md", body: "# demo"},
	})
	srv := registryServer(t, map[string][]byte{"demo-1.0.0": tgz}, nil)
	defer srv.Close()
	c := newClient(Options{RegistryBaseURL: srv.URL})

	pv, err := c.RegistryVersion(context.Background(), "demo", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if RepoFromRegistryURL(pv.Repository) != "example/demo" {
		t.Errorf("repository = %q", pv.Repository)
	}
	tb, err := c.FetchTarball(context.Background(), pv, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !tb.Artefact.Verified || tb.Artefact.Executed || tb.Artefact.SHA256 == "" {
		t.Errorf("artefact = %+v", tb.Artefact)
	}
	if len(tb.Files) != 2 || tb.Files["index.js"] == nil || tb.Files["lib/util.mjs"] == nil {
		t.Errorf("files = %v", keys(tb.Files))
	}
}

// Failure path: wrong integrity is reported (Verified false), a missing
// version is a not-found error, and a corrupt archive is an error.
func TestFetchTarball_IntegrityMismatchAndMissing(t *testing.T) {
	tgz := buildTGZ(t, []tarEntry{{name: "package/index.js", body: "x"}})
	srv := registryServer(t, map[string][]byte{"demo-1.0.0": tgz, "bad-1.0.0": []byte("not a gzip")},
		map[string]string{"demo-1.0.0": "sha512-AAAA"})
	defer srv.Close()
	c := newClient(Options{RegistryBaseURL: srv.URL})

	pv, _ := c.RegistryVersion(context.Background(), "demo", "1.0.0")
	tb, err := c.FetchTarball(context.Background(), pv, 0)
	if err != nil || tb.Artefact.Verified {
		t.Errorf("expected unverified artefact without error, got %v %+v", err, tb.Artefact)
	}
	if _, err := c.RegistryVersion(context.Background(), "demo", "9.9.9"); !isNotFound(err) {
		t.Errorf("expected not found, got %v", err)
	}
	bad, _ := c.RegistryVersion(context.Background(), "bad", "1.0.0")
	if _, err := c.FetchTarball(context.Background(), bad, 0); err == nil {
		t.Error("corrupt archive must be an error")
	}
}

// Boundary / untrusted input: entries that escape the package root, links,
// oversized entries and a size cap are refused or skipped and recorded;
// a tarball URL on another host is never fetched; bad names are rejected.
func TestFetchTarball_HostileArchive(t *testing.T) {
	tgz := buildTGZ(t, []tarEntry{
		{name: "package/index.js", body: "ok"},
		{name: "package/../../evil.js", body: "evil"},
		{name: "/abs/evil2.js", body: "evil"},
		{name: "package/link.js", typ: tar.TypeSymlink, link: "/etc/passwd"},
		{name: "loose.js", body: "outside package dir"},
		{name: "package/huge.js", body: strings.Repeat("a", maxSourceBytes+1)},
		{name: "package/bin/run.sh", body: "#!/bin/sh\nrm -rf /\n"},
	})
	srv := registryServer(t, map[string][]byte{"demo-1.0.0": tgz}, nil)
	defer srv.Close()
	c := newClient(Options{RegistryBaseURL: srv.URL})
	pv, _ := c.RegistryVersion(context.Background(), "demo", "1.0.0")

	tb, err := c.FetchTarball(context.Background(), pv, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(tb.Files) != 1 || tb.Files["index.js"] == nil {
		t.Errorf("only index.js should survive, got %v", keys(tb.Files))
	}
	joined := strings.Join(tb.Skipped, "\n")
	for _, want := range []string{"escapes package root", "not a regular file", "outside package directory", "exceeds source limit"} {
		if !strings.Contains(joined, want) {
			t.Errorf("skipped list missing %q: %v", want, tb.Skipped)
		}
	}

	// Download cap.
	if _, err := c.FetchTarball(context.Background(), pv, 16); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("expected size cap error, got %v", err)
	}
	// Tarball on a foreign host is refused before any request.
	foreign := *pv
	foreign.Tarball = "https://evil.example/demo/-/demo-1.0.0.tgz"
	if _, err := c.FetchTarball(context.Background(), &foreign, 0); err == nil {
		t.Error("foreign tarball host must be refused")
	}
	// Package names that could steer the request path are rejected.
	for _, name := range []string{"../etc", "a/b/c", "UPPER", "@scope", "", "name with space"} {
		if _, err := c.RegistryVersion(context.Background(), name, "1.0.0"); err == nil || isNotFound(err) {
			t.Errorf("%q: expected validation error, got %v", name, err)
		}
	}
}

func TestParsePURL(t *testing.T) {
	good := map[string][2]string{
		"pkg:npm/lodash@4.17.20":                {"lodash", "4.17.20"},
		"pkg:npm/%40babel/core@7.0.0":           {"@babel/core", "7.0.0"},
		"pkg:npm/@babel/core@7.0.0?foo=bar":     {"@babel/core", "7.0.0"},
		"pkg:npm/decode-uri-component@0.2.0":    {"decode-uri-component", "0.2.0"},
		"pkg:npm/node-fetch@2.6.6#lib/index.js": {"node-fetch", "2.6.6"},
	}
	for purl, want := range good {
		n, v, err := ParsePURL(purl)
		if err != nil || n != want[0] || v != want[1] {
			t.Errorf("%s: got %q %q %v", purl, n, v, err)
		}
	}
	for _, bad := range []string{"pkg:pypi/requests@2.0", "pkg:npm/lodash", "pkg:npm/@4.1", "pkg:npm/../x@1", "lodash@1"} {
		if _, _, err := ParsePURL(bad); err == nil {
			t.Errorf("%s: expected error", bad)
		}
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
