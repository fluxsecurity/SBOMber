package reachability

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fileURL builds a correctly percent-encoded file:// URL from an absolute
// filesystem path, cross-platform. This matters concretely here: this
// repo's own path contains a space ("Project Uni"), which a naively
// concatenated file:// string would mangle.
func fileURL(absPath string) string {
	p := filepath.ToSlash(absPath)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return (&url.URL{Scheme: "file", Path: p}).String()
}

// fixtureEnv points GOPROXY and govulncheck's -db at the committed,
// offline testdata/fixtures/reachability fixture (see
// docs/design/reachability.md for how it was built and verified) rather
// than the real https://proxy.golang.org / https://vuln.go.dev, so these
// tests are deterministic and need no network access. t.Setenv restores
// GOPROXY/GOSUMDB after the test and disallows t.Parallel() alongside it,
// which is correct here: these tests shell out to a real subprocess and
// must not race on process-wide environment variables.
func fixtureEnv(t *testing.T) (modulePath, dbURL string) {
	t.Helper()
	if !IsGovulncheckAvailable() {
		t.Skip("govulncheck not installed; install with: go install golang.org/x/vuln/cmd/govulncheck@latest")
	}

	fixtureRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures", "reachability"))
	if err != nil {
		t.Fatalf("resolve fixture root: %v", err)
	}
	t.Setenv("GOPROXY", fileURL(filepath.Join(fixtureRoot, "proxy")))
	t.Setenv("GOSUMDB", "off")

	return fixtureRoot, fileURL(filepath.Join(fixtureRoot, "vulndb"))
}

// TestAnalyzeDirectCallIsCritical is the success case: application code
// (main) calls the vulnerable function directly. Verified by hand first —
// see docs/design/reachability.md — before being encoded as this test.
func TestAnalyzeDirectCallIsCritical(t *testing.T) {
	fixtureRoot, dbURL := fixtureEnv(t)
	modulePath := filepath.Join(fixtureRoot, "app", "critical")

	findings, err := analyze(context.Background(), modulePath, dbURL)
	if err != nil {
		t.Fatalf("analyze returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.OSV != "GO-9999-0001" {
		t.Fatalf("expected OSV GO-9999-0001, got %q", f.OSV)
	}
	if f.Tier != TierCritical {
		t.Errorf("expected TierCritical, got %q (%s)", f.Tier, f.Explanation)
	}
	if f.Score != 100 {
		t.Errorf("expected score 100, got %d", f.Score)
	}
	if !f.Reachable {
		t.Error("expected Reachable to be true")
	}
	if len(f.CVEs) != 1 || f.CVEs[0] != "CVE-9999-00001" {
		t.Errorf("expected CVEs [CVE-9999-00001], got %v", f.CVEs)
	}
	if f.Symbol != "example.com/sbomber-reachability/vendorpkg.Vulnerable" {
		t.Errorf("unexpected Symbol %q", f.Symbol)
	}
	if len(f.CallPath) != 2 {
		t.Fatalf("expected a 2-frame call path (main -> Vulnerable), got %+v", f.CallPath)
	}
	if entry := f.CallPath[0]; !entry.InApp || entry.Name() != "sbomber-reachability-app-critical.main" || entry.Location() != "main.go:6" {
		t.Errorf("unexpected entry frame %+v (name %q, location %q)", entry, entry.Name(), entry.Location())
	}
	if vuln := f.CallPath[1]; vuln.InApp || vuln.Name() != "vendorpkg.Vulnerable" {
		t.Errorf("unexpected vulnerable frame %+v", vuln)
	}
}

// TestMainModuleFromMultiPackageRoots: for a module with many packages,
// govulncheck's SBOM roots are the scanned packages, not the module, so
// the root module must come from the unversioned entry in modules.
// Taking roots[0] verbatim made every direct call from a real repo look
// like it came from a dependency.
func TestMainModuleFromMultiPackageRoots(t *testing.T) {
	output := []byte(`{"config":{"scan_level":"symbol"}}
{"SBOM":{"modules":[{"path":"github.com/acme/app"},{"path":"github.com/acme/app/tools"},{"path":"golang.org/x/net","version":"v0.1.0"},{"path":"stdlib","version":"v1.26.2"}],
"roots":["github.com/acme/app/internal/deps","github.com/acme/app/cmd/app"]}}
{"osv":{"id":"GO-1","aliases":["CVE-1","GHSA-x"]}}
{"finding":{"osv":"GO-1","trace":[{"module":"stdlib","package":"net/http","function":"Get","position":{"filename":"src/net/http/client.go","line":484}},{"module":"github.com/acme/app","package":"github.com/acme/app/internal/deps","function":"Fetch","receiver":"*Resolver","position":{"filename":"internal/deps/fetch.go","line":12}}]}}
`)
	rootModule, symbolLevel, osvs, byOSV, err := parseGovulncheckOutput(output)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rootModule != "github.com/acme/app" {
		t.Fatalf("rootModule = %q, want github.com/acme/app", rootModule)
	}

	f := classify("GO-1", osvs["GO-1"], byOSV["GO-1"], rootModule, symbolLevel)
	if f.Tier != TierCritical {
		t.Errorf("expected TierCritical for a direct call from app code, got %q", f.Tier)
	}
	if len(f.CVEs) != 1 || f.CVEs[0] != "CVE-1" {
		t.Errorf("expected only the CVE alias, got %v", f.CVEs)
	}
	if f.Symbol != "net/http.Get" {
		t.Errorf("Symbol = %q, want net/http.Get", f.Symbol)
	}
	if got := f.CallPath[0]; got.Name() != "deps.Resolver.Fetch" || got.Location() != "internal/deps/fetch.go:12" || !got.InApp {
		t.Errorf("unexpected caller frame %+v", got)
	}
}

// TestAnalyzeTransitiveCallIsHigh: main calls a dependency function
// (Wrapper) which itself calls the vulnerable function — the direct
// caller of the vulnerable symbol is dependency code, not app code.
func TestAnalyzeTransitiveCallIsHigh(t *testing.T) {
	fixtureRoot, dbURL := fixtureEnv(t)
	modulePath := filepath.Join(fixtureRoot, "app", "high")

	findings, err := analyze(context.Background(), modulePath, dbURL)
	if err != nil {
		t.Fatalf("analyze returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.Tier != TierHigh {
		t.Errorf("expected TierHigh, got %q (%s)", f.Tier, f.Explanation)
	}
	if f.Score != 85 {
		t.Errorf("expected score 85, got %d", f.Score)
	}
	if !f.Reachable {
		t.Error("expected Reachable to be true")
	}
	if !strings.Contains(f.DirectCaller, "vendorpkg") {
		t.Errorf("expected DirectCaller to be the vendorpkg dependency, got %q", f.DirectCaller)
	}
}

// TestAnalyzeImportedButUncalledIsLow is the boundary case: the vulnerable
// package is imported and required, but the app never calls the vulnerable
// symbol (it calls an unrelated Safe function instead) — present, but
// unreachable as far as static analysis can tell.
func TestAnalyzeImportedButUncalledIsLow(t *testing.T) {
	fixtureRoot, dbURL := fixtureEnv(t)
	modulePath := filepath.Join(fixtureRoot, "app", "low")

	findings, err := analyze(context.Background(), modulePath, dbURL)
	if err != nil {
		t.Fatalf("analyze returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.Tier != TierLow {
		t.Errorf("expected TierLow, got %q (%s)", f.Tier, f.Explanation)
	}
	if f.Reachable {
		t.Error("expected Reachable to be false")
	}
}

// TestGovulncheckFoundInGoBinWhenNotOnPath: `go install` puts govulncheck
// in $GOBIN or $GOPATH/bin, which is often not on PATH.
func TestGovulncheckFoundInGoBinWhenNotOnPath(t *testing.T) {
	gobin := t.TempDir()
	name := "govulncheck"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(gobin, name), []byte{}, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	t.Setenv("GOBIN", gobin)

	if got := govulncheckPath(); got != filepath.Join(gobin, name) {
		t.Errorf("govulncheckPath() = %q, want the copy in GOBIN", got)
	}
}

// TestAnalyzeMissingGovulncheckIsError is the failure/unknown-path case:
// govulncheck not being installed must return a clear error, matching how
// internal/vulnerability.ScanWithGrype fails when Grype is missing.
func TestAnalyzeMissingGovulncheckIsError(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	// Also hide the Go bin directory fallback.
	t.Setenv("GOBIN", "")
	t.Setenv("GOPATH", t.TempDir())

	_, err := Analyze(context.Background(), ".")
	if err == nil {
		t.Fatal("expected an error when govulncheck is not installed, got nil")
	}
	if !strings.Contains(err.Error(), "govulncheck not found") {
		t.Errorf("expected a clear 'not found' error, got: %v", err)
	}
}

// A tool that emitted a valid header before failing must not become an empty successful scan.
func TestAnalyzeRejectsToolFailureAfterHeader(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell stub")
	}
	dir := t.TempDir()
	stub := `#!/bin/sh
 echo '{"config":{"scan_level":"symbol"}}'
 echo '{"SBOM":{"roots":["example.com/app"]}}'
 echo 'load failed' >&2
 exit 1
`
	if err := os.WriteFile(filepath.Join(dir, "govulncheck"), []byte(stub), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if _, err := Analyze(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "load failed") {
		t.Fatalf("expected tool error, got %v", err)
	}
}

func TestMissingScanLevelDoesNotConfirmReachability(t *testing.T) {
	output := []byte(`{"SBOM":{"roots":["example.com/app"]}}
 {"finding":{"osv":"GO-TEST","trace":[{"module":"dep","package":"dep","function":"Vulnerable"},{"module":"example.com/app","package":"example.com/app","function":"main"}]}}`)
	root, symbol, summaries, findings, err := parseGovulncheckOutput(output)
	if err != nil {
		t.Fatal(err)
	}
	got := classify("GO-TEST", summaries["GO-TEST"], findings["GO-TEST"], root, symbol)
	if got.Reachable || got.Tier != TierMedium {
		t.Fatalf("unconfirmed scan level produced reachable result: %+v", got)
	}
}
