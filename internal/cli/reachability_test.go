package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/reachability"
	"github.com/Xsamsx/SBOMber/internal/vulnerability"
)

func reachabilityFixtureURL(absPath string) string {
	p := filepath.ToSlash(absPath)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return (&url.URL{Scheme: "file", Path: p}).String()
}

// TestReachabilityScoresCalledFunction runs the command end to end against
// the offline govulncheck fixture (see docs/design/reachability.md), with
// the NVD/EPSS/KEV lookup stubbed so no network is needed.
func TestReachabilityScoresCalledFunction(t *testing.T) {
	if !reachability.IsGovulncheckAvailable() {
		t.Skip("govulncheck not installed; install with: go install golang.org/x/vuln/cmd/govulncheck@latest")
	}
	fixtureRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures", "reachability"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOPROXY", reachabilityFixtureURL(filepath.Join(fixtureRoot, "proxy")))
	t.Setenv("GOSUMDB", "off")

	var lookedUp []string
	orig := lookupExploitIntel
	lookupExploitIntel = func(_ context.Context, cves []string, _ func(int, int)) map[string]vulnerability.ExploitIntel {
		lookedUp = cves
		return map[string]vulnerability.ExploitIntel{
			"CVE-9999-00001": {CVE: "CVE-9999-00001", CVSS: 9.8, EPSS: 0.5, InCISAKEV: true},
		}
	}
	defer func() { lookupExploitIntel = orig }()

	run := func(app string) reachabilityReport {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := Main([]string{"reachability", "--json",
			"--db", reachabilityFixtureURL(filepath.Join(fixtureRoot, "vulndb")),
			filepath.Join(fixtureRoot, "app", app)}, nil, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit %d, stderr: %s", code, stderr.String())
		}
		var report reachabilityReport
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
			t.Fatalf("decode JSON: %v\n%s", err, stdout.String())
		}
		return report
	}

	// Called directly: 9.8/10*40 + 0.5*25 + 20 + 15 = 86.7 -> 87% HIGH.
	critical := run("critical")
	if len(lookedUp) != 1 || lookedUp[0] != "CVE-9999-00001" {
		t.Errorf("expected intel lookup for CVE-9999-00001, got %v", lookedUp)
	}
	if len(critical.CalledFunctions) != 1 {
		t.Fatalf("expected 1 called function, got %+v", critical.CalledFunctions)
	}
	if c := critical.CalledFunctions[0]; c.Percent != 87 || c.Band != reachability.BandHigh {
		t.Errorf("got %d%% %s, want 87%% HIGH RISK", c.Percent, c.Band)
	}
	if critical.OverallPercent != 87 || critical.OverallBand != reachability.BandHigh {
		t.Errorf("overall = %d%% %s, want 87%% HIGH RISK", critical.OverallPercent, critical.OverallBand)
	}

	// Imported but never called: nothing scored, so no call path was resolved.
	lookedUp = nil
	low := run("low")
	if len(low.CalledFunctions) != 0 || len(low.Unresolved) != 1 {
		t.Errorf("expected 0 called / 1 not called, got %d / %d", len(low.CalledFunctions), len(low.Unresolved))
	}
	if low.OverallPercent != 0 || low.OverallBand != reachability.BandUndetermined {
		t.Errorf("overall = %d%% %s, want 0 points UNDETERMINED", low.OverallPercent, low.OverallBand)
	}
	if len(lookedUp) != 0 {
		t.Errorf("expected no intel lookups for uncalled code, got %v", lookedUp)
	}
}

func TestReachabilityRejectsExtraArguments(t *testing.T) {
	var out, errs bytes.Buffer
	if code := Main([]string{"reachability", ".", "--json"}, nil, &out, &errs); code != 2 {
		t.Fatalf("exit = %d, stderr = %s", code, errs.String())
	}
}

func TestUnresolvedReachabilityDoesNotClaimSafety(t *testing.T) {
	var out bytes.Buffer
	printReachabilityReport(&out, reachabilityReport{OverallBand: reachability.BandMinimal, Unresolved: []reachability.Finding{{OSV: "GO-TEST"}}})
	text := strings.ToLower(out.String())
	for _, bad := range []string{"secure", "never called"} {
		if strings.Contains(text, bad) {
			t.Fatalf("unsupported claim %q in %s", bad, text)
		}
	}
	if !strings.Contains(text, "risk is undetermined") {
		t.Fatalf("missing unresolved-risk caveat: %s", text)
	}
}

func TestMissingExploitIntelIsReportedAsUnavailable(t *testing.T) {
	var out bytes.Buffer
	printReachabilityReport(&out, reachabilityReport{CalledFunctions: []reachability.CalledFunctionRisk{{Finding: reachability.Finding{OSV: "GO-TEST"}, SeverityAssumed: true}}})
	text := out.String()
	for _, want := range []string{"EPSS not reported", "CISA KEV status unavailable", "CVSS n/a"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in %s", want, text)
		}
	}
	if strings.Contains(text, "not listed in CISA KEV") {
		t.Fatal("failed KEV lookup presented as a negative result")
	}
}
