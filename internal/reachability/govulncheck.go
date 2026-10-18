// Package reachability determines whether a known vulnerability in a Go
// module is actually reachable from application code, not just imported.
//
// It does this by shelling out to govulncheck (golang.org/x/vuln/cmd/govulncheck,
// the Go team's own static reachability analyzer), the same way
// internal/vulnerability shells out to Grype — govulncheck's -json output is
// its documented, stable integration contract; the package internals it's
// built from (SSA construction, call-graph analysis) are not part of Go's
// public API surface, so wrapping the CLI is the sanctioned approach rather
// than a shortcut. See docs/design/reachability.md for how the confidence
// tiers below were derived and verified against real govulncheck output.
package reachability

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Tier is a confidence classification for whether a vulnerability is
// actually reachable, matching the four-tier model in
// docs/design/reachability.md.
type Tier string

const (
	// TierCritical: application code directly calls the vulnerable
	// function. govulncheck found a call trace whose first frame after
	// the vulnerable function itself belongs to the module being scanned.
	TierCritical Tier = "CRITICAL"
	// TierHigh: the vulnerable function is reachable, but only through a
	// dependency that calls it on the application's behalf — the direct
	// caller is not in the module being scanned.
	TierHigh Tier = "HIGH"
	// TierMedium: govulncheck could not perform full symbol-level
	// call-graph analysis for this module (it fell back to a coarser
	// scan level), so reachability could not be confirmed either way.
	TierMedium Tier = "MEDIUM"
	// TierLow: the vulnerable package is imported/required, but no call
	// path to the vulnerable symbol was found — present, but (as far as
	// static analysis can tell) never invoked.
	TierLow Tier = "LOW"
)

// Finding is a per-vulnerability reachability verdict.
type Finding struct {
	OSV          string `json:"osv"`
	Summary      string `json:"summary"`
	FixedVersion string `json:"fixedVersion,omitempty"`
	Tier         Tier   `json:"tier"`
	Score        int    `json:"score"`
	Reachable    bool   `json:"reachable"`
	// DirectCaller is the package that directly calls the vulnerable
	// symbol, when a function-level trace was found.
	DirectCaller string `json:"directCaller,omitempty"`
	Explanation  string `json:"explanation"`
	// CVEs are the CVE aliases of the OSV entry, used to look up CVSS,
	// EPSS and CISA KEV data, which are all keyed by CVE.
	CVEs []string `json:"cves,omitempty"`
	// Symbol is the vulnerable function that is called, e.g.
	// "net/http.Client.Do", when a function-level trace was found.
	Symbol string `json:"symbol,omitempty"`
	// CallPath is the call chain govulncheck found, ordered from the
	// application's entry point down to the vulnerable function.
	CallPath []CallFrame `json:"callPath,omitempty"`
}

// CallFrame is one function in a call path.
type CallFrame struct {
	Module   string `json:"module"`
	Package  string `json:"package"`
	Function string `json:"function"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	// InApp is true when the function belongs to the module being scanned.
	InApp bool `json:"inApp"`
}

// Name renders the frame as package.Receiver.Function, using the last
// element of the package path, the way govulncheck's text output does.
func (f CallFrame) Name() string {
	pkg := f.Package
	if i := strings.LastIndex(pkg, "/"); i >= 0 {
		pkg = pkg[i+1:]
	}
	return pkg + "." + f.Function
}

// Location renders the frame's source position as file:line, or "" when
// govulncheck did not report one.
func (f CallFrame) Location() string {
	if f.File == "" {
		return ""
	}
	if f.Line == 0 {
		return f.File
	}
	return fmt.Sprintf("%s:%d", f.File, f.Line)
}

// IsGovulncheckAvailable reports whether govulncheck is installed, either on
// PATH or in the Go bin directory that `go install` puts it in.
func IsGovulncheckAvailable() bool {
	return govulncheckPath() != ""
}

// govulncheckPath finds the govulncheck binary. `go install` writes to
// $GOBIN, or $GOPATH/bin (default ~/go/bin), which is often not on PATH —
// especially on Windows — so those are checked as a fallback.
func govulncheckPath() string {
	if p, err := exec.LookPath("govulncheck"); err == nil {
		return p
	}
	name := "govulncheck"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	var dirs []string
	if gobin := os.Getenv("GOBIN"); gobin != "" {
		dirs = append(dirs, gobin)
	}
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		for _, p := range filepath.SplitList(gopath) {
			dirs = append(dirs, filepath.Join(p, "bin"))
		}
	} else if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "go", "bin"))
	}
	for _, d := range dirs {
		p := filepath.Join(d, name)
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

// Analyze runs govulncheck against the Go module rooted at modulePath and
// returns a reachability Finding for every vulnerability it reports,
// classified into the four confidence tiers. It uses govulncheck's default
// vulnerability database (https://vuln.go.dev) and whatever GOPROXY the
// caller's environment already has configured.
func Analyze(ctx context.Context, modulePath string) ([]Finding, error) {
	return analyze(ctx, modulePath, "")
}

// AnalyzeWithDB is Analyze against a specific vulnerability database URL
// (passed to govulncheck -db), e.g. an offline mirror. "" means
// govulncheck's default.
func AnalyzeWithDB(ctx context.Context, modulePath, dbURL string) ([]Finding, error) {
	return analyze(ctx, modulePath, dbURL)
}

// analyze is Analyze's implementation, with an optional dbURL override
// ("" for govulncheck's default), which tests use to point it at a local,
// offline test vulnerability database (see docs/design/reachability.md).
func analyze(ctx context.Context, modulePath, dbURL string) ([]Finding, error) {
	bin := govulncheckPath()
	if bin == "" {
		return nil, fmt.Errorf("govulncheck not found in PATH or the Go bin directory - install: go install golang.org/x/vuln/cmd/govulncheck@latest")
	}

	args := []string{"-json"}
	if dbURL != "" {
		args = append(args, "-db", dbURL)
	}
	args = append(args, "./...")

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = modulePath
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("run govulncheck: %w", ctx.Err())
	}
	if runErr != nil {
		exit, ok := runErr.(*exec.ExitError)
		if !ok || exit.ExitCode() != 3 {
			return nil, fmt.Errorf("run govulncheck: %w: %s", runErr, strings.TrimSpace(stderr.String()))
		}
	}

	rootModule, symbolLevel, osvSummaries, findingsByOSV, err := parseGovulncheckOutput(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("parse govulncheck output: %w", err)
	}

	if runErr != nil && len(findingsByOSV) == 0 {
		return nil, fmt.Errorf("govulncheck exited with findings status but emitted no findings")
	}
	results := make([]Finding, 0, len(findingsByOSV))
	for osvID, findings := range findingsByOSV {
		results = append(results, classify(osvID, osvSummaries[osvID], findings, rootModule, symbolLevel))
	}
	return results, nil
}

func classify(osvID string, summary govulncheckOSV, findings []govulncheckFinding, rootModule string, symbolLevel bool) Finding {
	base := Finding{
		OSV:     osvID,
		Summary: summary.Summary,
	}
	for _, alias := range summary.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			base.CVEs = append(base.CVEs, alias)
		}
	}
	if len(findings) > 0 {
		base.FixedVersion = findings[0].FixedVersion
	}

	if !symbolLevel {
		base.Tier = TierMedium
		base.Score = 50
		base.Explanation = "govulncheck could not perform full symbol-level call-graph analysis for this module (it fell back to a coarser scan level), so reachability could not be confirmed either way"
		return base
	}

	// Pick the function-level trace to report for this OSV, if any. A
	// trace with a function name on its first frame is one where
	// govulncheck actually resolved a call path, not just "this package
	// is present." A trace where application code is the direct caller
	// wins, since that is the most severe verdict; otherwise the most
	// complete (deepest) trace.
	var best *govulncheckFinding
	bestDirect := false
	for i := range findings {
		f := &findings[i]
		if len(f.Trace) == 0 || f.Trace[0].Function == "" {
			continue
		}
		direct := len(f.Trace) > 1 && f.Trace[1].Module == rootModule
		if best == nil || (direct && !bestDirect) || (direct == bestDirect && len(f.Trace) > len(best.Trace)) {
			best = f
			bestDirect = direct
		}
	}

	if best == nil {
		base.Tier = TierLow
		base.Score = 5
		base.Reachable = false
		base.Explanation = "imported/required, but no call path to the vulnerable symbol was found"
		return base
	}

	base.Reachable = true
	base.FixedVersion = best.FixedVersion
	// govulncheck orders a trace from the vulnerable function up to the
	// application entry point; CallPath reads top-down instead.
	for i := len(best.Trace) - 1; i >= 0; i-- {
		base.CallPath = append(base.CallPath, best.Trace[i].callFrame(rootModule))
	}
	vulnFrame := best.Trace[0]
	base.Symbol = vulnFrame.Package + "." + vulnFrame.symbolName()
	// trace[0] is the vulnerable function itself; trace[1], if present,
	// is its direct caller.
	if len(best.Trace) > 1 {
		base.DirectCaller = best.Trace[1].Package
		if best.Trace[1].Module == rootModule {
			base.Tier = TierCritical
			base.Score = 100
			base.Explanation = "application code directly calls the vulnerable function"
			return base
		}
	}

	base.Tier = TierHigh
	base.Score = 85
	base.Explanation = "the vulnerable function is reachable, but is called by a dependency on the application's behalf, not directly by application code"
	return base
}

// govulncheck -json emits a stream of top-level JSON objects (not a single
// array): {"config":...}, {"SBOM":...}, {"progress":...}, {"osv":...}, and
// {"finding":...}, in that rough order. See docs/design/reachability.md for
// how this shape was determined by direct inspection of real output.
type govulncheckEnvelope struct {
	Config  *govulncheckConfig  `json:"config"`
	SBOM    *govulncheckSBOM    `json:"SBOM"`
	OSV     *govulncheckOSV     `json:"osv"`
	Finding *govulncheckFinding `json:"finding"`
}

type govulncheckConfig struct {
	ScanLevel string `json:"scan_level"`
}

type govulncheckSBOM struct {
	Modules []struct {
		Path    string `json:"path"`
		Version string `json:"version"`
	} `json:"modules"`
	// Roots are the root *packages* scanned (e.g. every package matched
	// by ./...), not the module — they only equal the module path for a
	// single-package module.
	Roots []string `json:"roots"`
}

// mainModule returns the path of the module being scanned: the
// unversioned module that contains the first root package. Dependencies
// and stdlib always carry a version; the main module never does.
func (s govulncheckSBOM) mainModule() string {
	if len(s.Roots) == 0 {
		return ""
	}
	root := s.Roots[0]
	best := ""
	for _, m := range s.Modules {
		if m.Version != "" {
			continue
		}
		if (root == m.Path || strings.HasPrefix(root, m.Path+"/")) && len(m.Path) > len(best) {
			best = m.Path
		}
	}
	if best == "" {
		return root
	}
	return best
}

type govulncheckOSV struct {
	ID      string   `json:"id"`
	Summary string   `json:"summary"`
	Aliases []string `json:"aliases"`
}

type govulncheckFinding struct {
	OSV          string                  `json:"osv"`
	FixedVersion string                  `json:"fixed_version"`
	Trace        []govulncheckTraceFrame `json:"trace"`
}

type govulncheckTraceFrame struct {
	Module   string `json:"module"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Receiver string `json:"receiver"`
	Version  string `json:"version"`
	Position *struct {
		Filename string `json:"filename"`
		Line     int    `json:"line"`
	} `json:"position"`
}

// symbolName is the frame's function qualified by its receiver type, if
// it is a method: "Client.Do" for (*Client).Do, "Vulnerable" otherwise.
func (f govulncheckTraceFrame) symbolName() string {
	if f.Receiver == "" {
		return f.Function
	}
	return strings.TrimPrefix(f.Receiver, "*") + "." + f.Function
}

func (f govulncheckTraceFrame) callFrame(rootModule string) CallFrame {
	cf := CallFrame{
		Module:   f.Module,
		Package:  f.Package,
		Function: f.symbolName(),
		InApp:    f.Module == rootModule,
	}
	if f.Position != nil {
		cf.File = filepath.ToSlash(f.Position.Filename)
		cf.Line = f.Position.Line
	}
	return cf
}

func parseGovulncheckOutput(output []byte) (rootModule string, symbolLevel bool, osvSummaries map[string]govulncheckOSV, findingsByOSV map[string][]govulncheckFinding, err error) {
	symbolLevel = false
	osvSummaries = make(map[string]govulncheckOSV)
	findingsByOSV = make(map[string][]govulncheckFinding)

	dec := json.NewDecoder(bytes.NewReader(output))
	for dec.More() {
		var env govulncheckEnvelope
		if decErr := dec.Decode(&env); decErr != nil {
			return "", false, nil, nil, fmt.Errorf("decode govulncheck JSON stream: %w", decErr)
		}
		switch {
		case env.Config != nil:
			symbolLevel = env.Config.ScanLevel == "symbol"
		case env.SBOM != nil && len(env.SBOM.Roots) > 0:
			rootModule = env.SBOM.mainModule()
		case env.OSV != nil:
			osvSummaries[env.OSV.ID] = *env.OSV
		case env.Finding != nil:
			findingsByOSV[env.Finding.OSV] = append(findingsByOSV[env.Finding.OSV], *env.Finding)
		}
	}

	if rootModule == "" {
		return "", false, nil, nil, fmt.Errorf("govulncheck output did not include an SBOM root module")
	}
	return rootModule, symbolLevel, osvSummaries, findingsByOSV, nil
}
