package inventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Xsamsx/SBOMber/internal/deps"
	"github.com/Xsamsx/SBOMber/internal/netstatus"
	"github.com/Xsamsx/SBOMber/internal/vulnerability"
)

var fixedStart = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)

// checkInvariants is contracts/validate.py's validate_canonical, so a
// document these tests accept is one CI's validator accepts too.
func checkInvariants(t *testing.T, doc Document) {
	t.Helper()
	purls := map[string]bool{}
	for _, c := range doc.Components {
		purls[c.Purl] = true
		if strings.ContainsAny(c.Version, "^~*><= ") {
			t.Errorf("R0: %s version %q looks like a range", c.Purl, c.Version)
		}
		if c.DeclaredConstraint != "" && c.DeclaredConstraint == c.Version {
			t.Errorf("R0: %s stores its constraint as the version", c.Purl)
		}
	}
	occurrenceIDs := map[string]bool{}
	identity := map[string]string{}
	relationships := map[string]map[string]bool{}
	for _, o := range doc.Occurrences {
		if occurrenceIDs[o.OccurrenceID] {
			t.Errorf("duplicate occurrenceId %s", o.OccurrenceID)
		}
		occurrenceIDs[o.OccurrenceID] = true
		if !purls[o.Purl] {
			t.Errorf("%s references unknown component %s", o.OccurrenceID, o.Purl)
		}
		for _, step := range o.DependencyPath {
			if !purls[step] {
				t.Errorf("%s dependencyPath has %s, absent from components", o.OccurrenceID, step)
			}
		}
		key := o.Purl + "|" + o.Workspace + "|" + o.InstallPath
		if prior, ok := identity[key]; ok {
			t.Errorf("%s shares identity with %s", o.OccurrenceID, prior)
		}
		identity[key] = o.OccurrenceID
		path := o.Purl + "|" + o.InstallPath
		if relationships[path] == nil {
			relationships[path] = map[string]bool{}
		}
		relationships[path][o.Relationship] = true
	}
	for path, rels := range relationships {
		if len(rels) != 1 {
			t.Errorf("%s is both direct and transitive", path)
		}
	}
	for _, f := range doc.Findings {
		if !purls[f.Purl] {
			t.Errorf("%s references unknown component %s", f.FindingID, f.Purl)
		}
		for _, id := range f.OccurrenceIDs {
			if !occurrenceIDs[id] {
				t.Errorf("%s references unknown occurrence %s", f.FindingID, id)
			}
		}
	}
	if doc.Scan.Status == StatusComplete && doc.Scan.StatusDetail != nil && !doc.Scan.StatusDetail.empty() {
		t.Errorf("status is complete but statusDetail lists problems: %+v", doc.Scan.StatusDetail)
	}
	for _, e := range doc.Scan.Enrichment {
		if e.Status != "success" && e.Detail == "" {
			t.Errorf("enrichment %s is %s with no detail", e.Source, e.Status)
		}
	}
}

// valid runs every check a produced document must pass.
func valid(t *testing.T, doc Document) {
	t.Helper()
	checkSchema(t, canonicalSchema, doc)
	checkInvariants(t, doc)
}

func copyFixture(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "demo-app")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join("testdata", name, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func allSuccess() []netstatus.Report {
	return []netstatus.Report{
		{Source: "ghsa", Status: netstatus.Success},
		{Source: "kev", Status: netstatus.Success},
		{Source: "epss", Status: netstatus.Success},
		{Source: "npm_registry", Status: netstatus.Success},
		{Source: "malware", Status: netstatus.Skipped, Detail: "malware scanning is not yet implemented"},
	}
}

func occurrenceAt(t *testing.T, doc Document, installPath string) Occurrence {
	t.Helper()
	for _, o := range doc.Occurrences {
		if o.InstallPath == installPath {
			return o
		}
	}
	t.Fatalf("no occurrence at %s", installPath)
	return Occurrence{}
}

// Success: a lockfile with a nested second version, a dev-only chain and a
// scoped package becomes the identities the contract describes, and a Grype
// finding with its own PURL spelling joins to them.
func TestBuildFromLockfile(t *testing.T) {
	repo := copyFixture(t, "npm-nested")
	results := &vulnerability.ScanResults{
		ScannerVersion: "0.120.1",
		NetworkStatus:  allSuccess(),
		Vulnerabilities: []vulnerability.VulnerabilityResult{
			{
				Vulnerability: "GHSA-35jh-r3h4-6jhm", CVEID: "CVE-2021-23337", PURL: "pkg:npm/lodash@4.17.20",
				Severity: "high", CVSSScore: 7.2, PatchedVersions: "4.17.21", EPSSScore: 0.0142, EPSSPercentile: 0.842,
				GHSAAdvisoryID: "GHSA-35jh-r3h4-6jhm",
			},
			// Same vulnerability, same package, reported twice: one finding.
			{Vulnerability: "GHSA-35jh-r3h4-6jhm", PURL: "pkg:npm/lodash@4.17.20", Severity: "high"},
			// Grype's spelling: encoded scope and a qualifier.
			{Vulnerability: "GHSA-aaaa-bbbb-cccc", PURL: "pkg:npm/%40scope/util@1.0.0?arch=any", Severity: "Critical", InCISAKEV: true},
		},
	}
	doc := Build([]RepositoryInput{{Name: "demo-app", Path: repo, Vulnerabilities: results}}, Options{
		OutputDir: filepath.Dir(repo), StartedAt: fixedStart, VulnerabilitiesRequested: true,
	})
	valid(t, doc)

	if doc.Scan.Status != StatusComplete {
		t.Errorf("status = %s, want complete; detail %+v", doc.Scan.Status, doc.Scan.StatusDetail)
	}
	if got := doc.Scan.Repositories[0].Path; got != "demo-app" {
		t.Errorf("repository path = %q, want it relative to the output directory", got)
	}

	hoisted := occurrenceAt(t, doc, "node_modules/lodash")
	if hoisted.Purl != "pkg:npm/lodash@4.17.20" || hoisted.Relationship != "direct" || hoisted.Manifest != "package.json" {
		t.Errorf("hoisted lodash = %+v", hoisted)
	}
	nested := occurrenceAt(t, doc, "node_modules/legacy-reporter/node_modules/lodash")
	if nested.Purl != "pkg:npm/lodash@3.10.1" || nested.Relationship != "transitive" ||
		len(nested.DependencyPath) != 1 || nested.DependencyPath[0] != "pkg:npm/legacy-reporter@2.1.0" {
		t.Errorf("nested lodash = %+v", nested)
	}
	leftPad := occurrenceAt(t, doc, "node_modules/left-pad")
	if leftPad.Scope != "development" || leftPad.DependencyPath[0] != "pkg:npm/build-helper@4.0.2" {
		t.Errorf("left-pad = %+v", leftPad)
	}
	if orphan := occurrenceAt(t, doc, "node_modules/orphan"); orphan.Relationship != "transitive" || len(orphan.DependencyPath) != 0 {
		t.Errorf("an installed package nothing requires is still listed, as transitive with no path: %+v", orphan)
	}
	if scoped := occurrenceAt(t, doc, "node_modules/@scope/util"); scoped.Purl != "pkg:npm/%40scope/util@1.0.0" {
		t.Errorf("scoped purl = %s", scoped.Purl)
	}

	var lodash *Component
	for i := range doc.Components {
		if doc.Components[i].Purl == "pkg:npm/lodash@4.17.20" {
			lodash = &doc.Components[i]
		}
	}
	if lodash == nil || lodash.DeclaredConstraint != "^4.17.0" {
		t.Errorf("lodash component = %+v, want declaredConstraint ^4.17.0", lodash)
	}

	if len(doc.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 (one duplicate merged)", len(doc.Findings))
	}
	for _, f := range doc.Findings {
		switch f.VulnerabilityID {
		case "GHSA-35jh-r3h4-6jhm":
			if len(f.OccurrenceIDs) != 1 || f.OccurrenceIDs[0] != hoisted.OccurrenceID {
				t.Errorf("lodash finding occurrences = %v, want only the 4.17.20 one", f.OccurrenceIDs)
			}
			if f.FixedVersion != "4.17.21" || f.EPSS == nil || *f.CVSSScore != 7.2 || len(f.Aliases) != 1 || f.Aliases[0] != "CVE-2021-23337" {
				t.Errorf("lodash finding = %+v", f)
			}
			if f.CISAKev == nil || *f.CISAKev {
				t.Errorf("KEV lookup succeeded, so cisaKev should be stated false")
			}
		case "GHSA-aaaa-bbbb-cccc":
			if f.Purl != "pkg:npm/%40scope/util@1.0.0" || f.Severity != "critical" || f.CISAKev == nil || !*f.CISAKev {
				t.Errorf("scoped finding = %+v", f)
			}
		}
	}
}

// Unknown path: no lockfile, a failed source and a failed vulnerability
// scan all make the scan partial and say why. Nothing is reported as clean.
func TestBuildReportsWhatItCouldNotDo(t *testing.T) {
	repo := copyFixture(t, "npm-nested")
	if err := os.Remove(filepath.Join(repo, "package-lock.json")); err != nil {
		t.Fatal(err)
	}
	doc := Build([]RepositoryInput{{Name: "demo-app", Path: repo, Vulnerabilities: &vulnerability.ScanResults{
		NetworkStatus: []netstatus.Report{
			{Source: "kev", Status: netstatus.Unavailable, Detail: "HTTP 503"},
			{Source: "epss", Status: netstatus.Partial, Detail: "1 of 2 EPSS batches failed"},
			{Source: "ghsa", Status: netstatus.Success},
			{Source: "ghsa_packages", Status: netstatus.RateLimited},
		},
		Vulnerabilities: []vulnerability.VulnerabilityResult{
			{Vulnerability: "GHSA-35jh-r3h4-6jhm", PURL: "pkg:npm/lodash@4.17.20", Severity: "high", InstalledVersion: "4.17.20", PackageName: "lodash"},
			// What Grype reports when the SBOM carries the declared range.
			{Vulnerability: "GHSA-p6mc-m468-83gw", PURL: "pkg:npm/lodash@%5E4.17.0", Severity: "high", InstalledVersion: "^4.17.0", PackageName: "lodash"},
		},
	}}}, Options{OutputDir: filepath.Dir(repo), StartedAt: fixedStart, VulnerabilitiesRequested: true})
	valid(t, doc)

	var ranged *Finding
	for i := range doc.Findings {
		if doc.Findings[i].VulnerabilityID == "GHSA-p6mc-m468-83gw" {
			ranged = &doc.Findings[i]
		}
	}
	if ranged == nil || ranged.Purl != "pkg:npm/lodash" || len(ranged.OccurrenceIDs) != 1 {
		t.Errorf("a finding against a declared range belongs to the version-unknown component and its occurrence: %+v", ranged)
	}
	doc.Findings = removeFinding(doc.Findings, "GHSA-p6mc-m468-83gw")

	if doc.Scan.Status != StatusPartial || len(doc.Scan.StatusDetail.LimitsHit) != 1 ||
		!strings.Contains(doc.Scan.StatusDetail.LimitsHit[0], "no package-lock.json") {
		t.Errorf("status = %s, detail %+v", doc.Scan.Status, doc.Scan.StatusDetail)
	}
	// Without a lockfile a range is not a version: lodash is declared ^4.17.0.
	for _, c := range doc.Components {
		if c.Name == "lodash" && c.Version == "" && (c.VersionKnown == nil || *c.VersionKnown) {
			t.Errorf("lodash from a range should have versionKnown false: %+v", c)
		}
		if c.Name == "@scope/util" && c.Version != "1.0.0" {
			t.Errorf("an exact pin in package.json is a known version: %+v", c)
		}
	}
	byName := map[string]Enrichment{}
	for _, e := range doc.Scan.Enrichment {
		byName[e.Source] = e
	}
	if e := byName["cisa_kev"]; e.Status != "unavailable" || e.Detail != "HTTP 503" {
		t.Errorf("kev = %+v", e)
	}
	if e := byName["epss"]; e.Status != "unavailable" || !strings.HasPrefix(e.Detail, "partial:") {
		t.Errorf("a partial EPSS lookup must not read as success: %+v", e)
	}
	if e := byName["ghsa"]; e.Status != "rate_limited" {
		t.Errorf("ghsa keeps its worst report: %+v", e)
	}
	// Grype's lodash@4.17.20 is not in the inventory (which only knows the
	// range), so it is added as a component of its own.
	if len(doc.Findings) != 1 {
		t.Fatalf("findings = %+v", doc.Findings)
	}
	f := doc.Findings[0]
	if f.CISAKev != nil {
		t.Errorf("KEV was unavailable, so cisaKev must be omitted, got %v", *f.CISAKev)
	}
	if f.EPSS != nil {
		t.Errorf("EPSS was partial, so no score is stated: %+v", f.EPSS)
	}

	failed := Build([]RepositoryInput{{Name: "demo-app", Path: repo, ScanError: errors.New("grype exited 1")}},
		Options{StartedAt: fixedStart, VulnerabilitiesRequested: true})
	valid(t, failed)
	if failed.Scan.Status != StatusPartial || !strings.Contains(strings.Join(failed.Scan.StatusDetail.LimitsHit, "\n"), "vulnerability scan failed") {
		t.Errorf("a failed vulnerability scan must make the scan partial: %+v", failed.Scan)
	}

	notRequested := Build([]RepositoryInput{{Name: "demo-app", Path: repo}}, Options{StartedAt: fixedStart})
	valid(t, notRequested)
	for _, e := range notRequested.Scan.Enrichment {
		if e.Status != "skipped" {
			t.Errorf("without vulnerability scanning every source is skipped: %+v", e)
		}
	}
}

// Untrusted input: a malformed or oversized lockfile is a failure, never a
// partial parse; a HEAD pointing outside refs/ is ignored; packages from an
// ecosystem the contract cannot represent are counted, not dropped.
func TestBuildRejectsBadInput(t *testing.T) {
	repo := copyFixture(t, "npm-nested")
	if err := os.WriteFile(filepath.Join(repo, "package-lock.json"), []byte(`{"packages": {`), 0o644); err != nil {
		t.Fatal(err)
	}
	doc := Build([]RepositoryInput{{Name: "demo-app", Path: repo, Summary: deps.Summary{Direct: []deps.Dependency{
		{Name: "serde", Version: "1.0.0", Ecosystem: "cargo", SourceFile: "Cargo.lock"},
		{Name: "Flask_Login", Version: "0.6.3", Ecosystem: "pypi", SourceFile: "requirements.txt"},
	}}}}, Options{StartedAt: fixedStart})
	valid(t, doc)
	if doc.Scan.Status != StatusPartial || len(doc.Scan.StatusDetail.FailedFiles) != 1 {
		t.Errorf("malformed lockfile: status %s, detail %+v", doc.Scan.Status, doc.Scan.StatusDetail)
	}
	if !strings.Contains(strings.Join(doc.Scan.StatusDetail.LimitsHit, "\n"), `no "cargo" ecosystem`) {
		t.Errorf("cargo packages must be counted as not listed: %+v", doc.Scan.StatusDetail.LimitsHit)
	}
	if len(doc.Components) != 1 || doc.Components[0].Purl != "pkg:pypi/flask-login@0.6.3" {
		t.Errorf("components = %+v, want the normalised PyPI package only", doc.Components)
	}

	big := filepath.Join(t.TempDir(), "package.json")
	if err := os.WriteFile(big, bytes.Repeat([]byte(" "), maxManifestBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readNPM(filepath.Dir(big)); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized package.json: err = %v", err)
	}

	gitDir := filepath.Join(repo, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0o755); err != nil {
		t.Fatal(err)
	}
	commit := strings.Repeat("a", 40)
	_ = os.WriteFile(filepath.Join(gitDir, "refs", "heads", "main"), []byte(commit+"\n"), 0o644)
	_ = os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644)
	if got := headCommit(repo); got != commit {
		t.Errorf("headCommit = %q, want %q", got, commit)
	}
	_ = os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/../../../outside\n"), 0o644)
	if got := headCommit(repo); got != "" {
		t.Errorf("a ref outside refs/ must be ignored, got %q", got)
	}
	_ = os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte(commit+"\n"), 0o644)
	if got := headCommit(repo); got != commit {
		t.Errorf("detached HEAD = %q", got)
	}
}

// Two builds over the same inputs and the same SOURCE_DATE_EPOCH are
// byte-identical, and IDs come from content, not from position.
func TestBuildIsReproducible(t *testing.T) {
	repo := copyFixture(t, "npm-nested")
	build := func() []byte {
		doc := Build([]RepositoryInput{{Name: "demo-app", Path: repo}}, Options{
			OutputDir: filepath.Dir(repo), StartedAt: fixedStart, CompletedAt: fixedStart,
			ToolVersions: map[string]string{"sbomber": "test", "go": "go1.26.9"},
		})
		out := filepath.Join(t.TempDir(), "canonical-scan.json")
		if err := Write(out, doc); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	first, second := build(), build()
	if !bytes.Equal(first, second) {
		t.Fatal("two builds over the same inputs differ")
	}
	var doc Document
	decoder := json.NewDecoder(bytes.NewReader(first))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		t.Fatalf("written document does not decode: %v", err)
	}
	if !strings.HasPrefix(doc.Scan.ScanID, "scan-20261020T090000Z-") {
		t.Errorf("scanId = %s", doc.Scan.ScanID)
	}
	for _, o := range doc.Occurrences {
		if o.OccurrenceID != "occ-"+shortHash(o.RepositoryID, o.Workspace, o.Manifest, o.InstallPath, o.Purl) {
			t.Errorf("occurrence id %s is not derived from its identity", o.OccurrenceID)
		}
	}
}

func TestPurlKeyMatchesScannerSpellings(t *testing.T) {
	same := [][2]string{
		{"pkg:npm/%40scope/util@1.0.0", "pkg:npm/@scope/util@1.0.0"},
		{"pkg:npm/lodash@4.17.20", "pkg:npm/lodash@4.17.20?arch=any#sub"},
		{"pkg:pypi/flask-login@0.6.3", "pkg:pypi/Flask_Login@0.6.3"},
		{"pkg:gem/rails@7.0.0", "pkg:rubygems/rails@7.0.0"},
	}
	for _, pair := range same {
		if purlKey(pair[0]) != purlKey(pair[1]) {
			t.Errorf("%s and %s should match: %s vs %s", pair[0], pair[1], purlKey(pair[0]), purlKey(pair[1]))
		}
	}
	if purlKey("pkg:npm/@scope/util") == purlKey("pkg:npm/@scope/util@1.0.0") {
		t.Error("a versionless scoped PURL must not read its scope as a version")
	}
	if got := buildPurl(EcosystemMaven, "org.apache.logging.log4j:log4j-core", "2.14.1"); got != "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" {
		t.Errorf("maven purl = %s", got)
	}
}

func TestFixedVersionPicksTheFixForTheInstalledLine(t *testing.T) {
	cases := []struct{ reported, installed, want string }{
		{"4.17.21", "4.17.20", "4.17.21"},
		{"2.15.0, 2.12.2", "2.12.1", "2.12.2"},
		{"2.15.0, 2.12.2", "2.14.0", "2.15.0"},
		{">= 1.2.3", "1.0.0", ""},
		{"", "1.0.0", ""},
		{"1.2.0, 1.3.0", "", ""},
	}
	for _, c := range cases {
		if got := fixedVersion(c.reported, c.installed); got != c.want {
			t.Errorf("fixedVersion(%q, %q) = %q, want %q", c.reported, c.installed, got, c.want)
		}
	}
}

func removeFinding(findings []Finding, vulnerabilityID string) []Finding {
	out := findings[:0]
	for _, f := range findings {
		if f.VulnerabilityID != vulnerabilityID {
			out = append(out, f)
		}
	}
	return out
}
