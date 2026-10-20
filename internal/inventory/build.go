package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Xsamsx/SBOMber/internal/deps"
	"github.com/Xsamsx/SBOMber/internal/netstatus"
	"github.com/Xsamsx/SBOMber/internal/vulnerability"
)

// RepositoryInput is everything scan learned about one repository.
type RepositoryInput struct {
	Name string // directory name; becomes the repositoryId
	Path string // absolute path to the repository root

	// Summary is the dependency summary scan built. Its npm entries are not
	// used: npm occurrences are read from the lockfile directly, which keeps
	// install paths and dependency paths the summary does not carry.
	Summary      deps.Summary
	SummaryError error

	// Vulnerabilities is Grype's enriched result, or nil when vulnerability
	// scanning was not requested. ScanError is set when it was requested and
	// failed.
	Vulnerabilities *vulnerability.ScanResults
	ScanError       error
}

// Options are the scan-wide inputs.
type Options struct {
	// OutputDir is the directory canonical-scan.json is written to;
	// repository paths are written relative to it.
	OutputDir string
	// StartedAt and CompletedAt are the scan's times. A fixed StartedAt
	// (from SOURCE_DATE_EPOCH) makes the scanId, and so the whole document,
	// reproducible.
	StartedAt   time.Time
	CompletedAt time.Time
	// VulnerabilitiesRequested is false when scan ran without
	// --include-vulnerabilities: the document then has no findings, and
	// every enrichment source says it was skipped.
	VulnerabilitiesRequested bool
	ToolVersions             map[string]string
}

// Build turns scan's results into canonical-scan.json.
func Build(repos []RepositoryInput, opts Options) Document {
	b := builder{
		components:  make(map[string]*Component),
		occurrences: make(map[string]Occurrence),
		byRepoPurl:  make(map[string][]string),
		findings:    make(map[string]*Finding),
		warnings:    make(map[string]SupplyChainWarning),
		detail:      StatusDetail{SkippedFiles: []string{}, FailedFiles: []string{}, LimitsHit: []string{}},
		enrichment:  make(map[string]Enrichment),
	}

	repositories := make([]Repository, 0, len(repos))
	ids := make(map[string]int)
	for _, repo := range repos {
		id := repositoryID(repo.Name, ids)
		repositories = append(repositories, Repository{
			RepositoryID: id,
			Path:         relativePath(opts.OutputDir, repo.Path),
			Commit:       headCommit(repo.Path),
			Source:       "local",
		})
		b.addPackages(id, repo)
		if opts.VulnerabilitiesRequested {
			b.addVulnerabilities(id, repo)
		}
	}

	doc := Document{
		SchemaVersion: SchemaVersion,
		Scan: Scan{
			StartedAt:    timestamp(opts.StartedAt),
			ToolVersions: opts.ToolVersions,
			Repositories: repositories,
			Enrichment:   b.enrichmentReports(opts.VulnerabilitiesRequested),
		},
		Components:  b.sortedComponents(),
		Occurrences: b.sortedOccurrences(),
		Findings:    b.sortedFindings(),
	}
	if !opts.CompletedAt.IsZero() {
		doc.Scan.CompletedAt = timestamp(opts.CompletedAt)
	}
	if len(b.warnings) > 0 {
		doc.SupplyChainWarnings = b.sortedWarnings()
	}

	sort.Strings(b.detail.LimitsHit)
	sort.Strings(b.detail.FailedFiles)
	doc.Scan.StatusDetail = &b.detail
	switch {
	case len(repos) > 0 && b.failedRepos == len(repos):
		doc.Scan.Status = StatusFailed
	case !b.detail.empty():
		doc.Scan.Status = StatusPartial
	default:
		doc.Scan.Status = StatusComplete
	}
	doc.Scan.ScanID = scanID(doc.Scan.StartedAt, repositories)
	return doc
}

type builder struct {
	components  map[string]*Component // by purl
	occurrences map[string]Occurrence // by occurrenceId
	byRepoPurl  map[string][]string   // repositoryId + purlKey -> occurrenceIds
	purlByKey   map[string]string     // purlKey -> component purl
	findings    map[string]*Finding   // by findingId
	warnings    map[string]SupplyChainWarning
	detail      StatusDetail
	enrichment  map[string]Enrichment // contract source -> worst outcome
	failedRepos int
}

func (b *builder) limit(format string, values ...any) {
	b.detail.LimitsHit = append(b.detail.LimitsHit, fmt.Sprintf(format, values...))
}

func (b *builder) addPackages(repoID string, repo RepositoryInput) {
	failed := false

	npmPackages, note, err := readNPM(repo.Path)
	if err == nil && note != "" {
		// No package-lock.json. If scan resolved the npm packages from
		// yarn.lock instead, those are exact versions; only the install and
		// dependency paths are missing, which the contract does not require.
		if yarn := yarnPackages(repo.Path, repo.Summary); yarn != nil {
			npmPackages, note = yarn, ""
		}
	}
	switch {
	case err != nil:
		b.detail.FailedFiles = append(b.detail.FailedFiles, repoID+": "+err.Error())
		failed = true
	case note != "":
		b.limit("%s: %s", repoID, note)
	}
	for _, pkg := range npmPackages {
		path := make([]string, 0, len(pkg.dependencyPath))
		for _, step := range pkg.dependencyPath {
			path = append(path, b.component(EcosystemNPM, step.name, step.version, "").Purl)
		}
		relationship := "transitive"
		if pkg.direct {
			relationship = "direct"
		}
		purl := b.component(EcosystemNPM, pkg.name, pkg.version, pkg.declaredConstraint).Purl
		b.occurrence(Occurrence{
			Purl:           purl,
			RepositoryID:   repoID,
			Workspace:      pkg.workspace,
			Manifest:       pkg.manifest,
			Relationship:   relationship,
			DependencyPath: path,
			InstallPath:    pkg.installPath,
			Scope:          pkg.scope,
		})
	}

	if repo.SummaryError != nil {
		b.detail.FailedFiles = append(b.detail.FailedFiles, repoID+": "+repo.SummaryError.Error())
		failed = true
	}
	if failed && len(npmPackages) == 0 && repo.Summary.TotalCount() == 0 {
		b.failedRepos++
	}

	// Every other ecosystem comes from the summary. Each package is listed
	// once per repository: direct wins over transitive, so one package is
	// never both at the same (empty) install path.
	unsupported := make(map[string]int)
	type seenKey struct{ purl string }
	seen := make(map[seenKey]bool)
	add := func(dep deps.Dependency, direct bool) {
		if strings.EqualFold(dep.Ecosystem, "npm") {
			return
		}
		ecosystem, ok := contractEcosystem(dep.Ecosystem)
		if !ok {
			unsupported[dep.Ecosystem]++
			return
		}
		version, constraint := dep.Version, ""
		if !isExactVersion(version) {
			version, constraint = "", dep.Version
		}
		component := b.component(ecosystem, dep.Name, version, constraint)
		key := seenKey{component.Purl}
		if seen[key] {
			return
		}
		seen[key] = true
		relationship := "transitive"
		if direct {
			relationship = "direct"
		}
		manifest := dep.SourceFile
		if manifest == "" {
			manifest = "unknown"
		}
		b.occurrence(Occurrence{
			Purl:           component.Purl,
			RepositoryID:   repoID,
			Manifest:       manifest,
			Relationship:   relationship,
			DependencyPath: []string{},
			Scope:          contractScope(dep.Scope),
		})
	}
	for _, dep := range repo.Summary.Direct {
		add(dep, true)
	}
	for _, dep := range repo.Summary.Transitive {
		add(dep, dep.IsDirect)
	}
	names := make([]string, 0, len(unsupported))
	for name := range unsupported {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b.limit("%s: %d %s package(s) not listed: canonical-scan 1.0.0 has no %q ecosystem", repoID, unsupported[name], name, name)
	}
}

// component returns the component for a package version, adding it the
// first time.
func (b *builder) component(ecosystem, name, version, constraint string) *Component {
	name = normalisedName(ecosystem, name)
	purl := buildPurl(ecosystem, name, version)
	if existing, ok := b.components[purl]; ok {
		if existing.DeclaredConstraint == "" && constraint != "" && constraint != existing.Version {
			existing.DeclaredConstraint = constraint
		}
		return existing
	}
	c := &Component{Purl: purl, Ecosystem: ecosystem, Name: name, Version: version}
	if version == "" {
		known := false
		c.VersionKnown = &known
	}
	if constraint != "" && constraint != version {
		c.DeclaredConstraint = constraint
	}
	b.components[purl] = c
	if b.purlByKey == nil {
		b.purlByKey = make(map[string]string)
	}
	b.purlByKey[purlKey(purl)] = purl
	return c
}

func (b *builder) occurrence(o Occurrence) {
	o.OccurrenceID = "occ-" + shortHash(o.RepositoryID, o.Workspace, o.Manifest, o.InstallPath, o.Purl)
	if _, exists := b.occurrences[o.OccurrenceID]; exists {
		return
	}
	b.occurrences[o.OccurrenceID] = o
	key := o.RepositoryID + " " + purlKey(o.Purl)
	b.byRepoPurl[key] = append(b.byRepoPurl[key], o.OccurrenceID)
}

func (b *builder) addVulnerabilities(repoID string, repo RepositoryInput) {
	if repo.ScanError != nil {
		b.limit("%s: vulnerability scan failed: %v", repoID, repo.ScanError)
		return
	}
	results := repo.Vulnerabilities
	if results == nil {
		b.limit("%s: vulnerability scan did not run", repoID)
		return
	}
	statuses := make(map[string]netstatus.Status)
	for _, report := range results.NetworkStatus {
		b.recordEnrichment(report)
		statuses[report.Source] = report.Status
	}
	enrichedBy := func(v vulnerability.VulnerabilityResult) []string {
		var sources []string
		if statuses["epss"] == netstatus.Success && (v.EPSSScore > 0 || v.EPSSPercentile > 0) {
			sources = append(sources, "epss")
		}
		if statuses["kev"] == netstatus.Success {
			sources = append(sources, "cisa_kev")
		}
		if v.GHSAAdvisoryID != "" {
			sources = append(sources, "ghsa")
		}
		return sources
	}

	unrepresentable := 0
	for _, v := range results.Vulnerabilities {
		if v.Vulnerability == "" || v.PURL == "" {
			unrepresentable++
			continue
		}
		key := purlKey(v.PURL)
		purl, known := b.purlByKey[key]
		if !known {
			// Grype found a package the inventory does not list. Record it
			// as a component (with no occurrence) rather than drop the
			// finding; one it cannot represent is counted instead.
			ecosystem, ok := contractEcosystem(strings.SplitN(strings.TrimPrefix(v.PURL, "pkg:"), "/", 2)[0])
			version := v.InstalledVersion
			if version == "" {
				version = v.PackageVersion
			}
			if !ok || !isExactVersion(version) {
				unrepresentable++
				continue
			}
			purl = b.component(ecosystem, v.PackageName, version, "").Purl
		}

		id := "find-" + shortHash(v.Vulnerability, purl)
		finding, exists := b.findings[id]
		if !exists {
			finding = &Finding{
				FindingID:       id,
				VulnerabilityID: v.Vulnerability,
				Purl:            purl,
				OccurrenceIDs:   []string{},
				Severity:        contractSeverity(v.Severity),
				FixedVersion:    fixedVersion(v.PatchedVersions, b.components[purl].Version),
				Provenance: &Provenance{
					Scanner:        "grype",
					ScannerVersion: results.ScannerVersion,
					EnrichedBy:     enrichedBy(v),
				},
			}
			if v.CVSSScore > 0 && v.CVSSScore <= 10 {
				score := v.CVSSScore
				finding.CVSSScore = &score
			}
			if statuses["epss"] == netstatus.Success && (v.EPSSScore > 0 || v.EPSSPercentile > 0) {
				finding.EPSS = &EPSS{Score: v.EPSSScore, Percentile: v.EPSSPercentile}
			}
			// KEV membership is only stated when the KEV lookup worked;
			// otherwise "false" would claim something nobody checked.
			if statuses["kev"] == netstatus.Success {
				inKEV := v.InCISAKEV
				finding.CISAKev = &inKEV
			}
			b.findings[id] = finding
		}
		finding.Aliases = mergeAliases(finding.Aliases, v.Vulnerability, v.CVEID, v.GHSAAdvisoryID)
		finding.OccurrenceIDs = mergeSorted(finding.OccurrenceIDs, b.byRepoPurl[repoID+" "+purlKey(purl)])

		if v.RegistryDeprecated {
			w := SupplyChainWarning{Purl: purl, Kind: "deprecated", Detail: v.RegistryDeprecatedNote}
			w.WarningID = "warn-" + shortHash(w.Kind, purl)
			b.warnings[w.WarningID] = w
		}
	}
	if unrepresentable > 0 {
		b.limit("%s: %d finding(s) not listed: no package URL in a canonical-scan ecosystem", repoID, unrepresentable)
	}
}

// Contract enrichment sources, from netstatus source names.
var enrichmentSources = map[string]string{
	"epss":          "epss",
	"kev":           "cisa_kev",
	"ghsa":          "ghsa",
	"ghsa_packages": "ghsa",
	"npm_registry":  "registry",
	"malware":       "malware",
}

var contractSources = []string{"epss", "cisa_kev", "ghsa", "registry", "malware"}

// enrichmentRank orders outcomes from best to worst, so several reports for
// one source (GHSA has two, and each repository reports) keep the worst.
var enrichmentRank = map[string]int{"success": 0, "skipped": 1, "rate_limited": 2, "timed_out": 3, "unavailable": 4}

func (b *builder) recordEnrichment(report netstatus.Report) {
	source, ok := enrichmentSources[report.Source]
	if !ok {
		return
	}
	status, detail := string(report.Status), report.Detail
	if report.Status == netstatus.Partial {
		// canonical-scan 1.0.0 has no "partial": some lookups failed, so
		// some results are missing, which is what unavailable says.
		status = "unavailable"
		detail = strings.TrimSpace("partial: some lookups failed. " + detail)
	}
	if _, known := enrichmentRank[status]; !known {
		status = "unavailable"
	}
	if status != "success" && detail == "" {
		detail = "reported " + string(report.Status) + " with no detail"
	}
	current, seen := b.enrichment[source]
	if !seen || enrichmentRank[status] > enrichmentRank[current.Status] {
		e := Enrichment{Source: source, Status: status}
		if status != "success" {
			e.Detail = detail
		}
		b.enrichment[source] = e
	}
}

func (b *builder) enrichmentReports(requested bool) []Enrichment {
	reports := make([]Enrichment, 0, len(contractSources))
	for _, source := range contractSources {
		e, ok := b.enrichment[source]
		switch {
		case ok:
		case !requested:
			e = Enrichment{Source: source, Status: "skipped", Detail: "vulnerability scanning was not requested"}
		default:
			e = Enrichment{Source: source, Status: "skipped", Detail: "no enrichment report for this source"}
		}
		reports = append(reports, e)
	}
	return reports
}

func (b *builder) sortedComponents() []Component {
	out := make([]Component, 0, len(b.components))
	for _, c := range b.components {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Purl < out[j].Purl })
	return out
}

func (b *builder) sortedOccurrences() []Occurrence {
	out := make([]Occurrence, 0, len(b.occurrences))
	for _, o := range b.occurrences {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool {
		a, c := out[i], out[j]
		if a.RepositoryID != c.RepositoryID {
			return a.RepositoryID < c.RepositoryID
		}
		if a.Purl != c.Purl {
			return a.Purl < c.Purl
		}
		return a.OccurrenceID < c.OccurrenceID
	})
	return out
}

func (b *builder) sortedFindings() []Finding {
	out := make([]Finding, 0, len(b.findings))
	for _, f := range b.findings {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Purl != out[j].Purl {
			return out[i].Purl < out[j].Purl
		}
		return out[i].VulnerabilityID < out[j].VulnerabilityID
	})
	return out
}

func (b *builder) sortedWarnings() []SupplyChainWarning {
	out := make([]SupplyChainWarning, 0, len(b.warnings))
	for _, w := range b.warnings {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].WarningID < out[j].WarningID })
	return out
}

func contractScope(scope deps.Scope) string {
	switch scope {
	case deps.ScopeDev, deps.ScopeBuild:
		return "development"
	case deps.ScopeOptional:
		return "optional"
	case deps.ScopeTest:
		return "test"
	default:
		return "runtime"
	}
}

func contractSeverity(severity string) string {
	switch s := strings.ToLower(strings.TrimSpace(severity)); s {
	case "critical", "high", "medium", "low", "negligible":
		return s
	case "moderate":
		return "medium"
	default:
		return "unknown"
	}
}

// fixedVersion picks the reported fix that applies to the installed
// version: the lowest one above it. With one reported fix that is the fix;
// when none can be ordered against the installed version, none is written
// rather than a guess.
func fixedVersion(reported, installed string) string {
	var fixes []string
	for _, part := range strings.Split(reported, ",") {
		if v := strings.TrimSpace(part); isExactVersion(v) {
			fixes = append(fixes, v)
		}
	}
	if len(fixes) == 1 {
		return fixes[0]
	}
	best := ""
	for _, fix := range fixes {
		above, ok := compareVersions(fix, installed)
		if !ok || above <= 0 {
			continue
		}
		if best == "" {
			best = fix
			continue
		}
		if lower, ok := compareVersions(fix, best); ok && lower < 0 {
			best = fix
		}
	}
	return best
}

var numericVersion = regexp.MustCompile(`^v?(\d+(?:\.\d+)*)`)

// compareVersions compares the leading dotted-numeric parts of two versions.
func compareVersions(a, b string) (int, bool) {
	ma, mb := numericVersion.FindStringSubmatch(a), numericVersion.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return 0, false
	}
	pa, pb := strings.Split(ma[1], "."), strings.Split(mb[1], ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func mergeAliases(existing []string, primary string, candidates ...string) []string {
	set := make(map[string]bool, len(existing)+len(candidates))
	for _, a := range existing {
		set[a] = true
	}
	for _, c := range candidates {
		if c != "" && c != primary {
			set[c] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

func mergeSorted(a, b []string) []string {
	set := make(map[string]bool, len(a)+len(b))
	for _, v := range a {
		set[v] = true
	}
	for _, v := range b {
		set[v] = true
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

var unsafeID = regexp.MustCompile(`[^a-z0-9._-]+`)

func repositoryID(name string, used map[string]int) string {
	id := "repo-" + strings.Trim(unsafeID.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if id == "repo-" {
		id = "repo-root"
	}
	used[id]++
	if n := used[id]; n > 1 {
		id = fmt.Sprintf("%s-%d", id, n)
	}
	return id
}

func relativePath(base, target string) string {
	if base != "" {
		if rel, err := filepath.Rel(base, target); err == nil {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(target)
}

func timestamp(t time.Time) string {
	if t.IsZero() {
		t = time.Now()
	}
	return t.UTC().Format(time.RFC3339)
}

func scanID(startedAt string, repositories []Repository) string {
	parts := []string{startedAt}
	for _, r := range repositories {
		parts = append(parts, r.RepositoryID, r.Commit)
	}
	stamp := strings.NewReplacer("-", "", ":", "").Replace(startedAt)
	return "scan-" + stamp + "-" + shortHash(parts...)[:8]
}

func shortHash(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])[:12]
}
