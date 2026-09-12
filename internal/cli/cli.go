package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Xsamsx/SBOMber/internal/cargo"
	"github.com/Xsamsx/SBOMber/internal/composer"
	"github.com/Xsamsx/SBOMber/internal/deps"
	"github.com/Xsamsx/SBOMber/internal/diff"
	"github.com/Xsamsx/SBOMber/internal/discovery"
	"github.com/Xsamsx/SBOMber/internal/ecosystem"
	"github.com/Xsamsx/SBOMber/internal/github"
	"github.com/Xsamsx/SBOMber/internal/gitlab"
	"github.com/Xsamsx/SBOMber/internal/golang"
	"github.com/Xsamsx/SBOMber/internal/health"
	"github.com/Xsamsx/SBOMber/internal/localisation"
	"github.com/Xsamsx/SBOMber/internal/maven"
	"github.com/Xsamsx/SBOMber/internal/npm"
	"github.com/Xsamsx/SBOMber/internal/nuget"
	"github.com/Xsamsx/SBOMber/internal/python"
	"github.com/Xsamsx/SBOMber/internal/remote"
	"github.com/Xsamsx/SBOMber/internal/ruby"
	"github.com/Xsamsx/SBOMber/internal/sbom"
	"github.com/Xsamsx/SBOMber/internal/verify"
	"github.com/Xsamsx/SBOMber/internal/vulnerability"
)

const version = "0.1.0"

var (
	colorReset = "\033[0m"
	colorCyan  = "\033[36m"
	colorBlue  = "\033[34m"
	colorBold  = "\033[1m"
)

const (
	formatCycloneDX = "cyclonedx"
	formatSPDX      = "spdx"
	formatBoth      = "both"
)

func setColorOutput(enabled bool) {
	if enabled {
		colorReset = "\033[0m"
		colorCyan = "\033[36m"
		colorBlue = "\033[34m"
		colorBold = "\033[1m"
		return
	}
	colorReset = ""
	colorCyan = ""
	colorBlue = ""
	colorBold = ""
}

func flagErrorCode(err error) int {
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return 2
}

func validateVulnOptions(includeVulns, failOnVuln bool) error {
	if failOnVuln && !includeVulns {
		return fmt.Errorf("--fail-on-vuln requires --include-vulnerabilities")
	}
	return nil
}

// Main executes the CLI and returns the exit code.
func Main(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		return runInteractive(stdin, stdout, stderr)
	}

	switch args[0] {
	case "version", "--version", "-v":
		_, _ = fmt.Fprintf(stdout, "sbomber %s\n", version)
		return 0
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "github":
		return runGitHubScan(args[1:], stdout, stderr)
	case "gitlab":
		return runGitLabScan(args[1:], stdout, stderr)
	case "trace":
		return runTrace(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "diff":
		return runDiff(args[1:], stdout, stderr)
	case "localise", "localize":
		return runLocalise(args[1:], stdout, stderr)
	case "demo":
		return runDemo(stdout, stderr)
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runScan(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", formatCycloneDX, "export format: cyclonedx, spdx, or both")
	includeVulnerabilities := fs.Bool("include-vulnerabilities", false, "scan for vulnerabilities using Grype")
	failOnVuln := fs.Bool("fail-on-vuln", false, "exit with a non-zero status if any vulnerabilities are found")
	noColor := fs.Bool("no-color", false, "disable ANSI color output")

	if err := fs.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if *noColor {
		setColorOutput(false)
	}
	if err := validateVulnOptions(*includeVulnerabilities, *failOnVuln); err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	if *includeVulnerabilities && !vulnerability.IsGrypeAvailable() {
		_, _ = fmt.Fprintf(stderr, "ERROR: vulnerability scanning requested but Grype is not installed or not in PATH\n")
		_, _ = fmt.Fprintf(stderr, "Install Grype from: https://github.com/anchore/grype\n")
		return 2
	}

	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}

	absoluteRoot, err := resolveScanRoot(root)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "resolve path: %v\n", err)
		return 2
	}

	selectedFormat, err := normalizeExportFormat(*format)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid format: %v\n", err)
		return 2
	}

	repos, err := discovery.FindGitRepositories(absoluteRoot)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "scan repositories: %v\n", err)
		return 1
	}

	if len(repos) == 0 {
		_, _ = fmt.Fprintf(stdout, "No repositories found under %s\n", absoluteRoot)
		return 0
	}

	plural := "repositories"
	if len(repos) == 1 {
		plural = "repository"
	}

	_, _ = fmt.Fprintf(stdout, "Selected SBOM export format: %s\n", selectedFormat)
	if *includeVulnerabilities {
		_, _ = fmt.Fprintf(stdout, "Vulnerability scanning: enabled (Grype)\n")
	}
	_, _ = fmt.Fprintf(stdout, "Found %d %s under %s\n", len(repos), plural, absoluteRoot)
	vulnCount := 0
	for _, repo := range repos {
		detection, err := ecosystem.Detect(repo.Path)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "detect ecosystem for %s: %v\n", repo.Path, err)
			return 1
		}

		stack := "unknown"
		if len(detection.Names) > 0 {
			names := make([]string, 0, len(detection.Names))
			for _, name := range detection.Names {
				names = append(names, string(name))
			}

			stack = strings.Join(names, ", ")
		}

		_, _ = fmt.Fprintf(stdout, "- %s  %s  [%s]\n", repo.Name, repo.Path, stack)
		vulnCount += printDependencySummary(stdout, stderr, repo.Name, repo.Path, detection, selectedFormat, *includeVulnerabilities)
	}
	_, _ = fmt.Fprintf(stdout, "\nScan complete: %d repositories scanned\n", len(repos))
	if *failOnVuln && vulnCount > 0 {
		return 1
	}
	return 0
}

func runGitHubScan(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("github", flag.ContinueOnError)
	fs.SetOutput(stderr)
	includeHealth := fs.Bool("health", false, "include supply chain health metrics")
	includeVulns := fs.Bool("include-vulnerabilities", false, "scan for vulnerabilities using Grype")
	failOnVuln := fs.Bool("fail-on-vuln", false, "exit with a non-zero status if any vulnerabilities are found")
	noColor := fs.Bool("no-color", false, "disable ANSI color output")
	format := fs.String("format", formatCycloneDX, "export format: cyclonedx, spdx, or both")

	if err := fs.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if *noColor {
		setColorOutput(false)
	}
	if err := validateVulnOptions(*includeVulns, *failOnVuln); err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	if *includeVulns && !vulnerability.IsGrypeAvailable() {
		_, _ = fmt.Fprintf(stderr, "ERROR: vulnerability scanning requested but Grype is not installed or not in PATH\n")
		_, _ = fmt.Fprintf(stderr, "Install Grype from: https://github.com/anchore/grype\n\n")
		return 2
	}

	if fs.NArg() == 0 {
		_, _ = fmt.Fprintf(stderr, "Usage: sbomber github [--health] [--include-vulnerabilities] [--format FORMAT] <repo-url> [repo-url...]\n")
		_, _ = fmt.Fprintf(stderr, "\nExamples:\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber github https://github.com/expressjs/express\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber github --health https://github.com/lodash/lodash\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber github --include-vulnerabilities https://github.com/org/repo\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber github https://github.com/org/repo1 https://github.com/org/repo2\n")
		return 2
	}

	token := os.Getenv("GITHUB_TOKEN")
	client := github.NewClient(token)

	if !client.HasToken() {
		_, _ = fmt.Fprintf(stderr, "WARNING: No GITHUB_TOKEN set. Rate limit is 60 requests/hour.\n")
		_, _ = fmt.Fprintf(stderr, "Set GITHUB_TOKEN for 5000 requests/hour.\n\n")
	}

	selectedFormat, err := normalizeExportFormat(*format)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid format: %v\n", err)
		return 2
	}

	if *includeVulns {
		_, _ = fmt.Fprintf(stdout, "Vulnerability scanning: enabled (Grype)\n")
	}

	scanner := remote.NewScanner(client)
	scanner.SetProgress(func(msg string) {
		_, _ = fmt.Fprintf(stdout, "  %s\n", msg)
	})
	repoURLs := fs.Args()

	_, _ = fmt.Fprintf(stdout, "Scanning %d GitHub repositories...\n\n", len(repoURLs))

	outputDir, err := sbom.GetOutputDir("github-scan")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "create output directory: %v\n", err)
		return 1
	}

	var healthResolver *health.Resolver
	if *includeHealth {
		healthResolver = health.NewResolver(client)
	}

	vulnFound := false
	for _, repoURL := range repoURLs {
		_, _ = fmt.Fprintf(stdout, "Scanning: %s\n", repoURL)

		result, err := scanner.ScanRepo(repoURL)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "  Error: %v\n", err)
			continue
		}

		_, _ = fmt.Fprintf(stdout, "  Found %d manifests: %s\n", len(result.Manifests), strings.Join(result.Manifests, ", "))
		_, _ = fmt.Fprintf(stdout, "  Dependencies: %d direct, %d transitive\n",
			len(result.Summary.Direct), len(result.Summary.Transitive))

		repoOutputDir := filepath.Join(outputDir, result.Owner+"_"+result.Repo)
		if err := os.MkdirAll(repoOutputDir, 0755); err != nil {
			_, _ = fmt.Fprintf(stderr, "  Error creating output dir: %v\n", err)
			continue
		}

		savedPaths, err := sbom.SaveSBOMToDir(repoOutputDir, result.Repo, result.Summary, selectedFormat)
		var sbomPath string
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "  Error exporting SBOM: %v\n", err)
		} else {
			for _, p := range savedPaths {
				_, _ = fmt.Fprintf(stdout, "  Exported: %s\n", p)
				// Prefer CycloneDX for vulnerability scanning
				if strings.HasSuffix(p, ".cdx.xml") {
					sbomPath = p
				} else if sbomPath == "" && strings.HasSuffix(p, ".spdx") {
					sbomPath = p
				}
			}
		}

		// Collect health metrics if requested
		var healthMetrics []*health.DependencyHealth
		if *includeHealth && healthResolver != nil {
			allDeps := append(result.Summary.Direct, result.Summary.Transitive...)
			_, _ = fmt.Fprintf(stdout, "  Fetching health metrics for %d dependencies...\n", len(allDeps))

			progressFn := func(current, total int, depName string) {
				_, _ = fmt.Fprintf(stdout, "\r  [%d/%d] Checking: %-50s", current, total, truncate(depName, 50))
			}
			healthMetrics = healthResolver.ResolveAllWithProgress(allDeps, progressFn)
			_, _ = fmt.Fprintf(stdout, "\r  %-70s\n", "Health check complete!")

			var highRisk, mediumRisk, lowRisk int
			for _, m := range healthMetrics {
				switch m.RiskLevel {
				case "high":
					highRisk++
				case "medium":
					mediumRisk++
				default:
					lowRisk++
				}
			}
			_, _ = fmt.Fprintf(stdout, "  Health: %d low risk, %d medium risk, %d high risk\n",
				lowRisk, mediumRisk, highRisk)
		}

		// Build package refs for GHSA advisory scan (always runs regardless of Grype)
		allDepsForGHSA := append(result.Summary.Direct, result.Summary.Transitive...)
		pkgRefs := make([]vulnerability.PackageRef, 0, len(allDepsForGHSA))
		for _, d := range result.Summary.Direct {
			pkgRefs = append(pkgRefs, vulnerability.PackageRef{Name: d.Name, Ecosystem: d.Ecosystem, IsDirect: true})
		}
		for _, d := range result.Summary.Transitive {
			pkgRefs = append(pkgRefs, vulnerability.PackageRef{Name: d.Name, Ecosystem: d.Ecosystem, IsDirect: false})
		}
		_ = allDepsForGHSA

		_, _ = fmt.Fprintf(stdout, "  Scanning %d packages against GitHub Advisory Database...\n", len(pkgRefs))
		ghsaCtx, ghsaCancel := context.WithTimeout(context.Background(), 120*time.Second)
		ghsaResults, ghsaErr := vulnerability.ScanPackagesWithGHSA(ghsaCtx, pkgRefs)
		ghsaCancel()
		if ghsaErr != nil || ghsaResults == nil {
			ghsaResults = &vulnerability.ScanResults{Vulnerabilities: make([]vulnerability.VulnerabilityResult, 0)}
		}
		if ghsaResults.TotalCount > 0 {
			_, _ = fmt.Fprintf(stdout, "  GitHub Advisories found: %d\n", ghsaResults.TotalCount)
		}

		// Run Grype vulnerability scan on the SBOM if requested
		var vulnResults *vulnerability.ScanResults
		if *includeVulns && sbomPath != "" && vulnerability.IsGrypeAvailable() {
			_, _ = fmt.Fprintf(stdout, "  Scanning SBOM for vulnerabilities (Grype)...\n")
			ctx := context.Background()
			vulnResults, err = vulnerability.ScanSBOMWithGrype(ctx, sbomPath)
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "  Vulnerability scan failed: %v\n", err)
			} else {
				if vulnResults.TotalCount == 0 {
					_, _ = fmt.Fprintf(stdout, "  Vulnerabilities found: 0\n")
				} else {
					_, _ = fmt.Fprintf(stdout, "  Vulnerabilities found: %d\n", vulnResults.TotalCount)
					counts := vulnResults.CountBySeverity()
					for sev, count := range counts {
						_, _ = fmt.Fprintf(stdout, "    - %s: %d\n", sev, count)
					}
				}
			}
		}

		// Merge GHSA advisory results into vuln results (deduplicate by CVE/GHSA ID)
		if ghsaResults.TotalCount > 0 {
			if vulnResults == nil {
				vulnResults = ghsaResults
			} else {
				grypeIDs := make(map[string]struct{}, len(vulnResults.Vulnerabilities))
				for _, v := range vulnResults.Vulnerabilities {
					grypeIDs[strings.ToUpper(v.Vulnerability)] = struct{}{}
				}
				for _, v := range ghsaResults.Vulnerabilities {
					if _, dup := grypeIDs[strings.ToUpper(v.Vulnerability)]; !dup {
						vulnResults.Vulnerabilities = append(vulnResults.Vulnerabilities, v)
					}
				}
				vulnResults.TotalCount = len(vulnResults.Vulnerabilities)
			}
		}

		// Generate report (combined if we have both, otherwise just what we have)
		if vulnResults != nil && len(healthMetrics) > 0 {
			reportPath, err := vulnerability.GenerateFullReport(repoOutputDir, result.Repo, vulnResults, healthMetrics)
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "  Error generating report: %v\n", err)
			} else {
				_, _ = fmt.Fprintf(stdout, "  Report: %s\n", reportPath)
			}
		} else if vulnResults != nil {
			reportPath, err := vulnerability.GenerateHTMLReport(repoOutputDir, result.Repo, vulnResults)
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "  Error generating report: %v\n", err)
			} else {
				_, _ = fmt.Fprintf(stdout, "  Report: %s\n", reportPath)
			}
		} else if len(healthMetrics) > 0 {
			reportPath, err := vulnerability.GenerateHealthReport(repoOutputDir, result.Repo, healthMetrics)
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "  Error generating report: %v\n", err)
			} else {
				_, _ = fmt.Fprintf(stdout, "  Report: %s\n", reportPath)
			}
		}

		rateLimit := client.GetRateLimit()
		if rateLimit.Remaining > 0 {
			_, _ = fmt.Fprintf(stdout, "  [Rate limit: %d/%d remaining]\n", rateLimit.Remaining, rateLimit.Limit)
		}
		_, _ = fmt.Fprintf(stdout, "\n")
	}

	_, _ = fmt.Fprintf(stdout, "GitHub scan complete. Output saved to: %s\n", outputDir)
	if *failOnVuln && vulnFound {
		return 1
	}
	return 0
}

func runTrace(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("trace", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showTree := fs.Bool("tree", false, "show full dependency tree instead of chain")
	showList := fs.Bool("list", false, "list all dependencies with optional filters")
	showGraph := fs.Bool("graph", false, "show ASCII dependency graph")
	showDot := fs.Bool("dot", false, "output DOT format for Graphviz visualization")
	showConnections := fs.Bool("connections", false, "show detailed connection info for a package")
	showFalsePositives := fs.Bool("fp", false, "highlight potential false positives")
	noColor := fs.Bool("no-color", false, "disable ANSI color output")
	filterEcosystem := fs.String("ecosystem", "", "filter by ecosystem (npm, maven, pypi, golang, rubygems)")
	filterScope := fs.String("scope", "", "filter by build-scope (runtime, dev, test, build-tooling)")
	filterType := fs.String("type", "", "filter by dependency-type (direct, transitive)")
	filterSourceFile := fs.String("source-file", "", "filter by source manifest file")
	minDepth := fs.Int("min-depth", 0, "minimum depth (0 = direct)")
	maxDepth := fs.Int("max-depth", -1, "maximum depth (-1 = no limit)")

	if err := fs.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if *noColor {
		setColorOutput(false)
	}

	if fs.NArg() < 1 {
		_, _ = fmt.Fprintf(stderr, "Usage: sbomber trace <path> [package-name] [flags]\n")
		_, _ = fmt.Fprintf(stderr, "\nVisualization Flags:\n")
		_, _ = fmt.Fprintf(stderr, "  --tree                  Show full dependency tree\n")
		_, _ = fmt.Fprintf(stderr, "  --graph                 Show ASCII dependency graph\n")
		_, _ = fmt.Fprintf(stderr, "  --dot                   Output DOT format for Graphviz\n")
		_, _ = fmt.Fprintf(stderr, "  --connections           Show detailed connection info\n")
		_, _ = fmt.Fprintf(stderr, "  --fp                    Highlight potential false positives\n")
		_, _ = fmt.Fprintf(stderr, "\nFilter Flags:\n")
		_, _ = fmt.Fprintf(stderr, "  --list                  List all dependencies with filters\n")
		_, _ = fmt.Fprintf(stderr, "  --ecosystem <name>      Filter by ecosystem (npm, maven, pypi, golang, rubygems)\n")
		_, _ = fmt.Fprintf(stderr, "  --scope <name>          Filter by build-scope (runtime, dev, test, build-tooling)\n")
		_, _ = fmt.Fprintf(stderr, "  --type <name>           Filter by dependency-type (direct, transitive)\n")
		_, _ = fmt.Fprintf(stderr, "  --source-file <path>    Filter by source manifest file\n")
		_, _ = fmt.Fprintf(stderr, "  --min-depth <n>         Minimum depth (default: 0)\n")
		_, _ = fmt.Fprintf(stderr, "  --max-depth <n>         Maximum depth (default: no limit)\n")
		_, _ = fmt.Fprintf(stderr, "\nExamples:\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber trace . lodash\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber trace . express --tree\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber trace --graph .                    # ASCII tree of all deps\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber trace --dot . > deps.dot           # DOT format for Graphviz\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber trace --connections . lodash       # Show how lodash is connected\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber trace --fp --list .                # Show potential false positives\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber trace . --list --ecosystem npm\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber trace . --list --type transitive --min-depth 2\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber trace . --list --source-file package.json\n")
		return 2
	}

	root := fs.Arg(0)
	packageName := ""
	if fs.NArg() >= 2 {
		packageName = fs.Arg(1)
	}

	absoluteRoot, err := resolveScanRoot(root)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "resolve path: %v\n", err)
		return 2
	}

	repos, err := discovery.FindGitRepositories(absoluteRoot)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "scan repositories: %v\n", err)
		return 1
	}

	if len(repos) == 0 {
		_, _ = fmt.Fprintf(stdout, "No repositories found under %s\n", absoluteRoot)
		return 0
	}

	// Build filter options
	filterOpts := deps.NewFilterOptions()
	filterOpts.Ecosystem = *filterEcosystem
	filterOpts.Scope = *filterScope
	filterOpts.Type = *filterType
	filterOpts.SourceFile = *filterSourceFile
	filterOpts.MinDepth = *minDepth
	filterOpts.MaxDepth = *maxDepth
	filterOpts.NameFilter = packageName

	found := false
	for _, repo := range repos {
		detection, err := ecosystem.Detect(repo.Path)
		if err != nil {
			continue
		}

		summary, err := buildRepoDependencySummary(repo.Path, detection)
		if err != nil {
			continue
		}

		// Build the dependency graph and detect false positives
		summary.BuildGraph(repo.Name)
		summary.DetectFalsePositives()

		// DOT graph output (for Graphviz)
		if *showDot {
			found = true
			dot := summary.GenerateDOTGraph(repo.Name)
			_, _ = fmt.Fprintf(stdout, "%s", dot)
			continue
		}

		// ASCII graph output
		if *showGraph {
			found = true
			_, _ = fmt.Fprintf(stdout, "\n%s[%s]%s Dependency Graph\n", colorBold, repo.Name, colorReset)
			_, _ = fmt.Fprintf(stdout, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
			tree := summary.GenerateASCIITree(repo.Name)
			_, _ = fmt.Fprintf(stdout, "%s\n", tree)

			// Legend
			_, _ = fmt.Fprintf(stdout, "%sLegend:%s\n", colorCyan, colorReset)
			_, _ = fmt.Fprintf(stdout, "  ⚠️  = Potential false positive (test/example dependency)\n\n")
			continue
		}

		// Show false positives summary
		if *showFalsePositives {
			var fpDeps []deps.Dependency
			for _, d := range summary.AllDependencies() {
				if d.IsPotentialFalsePositive() {
					fpDeps = append(fpDeps, d)
				}
			}

			if len(fpDeps) == 0 && packageName == "" {
				continue
			}

			found = true
			_, _ = fmt.Fprintf(stdout, "\n%s[%s]%s %s\n", colorBold, repo.Name, colorReset, repo.Path)
			_, _ = fmt.Fprintf(stdout, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

			if len(fpDeps) > 0 {
				_, _ = fmt.Fprintf(stdout, "\n%s⚠️  Potential False Positives (%d):%s\n\n", colorCyan, len(fpDeps), colorReset)
				for _, d := range fpDeps {
					_, _ = fmt.Fprintf(stdout, "  %s%-40s%s\n", colorBlue, d.Name+"@"+d.Version, colorReset)
					_, _ = fmt.Fprintf(stdout, "    Reason:  %s\n", d.FPReason)
					_, _ = fmt.Fprintf(stdout, "    Source:  %s\n", d.SourceFile)
					_, _ = fmt.Fprintf(stdout, "    Path:    %s\n\n", d.SourceLocation)
				}
			} else {
				_, _ = fmt.Fprintf(stdout, "\n%s✓ No potential false positives detected%s\n\n", colorCyan, colorReset)
			}
			continue
		}

		// List mode - show filtered dependencies
		if *showList || (packageName == "" && !*showConnections) {
			filtered := summary.Filter(filterOpts)
			if len(filtered) == 0 {
				continue
			}

			found = true
			_, _ = fmt.Fprintf(stdout, "\n%s[%s]%s %s\n", colorBold, repo.Name, colorReset, repo.Path)
			_, _ = fmt.Fprintf(stdout, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
			_, _ = fmt.Fprintf(stdout, "Found %d dependencies matching filters\n\n", len(filtered))

			// Group by source file for clarity
			bySource := make(map[string][]deps.Dependency)
			for _, d := range filtered {
				key := d.SourceFile
				if key == "" {
					key = "unknown"
				}
				bySource[key] = append(bySource[key], d)
			}

			for source, sourceDeps := range bySource {
				_, _ = fmt.Fprintf(stdout, "%sSource: %s%s\n", colorCyan, source, colorReset)
				for _, d := range sourceDeps {
					depType := "T"
					if d.IsDirect {
						depType = "D"
					}
					fpMarker := ""
					if d.IsPotentialFalsePositive() {
						fpMarker = " ⚠️"
					}
					_, _ = fmt.Fprintf(stdout, "  [%s] %-40s %s%-12s%s depth=%d%s\n",
						depType, truncate(d.Name+"@"+d.Version, 40),
						colorBlue, d.Ecosystem, colorReset, d.Depth, fpMarker)
				}
				_, _ = fmt.Fprintf(stdout, "\n")
			}
			continue
		}

		// Find specific dependency
		dep := summary.FindDependency(packageName)
		if dep == nil {
			continue
		}

		found = true
		_, _ = fmt.Fprintf(stdout, "\n%s[%s]%s %s\n", colorBold, repo.Name, colorReset, repo.Path)
		_, _ = fmt.Fprintf(stdout, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

		// Show detailed connections
		if *showConnections {
			connInfo := summary.GetConnectionInfo(dep.Name)
			if connInfo != nil {
				_, _ = fmt.Fprintf(stdout, "\n%sConnection Analysis for:%s %s@%s\n", colorCyan, colorReset, dep.Name, dep.Version)
				_, _ = fmt.Fprintf(stdout, "\n%sIntroduced by:%s\n", colorCyan, colorReset)
				if len(connInfo.IntroducedBy) == 0 {
					_, _ = fmt.Fprintf(stdout, "  (unknown)\n")
				} else {
					for _, parent := range connInfo.IntroducedBy {
						_, _ = fmt.Fprintf(stdout, "  → %s\n", parent)
					}
				}

				_, _ = fmt.Fprintf(stdout, "\n%sPulls in:%s\n", colorCyan, colorReset)
				if len(connInfo.UsedBy) == 0 {
					_, _ = fmt.Fprintf(stdout, "  (no dependencies)\n")
				} else {
					for i, child := range connInfo.UsedBy {
						if i >= 15 {
							_, _ = fmt.Fprintf(stdout, "  ... and %d more\n", len(connInfo.UsedBy)-15)
							break
						}
						_, _ = fmt.Fprintf(stdout, "  ← %s\n", child)
					}
				}

				_, _ = fmt.Fprintf(stdout, "\n%sPaths to root:%s\n", colorCyan, colorReset)
				if len(connInfo.PathsToRoot) == 0 {
					_, _ = fmt.Fprintf(stdout, "  %s (direct dependency)\n", dep.Name)
				} else {
					for i, path := range connInfo.PathsToRoot {
						if i >= 5 {
							_, _ = fmt.Fprintf(stdout, "  ... and %d more paths\n", len(connInfo.PathsToRoot)-5)
							break
						}
						_, _ = fmt.Fprintf(stdout, "  %s\n", strings.Join(path, " → "))
					}
				}

				// False positive warning
				if dep.IsPotentialFalsePositive() {
					_, _ = fmt.Fprintf(stdout, "\n%s⚠️  Potential False Positive:%s\n", colorCyan, colorReset)
					_, _ = fmt.Fprintf(stdout, "  Reason: %s\n", dep.FPReason)
				}
			}
			_, _ = fmt.Fprintf(stdout, "\n")
			continue
		}

		if *showTree {
			// Show full tree
			_, _ = fmt.Fprintf(stdout, "\n%sDependency Tree:%s\n", colorCyan, colorReset)
			tree := summary.GetDependencyTree(dep.Name, "  ", nil)
			_, _ = fmt.Fprintf(stdout, "%s", tree)
		} else {
			// Show detailed chain information
			_, _ = fmt.Fprintf(stdout, "\n%sPackage:%s       %s@%s\n", colorCyan, colorReset, dep.Name, dep.Version)
			_, _ = fmt.Fprintf(stdout, "%sEcosystem:%s     %s\n", colorCyan, colorReset, dep.Ecosystem)

			depType := "transitive"
			if dep.IsDirect {
				depType = "direct"
			}
			_, _ = fmt.Fprintf(stdout, "%sType:%s          %s\n", colorCyan, colorReset, depType)
			_, _ = fmt.Fprintf(stdout, "%sDepth:%s         %d hops from root\n", colorCyan, colorReset, dep.Depth)
			_, _ = fmt.Fprintf(stdout, "%sScope:%s         %s\n", colorCyan, colorReset, dep.BuildScope())

			// False positive warning
			if dep.IsPotentialFalsePositive() {
				_, _ = fmt.Fprintf(stdout, "\n%s⚠️  Potential False Positive:%s\n", colorCyan, colorReset)
				_, _ = fmt.Fprintf(stdout, "  Reason: %s\n", dep.FPReason)
			}

			// Source information
			_, _ = fmt.Fprintf(stdout, "\n%sSource Information:%s\n", colorCyan, colorReset)
			sourceFile := dep.SourceFile
			if sourceFile == "" {
				sourceFile = "unknown"
			}
			_, _ = fmt.Fprintf(stdout, "  File:     %s\n", sourceFile)
			sourceLocation := dep.SourceLocation
			if sourceLocation == "" {
				sourceLocation = "unknown"
			}
			_, _ = fmt.Fprintf(stdout, "  Location: %s\n", sourceLocation)

			_, _ = fmt.Fprintf(stdout, "\n%sChain (path from root):%s\n", colorCyan, colorReset)
			printChain(stdout, dep.Chain)

			if len(dep.Children) > 0 {
				_, _ = fmt.Fprintf(stdout, "\n%sDepends on:%s  %d packages\n", colorCyan, colorReset, len(dep.Children))
				for i, child := range dep.Children {
					if i >= 10 {
						_, _ = fmt.Fprintf(stdout, "  ... and %d more\n", len(dep.Children)-10)
						break
					}
					_, _ = fmt.Fprintf(stdout, "  • %s\n", child)
				}
			}
		}
		_, _ = fmt.Fprintf(stdout, "\n")
	}

	if !found {
		if packageName != "" {
			_, _ = fmt.Fprintf(stderr, "Package %q not found in any repository\n", packageName)
		} else {
			_, _ = fmt.Fprintf(stderr, "No dependencies match the specified filters\n")
		}
		return 1
	}

	return 0
}

func runVerify(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	outputJSON := fs.Bool("json", false, "output results as JSON")
	noColor := fs.Bool("no-color", false, "disable ANSI color output")

	if err := fs.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if *noColor {
		setColorOutput(false)
	}

	if fs.NArg() < 2 {
		_, _ = fmt.Fprintf(stderr, "Usage: sbomber verify <ground-truth-sbom> <generated-sbom> [--json]\n")
		_, _ = fmt.Fprintf(stderr, "\nCompare a generated SBOM against a verified ground truth SBOM.\n")
		_, _ = fmt.Fprintf(stderr, "\nSupported formats:\n")
		_, _ = fmt.Fprintf(stderr, "  - CycloneDX (XML and JSON)\n")
		_, _ = fmt.Fprintf(stderr, "  - SPDX (JSON)\n")
		_, _ = fmt.Fprintf(stderr, "\nExamples:\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber verify reference.cdx.xml my-output.cdx.xml\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber verify benchmark.json generated.json --json\n")
		_, _ = fmt.Fprintf(stderr, "\nBenchmark repositories:\n")
		_, _ = fmt.Fprintf(stderr, "  - https://github.com/CycloneDX/bom-examples\n")
		_, _ = fmt.Fprintf(stderr, "  - https://github.com/sbomify/sbom-benchmarks\n")
		_, _ = fmt.Fprintf(stderr, "  - https://github.com/spdx/spdx-examples\n")
		return 2
	}

	groundTruthPath := fs.Arg(0)
	generatedPath := fs.Arg(1)

	result, err := verify.VerifyFiles(groundTruthPath, generatedPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	if *outputJSON {
		// Output as JSON for CI/CD integration
		jsonOut := struct {
			GroundTruthCount int     `json:"ground_truth_count"`
			GeneratedCount   int     `json:"generated_count"`
			MatchedCount     int     `json:"matched_count"`
			MissingCount     int     `json:"missing_count"`
			ExtraCount       int     `json:"extra_count"`
			VersionMismatch  int     `json:"version_mismatch"`
			Precision        float64 `json:"precision"`
			Recall           float64 `json:"recall"`
			F1Score          float64 `json:"f1_score"`
			VersionAccuracy  float64 `json:"version_accuracy"`
		}{
			GroundTruthCount: result.GroundTruthCount,
			GeneratedCount:   result.GeneratedCount,
			MatchedCount:     result.MatchedCount,
			MissingCount:     result.MissingCount,
			ExtraCount:       result.ExtraCount,
			VersionMismatch:  result.VersionMismatch,
			Precision:        result.Precision,
			Recall:           result.Recall,
			F1Score:          result.F1Score,
			VersionAccuracy:  result.VersionAccuracy,
		}
		data, _ := json.MarshalIndent(jsonOut, "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", data)
	} else {
		_, _ = fmt.Fprint(stdout, result.PrintReport())
	}

	// Write scorecard note file next to the generated SBOM
	noteDir := filepath.Dir(generatedPath)
	notePath := filepath.Join(noteDir, "sbom-verify-note.txt")
	if err := result.SaveNote(notePath, groundTruthPath, generatedPath); err != nil {
		_, _ = fmt.Fprintf(stderr, "note: could not save verification note: %v\n", err)
	} else {
		_, _ = fmt.Fprintf(stdout, "\nVerification note saved: %s\n", notePath)
	}

	// Return non-zero if accuracy is below threshold
	if result.F1Score < 70 {
		return 1
	}
	return 0
}

func runDiff(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	noColor := fs.Bool("no-color", false, "disable ANSI color output")

	if err := fs.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if *noColor {
		setColorOutput(false)
	}

	if fs.NArg() < 2 {
		_, _ = fmt.Fprintf(stderr, "Usage: sbomber diff <old-sbom> <new-sbom>\n")
		_, _ = fmt.Fprintf(stderr, "\nExamples:\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber diff old.cdx.xml new.cdx.xml\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber diff v1.0.cdx.json v1.1.cdx.json\n")
		return 2
	}

	result, err := diff.DiffFiles(fs.Arg(0), fs.Arg(1))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	_, _ = fmt.Fprint(stdout, result.PrintReport())
	return 0
}

func runDemo(stdout io.Writer, stderr io.Writer) int {
	outputDir, err := sbom.GetOutputDir("demo")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	results := vulnerability.GenerateDemoResults()
	reportPath, err := vulnerability.GenerateHTMLReport(outputDir, "demo-project", results)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error generating demo report: %v\n", err)
		return 1
	}

	_, _ = fmt.Fprintf(stdout, "Demo report generated: %s\n", reportPath)
	_, _ = fmt.Fprintf(stdout, "\nCovers all vulnerability types:\n")
	_, _ = fmt.Fprintf(stdout, "  • Critical + CISA KEV + EPSS + GHSA  (Log4Shell, Spring4Shell)\n")
	_, _ = fmt.Fprintf(stdout, "  • High + KEV / High EPSS only\n")
	_, _ = fmt.Fprintf(stdout, "  • Medium: direct, transitive, Cargo, NuGet, Composer\n")
	_, _ = fmt.Fprintf(stdout, "  • Low: npm, Ruby gem, Go module\n")
	_, _ = fmt.Fprintf(stdout, "  • Test/fixture data (false-positive candidates)\n")
	_, _ = fmt.Fprintf(stdout, "  • GHSA-only ID (no CVE)\n")
	_, _ = fmt.Fprintf(stdout, "  • Negligible/unknown severity\n")
	return 0
}

func runGitLabScan(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("gitlab", flag.ContinueOnError)
	fs.SetOutput(stderr)
	includeHealth := fs.Bool("health", false, "include supply chain health metrics")
	includeVulns := fs.Bool("include-vulnerabilities", false, "scan for vulnerabilities using Grype")
	failOnVuln := fs.Bool("fail-on-vuln", false, "exit with a non-zero status if any vulnerabilities are found")
	noColor := fs.Bool("no-color", false, "disable ANSI color output")
	format := fs.String("format", formatCycloneDX, "export format: cyclonedx, cyclonedx-json, spdx, or both")
	instanceURL := fs.String("instance", "", "GitLab instance URL (default: https://gitlab.com)")

	if err := fs.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if *noColor {
		setColorOutput(false)
	}
	if err := validateVulnOptions(*includeVulns, *failOnVuln); err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	if *includeVulns && !vulnerability.IsGrypeAvailable() {
		_, _ = fmt.Fprintf(stderr, "ERROR: vulnerability scanning requested but Grype is not installed or not in PATH\n")
		_, _ = fmt.Fprintf(stderr, "Install Grype from: https://github.com/anchore/grype\n\n")
		return 2
	}

	if fs.NArg() == 0 {
		_, _ = fmt.Fprintf(stderr, "Usage: sbomber gitlab [--health] [--include-vulnerabilities] [--format FORMAT] [--instance URL] <repo-url>...\n")
		_, _ = fmt.Fprintf(stderr, "\nExamples:\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber gitlab https://gitlab.com/namespace/project\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber gitlab --health https://gitlab.com/org/repo\n")
		_, _ = fmt.Fprintf(stderr, "  sbomber gitlab --instance https://gitlab.company.com https://gitlab.company.com/org/repo\n")
		return 2
	}

	token := os.Getenv("GITLAB_TOKEN")
	client := gitlab.NewClient(token, *instanceURL)

	if !client.HasToken() {
		_, _ = fmt.Fprintf(stderr, "WARNING: No GITLAB_TOKEN set. You may hit rate limits on unauthenticated requests.\n\n")
	}

	selectedFormat, err := normalizeExportFormat(*format)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid format: %v\n", err)
		return 2
	}

	if *includeVulns {
		_, _ = fmt.Fprintf(stdout, "Vulnerability scanning: enabled (Grype)\n")
	}

	outputDir, err := sbom.GetOutputDir("gitlab-scan")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "create output directory: %v\n", err)
		return 1
	}

	var healthResolver *health.Resolver
	if *includeHealth {
		ghClient := github.NewClient("")
		healthResolver = health.NewResolver(ghClient)
	}

	_, _ = fmt.Fprintf(stdout, "Scanning %d GitLab repositories...\n\n", fs.NArg())
	vulnFound := false

	for _, repoURL := range fs.Args() {
		_, _ = fmt.Fprintf(stdout, "Scanning: %s\n", repoURL)

		namespace, project, _, err := gitlab.ParseRepoURL(repoURL)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "  Error: %v\n", err)
			continue
		}

		tree, err := client.GetRepoTree(namespace, project, "HEAD")
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "  Error fetching tree: %v\n", err)
			continue
		}
		_, _ = fmt.Fprintf(stdout, "  Found %d files\n", len(tree))

		// Find and parse manifests using the existing remote manifest map
		summary := deps.Summary{
			Direct:     make([]deps.Dependency, 0),
			Transitive: make([]deps.Dependency, 0),
		}
		var manifests []string

		for _, entry := range tree {
			if entry.Type != "blob" {
				continue
			}
			filename := entry.Name
			if _, known := remote.KnownManifests[filename]; !known {
				continue
			}

			fc, err := client.GetFileContent(namespace, project, entry.Path, "HEAD")
			if err != nil {
				_, _ = fmt.Fprintf(stdout, "  Warning: could not fetch %s: %v\n", entry.Path, err)
				continue
			}

			// Delegate to existing remote parser
			parsed, err := remote.ParseContent(entry.Path, fc.Content)
			if err != nil {
				continue
			}
			manifests = append(manifests, entry.Path)
			summary.Direct = append(summary.Direct, parsed.Direct...)
			summary.Transitive = append(summary.Transitive, parsed.Transitive...)
		}

		_, _ = fmt.Fprintf(stdout, "  Manifests: %s\n", strings.Join(manifests, ", "))
		_, _ = fmt.Fprintf(stdout, "  Dependencies: %d direct, %d transitive\n",
			len(summary.Direct), len(summary.Transitive))

		repoOutputDir := filepath.Join(outputDir, namespace+"_"+project)
		if err := os.MkdirAll(repoOutputDir, 0755); err != nil {
			_, _ = fmt.Fprintf(stderr, "  Error creating output dir: %v\n", err)
			continue
		}

		savedPaths, err := sbom.SaveSBOMToDir(repoOutputDir, project, summary, selectedFormat)
		var sbomPath string
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "  Error exporting SBOM: %v\n", err)
		} else {
			for _, p := range savedPaths {
				_, _ = fmt.Fprintf(stdout, "  Exported: %s\n", p)
				if strings.HasSuffix(p, ".cdx.xml") || strings.HasSuffix(p, ".cdx.json") {
					sbomPath = p
				} else if sbomPath == "" {
					sbomPath = p
				}
			}
		}

		var healthMetrics []*health.DependencyHealth
		if *includeHealth && healthResolver != nil {
			allDeps := append(summary.Direct, summary.Transitive...)
			_, _ = fmt.Fprintf(stdout, "  Fetching health metrics for %d dependencies...\n", len(allDeps))
			healthMetrics = healthResolver.ResolveAll(allDeps)
			var hi, hm, hl int
			for _, m := range healthMetrics {
				switch m.RiskLevel {
				case "high":
					hi++
				case "medium":
					hm++
				default:
					hl++
				}
			}
			_, _ = fmt.Fprintf(stdout, "  Health: %d low, %d medium, %d high risk\n", hl, hm, hi)
		}

		var vulnResults *vulnerability.ScanResults
		if *includeVulns && sbomPath != "" && vulnerability.IsGrypeAvailable() {
			ctx := context.Background()
			vulnResults, err = vulnerability.ScanSBOMWithGrype(ctx, sbomPath)
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "  Vulnerability scan failed: %v\n", err)
			} else {
				_, _ = fmt.Fprintf(stdout, "  Vulnerabilities: %d\n", vulnResults.TotalCount)
			}
		}
		if vulnResults != nil && vulnResults.TotalCount > 0 {
			vulnFound = true
		}

		if vulnResults != nil && len(healthMetrics) > 0 {
			if rp, err := vulnerability.GenerateFullReport(repoOutputDir, project, vulnResults, healthMetrics); err == nil {
				_, _ = fmt.Fprintf(stdout, "  Report: %s\n", rp)
			}
		} else if vulnResults != nil {
			if rp, err := vulnerability.GenerateHTMLReport(repoOutputDir, project, vulnResults); err == nil {
				_, _ = fmt.Fprintf(stdout, "  Report: %s\n", rp)
			}
		} else if len(healthMetrics) > 0 {
			if rp, err := vulnerability.GenerateHealthReport(repoOutputDir, project, healthMetrics); err == nil {
				_, _ = fmt.Fprintf(stdout, "  Report: %s\n", rp)
			}
		}

		_, _ = fmt.Fprintln(stdout)
	}

	_, _ = fmt.Fprintf(stdout, "GitLab scan complete. Output saved to: %s\n", outputDir)
	if *failOnVuln && vulnFound {
		return 1
	}
	return 0
}

// printChain prints a dependency chain with nice formatting
func printChain(w io.Writer, chain string) {
	parts := strings.Split(chain, " > ")
	for i, part := range parts {
		indent := strings.Repeat("  ", i)
		if i == 0 {
			_, _ = fmt.Fprintf(w, "  %s%s%s (root)\n", colorBlue, part, colorReset)
		} else if i == len(parts)-1 {
			_, _ = fmt.Fprintf(w, "  %s└─ %s%s%s (target)\n", indent, colorCyan, part, colorReset)
		} else {
			_, _ = fmt.Fprintf(w, "  %s└─ %s\n", indent, part)
		}
	}
}

// runInteractive branches on the bubbletea TUI vs. a plain-text numbered
// prompt flow. In practice only the TUI branch is ever reached from the
// real binary: cmd/sbomber/main.go always calls Main with the literal
// os.Stdin/os.Stdout package values, so this identity check is true for
// every real invocation regardless of whether stdin is a terminal, a pipe,
// or a redirected file — Go doesn't change which *os.File value os.Stdin
// holds based on what's connected to fd 0. The plain-text branch below
// (promptExportFormat, promptVulnerabilityScan,
// runScanAndOfferGroundTruthCheck) is exercised only by tests that call
// Main directly with a substitute io.Reader/io.Writer (e.g.
// strings.NewReader), which is a different Go value than os.Stdin. It is
// real, tested code — just not reachable by running `sbomber`. Fixing
// that would mean adding proper terminal detection (e.g.
// golang.org/x/term.IsTerminal), which is a larger, separate change
// affecting every existing prompt here, not just the ground-truth one
// added alongside this comment; noted here rather than fixed silently.
func runInteractive(stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	if stdin == os.Stdin && stdout == os.Stdout {
		for {
			result := runTUIFull()
			switch result.Action {
			case "scan":
				scanPath := result.ScanPath
				scanFormat := result.ScanFormat
				includeVulns := result.IncludeVulns
				if scanPath == "" {
					scanPath = "."
				}
				if scanFormat == "" {
					scanFormat = formatCycloneDX
				}
				// Resolve path (expand ~ and make absolute)
				absPath, err := resolveScanRoot(scanPath)
				if err != nil {
					_, _ = fmt.Fprintf(stderr, "Invalid path: %v\n", err)
					continue
				}
				// Get central output folder in ~/.sbomber/reports/
				outputFolder, err := sbom.GetOutputDir(absPath)
				if err != nil {
					_, _ = fmt.Fprintf(stderr, "Failed to create output directory: %v\n", err)
					continue
				}

				// Show scanning message
				fmt.Print("\033[H\033[2J") // Clear screen
				fmt.Println()
				fmt.Println("  \033[1m\033[36mScanning...\033[0m")
				fmt.Println()
				fmt.Printf("  Path:   %s\n", absPath)
				fmt.Printf("  Format: %s\n", scanFormat)
				if includeVulns {
					fmt.Println("  Vulns:  enabled (Grype)")
				}
				fmt.Println()
				fmt.Println("  \033[90mThis may take a moment...\033[0m")

				var buf bytes.Buffer
				args := []string{"--format", scanFormat}
				if includeVulns {
					args = append(args, "--include-vulnerabilities")
				}
				args = append(args, scanPath)
				runScan(args, &buf, &buf) // Capture both stdout and stderr

				if quit := showResultsScreen(buf.String(), outputFolder); quit {
					fmt.Print("\033[H\033[2J")
					_, _ = fmt.Fprint(stdout, "Goodbye!\n")
					return 0
				}
			case "github":
				// Show scanning message
				fmt.Print("\033[H\033[2J") // Clear screen
				fmt.Println()
				fmt.Println("  \033[1m\033[36mScanning GitHub repositories...\033[0m")
				fmt.Println()

				// Parse URLs (space or comma separated)
				urlInput := strings.ReplaceAll(result.GitHubURLs, ",", " ")
				urls := strings.Fields(urlInput)

				fmt.Printf("  Repos:  %d\n", len(urls))
				fmt.Printf("  Format: %s\n", result.ScanFormat)
				if result.IncludeHealth {
					fmt.Println("  Health: enabled")
				}
				fmt.Println()

				args := []string{}
				if result.ScanFormat != "" {
					args = append(args, "--format", result.ScanFormat)
				}
				if result.IncludeHealth {
					args = append(args, "--health")
				}
				if result.IncludeVulns {
					args = append(args, "--include-vulnerabilities")
				}
				args = append(args, urls...)

				// Set token in env if provided via TUI
				if result.GitHubToken != "" {
					_ = os.Setenv("GITHUB_TOKEN", result.GitHubToken)
				}

				// Run with real-time output to stdout (not buffered)
				var buf bytes.Buffer
				// Create a writer that writes to both stdout (real-time) and buffer (for results screen)
				multiWriter := io.MultiWriter(os.Stdout, &buf)
				runGitHubScan(args, multiWriter, multiWriter)

				fmt.Println()
				fmt.Println("  \033[90mPress Enter to continue...\033[0m")
				_, _ = bufio.NewReader(os.Stdin).ReadBytes('\n')

				outputFolder, _ := sbom.GetOutputDir("github-scan")
				if quit := showResultsScreen(buf.String(), outputFolder); quit {
					fmt.Print("\033[H\033[2J")
					_, _ = fmt.Fprint(stdout, "Goodbye!\n")
					return 0
				}
			case "version":
				if quit := showResultsScreen(fmt.Sprintf("SBOMber %s", version), ""); quit {
					return 0
				}
			case "help":
				var buf bytes.Buffer
				printUsage(&buf)
				if quit := showResultsScreen(buf.String(), ""); quit {
					return 0
				}
			case "exit", "":
				fmt.Print("\033[H\033[2J")
				_, _ = fmt.Fprint(stdout, "Goodbye!\n")
				return 0
			}
		}
	}

	printBanner(stdout)
	_, _ = fmt.Fprintf(stdout, "%sA lightweight CLI for scanning local repositories and generating SBOMs.%s\n\n", colorBlue, colorReset)
	_, _ = fmt.Fprint(stdout, "Choose an option:\n")
	_, _ = fmt.Fprint(stdout, "  1. Scan the current folder\n")
	_, _ = fmt.Fprint(stdout, "  2. Scan a custom folder\n")
	_, _ = fmt.Fprint(stdout, "  3. Show version\n")
	_, _ = fmt.Fprint(stdout, "  4. Show help\n\n")
	_, _ = fmt.Fprint(stdout, "Enter choice [1-4]: ")

	reader := bufio.NewReader(stdin)
	choice, err := reader.ReadString('\n')
	if err != nil && len(choice) == 0 {
		_, _ = fmt.Fprintf(stderr, "read choice: %v\n", err)
		return 1
	}

	switch strings.TrimSpace(choice) {
	case "", "1":
		format, exitCode := promptExportFormat(reader, stdout, stderr)
		if exitCode != 0 {
			return exitCode
		}

		includeVulns, exitCode := promptVulnerabilityScan(reader, stdout, stderr)
		if exitCode != 0 {
			return exitCode
		}

		args := []string{"--format", format}
		if includeVulns {
			args = append(args, "--include-vulnerabilities")
		}
		args = append(args, ".")

		return runScanAndOfferGroundTruthCheck(args, reader, stdout, stderr)
	case "2":
		_, _ = fmt.Fprint(stdout, "Folder to scan: ")
		path, err := reader.ReadString('\n')
		if err != nil && len(path) == 0 {
			_, _ = fmt.Fprintf(stderr, "read path: %v\n", err)
			return 1
		}

		path = strings.TrimSpace(path)
		if path == "" {
			path = "."
		}

		format, exitCode := promptExportFormat(reader, stdout, stderr)
		if exitCode != 0 {
			return exitCode
		}

		includeVulns, exitCode := promptVulnerabilityScan(reader, stdout, stderr)
		if exitCode != 0 {
			return exitCode
		}

		args := []string{"--format", format}
		if includeVulns {
			args = append(args, "--include-vulnerabilities")
		}
		args = append(args, path)

		return runScanAndOfferGroundTruthCheck(args, reader, stdout, stderr)
	case "3":
		_, _ = fmt.Fprintf(stdout, "sbomber %s\n", version)
		return 0
	case "4":
		printUsage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "invalid choice %q\n", strings.TrimSpace(choice))
		return 1
	}
}

func printBanner(w io.Writer) {
	_, _ = fmt.Fprintf(w, "%s%s", colorBold, colorCyan)
	_, _ = fmt.Fprint(w, `
  ____  ____   ___  __  __ ____             
 / ___|| __ ) / _ \|  \/  | __ )  ___ _ __  
 \___ \|  _ \| | | | |\/| |  _ \ / _ \ '__| 
  ___) | |_) | |_| | |  | | |_) |  __/ |    
 |____/|____/ \___/|_|  |_|____/ \___|_|    
`)
	_, _ = fmt.Fprintf(w, "%s\n", colorReset)
}

func promptExportFormat(reader *bufio.Reader, stdout io.Writer, stderr io.Writer) (string, int) {
	_, _ = fmt.Fprint(stdout, "\nChoose SBOM export format:\n")
	_, _ = fmt.Fprint(stdout, "  1. CycloneDX\n")
	_, _ = fmt.Fprint(stdout, "  2. SPDX\n")
	_, _ = fmt.Fprint(stdout, "  3. Both\n\n")
	_, _ = fmt.Fprint(stdout, "Enter choice [1-3] (default 1): ")

	choice, err := reader.ReadString('\n')
	if err != nil && len(choice) == 0 {
		_, _ = fmt.Fprintf(stderr, "read format choice: %v\n", err)
		return "", 1
	}

	switch strings.TrimSpace(choice) {
	case "", "1":
		return formatCycloneDX, 0
	case "2":
		return formatSPDX, 0
	case "3":
		return formatBoth, 0
	default:
		_, _ = fmt.Fprintf(stderr, "invalid export format choice %q\n", strings.TrimSpace(choice))
		return "", 1
	}
}

func promptVulnerabilityScan(reader *bufio.Reader, stdout io.Writer, stderr io.Writer) (bool, int) {
	_, _ = fmt.Fprint(stdout, "\nInclude vulnerability scanning with Grype? [y/N]: ")

	choice, err := reader.ReadString('\n')
	if err != nil && len(choice) == 0 {
		_, _ = fmt.Fprintf(stderr, "read vulnerability choice: %v\n", err)
		return false, 1
	}

	switch strings.ToLower(strings.TrimSpace(choice)) {
	case "y", "yes":
		return true, 0
	case "", "n", "no":
		return false, 0
	default:
		_, _ = fmt.Fprintf(stderr, "invalid vulnerability choice %q\n", strings.TrimSpace(choice))
		return false, 1
	}
}

// runScanAndOfferGroundTruthCheck runs a scan, prints its output, and then
// — only when the scan produced exactly one repo's SBOM, since a
// ground-truth comparison needs exactly one generated SBOM to compare
// against — offers to check that SBOM's accuracy against a ground-truth
// SBOM the user points to.
func runScanAndOfferGroundTruthCheck(args []string, reader *bufio.Reader, stdout io.Writer, stderr io.Writer) int {
	var buf bytes.Buffer
	exitCode := runScan(args, &buf, &buf)
	output := buf.String()
	_, _ = fmt.Fprint(stdout, output)
	if exitCode != 0 {
		return exitCode
	}

	sbomPath := extractSingleScanSBOM(output)
	if sbomPath == "" {
		return 0
	}

	return promptGroundTruthCheck(reader, stdout, stderr, sbomPath)
}

// extractSingleScanSBOM parses a scan's captured output for exactly one
// repo's "output folder:"/"exported SBOM:" lines (printed by
// printDependencySummary), preferring the CycloneDX file when both formats
// were exported. Returns "" when zero or more than one repo was scanned,
// since there is then no single generated SBOM to offer a ground-truth
// comparison against.
func extractSingleScanSBOM(scanOutput string) string {
	var outputDir string
	var sbomFiles []string
	repoCount := 0

	for _, line := range strings.Split(scanOutput, "\n") {
		trimmed := strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(trimmed, "output folder:"); ok {
			repoCount++
			outputDir = strings.TrimSpace(after)
			sbomFiles = nil
			continue
		}
		if after, ok := strings.CutPrefix(trimmed, "exported SBOM:"); ok {
			sbomFiles = append(sbomFiles, strings.TrimSpace(after))
		}
	}

	if repoCount != 1 || len(sbomFiles) == 0 {
		return ""
	}

	for _, name := range sbomFiles {
		if name == "sbom-cyclonedx.xml" {
			return filepath.Join(outputDir, name)
		}
	}
	return filepath.Join(outputDir, sbomFiles[0])
}

// promptGroundTruthCheck asks whether to check the just-generated SBOM's
// accuracy against a ground-truth SBOM and, if so, for that file's path,
// then runs the same comparison sbomber verify uses and prints the report.
func promptGroundTruthCheck(reader *bufio.Reader, stdout io.Writer, stderr io.Writer, generatedSBOMPath string) int {
	_, _ = fmt.Fprint(stdout, "\nCheck accuracy against a ground-truth SBOM? [y/N]: ")

	choice, err := reader.ReadString('\n')
	if err != nil && len(choice) == 0 {
		_, _ = fmt.Fprintf(stderr, "read ground-truth choice: %v\n", err)
		return 1
	}

	switch strings.ToLower(strings.TrimSpace(choice)) {
	case "", "n", "no":
		return 0
	case "y", "yes":
		// fall through to the path prompt below
	default:
		_, _ = fmt.Fprintf(stderr, "invalid ground-truth choice %q\n", strings.TrimSpace(choice))
		return 1
	}

	_, _ = fmt.Fprint(stdout, "Path to ground-truth SBOM: ")
	pathInput, err := reader.ReadString('\n')
	if err != nil && len(pathInput) == 0 {
		_, _ = fmt.Fprintf(stderr, "read ground-truth path: %v\n", err)
		return 1
	}

	groundTruthPath := strings.TrimSpace(pathInput)
	if groundTruthPath == "" {
		_, _ = fmt.Fprintln(stderr, "no ground-truth path provided, skipping accuracy check")
		return 0
	}

	result, err := verify.VerifyFiles(groundTruthPath, generatedSBOMPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "ground-truth check failed: %v\n", err)
		return 2
	}

	_, _ = fmt.Fprint(stdout, result.PrintReport())
	if result.F1Score < 70 {
		return 1
	}
	return 0
}

func printDependencySummary(stdout io.Writer, stderr io.Writer, repoName, repoPath string, detection ecosystem.Detection, selectedFormat string, includeVulnerabilities bool) int {
	summary, err := buildRepoDependencySummary(repoPath, detection)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "read npm dependencies for %s: %v\n", repoPath, err)
		return 0
	}

	savedPaths, outputDir, err := sbom.SaveSBOM(repoPath, repoName, summary, selectedFormat)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "save SBOM for %s: %v\n", repoPath, err)
	} else {
		_, _ = fmt.Fprintf(stdout, "  output folder: %s\n", outputDir)
		var spdxPath string
		for _, path := range savedPaths {
			_, _ = fmt.Fprintf(stdout, "  exported SBOM: %s\n", filepath.Base(path))
			if strings.HasSuffix(path, "sbom.spdx") {
				spdxPath = path
			}
		}
		if includeVulnerabilities {
			// Run vulnerability scan and generate HTML report
			scanPath := repoPath
			if spdxPath != "" {
				scanPath = "sbom:" + spdxPath
			}
			vulnCount := generateVulnReport(stdout, stderr, scanPath, outputDir, repoName)
			if vulnCount > 0 {
				return vulnCount
			}
		}
	}

	totalDirect := summary.Count()
	totalTransitive := summary.TransitiveCount()

	if totalDirect == 0 && totalTransitive == 0 {
		return 0
	}

	_, _ = fmt.Fprintf(stdout, "  packages:  %d direct", totalDirect)
	if totalTransitive > 0 {
		_, _ = fmt.Fprintf(stdout, ", %d transitive (%d total)", totalTransitive, summary.TotalCount())
	}
	_, _ = fmt.Fprintln(stdout)

	sourceLabel := "package.json"
	if containsEcosystem(detection.Names, ecosystem.Python) {
		sourceLabel = "requirements.txt"
	}
	if containsEcosystem(detection.Names, ecosystem.NPM) && containsEcosystem(detection.Names, ecosystem.Python) {
		sourceLabel = "package.json + requirements.txt"
	}

	_, _ = fmt.Fprintf(stdout, "  direct dependencies (%s): %d", sourceLabel, summary.Count())

	runtimeCount := summary.CountByScope(deps.ScopeRuntime)
	devCount := summary.CountByScope(deps.ScopeDev)
	peerCount := summary.CountByScope(deps.ScopePeer)
	optionalCount := summary.CountByScope(deps.ScopeOptional)

	scopeParts := make([]string, 0, 4)
	if runtimeCount > 0 {
		scopeParts = append(scopeParts, fmt.Sprintf("runtime: %d", runtimeCount))
	}
	if devCount > 0 {
		scopeParts = append(scopeParts, fmt.Sprintf("development: %d", devCount))
	}
	if peerCount > 0 {
		scopeParts = append(scopeParts, fmt.Sprintf("peer: %d", peerCount))
	}
	if optionalCount > 0 {
		scopeParts = append(scopeParts, fmt.Sprintf("optional: %d", optionalCount))
	}

	if len(scopeParts) > 0 {
		_, _ = fmt.Fprintf(stdout, " (%s)", strings.Join(scopeParts, ", "))
	}
	_, _ = fmt.Fprint(stdout, "\n")

	if summary.TransitiveCount() > 0 {
		_, _ = fmt.Fprintf(stdout, "  transitive dependencies: %d\n", summary.TransitiveCount())
		_, _ = fmt.Fprintf(stdout, "  total known dependencies: %d\n", summary.TotalCount())
	}

	preview := summary.PreviewNames(5)
	if len(preview) == 0 {
		return 0
	}

	_, _ = fmt.Fprintf(stdout, "  sample packages: %s\n", strings.Join(preview, ", "))
	return 0
}

func buildRepoDependencySummary(repoPath string, detection ecosystem.Detection) (deps.Summary, error) {
	summary := deps.Summary{
		Direct:     make([]deps.Dependency, 0),
		Transitive: make([]deps.Dependency, 0),
	}

	if containsEcosystem(detection.Names, ecosystem.NPM) {
		npmSummary, err := npm.ParsePackageJSON(repoPath)
		if err != nil {
			return deps.Summary{}, err
		}

		if enriched, err := npm.EnrichFromYarnLock(repoPath, npmSummary); err == nil {
			npmSummary = enriched
		} else if enriched, err := npm.EnrichFromPackageLock(repoPath, npmSummary); err == nil {
			npmSummary = enriched
		}

		summary.Direct = append(summary.Direct, npmSummary.Direct...)
		summary.Transitive = append(summary.Transitive, npmSummary.Transitive...)
	}

	if containsEcosystem(detection.Names, ecosystem.Python) {
		pythonSummary, err := python.ParseRequirements(repoPath)
		if err != nil {
			return deps.Summary{}, err
		}
		summary.Direct = append(summary.Direct, pythonSummary.Direct...)
		summary.Transitive = append(summary.Transitive, pythonSummary.Transitive...)
	}
	if containsEcosystem(detection.Names, ecosystem.Maven) {
		mavenSummary, err := maven.ParsePOM(repoPath)
		if err != nil {
			return deps.Summary{}, err
		}
		summary.Direct = append(summary.Direct, mavenSummary.Direct...)
	}

	if containsEcosystem(detection.Names, ecosystem.Ruby) {
		rubySummary, err := ruby.ParseGemfileLock(repoPath)
		if err != nil {
			return deps.Summary{}, err
		}
		summary.Direct = append(summary.Direct, rubySummary.Direct...)
	}

	if containsEcosystem(detection.Names, ecosystem.Go) {
		goSummary, err := golang.ParseGoMod(repoPath)
		if err != nil {
			return deps.Summary{}, err
		}
		summary.Direct = append(summary.Direct, goSummary.Direct...)
		summary.Transitive = append(summary.Transitive, goSummary.Transitive...)
	}

	if containsEcosystem(detection.Names, ecosystem.Cargo) {
		cargoSummary, err := cargo.ParseCargoLock(repoPath)
		if err == nil {
			summary.Direct = append(summary.Direct, cargoSummary.Direct...)
			summary.Transitive = append(summary.Transitive, cargoSummary.Transitive...)
		}
	}

	if containsEcosystem(detection.Names, ecosystem.Composer) {
		composerSummary, err := composer.ParseComposerLock(repoPath)
		if err == nil {
			summary.Direct = append(summary.Direct, composerSummary.Direct...)
			summary.Transitive = append(summary.Transitive, composerSummary.Transitive...)
		}
	}

	if containsEcosystem(detection.Names, ecosystem.NuGet) {
		nugetSummary, err := nuget.ParsePackagesLock(repoPath)
		if err == nil {
			summary.Direct = append(summary.Direct, nugetSummary.Direct...)
			summary.Transitive = append(summary.Transitive, nugetSummary.Transitive...)
		}
	}

	return summary, nil
}

func generateVulnReport(stdout io.Writer, stderr io.Writer, scanPath, outputDir, repoName string) int {
	if !vulnerability.IsGrypeAvailable() {
		_, _ = fmt.Fprintf(stderr, "  note: grype not available, skipping vulnerability scan\n")
		return 0
	}

	ctx := context.Background()
	vulnResults, err := vulnerability.ScanWithGrype(ctx, scanPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "  vulnerability scan failed: %v\n", err)
		return 0
	}

	// Print summary to terminal
	if vulnResults.TotalCount == 0 {
		_, _ = fmt.Fprintf(stdout, "  vulnerabilities found: 0\n")
	} else {
		_, _ = fmt.Fprintf(stdout, "  vulnerabilities found: %d\n", vulnResults.TotalCount)
		counts := vulnResults.CountBySeverity()
		for severity, count := range counts {
			_, _ = fmt.Fprintf(stdout, "    - %s: %d\n", severity, count)
		}
	}

	// Generate HTML report
	reportPath, err := vulnerability.GenerateHTMLReport(outputDir, repoName, vulnResults)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "  failed to generate HTML report: %v\n", err)
		return vulnResults.TotalCount
	}
	_, _ = fmt.Fprintf(stdout, "  HTML report: %s\n", filepath.Base(reportPath))
	return vulnResults.TotalCount
}

func containsEcosystem(names []ecosystem.Name, candidate ecosystem.Name) bool {
	for _, name := range names {
		if name == candidate {
			return true
		}
	}

	return false
}

func resolveScanRoot(root string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		root = "."
	}

	root = os.ExpandEnv(root)
	if root == "~" || strings.HasPrefix(root, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}

		if root == "~" {
			root = home
		} else {
			root = filepath.Join(home, strings.TrimPrefix(root, "~/"))
		}
	}

	return filepath.Abs(root)
}

func normalizeExportFormat(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case formatCycloneDX:
		return formatCycloneDX, nil
	case "cyclonedx-json":
		return "cyclonedx-json", nil
	case formatSPDX:
		return formatSPDX, nil
	case formatBoth:
		return formatBoth, nil
	default:
		return "", fmt.Errorf("%q (expected cyclonedx, cyclonedx-json, spdx, or both)", value)
	}
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `SBOMber scans workspaces of local Git repositories.

Usage:
  sbomber
  sbomber scan [path] [--format FORMAT] [--include-vulnerabilities] [--fail-on-vuln] [--no-color]
  sbomber github [--health] [--include-vulnerabilities] [--fail-on-vuln] [--format FORMAT] <repo-url>...
  sbomber gitlab [--health] [--include-vulnerabilities] [--fail-on-vuln] [--format FORMAT] [--instance URL] <repo-url>...
  sbomber trace <path> [package-name] [flags] [--no-color]
  sbomber verify <ground-truth-sbom> <generated-sbom> [--json]
  sbomber diff <old-sbom> <new-sbom> [--no-color]
  sbomber localise --canonical-scan <canonical-scan.json> [--out localisation.json] [--trace trace.json]
  sbomber version

Scan Flags:
  --format cyclonedx|cyclonedx-json|spdx|both   Export format (default: cyclonedx)
  --include-vulnerabilities                      Enable vulnerability scanning with Grype
  --fail-on-vuln                                 Exit non-zero if any vulnerabilities are found
  --no-color                                     Disable ANSI color output
  --health                                       Supply chain health metrics (github/gitlab)
  --instance <url>                               GitLab instance URL (default: https://gitlab.com)

Supported Ecosystems:
  npm, yarn, Python, Go, Maven, Ruby, Rust/Cargo, PHP/Composer, .NET/NuGet

Trace Flags:
  --tree                                Show full dependency tree
  --list                                List all dependencies with filters
  --ecosystem <name>                    Filter by ecosystem
  --scope <name>                        Filter by build-scope (runtime, dev, test, build-tooling)
  --type <name>                         Filter by dependency-type (direct, transitive)
  --source-file <path>                  Filter by source manifest file
  --min-depth <n>                       Minimum depth (default: 0)
  --max-depth <n>                       Maximum depth (default: no limit)

Verify Flags:
  --json                                Output results as JSON (for CI/CD)

Localise Flags (Component 3: which function does an advisory implicate?):
  --canonical-scan <file>               canonical-scan.json produced by the scan (required)
  --out <file>                          localisation.json to write (default: localisation.json)
  --trace <file>                        also write the per-method evidence trace
  --all-methods                         run every method, not just until the first answer
  --client-search                       also search commit messages for the vulnerability ID
  --max-tarball-mb <n>                  npm tarball download limit (default: 30)
  --timeout <duration>                  overall time budget (default: 15m)
  GITHUB_TOKEN                          environment variable used for GitHub API requests

Examples:
  sbomber
  sbomber scan .
  sbomber scan ../workspace --format cyclonedx-json --include-vulnerabilities
  sbomber github https://github.com/expressjs/express
  sbomber github --health --include-vulnerabilities https://github.com/lodash/lodash
  sbomber gitlab https://gitlab.com/namespace/project
  sbomber gitlab --instance https://gitlab.company.com https://gitlab.company.com/org/repo
  sbomber trace . lodash
  sbomber trace . --list --ecosystem cargo
  sbomber verify reference.cdx.xml my-output.cdx.xml
  sbomber diff v1.0.cdx.xml v1.1.cdx.xml

Environment:
  GITHUB_TOKEN    GitHub personal access token (recommended for higher rate limits)
  GITLAB_TOKEN    GitLab personal access token
`)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// localiseInput is the subset of canonical-scan.json the localiser reads.
type localiseInput struct {
	Scan struct {
		ScanID string `json:"scanId"`
	} `json:"scan"`
	Findings []struct {
		FindingID       string   `json:"findingId"`
		VulnerabilityID string   `json:"vulnerabilityId"`
		Aliases         []string `json:"aliases"`
		PURL            string   `json:"purl"`
		FixedVersion    string   `json:"fixedVersion"`
	} `json:"findings"`
}

// runLocalise reads canonical-scan.json and writes localisation.json:
// for each finding, the candidate functions the advisory implicates and how
// that was established. Downloaded package code is never executed.
func runLocalise(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("localise", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("canonical-scan", "", "canonical-scan.json to read (required)")
	out := fs.String("out", "localisation.json", "localisation.json to write")
	tracePath := fs.String("trace", "", "write the per-method evidence trace to this file")
	allMethods := fs.Bool("all-methods", false, "run every method even after one has answered")
	clientSearch := fs.Bool("client-search", false, "search commit messages for the vulnerability ID (one GitHub search per finding)")
	maxTarballMB := fs.Int64("max-tarball-mb", 30, "npm tarball download limit in MB")
	timeout := fs.Duration("timeout", 15*time.Minute, "overall time budget")
	osvURL := fs.String("osv-url", "", "OSV API base URL (default https://api.osv.dev)")
	githubURL := fs.String("github-api-url", "", "GitHub API base URL (default https://api.github.com)")
	registryURL := fs.String("registry-url", "", "npm registry base URL (default https://registry.npmjs.org)")

	if err := fs.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if *in == "" {
		_, _ = fmt.Fprintf(stderr, "Usage: sbomber localise --canonical-scan <canonical-scan.json> [--out localisation.json] [--trace trace.json]\n")
		return 2
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: read %s: %v\n", *in, err)
		return 2
	}
	var input localiseInput
	if err := json.Unmarshal(data, &input); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %s is not a canonical-scan.json document: %v\n", *in, err)
		return 2
	}
	if input.Scan.ScanID == "" {
		_, _ = fmt.Fprintf(stderr, "Error: %s has no scan.scanId\n", *in)
		return 2
	}

	findings := make([]localisation.Finding, 0, len(input.Findings))
	for _, f := range input.Findings {
		findings = append(findings, localisation.Finding{
			FindingID: f.FindingID, VulnerabilityID: f.VulnerabilityID, Aliases: f.Aliases,
			PURL: f.PURL, FixedVersion: f.FixedVersion,
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	loc := localisation.New(localisation.Options{
		GitHubToken:        os.Getenv("GITHUB_TOKEN"),
		MaxTarballBytes:    *maxTarballMB << 20,
		AllMethods:         *allMethods,
		ClientMethodSearch: *clientSearch,
		OSVBaseURL:         *osvURL,
		GitHubAPIBaseURL:   *githubURL,
		RegistryBaseURL:    *registryURL,
	})

	_, _ = fmt.Fprintf(stdout, "Localising %d finding(s) from %s\n", len(findings), input.Scan.ScanID)
	doc, traces := loc.LocaliseAll(ctx, input.Scan.ScanID, findings)

	for _, r := range doc.Results {
		syms := make([]string, 0, len(r.CandidateSymbols))
		for _, c := range r.CandidateSymbols {
			syms = append(syms, c.Symbol)
		}
		if len(syms) > 6 {
			syms = append(syms[:6], fmt.Sprintf("+%d more", len(r.CandidateSymbols)-6))
		}
		_, _ = fmt.Fprintf(stdout, "  %-8s %-16s %-36s %-18s %-6s %s\n",
			r.FindingID, r.VulnerabilityID, r.PURL, r.Method, r.Confidence, strings.Join(syms, ", "))
	}
	if doc.Summary != nil {
		_, _ = fmt.Fprintf(stdout, "Processed %d, unknown %d, by method %v\n",
			doc.Summary.FindingsProcessed, doc.Summary.UnknownCount, doc.Summary.ByMethod)
	}

	if err := writeJSONFile(*out, doc); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	_, _ = fmt.Fprintf(stdout, "Wrote %s\n", *out)
	if *tracePath != "" {
		if err := writeJSONFile(*tracePath, traces); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return 2
		}
		_, _ = fmt.Fprintf(stdout, "Wrote %s\n", *tracePath)
	}
	if ctx.Err() != nil {
		_, _ = fmt.Fprintf(stderr, "Warning: time budget exhausted; later findings may be unknown for that reason\n")
	}
	return 0
}

func writeJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
