package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Xsamsx/SBOMber/internal/sourceanalysis"
	"github.com/Xsamsx/SBOMber/internal/usagegraph"
)

// maxPackageJSONBytes bounds the root package.json read for entry points.
const maxPackageJSONBytes = 1 << 20

// repeatedFlag collects a flag that may be given more than once.
type repeatedFlag []string

func (values *repeatedFlag) String() string { return strings.Join(*values, ",") }

func (values *repeatedFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

const usageCommandHelp = "Usage: sbomber usage --canonical-scan <canonical-scan.json> [--out usage-graph.json] [--repo [repositoryId=]<path>] [--entry [repositoryId=]<file>:<function>[:line]]"

// runUsage reads canonical-scan.json, analyses each local repository's
// JavaScript/TypeScript source and writes usage-graph.json (Component 2).
//
// Exit codes: 0 when the analysis is complete; 2 for bad input, a missing
// repository, or an analysis that is partial or failed. A partial graph is
// still written so its coverage can be inspected; --allow-partial returns 0
// for it instead.
func runUsage(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("usage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("canonical-scan", "", "canonical-scan.json to read (required)")
	out := fs.String("out", "usage-graph.json", "usage-graph.json to write")
	var repoOverrides, entries repeatedFlag
	fs.Var(&repoOverrides, "repo", "local source path for a repository, as [repositoryId=]path (repeatable)")
	fs.Var(&entries, "entry", "declared entry point, as [repositoryId=]file:function[:line] (repeatable)")
	noReachability := fs.Bool("no-reachability", false, "skip the reachability pass; call sites report not_analysed")
	allowPartial := fs.Bool("allow-partial", false, "exit 0 when the analysis is partial")
	maxFiles := fs.Int("max-files", sourceanalysis.DefaultMaxSourceFiles, "maximum candidate source files considered per repository")
	maxFileBytes := fs.Int64("max-file-bytes", sourceanalysis.DefaultMaxSourceBytes, "maximum size of one source file in bytes")
	maxScanBytes := fs.Int64("max-canonical-scan-bytes", usagegraph.DefaultMaxCanonicalScanBytes, "maximum size of canonical-scan.json in bytes")

	if err := fs.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if *in == "" || fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, usageCommandHelp)
		return 2
	}
	fail := func(format string, values ...any) int {
		_, _ = fmt.Fprintf(stderr, "Error: "+format+"\n", values...)
		return 2
	}

	file, err := os.Open(*in)
	if err != nil {
		return fail("open %s: %v", *in, err)
	}
	scan, err := usagegraph.ReadCanonicalScan(file, *maxScanBytes)
	_ = file.Close()
	if err != nil {
		return fail("%s: %v", *in, err)
	}
	if scan.Scan.Status != "" && scan.Scan.Status != "complete" {
		_, _ = fmt.Fprintf(stderr, "Warning: canonical scan status is %q; packages it skipped are not in this usage graph either\n", scan.Scan.Status)
	}

	// Which repositories to analyse, and where their source is.
	paths, err := repositoryPaths(scan, *in, repoOverrides)
	if err != nil {
		return fail("%v", err)
	}
	occurrences := scan.OccurrenceInputs()

	if len(paths) == 0 {
		graph, err := usagegraph.ProduceUnavailable(
			scan.Scan.ScanID, usagegraph.AnalysisUnsupported, "no_local_source", occurrences)
		if err != nil {
			return fail("%v", err)
		}
		if err := usagegraph.WriteGraph(*out, graph); err != nil {
			return fail("%v", err)
		}
		_, _ = fmt.Fprintf(stdout, "No repository in %s has local source, so usage was not analysed.\nWrote %s (status unsupported)\n", scan.Scan.ScanID, *out)
		return 2
	}

	defaultRepository := ""
	if len(paths) == 1 {
		for id := range paths {
			defaultRepository = id
		}
	}
	declared := make([]usagegraph.DeclaredEntryPoint, 0, len(entries))
	for _, spec := range entries {
		entry, err := usagegraph.ParseDeclaredEntryPoint(spec, defaultRepository)
		if err != nil {
			return fail("%v", err)
		}
		if _, known := paths[entry.RepositoryID]; !known {
			return fail("entry point %q names repository %q, which is not being analysed", spec, entry.RepositoryID)
		}
		declared = append(declared, entry)
	}

	ids := make([]string, 0, len(paths))
	for id := range paths {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	options := sourceanalysis.RepositoryOptions{
		MaxSourceFiles: *maxFiles,
		MaxSourceBytes: *maxFileBytes,
	}
	repositories := make([]usagegraph.RepositoryInput, 0, len(ids))
	for _, id := range ids {
		root := paths[id]
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			return fail("repository %s: source directory %s not found", id, root)
		}
		result, err := sourceanalysis.AnalyzeRepository(root, options)
		if err != nil {
			return fail("repository %s: %v", id, err)
		}
		packageJSON, err := readBoundedFile(filepath.Join(root, "package.json"), maxPackageJSONBytes)
		if err != nil {
			return fail("repository %s: %v", id, err)
		}
		aliases, err := readPathAliases(root)
		if err != nil {
			// Aliases only reclassify imports that match no package, so
			// without them the graph is noisier but never less safe.
			_, _ = fmt.Fprintf(stderr, "Warning: repository %s: %v; path aliases ignored\n", id, err)
		}
		repositories = append(repositories, usagegraph.RepositoryInput{
			RepositoryID: id,
			Result:       result,
			PackageJSON:  packageJSON,
			PathAliases:  aliases,
		})
	}

	graph, err := usagegraph.Produce(repositories, occurrences, usagegraph.ProduceOptions{
		ScanID:               scan.Scan.ScanID,
		Ecosystem:            "npm",
		AnalyzerID:           usagegraph.AnalyzerID,
		ReachabilityAnalysed: !*noReachability,
		DeclaredEntryPoints:  declared,
	})
	if err != nil {
		return fail("%v", err)
	}
	if err := usagegraph.WriteGraph(*out, graph); err != nil {
		return fail("%v", err)
	}

	printUsageSummary(stdout, graph, len(repositories))
	_, _ = fmt.Fprintf(stdout, "Wrote %s\n", *out)

	switch graph.Analysis.Status {
	case usagegraph.AnalysisComplete:
		return 0
	case usagegraph.AnalysisPartial:
		if *allowPartial {
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "Analysis is partial (see coverage in %s); exiting 2. Use --allow-partial to accept it.\n", *out)
		return 2
	default:
		_, _ = fmt.Fprintf(stderr, "Analysis status is %s; exiting 2.\n", graph.Analysis.Status)
		return 2
	}
}

// repositoryPaths returns repositoryId -> local source path. Paths in the
// canonical scan are resolved relative to the canonical-scan.json file.
// Remote repositories have no source and are left out unless --repo gives one.
func repositoryPaths(
	scan usagegraph.CanonicalScan,
	scanFile string,
	overrides []string,
) (map[string]string, error) {
	known := make(map[string]usagegraph.CanonicalRepository, len(scan.Scan.Repositories))
	for _, repository := range scan.Scan.Repositories {
		known[repository.RepositoryID] = repository
	}

	paths := make(map[string]string)
	base := filepath.Dir(scanFile)
	for _, repository := range scan.Scan.Repositories {
		if repository.Path == "" || (repository.Source != "" && repository.Source != "local") {
			continue
		}
		path := repository.Path
		if !filepath.IsAbs(path) {
			path = filepath.Join(base, path)
		}
		paths[repository.RepositoryID] = filepath.Clean(path)
	}

	for _, override := range overrides {
		id, path := "", override
		if equals := strings.Index(override, "="); equals > 0 &&
			!strings.ContainsAny(override[:equals], `/\`) {
			id, path = override[:equals], override[equals+1:]
		} else if len(known) == 1 {
			for only := range known {
				id = only
			}
		} else {
			return nil, fmt.Errorf("--repo %q: name the repository as repositoryId=path when the scan has %d repositories", override, len(known))
		}
		if _, exists := known[id]; !exists {
			return nil, fmt.Errorf("--repo %q: repository %q is not in the canonical scan", override, id)
		}
		if path == "" {
			return nil, fmt.Errorf("--repo %q: path is empty", override)
		}
		paths[id] = filepath.Clean(path)
	}
	return paths, nil
}

// readPathAliases reads compilerOptions.paths from the root tsconfig.json,
// if there is one.
func readPathAliases(root string) ([]usagegraph.PathAlias, error) {
	data, err := readBoundedFile(filepath.Join(root, "tsconfig.json"), maxPackageJSONBytes)
	if err != nil || data == nil {
		return nil, err
	}
	return usagegraph.ParseTSConfigPaths(data)
}

// readBoundedFile returns nil when the file does not exist.
func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return data, nil
}

func printUsageSummary(stdout io.Writer, graph usagegraph.Graph, repositories int) {
	coverage := graph.Coverage
	reasons := make(map[string]int)
	for _, occurrence := range graph.UnanalysedOccurrences {
		reasons[occurrence.Reason]++
	}
	reasonKeys := make([]string, 0, len(reasons))
	for reason := range reasons {
		reasonKeys = append(reasonKeys, reason)
	}
	sort.Strings(reasonKeys)
	reasonText := make([]string, 0, len(reasonKeys))
	for _, reason := range reasonKeys {
		reasonText = append(reasonText, fmt.Sprintf("%s %d", reason, reasons[reason]))
	}

	_, _ = fmt.Fprintf(stdout, "Usage analysis for %s: %s\n", graph.ScanID, graph.Analysis.Status)
	_, _ = fmt.Fprintf(stdout, "  Repositories      %d\n", repositories)
	_, _ = fmt.Fprintf(stdout, "  Source files      %d found, %d parsed, %d with errors, %d failed, %d skipped\n",
		coverage.FilesDiscovered, coverage.FilesParsed, coverage.FilesParsedWithErrors, coverage.FilesFailed, coverage.FilesSkipped)
	_, _ = fmt.Fprintf(stdout, "  Package imports   %d resolved, %d type-only, %d unresolved\n",
		coverage.ThirdPartyImportsResolved, coverage.ThirdPartyImportsTypeOnly, coverage.ThirdPartyImportsUnresolved)
	_, _ = fmt.Fprintf(stdout, "  Package calls     %d resolved, %d unresolved\n",
		coverage.ThirdPartyCallSitesResolved, coverage.ThirdPartyCallSitesUnresolved)
	if graph.Analyser.ReachabilityAnalysed {
		_, _ = fmt.Fprintf(stdout, "  Reachability      %d entry points, %d calls reachable, %d unknown\n",
			coverage.EntryPointsDetected, coverage.CallPathsResolved, coverage.CallPathsUnresolved)
	} else {
		_, _ = fmt.Fprintf(stdout, "  Reachability      not analysed\n")
	}
	if len(reasonText) != 0 {
		_, _ = fmt.Fprintf(stdout, "  Not imported/analysed  %s\n", strings.Join(reasonText, ", "))
	}
	if len(coverage.LimitsHit) != 0 {
		_, _ = fmt.Fprintf(stdout, "  Limits hit        %s\n", strings.Join(coverage.LimitsHit, ", "))
	}
}
