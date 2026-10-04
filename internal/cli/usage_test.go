package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/usagegraph"
)

type usageRepo struct {
	id     string
	path   string
	source string
}

type usageOcc struct {
	id, purl, repo, relationship string
}

func writeUsageScan(t *testing.T, dir string, repos []usageRepo, occs []usageOcc) string {
	t.Helper()
	repositories := []map[string]any{}
	for _, repo := range repos {
		entry := map[string]any{"repositoryId": repo.id, "path": repo.path}
		if repo.source != "" {
			entry["source"] = repo.source
		}
		repositories = append(repositories, entry)
	}
	occurrences := []map[string]any{}
	for _, occ := range occs {
		occurrences = append(occurrences, map[string]any{
			"occurrenceId": occ.id, "purl": occ.purl, "repositoryId": occ.repo,
			"manifest": "package.json", "relationship": occ.relationship,
			"dependencyPath": []string{}, "scope": "runtime",
		})
	}
	document := map[string]any{
		"schemaVersion": "1.0.0",
		"scan": map[string]any{
			"scanId": "scan-usage-test", "startedAt": "2026-09-29T00:00:00Z",
			"status": "complete", "repositories": repositories,
		},
		"components": []any{}, "occurrences": occurrences, "findings": []any{},
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "canonical-scan.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeUsageSource(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for relative, content := range files {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func runUsageCommand(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Main(append([]string{"usage"}, args...), strings.NewReader(""), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func readUsageGraph(t *testing.T, path string) usagegraph.Graph {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("usage graph not written: %v", err)
	}
	var graph usagegraph.Graph
	if err := json.Unmarshal(data, &graph); err != nil {
		t.Fatal(err)
	}
	return graph
}

func unanalysedReasons(graph usagegraph.Graph) map[string]string {
	reasons := make(map[string]string)
	for _, occurrence := range graph.UnanalysedOccurrences {
		reasons[occurrence.OccurrenceID] = occurrence.Reason
	}
	return reasons
}

// Success: a real contract file and a local repository produce a complete
// graph with a reachable call, and every occurrence is accounted for.
func TestUsageCommandWritesGraphFromContract(t *testing.T) {
	dir := t.TempDir()
	writeUsageSource(t, filepath.Join(dir, "app"), map[string]string{
		"package.json": `{"name":"app","main":"src/server.js"}`,
		"src/server.js": "import { merge } from 'lodash';\n" +
			"function handle(x) { return merge({}, x); }\n" +
			"handle({});\n",
	})
	scan := writeUsageScan(t, dir,
		[]usageRepo{{id: "repo-app", path: "app", source: "local"}},
		[]usageOcc{
			{"occ-lodash", "pkg:npm/lodash@4.17.21", "repo-app", "direct"},
			{"occ-axios", "pkg:npm/axios@1.7.0", "repo-app", "direct"},
			{"occ-nested", "pkg:npm/minimist@1.2.8", "repo-app", "transitive"},
			{"occ-python", "pkg:pypi/requests@2.31.0", "repo-app", "direct"},
		})
	out := filepath.Join(dir, "usage-graph.json")

	code, stdout, stderr := runUsageCommand(t, "--canonical-scan", scan, "--out", out)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Wrote "+out) {
		t.Fatalf("stdout = %q", stdout)
	}

	graph := readUsageGraph(t, out)
	if graph.SchemaVersion != usagegraph.SchemaVersion ||
		graph.ScanID != "scan-usage-test" ||
		graph.Analysis.Status != usagegraph.AnalysisComplete {
		t.Fatalf("graph header = %+v %+v", graph.SchemaVersion, graph.Analysis)
	}
	if len(graph.Observations) != 1 || graph.Observations[0].OccurrenceID != "occ-lodash" {
		t.Fatalf("observations = %+v", graph.Observations)
	}
	callSite := graph.Observations[0].CallSites[0]
	if callSite.Reachability != usagegraph.Reachable ||
		callSite.CallPath[0].Function != "<module>" {
		t.Fatalf("package.json main did not reach the call: %+v", callSite)
	}

	want := map[string]string{
		"occ-axios":  "not_imported_by_analysed_source",
		"occ-nested": "nested_under_dependency",
		"occ-python": "ecosystem_unsupported",
	}
	got := unanalysedReasons(graph)
	for id, reason := range want {
		if got[id] != reason {
			t.Fatalf("%s reason = %q, want %q (all: %v)", id, got[id], reason, got)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("unanalysed = %v", got)
	}
}

func TestUsageCommandDeclaredEntryPoint(t *testing.T) {
	dir := t.TempDir()
	writeUsageSource(t, filepath.Join(dir, "app"), map[string]string{
		"lib/jobs.js": "const { template } = require('lodash');\n" +
			"function nightly() { return render(); }\n" +
			"function render() { return template('x'); }\n",
	})
	scan := writeUsageScan(t, dir,
		[]usageRepo{{id: "repo-app", path: "app"}},
		[]usageOcc{{"occ-lodash", "pkg:npm/lodash@4.17.21", "repo-app", "direct"}})
	out := filepath.Join(dir, "usage-graph.json")

	code, _, stderr := runUsageCommand(t, "--canonical-scan", scan, "--out", out,
		"--entry", "lib/jobs.js:nightly")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	graph := readUsageGraph(t, out)
	if len(graph.EntryPoints) != 1 || graph.EntryPoints[0].Kind != "declared" {
		t.Fatalf("entry points = %+v", graph.EntryPoints)
	}
	callSite := graph.Observations[0].CallSites[0]
	if callSite.Reachability != usagegraph.Reachable || len(callSite.CallPath) != 2 {
		t.Fatalf("declared entry did not reach the call: %+v", callSite)
	}
}

// Failure paths: bad input is a tool error (exit 2) with a message.
func TestUsageCommandRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	writeUsageSource(t, filepath.Join(dir, "app"), map[string]string{"index.js": "export function f() {}\n"})
	good := writeUsageScan(t, dir,
		[]usageRepo{{id: "repo-app", path: "app"}},
		[]usageOcc{{"occ-1", "pkg:npm/lodash@4.17.21", "repo-app", "direct"}})

	notJSON := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(notJSON, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrongVersion := filepath.Join(dir, "wrong-version.json")
	data, _ := os.ReadFile(good)
	if err := os.WriteFile(wrongVersion,
		[]byte(strings.Replace(string(data), `"schemaVersion":"1.0.0"`, `"schemaVersion":"2.0.0"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	missingRepoDir := t.TempDir()
	missingRepo := writeUsageScan(t, missingRepoDir,
		[]usageRepo{{id: "repo-gone", path: "does-not-exist"}},
		[]usageOcc{{"occ-1", "pkg:npm/lodash@4.17.21", "repo-gone", "direct"}})
	unknownRepoDir := t.TempDir()
	unknownRepo := writeUsageScan(t, unknownRepoDir,
		[]usageRepo{{id: "repo-app", path: "app"}},
		[]usageOcc{{"occ-1", "pkg:npm/lodash@4.17.21", "repo-other", "direct"}})

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no canonical scan", []string{}, "Usage: sbomber usage"},
		{"missing file", []string{"--canonical-scan", filepath.Join(dir, "nope.json")}, "open"},
		{"not JSON", []string{"--canonical-scan", notJSON}, "decode canonical scan"},
		{"unsupported contract version", []string{"--canonical-scan", wrongVersion}, "supports 1.0.0"},
		{"repository directory missing", []string{"--canonical-scan", missingRepo}, "not found"},
		{"occurrence in unknown repository", []string{"--canonical-scan", unknownRepo}, "not in scan.repositories"},
		{"malformed entry", []string{"--canonical-scan", good, "--entry", "index.js"}, "missing file or function"},
		{"entry in unknown repository", []string{"--canonical-scan", good, "--entry", "repo-x=index.js:f"}, "not being analysed"},
		{"override for unknown repository", []string{"--canonical-scan", good, "--repo", "repo-x=/tmp"}, "not in the canonical scan"},
		{"oversized canonical scan", []string{"--canonical-scan", good, "--max-canonical-scan-bytes", "10"}, "larger than 10 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "usage-graph.json")
			code, _, stderr := runUsageCommand(t, append(tc.args, "--out", out)...)
			if code != 2 || !strings.Contains(stderr, tc.want) {
				t.Fatalf("exit %d, stderr %q, want exit 2 mentioning %q", code, stderr, tc.want)
			}
		})
	}
}

// Boundary: an unparseable component file makes the analysis partial. The
// graph is still written, and the exit code says it is incomplete.
func TestUsageCommandPartialAnalysis(t *testing.T) {
	dir := t.TempDir()
	writeUsageSource(t, filepath.Join(dir, "app"), map[string]string{
		"src/main.js": "export function main() { return 1; }\n",
		"src/App.vue": "<script>\nimport _ from 'lodash';\n</script>\n",
	})
	scan := writeUsageScan(t, dir,
		[]usageRepo{{id: "repo-app", path: "app"}},
		[]usageOcc{{"occ-lodash", "pkg:npm/lodash@4.17.21", "repo-app", "direct"}})
	out := filepath.Join(dir, "usage-graph.json")

	code, _, stderr := runUsageCommand(t, "--canonical-scan", scan, "--out", out)
	if code != 2 || !strings.Contains(stderr, "--allow-partial") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	graph := readUsageGraph(t, out)
	if graph.Analysis.Status != usagegraph.AnalysisPartial ||
		unanalysedReasons(graph)["occ-lodash"] == "not_imported_by_analysed_source" {
		t.Fatalf("partial graph = %+v, reasons %v", graph.Analysis, unanalysedReasons(graph))
	}

	code, _, stderr = runUsageCommand(t, "--canonical-scan", scan, "--out", out, "--allow-partial")
	if code != 0 {
		t.Fatalf("--allow-partial exit %d, stderr %q", code, stderr)
	}
}

// A repository with no local source (a remote, manifest-only scan) is not
// analysed, and its packages must not read as unused.
func TestUsageCommandRemoteRepositories(t *testing.T) {
	t.Run("mixed local and remote", func(t *testing.T) {
		dir := t.TempDir()
		writeUsageSource(t, filepath.Join(dir, "app"), map[string]string{"index.js": "export function f() { return 1; }\n"})
		scan := writeUsageScan(t, dir,
			[]usageRepo{
				{id: "repo-local", path: "app", source: "local"},
				{id: "repo-remote", path: "https://github.com/example/remote", source: "github"},
			},
			[]usageOcc{
				{"occ-local", "pkg:npm/lodash@4.17.21", "repo-local", "direct"},
				{"occ-remote", "pkg:npm/lodash@4.17.21", "repo-remote", "direct"},
			})
		out := filepath.Join(dir, "usage-graph.json")
		code, _, stderr := runUsageCommand(t, "--canonical-scan", scan, "--out", out)
		if code != 0 {
			t.Fatalf("exit %d, stderr %s", code, stderr)
		}
		reasons := unanalysedReasons(readUsageGraph(t, out))
		if reasons["occ-local"] != "not_imported_by_analysed_source" ||
			reasons["occ-remote"] != "excluded_by_limits" {
			t.Fatalf("reasons = %v", reasons)
		}
	})

	t.Run("remote only", func(t *testing.T) {
		dir := t.TempDir()
		scan := writeUsageScan(t, dir,
			[]usageRepo{{id: "repo-remote", path: "https://github.com/example/remote", source: "github"}},
			[]usageOcc{{"occ-remote", "pkg:npm/lodash@4.17.21", "repo-remote", "direct"}})
		out := filepath.Join(dir, "usage-graph.json")
		code, _, _ := runUsageCommand(t, "--canonical-scan", scan, "--out", out)
		if code != 2 {
			t.Fatalf("exit %d, want 2", code)
		}
		graph := readUsageGraph(t, out)
		if graph.Analysis.Status != usagegraph.AnalysisUnsupported ||
			graph.Analysis.ReasonCode != "no_local_source" ||
			unanalysedReasons(graph)["occ-remote"] != "excluded_by_limits" {
			t.Fatalf("remote-only graph = %+v %v", graph.Analysis, unanalysedReasons(graph))
		}
	})

	t.Run("override supplies the source", func(t *testing.T) {
		dir := t.TempDir()
		source := filepath.Join(t.TempDir(), "checkout")
		writeUsageSource(t, source, map[string]string{"index.js": "import 'lodash';\n"})
		scan := writeUsageScan(t, dir,
			[]usageRepo{{id: "repo-remote", path: "https://github.com/example/remote", source: "github"}},
			[]usageOcc{{"occ-remote", "pkg:npm/lodash@4.17.21", "repo-remote", "direct"}})
		out := filepath.Join(dir, "usage-graph.json")
		code, _, stderr := runUsageCommand(t, "--canonical-scan", scan, "--out", out, "--repo", source)
		if code != 0 {
			t.Fatalf("exit %d, stderr %s", code, stderr)
		}
		graph := readUsageGraph(t, out)
		if len(graph.Observations) != 1 || graph.Observations[0].OccurrenceID != "occ-remote" {
			t.Fatalf("observations = %+v", graph.Observations)
		}
	})
}

// #121 acceptance case 6: zero discovered source files cannot support a
// negative. The repository has a package.json and nothing to parse.
func TestUsageCommandZeroSourceFilesIsNotNegative(t *testing.T) {
	dir := t.TempDir()
	writeUsageSource(t, filepath.Join(dir, "app"), map[string]string{
		"package.json": `{"name":"app"}`,
		"README.md":    "# no source here\n",
	})
	scan := writeUsageScan(t, dir,
		[]usageRepo{{id: "repo-app", path: "app"}},
		[]usageOcc{{"occ-lodash", "pkg:npm/lodash@4.17.21", "repo-app", "direct"}})
	out := filepath.Join(dir, "usage-graph.json")

	for _, test := range []struct {
		name string
		args []string
		want int
	}{
		{name: "default", want: 2},
		{name: "allow partial", args: []string{"--allow-partial"}, want: 0},
		{name: "without reachability", args: []string{"--no-reachability"}, want: 2},
		{name: "allow partial without reachability", args: []string{"--allow-partial", "--no-reachability"}, want: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string{"--canonical-scan", scan, "--out", out}, test.args...)
			code, _, stderr := runUsageCommand(t, args...)
			if code != test.want {
				t.Fatalf("exit %d, want %d; stderr %s", code, test.want, stderr)
			}
			graph := readUsageGraph(t, out)
			if graph.Analysis.Status != usagegraph.AnalysisPartial ||
				graph.Analysis.ReasonCode != "no_source_files" ||
				graph.Coverage.FilesDiscovered != 0 ||
				unanalysedReasons(graph)["occ-lodash"] != "no_source_files" {
				t.Fatalf("empty source graph = %+v", graph)
			}
			if graph.SchemaVersion != "1.4.0" {
				t.Fatalf("schema version = %q, want 1.4.0", graph.SchemaVersion)
			}
			if test.want == 2 && !strings.Contains(stderr, "Analysis is partial") {
				t.Fatalf("partial exit omitted its explanation: %q", stderr)
			}
		})
	}
}

func TestUsageCommandReadsTSConfigAliases(t *testing.T) {
	dir := t.TempDir()
	writeUsageSource(t, filepath.Join(dir, "app"), map[string]string{
		"tsconfig.json": "{\n  // app aliases\n  \"compilerOptions\": { \"paths\": { \"@app/*\": [\"./src/*\"], }, },\n}\n",
		"src/index.ts":  "import { handle } from '@app/api';\nexport function main() { return handle(); }\n",
		"src/api.ts":    "import { merge } from 'lodash';\nexport function handle() { return merge({}, {}); }\n",
	})
	scan := writeUsageScan(t, dir,
		[]usageRepo{{id: "repo-app", path: "app"}},
		[]usageOcc{{"occ-lodash", "pkg:npm/lodash@4.17.21", "repo-app", "direct"}})
	out := filepath.Join(dir, "usage-graph.json")

	if code, _, stderr := runUsageCommand(t, "--canonical-scan", scan, "--out", out); code != 0 {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
	graph := readUsageGraph(t, out)
	if graph.Coverage.ThirdPartyImportsUnresolved != 0 {
		t.Fatalf("alias import counted as an unresolved package: %+v", graph.Coverage)
	}

	// A broken tsconfig.json is a warning, not a failure.
	writeUsageSource(t, filepath.Join(dir, "app"), map[string]string{"tsconfig.json": "{ broken"})
	code, _, stderr := runUsageCommand(t, "--canonical-scan", scan, "--out", out)
	if code != 0 || !strings.Contains(stderr, "path aliases ignored") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestUsageCommandEmptyRepositoryAlongsideReachableSource(t *testing.T) {
	dir := t.TempDir()
	writeUsageSource(t, filepath.Join(dir, "app"), map[string]string{
		"index.js": "import { merge } from 'lodash';\nexport function main() { return merge({}, {}); }\n",
	})
	writeUsageSource(t, filepath.Join(dir, "empty"), map[string]string{
		"package.json": `{"name":"empty"}`,
	})
	scan := writeUsageScan(t, dir,
		[]usageRepo{{id: "repo-app", path: "app"}, {id: "repo-empty", path: "empty"}},
		[]usageOcc{
			{"occ-app", "pkg:npm/lodash@4.17.21", "repo-app", "direct"},
			{"occ-empty", "pkg:npm/chalk@5.3.0", "repo-empty", "direct"},
		})
	out := filepath.Join(dir, "usage-graph.json")
	for _, allowPartial := range []bool{false, true} {
		args := []string{"--canonical-scan", scan, "--out", out}
		want := 2
		if allowPartial {
			args = append(args, "--allow-partial")
			want = 0
		}
		code, _, stderr := runUsageCommand(t, args...)
		if code != want {
			t.Fatalf("exit %d, want %d; stderr %s", code, want, stderr)
		}
		graph := readUsageGraph(t, out)
		if graph.Analysis.Status != usagegraph.AnalysisPartial ||
			graph.Coverage.FilesDiscovered != 1 || graph.Coverage.FilesParsed != 1 ||
			unanalysedReasons(graph)["occ-empty"] != "no_source_files" {
			t.Fatalf("mixed repository graph = %+v", graph)
		}
		if len(graph.Observations) != 1 || graph.Observations[0].OccurrenceID != "occ-app" ||
			len(graph.Observations[0].CallSites) != 1 ||
			graph.Observations[0].CallSites[0].Reachability != usagegraph.Reachable {
			t.Fatalf("positive evidence lost: %+v", graph.Observations)
		}
	}
}
