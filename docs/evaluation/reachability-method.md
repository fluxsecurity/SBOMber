# Issue #152 reachability evaluation method

## Objective and scope

Measure the delivered Component 2 entry-point-to-third-party-call slice separately from issue #149 import/call precision and recall. The five requested repository roles contain four unique source repositories. The pinned demonstration and Kirill89 audit case share a commit and run.

Use the production inventory-only `scan` and `usage` commands, default entry detection, root tsconfig aliases, 10,000 maximum source files and 1,000,000 bytes per file. Do not add declared entry points to improve measured rates. Preserve partial output and exit 2; do not use `--allow-partial` to hide incomplete analysis. Parse source without installing or executing it. Installed package versions unavailable from lockfiles stay unknown; do not invent exact versions from ranges.

## Measurements

Primary: `reachable / (reachable + unknown)` over emitted contract call records. Cross-check record counts against all public call and path counters. Show numerator, denominator and `not_analysed` separately. An empty denominator is N/A.

The public contract's `callSites` includes conservative unresolved-use markers located at imports. It can also attribute multiple records to one expression. Do not describe its total as unique call expressions. Secondary: the same rate restricted to records with `resolution: resolved`; these records are actual symbol-resolved calls and exclude synthetic unresolved-use markers. This secondary subset excludes unresolved real calls too; it is not a replacement estimate for all source calls.

An unresolved record at the import's exact file/line/column with no called symbol is flagged as a *possible* synthetic marker for review, never treated as a definitive classification or removed from the primary denominator. Exact marker versus expression attribution is not available in the current public schema.

Save entry points, full call paths, grammar metadata, parser failures, skipped/failed file counts, limits, unresolved import-only observations and unanalysed occurrence reasons. Neither denominator covers calls the analyser could not observe. A parse-failure count cannot be converted into a missing-call count.

## Unknown categories

Use the first observable blocking condition: unresolved import (with reason), unresolved call (with reason), no recorded enclosing function, or no resolved entry-point path. These are deterministic output categories, not causal proof about the source. Review representative saved locations to explain callbacks, framework invocation, computed calls and disconnected functions; do not infer these constructs merely from an unknown path. Save any manual annotation separately with the source SHA, file/line, source excerpt, reasoning and reviewer.

## Reproduction and evidence

Require full pinned source SHAs and pristine checkouts, including no ignored build/install artefacts. Never reset an existing checkout. Clone only into new cache subdirectories. Reuse existing cache paths only when they match and are clean. Freeze production timestamps with the repository commit time. Preserve exact config, argv, logs, exit codes, canonical inventory and graph. Save the analyser checkout SHA, all tracked Go source/go.mod/go.sum hashes, runner hash and working-tree status. Repeat usage on identical input and require byte-identical JSON.

Run the existing `TestFrozenUsageGroundTruth` test, which compares production results against the four committed labelled cases: direct cross-file path, disconnected function, callback indirection and route handler. Preserve Go JSON events and require all four cases to pass. Do not blend these controlled correctness checks with real-repository resolution rates.

Require JSON Schema plus the existing canonical/usage cross-contract invariant validator. This evaluation does not fabricate localisation or decision output just to invoke the four-contract CLI validator.

Example (after replacing the Juice Shop SHA):

```bash
python3 -B scripts/evaluate_reachability.py \
  --config docs/evaluation/reachability-repositories.json \
  --work-dir /home/sbomber1/dev/sbomber/evaluation-repos-152 \
  --out docs/evidence/s6-14/run-01
```

Output must be a new directory. A failed run remains marked failed with logs; retry into a new output directory after diagnosing it. The generated report is provisional until source review and full checks. Commit the runner and final config before the final evidence run, and keep evidence-only commits distinct for provenance.

## Safety and completion

Issue #172 is not implemented here. Missing direct application evidence says nothing conclusive about dependency-internal use. These rates do not justify `no_usage_detected` or a risk downgrade. A confirmed unsafe downgrade requires a separately evidenced release-blocker report. Keep issue #151 changes separate and rerun affected measurements if its scope policy changes.

Before PR: source-review unresolved examples, inspect actual paths, run relevant Component 2 tests, contract checks, `make build`, `make test`, `go vet ./...`, `golangci-lint run ./...`, and a nonmutating gofmt check. Obtain paired-owner review. Link saved evidence and leave the issue open until acceptance criteria are met and the PR is merged.
