# Sprint 6 Issue #149 — per-construct usage evaluation

Analyser Git commit: `d8ab2e24ed61415ae7df559a04d20576a897bcd4`. Fixtures: **21**; construct categories: **11**.

All metrics are based on controlled, author-labelled fixtures, not overall real-world scanner accuracy.
A call metric of N/A means no measurable resolved/unresolved calls were present, not 100% accuracy.
Many cells contain just one labelled item. Read the TP/FP/FN counts and denominators before interpreting percentages.

| Fixture | Import TP/FP/FN | Import P/R | Call TP/FP/FN | Call P/R | Unknown TP/FP/FN | Unknown P/R | Safety |
|---|---|---|---|---|---|---|---|
| [component2-s6-bare-require](metrics/component2-s6-bare-require.json) | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-cjs-destructured](metrics/component2-s6-cjs-destructured.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-cjs-function](metrics/component2-s6-cjs-function.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-cjs-inline](metrics/component2-s6-cjs-inline.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-cjs-require](metrics/component2-s6-cjs-require.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-cjs-shorthand](metrics/component2-s6-cjs-shorthand.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-dynamic-computed](metrics/component2-s6-dynamic-computed.json) | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-dynamic-static](metrics/component2-s6-dynamic-static.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-esm-alias](metrics/component2-s6-esm-alias.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-esm-default](metrics/component2-s6-esm-default.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-esm-named](metrics/component2-s6-esm-named.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-esm-namespace](metrics/component2-s6-esm-namespace.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-import-type](metrics/component2-s6-import-type.json) | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-import-type-alias](metrics/component2-s6-import-type-alias.json) | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-inline-type](metrics/component2-s6-inline-type.json) | 2/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-package-subpath](metrics/component2-s6-package-subpath.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-reexport](metrics/component2-s6-reexport.json) | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | 1/0/0 | 100%/100% | PASS |
| [component2-s6-reexport-star](metrics/component2-s6-reexport-star.json) | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | 1/0/0 | 100%/100% | PASS |
| [component2-s6-scoped-subpath](metrics/component2-s6-scoped-subpath.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-side-effect](metrics/component2-s6-side-effect.json) | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-ts-path-alias](metrics/component2-s6-ts-path-alias.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |

## Aggregated results by construct

Counts are TP/FP/FN. P/R denominators are predicted/expected respectively.

| Construct | Imports: counts; P/R; denominators | Calls: counts; P/R; denominators | Unknown: counts; P/R; denominators |
|---|---|---|---|
| cjs_destructured | 2/0/0; 100%/100%; 2/2 | 2/0/0; 100%/100%; 2/2 | 0/0/0; N/A/N/A; 0/0 |
| cjs_require | 4/0/0; 100%/100%; 4/4 | 3/0/0; 100%/100%; 3/3 | 0/0/0; N/A/N/A; 0/0 |
| dynamic_import | 2/0/0; 100%/100%; 2/2 | 1/0/0; 100%/100%; 1/1 | 0/0/0; N/A/N/A; 0/0 |
| esm_default | 1/0/0; 100%/100%; 1/1 | 1/0/0; 100%/100%; 1/1 | 0/0/0; N/A/N/A; 0/0 |
| esm_named | 2/0/0; 100%/100%; 2/2 | 2/0/0; 100%/100%; 2/2 | 0/0/0; N/A/N/A; 0/0 |
| esm_namespace | 1/0/0; 100%/100%; 1/1 | 1/0/0; 100%/100%; 1/1 | 0/0/0; N/A/N/A; 0/0 |
| import_type | 4/0/0; 100%/100%; 4/4 | 1/0/0; 100%/100%; 1/1 | 0/0/0; N/A/N/A; 0/0 |
| package_subpath | 2/0/0; 100%/100%; 2/2 | 2/0/0; 100%/100%; 2/2 | 0/0/0; N/A/N/A; 0/0 |
| reexport | 2/0/0; 100%/100%; 2/2 | 0/0/0; N/A/N/A; 0/0 | 2/0/0; 100%/100%; 2/2 |
| side_effect_import | 1/0/0; 100%/100%; 1/1 | 0/0/0; N/A/N/A; 0/0 | 0/0/0; N/A/N/A; 0/0 |
| ts_path_alias | 1/0/0; 100%/100%; 1/1 | 1/0/0; 100%/100%; 1/1 | 0/0/0; N/A/N/A; 0/0 |
| ALL | 22/0/0; 100%/100%; 22/22 | 14/0/0; 100%/100%; 14/14 | 2/0/0; 100%/100%; 2/2 |

## Evidence and limitations

- Original labels are author-labelled; review additions and label corrections are recorded separately in the manifest. No independent labelling claim is made.
- Each fixture has a graph in `graphs/`, a per-fixture metrics file in `metrics/`, and provenance in `manifest.json`.
- Import evidence, resolved calls and unresolved calls are scored independently. False positives and false negatives are not blended.
- Computed imports, re-exports, type-only imports, side-effect imports and TS aliases receive additional conservative-evidence checks.
- The original `component2-s6-import-type` label was corrected after evaluation; its initial and correction commits are preserved in `manifest.json`. The separate alias type-only fixture was prelabelled and evaluated separately.
- This uses the production source analyser and usagegraph producer via a Go test exporter, not a complete end-to-end CLI scan. Reachability accuracy belongs to Issue #152.

## Reproduction

Run `python3 -B scripts/run_s6_usage_evaluation.py` from a clean committed worktree. The runner removes inherited GitHub tokens from the Go test environment. `analyserGitCommit` is the last commit touching `cmd/`, `internal/`, `scripts/`, `testdata/`, `go.mod` or `go.sum`, so committing generated evidence alone does not change it. Preserve commit history when reproducing label provenance.
