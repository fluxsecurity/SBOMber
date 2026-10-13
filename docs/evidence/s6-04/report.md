# Sprint 6 Issue #149 — per-construct usage evaluation

Analyser Git commit: `e44fc80140a51362ad22eb8550d32b6a2dcc9a32`. Fixtures: **13**; construct categories: **11**.

All metrics are based on controlled, independently source-reviewed fixtures, not overall real-world scanner accuracy.
A call metric of N/A means no measurable resolved/unresolved calls were present, not 100% accuracy.

| Fixture | Import TP/FP/FN | Import P/R | Call TP/FP/FN | Call P/R | Unknown TP/FP/FN | Unknown P/R | Safety |
|---|---|---|---|---|---|---|---|
| [component2-s6-cjs-destructured](metrics/component2-s6-cjs-destructured.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-cjs-require](metrics/component2-s6-cjs-require.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-dynamic-computed](metrics/component2-s6-dynamic-computed.json) | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-dynamic-static](metrics/component2-s6-dynamic-static.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-esm-default](metrics/component2-s6-esm-default.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-esm-named](metrics/component2-s6-esm-named.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-esm-namespace](metrics/component2-s6-esm-namespace.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-import-type](metrics/component2-s6-import-type.json) | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-import-type-alias](metrics/component2-s6-import-type-alias.json) | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-package-subpath](metrics/component2-s6-package-subpath.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-reexport](metrics/component2-s6-reexport.json) | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | 1/0/0 | 100%/100% | PASS |
| [component2-s6-side-effect](metrics/component2-s6-side-effect.json) | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | 0/0/0 | N/A/N/A | PASS |
| [component2-s6-ts-path-alias](metrics/component2-s6-ts-path-alias.json) | 1/0/0 | 100%/100% | 1/0/0 | 100%/100% | 0/0/0 | N/A/N/A | PASS |

## Evidence and limitations

- Each fixture has a graph in `graphs/`, a per-fixture metrics file in `metrics/`, and provenance in `manifest.json`.
- Import evidence, resolved calls and unresolved calls are scored independently. False positives and false negatives are not blended.
- Computed imports, re-exports, type-only imports, side-effect imports and TS aliases receive additional conservative-evidence checks.
- The original `component2-s6-import-type` label was corrected after evaluation; its initial and correction commits are preserved in `manifest.json`. The independent alias type-only fixture was prelabelled and evaluated separately.
- This uses the production source analyser and usagegraph producer via a Go test exporter, not a complete end-to-end CLI scan. Reachability accuracy belongs to Issue #152.

## Reproduction

Run `python3 -B scripts/run_s6_usage_evaluation.py` from a clean committed worktree. The runner removes inherited GitHub tokens from the Go test environment.
