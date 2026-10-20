# Issue #152 — reachability evaluation

Analyser checkout: `da36e17a530a9f29a9330e25d44b1e0585c7ac3d`.

Production `scan` (inventory only) → `usage`; no package install or execution, Grype, localisation or risk decision is performed.
This measures statically resolved paths to third-party calls, not exploitability or paths inside dependency source.

## Denominators

Primary rate = reachable / (reachable + unknown) over emitted contract call records. These records include conservative unresolved-use markers and may duplicate a source expression across observations. They are not a census of runtime calls.
Secondary rate uses only records with resolved call symbols. It excludes unresolved calls/markers and therefore describes a narrower subset. Neither rate includes not_analysed; zero denominator is N/A.
Unseen calls in parse failures, skipped source, unsupported syntax or dependency internals cannot be counted in either denominator. Read coverage alongside every rate. Import-only unresolved observations are reported separately.

## Repository results

| Repository | Commit | Status | Entries | Resolved | Unknown | Not analysed | Denominator | Rate | Resolved-symbol subset rate |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| kirill89-prototype-pollution-explained | `d7b5d98515a95f9a8cb0fedef034010ee083a6a9` | complete | 4 | 3 | 0 | 0 | 3 | 100.00% | 100.00% |
| juice-shop | `399fba76194305a312693eee44f4df64bdf0c3ce` | partial | 8 | 2 | 5595 | 0 | 5597 | 0.04% | 0.05% |
| appsecco-dvna | `9ba473add536f66ac9007966acb2a775dd31277a` | partial | 15 | 8 | 17 | 0 | 25 | 32.00% | 34.78% |
| gitaalekhyapaul-vuln-app | `0ddf9bdc9672cc53ebd66cb829382bd702a98876` | complete | 4 | 1 | 5 | 0 | 6 | 16.67% | 16.67% |

## kirill89-prototype-pollution-explained

Roles: pinned Component 2 evaluation repository, end-to-end audit repository.
Unknown categories: `{}`.
Files: 1 discovered, 1 parsed, 0 with syntax errors, 0 failed, 0 skipped.
Limits hit: `[]`. Unresolved imports without call records: 0.
Possible synthetic-marker records: 0. This is a location-based review aid, not an exact identification.
See `kirill89-prototype-pollution-explained/call-records.json` for every path, location and classification; `kirill89-prototype-pollution-explained/metrics.json` for counters, grammar versions and coverage.

## juice-shop

Roles: OWASP Juice Shop real-repository evaluation.
Unknown categories: `{"call_resolution:outside_supported_syntax": 46, "import_resolution:not_in_inventory": 4336, "no_recorded_enclosing_function": 800, "no_resolved_entry_point_path": 413}`.
Files: 657 discovered, 616 parsed, 39 with syntax errors, 0 failed, 2 skipped.
Limits hit: `[]`. Unresolved imports without call records: 266.
Possible synthetic-marker records: 1620. This is a location-based review aid, not an exact identification.
See `juice-shop/call-records.json` for every path, location and classification; `juice-shop/metrics.json` for counters, grammar versions and coverage.

## appsecco-dvna

Roles: end-to-end audit repository.
Unknown categories: `{"call_resolution:outside_supported_syntax": 2, "import_resolution:not_in_inventory": 1, "no_recorded_enclosing_function": 12, "no_resolved_entry_point_path": 2}`.
Files: 14 discovered, 12 parsed, 0 with syntax errors, 0 failed, 2 skipped.
Limits hit: `[]`. Unresolved imports without call records: 0.
Possible synthetic-marker records: 2. This is a location-based review aid, not an exact identification.
See `appsecco-dvna/call-records.json` for every path, location and classification; `appsecco-dvna/metrics.json` for counters, grammar versions and coverage.

## gitaalekhyapaul-vuln-app

Roles: end-to-end audit repository.
Unknown categories: `{"no_recorded_enclosing_function": 1, "no_resolved_entry_point_path": 4}`.
Files: 6 discovered, 6 parsed, 0 with syntax errors, 0 failed, 0 skipped.
Limits hit: `[]`. Unresolved imports without call records: 0.
Possible synthetic-marker records: 0. This is a location-based review aid, not an exact identification.
See `gitaalekhyapaul-vuln-app/call-records.json` for every path, location and classification; `gitaalekhyapaul-vuln-app/metrics.json` for counters, grammar versions and coverage.

## Ground truth and limitations

The existing four frozen reachability fixtures are checked separately in `fixture-tests.jsonl`: cross-file direct path, disconnected function, callback indirection and route handler. These are controlled correctness checks, not independently labelled real-repository accuracy estimates.
Unknown categories describe the first blocking condition observable in public output; they are not mutually exhaustive root causes. `no_resolved_entry_point_path` does not prove callback, dynamic dispatch or unreachability. Specific construct explanations require source review at saved locations before final submission.
The pinned demonstration repository and one audit repository are the same source and commit: one run covers both roles. No aggregate rate double-counts it.
Issue #172 remains a safety dependency: application-only analysis cannot exclude dependency-internal use of direct-but-unimported packages. These measurements do not validate downstream downgrades. No unsafe negative result is ruled out by this evaluation.
Issue #151 scope decisions are unchanged. Any subsequent change affecting analysis requires rerunning affected measurements.

## Reproduction

Use the exact saved config and analyser commit. Run `python3 -B scripts/evaluate_reachability.py --config CONFIG --work-dir CACHE --out NEW_OUTPUT`. The output directory must be new. Each source checkout must match its full SHA and be clean. The runner saves commands, exit codes, schema/invariant validation and SHA-256 hashes. It repeats usage with the identical canonical input and requires byte-identical graphs.
Saved canonical inventory is unmodified production output. A missing lockfile leaves range-only installed versions unknown; these must not be represented as resolved installed versions.
Evaluation evidence is provisional until construct-level source review, required full checks and paired-owner review are complete. This report alone does not close #152.
