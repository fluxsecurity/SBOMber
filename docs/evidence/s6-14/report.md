# S6-14 / Issue #152 — reachability evaluation

## Objective and measured scope

Measure the delivered R1.3 application entry-point-to-third-party-call analysis separately from Issue #149 usage precision and recall. The client requested call-path evidence to support prioritisation where a path can be resolved. The question here is how often the delivered pipeline emits that evidence, and which boundaries prevent it.

This run uses the production `sbomber scan` inventory producer followed by production `sbomber usage`. No application was installed, built or executed. Vulnerability scanning, localisation and final risk decisions were not requested. These results therefore measure static application call-path evidence, not vulnerable-function reachability inside dependencies, exploitability or decision accuracy.

The default repository-wide source scope includes tests, configuration and tooling unless excluded by the analyser's fixed directory/file policy. Root tsconfig path aliases are read, but tsconfig `include`/`exclude` is not applied as a source selection policy. No manual entry points or improved inventories were introduced to increase the rates.

## Provenance and repository set

- Analyser checkout: `da36e17a530a9f29a9330e25d44b1e0585c7ac3d`, based on main `e2805c59d9b032f10bec72ee0220b0f33f952704`.
- Go: `go1.26.9 linux/amd64`; SBOMber reported version: `0.1.1`. The Git commit identifies the implementation more precisely than the release version.
- Tree-sitter Go binding: `0.25.0`; JavaScript grammar: `0.25.0`; TypeScript grammar: `0.23.2`; CGO enabled.
- Exact input configuration: [run-01/config.json](run-01/config.json). Maximum source files: 10,000; maximum file bytes: 1,000,000. Default entry detection and root tsconfig aliases.
- Full raw outputs and provenance: [run-01/manifest.json](run-01/manifest.json). The run began with a clean analyser worktree.
- All 259 recorded tracked analyser-source/go.mod/go.sum hashes match the supplied source snapshot. Canonical and graph hashes were independently recomputed during this review and match the manifest.
- Juice Shop is a new evaluation pin selected on 20 October from the then-current GitHub HEAD; it is not claimed to reproduce a previously recovered baseline.

| Repository | Source commit | Evaluation role |
|---|---|---|
| Kirill89/prototype-pollution-explained | `d7b5d98515a95f9a8cb0fedef034010ee083a6a9` | Pinned Component 2 demonstration **and** one audit case |
| juice-shop/juice-shop | `399fba76194305a312693eee44f4df64bdf0c3ce` | OWASP Juice Shop |
| appsecco/dvna | `9ba473add536f66ac9007966acb2a775dd31277a` | Audit case |
| gitaalekhyapaul/vuln-app | `0ddf9bdc9672cc53ebd66cb829382bd702a98876` | Audit case |

The five requested roles cover four unique repository/commit pairs. The demo/audit overlap is measured once, and no aggregate double-counts it.

## Denominators and interpretation

Primary resolution rate = `reachable / (reachable + unknown)` over emitted contract `callSites` records. `not_analysed` is reported separately and excluded. A zero denominator is N/A.

Contract call records are not unique runtime call expressions. They include unresolved-use markers at imports, and the representation may attribute multiple records to one expression. A source call not observed because of syntax errors, skipped files, unsupported syntax or dependency-internal execution does not appear in the denominator. File coverage must accompany every rate.

The runner also reports a symbol-resolved subset. A further explicit stratum below requires **both import identity and call symbol** to be resolved. These subsets explain the primary result; they do not replace it, and are not a way to exclude difficult cases from the headline measurement.

## Results

| Repository | Entry points | Reachable | Unknown | Not analysed | Primary denominator | Primary rate | Inventory status | Source-analysis status |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Demo / Kirill89 | 4 | 3 | 0 | 0 | 3 | 100.00% | partial | complete |
| Juice Shop | 8 | 2 | 5,595 | 0 | 5,597 | 0.04% | partial | partial |
| DVNA | 15 | 8 | 17 | 0 | 25 | 32.00% | partial | partial |
| TypeScript vuln-app | 4 | 1 | 5 | 0 | 6 | 16.67% | complete | complete |

The primary percentages are resolution rates over emitted records, not precision, recall or product-wide security accuracy. In particular, 100% on three demo records cannot establish general capability.

Inventory and source-analysis status describe different stages. The three partial inventories explicitly report missing npm lockfile coverage and absent transitive enumeration. `usage` can still report complete source analysis for the packages it was supplied, as in the demo. That does not make the overall inventory complete.

### Resolved and unresolved strata

| Repository | Resolved imports + resolved call symbols | Reachable within that stratum | Stratum rate | Resolved imports + unresolved call records | Unresolved imports + resolved call symbols | Unresolved imports + unresolved call records |
|---|---:|---:|---:|---:|---:|---:|
| Demo / Kirill89 | 3 | 3 | 100.00% | 0 | 0 | 0 |
| Juice Shop | 1,215 | 2 | 0.16% | 46 | 2,762 | 1,574 |
| DVNA | 22 | 8 | 36.36% | 2 | 1 | 0 |
| TypeScript vuln-app | 6 | 1 | 16.67% | 0 | 0 | 0 |

Juice Shop has 4,336 call records under imports unresolved against the supplied inventory. Source review confirms Angular declarations in `frontend/package.json`, while the saved canonical inventory covers the root inventory rather than those frontend packages. This is an inventory/source-scope mismatch in the measured pipeline. Even among the 1,215 records with resolved imports and call symbols, only two paths resolve. Both inventory coverage and the narrow application call-path model therefore constrain the result.

The runner's broader **symbol-only** subset contains 3,977 Juice Shop records (2 reachable, 3,975 unknown; 0.05%) and 23 DVNA records (8 reachable, 15 unknown; 34.78%). It retains symbol-resolved calls whose package identity is unresolved. This explains why those rates differ from the stricter stratum above.

### File coverage

| Repository | Discovered | Parsed cleanly | Parsed with syntax errors | Failed | Skipped | Unresolved imports with no call records |
|---|---:|---:|---:|---:|---:|---:|
| Demo / Kirill89 | 1 | 1 | 0 | 0 | 0 | 0 |
| Juice Shop | 657 | 616 | 39 | 0 | 2 | 266 |
| DVNA | 14 | 12 | 0 | 0 | 2 | 0 |
| TypeScript vuln-app | 6 | 6 | 0 | 0 | 0 | 0 |

No source file-count or file-size limit was hit. Directory exclusions are outside the discovery denominator. The current public graph exposes counts for skipped files and syntax-error files without their per-file lists; no specific filenames or individual skip causes are inferred from those counts. `parseFailures: []` describes failed files, and does not erase the 39 syntax-error files.

## Unknown-path categories

These categories use the first observable blocking condition in public output. A single record may have additional limitations; for example, an unresolved import can also sit inside a callback. Categories are disjoint by this precedence, not a complete causal decomposition.

| First observable blocking condition | Demo | Juice Shop | DVNA | TypeScript vuln-app |
|---|---:|---:|---:|---:|
| Import not in supplied inventory | 0 | 4,336 | 1 | 0 |
| Call outside supported syntax, with resolved import | 0 | 46 | 2 | 0 |
| No recorded enclosing function, with resolved import/call | 0 | 800 | 12 | 1 |
| No resolved entry-point path, with recorded owner and resolved import/call | 0 | 413 | 2 | 4 |
| **Total unknown** | **0** | **5,595** | **17** | **5** |

Every record, category and location is preserved in each repository's `run-01/<repository>/call-records.json`. Source-backed examples and hashes are in [source-review.json](source-review.json). The review is an assistant static inspection, not independent human labelling or paired-owner approval.

### Source-backed explanations

- **Known route path:** the demo's `index.js:42` PUT handler directly calls `_.merge` at line 55. Its saved one-step route path is consistent with the source. This stops at the dependency call; it does not analyse Lodash internals.
- **TypeScript route path:** `api/app.ts:19` in vuln-app directly calls `unserialize(payload)` at line 22. The saved path references that handler.
- **Juice Shop paths:** `server.ts:199` calls `config.get` in middleware starting at line 198; `server.ts:284` invokes the `express.static` factory inside the handler starting at line 271. Both saved paths identify the corresponding handler.
- **Callback reference becomes a marker:** Juice Shop imports `safeLoad` at `data/staticData.ts:3` and passes it to `.then(safeLoad)` at line 10. The graph's unresolved-use record is located at the import. It is not a directly observed `safeLoad(...)` expression. The later invocation is delegated to Promise machinery.
- **Anonymous callbacks:** Juice Shop's `data/datacreator.ts:172` calls `config.get` inside nested `flatMap`/`map` arrows. That record lacks an enclosing function. This supports a callback/owner-attribution limitation for this inspected example, not a universal explanation for all 800 records.
- **CommonJS member-exported handlers:** DVNA's `core/appHandler.js:197` calls `mathjs.eval` inside `module.exports.calc = function (...)`; `routes/app.js:60` registers `appHandler.calc` with middleware arguments. The dependency call resolves, but its anonymous member-exported owner and member-expression route registration do not yield a path. This is a source-supported boundary case, not an absent runtime route.
- **Missing inventory identity:** DVNA's `server.js:16` calls `bodyParser.urlencoded`, but the supplied inventory has no matching direct occurrence. Retain `unknown`; do not manufacture an inventory match.
- **Compiled entry:** vuln-app declares `main: ./build/app.js`, while source analysis reads `api/app.ts`. Startup calls such as `express()` at `api/app.ts:8` have a recorded module owner but no entry path. Detected route entries still support the call at line 22. Do not infer that module initialisation cannot execute.
- **Tooling and nonshipping source remain counted:** Juice Shop's `cypress.config.ts:8` calls `defineConfig` in a configuration module; vuln-app's `exploit-poc/poc.js:33` calls `serialize` inside a child-process output callback. Both are part of the default repository-wide measurement, not evidence of shipped application reachability.

The location heuristic flags 1,620 possible import-site markers in Juice Shop and two in DVNA. Reviewed examples confirm that such markers exist, but the contract has no explicit marker flag. These counts are review candidates, not a verified exact marker/expression split; none was removed from the primary denominator.

## Controlled correctness checks

The saved Go JSON test log [run-01/fixture-tests.jsonl](run-01/fixture-tests.jsonl) records passes for all four existing hand-authored frozen fixtures:

| Fixture | Expected behaviour |
|---|---|
| component2-usage-reachable | Entry `postWelcome` → cross-file `handleRequest` → dependency `merge` call |
| component2-usage-unknown | Disconnected function call remains unknown |
| component2-usage-callback | Direct `forEach` call resolves; callback-only `merge` path stays unknown |
| component2-usage-route | Recognised route → `sendWelcome` → `renderWelcome` → dependency call |

These compare production output with pre-existing labels. They are separate controlled correctness checks, not real-repository accuracy percentages and not part of #149 precision/recall.

## Validation and reproducibility

The original run records schema conformance plus cross-contract invariant validation: demo 73 checks, Juice Shop 32,713, DVNA 339, and vuln-app 907. Each production usage run was repeated on the identical canonical input and produced byte-identical graphs. Usage exit codes were respectively 0, 2, 2 and 0, consistent with complete/partial source-analysis status. All inventory-only `scan` commands returned 0; partial inventory statuses and explanations remain visible in the canonical files.

Reproduce from analyser commit `da36e17a530a9f29a9330e25d44b1e0585c7ac3d`, using Python with `contracts/requirements.txt` installed:

```bash
export GOCACHE="$PWD/.cache/go-build"
python3 -B scripts/evaluate_reachability.py \
  --config docs/evaluation/reachability-repositories.json \
  --work-dir /home/sbomber1/dev/sbomber/evaluation-repos-152 \
  --out docs/evidence/s6-14/reproduction-01
```

The output directory must be new. Existing cache checkouts must match the pinned SHAs and contain no tracked changes, untracked files or ignored build/install outputs. The runner never resets an existing checkout. Its manifest preserves exact argv, environment clock, grammar versions, source hashes and input/output hashes. Absolute paths may differ on another machine; the byte-identical check establishes repeatability for identical saved input within a run, not universal path-independent artifact hashes.

The supplementary stratum table can be recomputed from each raw graph by counting `(observation.resolution, call.resolution, call.reachability)` for every observation/call pair. [source-review.json](source-review.json) stores these integer counts and the raw graph hashes. No analyser rerun or manually edited graph was used to produce the supplement.

## Safety dependencies and conclusion

The narrow R1.3 slice produces useful static path evidence in the small demo and the TypeScript route case. Most emitted records on the larger repository remain unknown. This result reflects limited entry detection, call-owner tracking and callback/route handling, compounded by inventory and source-selection coverage. It is not evidence that those dependencies or functions are unreachable.

Issue #151 remains separate. Juice Shop's computed import at `scripts/package.mjs:21` has zero call records, so it does not enter this reachability denominator. It still affects unmatched-package classification repository-wide under current policy. Any scope-policy change requires checking whether these measurements need rerunning.

Issue #172 remains a safety dependency. In vuln-app, `api/app.ts:9` configures EJS as the view engine and line 14 calls `res.render`, while the direct `ejs@3.1.6` occurrence is recorded as `not_imported_by_analysed_source`. This confirms the Component 2 absence-of-direct-import evidence gap. This run contains no vulnerability findings or final decisions, so it does **not** newly confirm a downstream unsafe downgrade. A separate real `usage → decide` case is needed to verify that outcome. These rates provide no justification for reducing risk or producing a negative VEX assertion.

No production implementation change was required to report these findings. Full repository checks passed on 20 October 2026; see validation.md and checks/. Paired-owner review remains pending. Keep #152 open until required checks, review, saved evidence and PR merge are complete.
