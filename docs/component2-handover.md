# Component 2 completion and handover

Owner: Yevhen Hrekov. Paired reviewer: Bob (Component 3).

**Status:** handover prepared against the #179 implementation. This is not a
release sign-off or a claim that pending agreement/review has completed. The
source baseline is recorded in `evidence/s6-05/completion-draft-baseline.json`.

## Delivered scope

`sbomber usage` consumes canonical package occurrences and a local JavaScript /
TypeScript checkout. Tree-sitter extracts imports, calls and named application
functions. Package-occurrence resolution links observations to the supplied
inventory. Coverage makes incomplete source analysis visible. Narrow static
application call paths provide optional level-3 support.

The output is `usage-graph.json` 1.4.0. An import, a resolved call symbol and a
resolved entry-point path are distinct evidence levels. Reachability is
reachable, unknown or not_analysed; absence of a path is not unreachability.
The Go-only `sbomber reachability` command is a separate capability.

Dependency internals, whole-program execution and exploitability are outside
this scope. Fixed directory pruning, grammar limitations, root-only tsconfig
aliases and unsupported frameworks/formats remain documented in the README.

## Completion map

| Deliverable | Evidence | Remaining step |
|---|---|---|
| Production JS/TS analysis, coverage and usage CLI | `internal/sourceanalysis/`, `internal/usagegraph/`, `internal/cli/usage.go`, `contracts/usage-graph.schema.json` | Verify once on final accepted main. |
| Narrow R1.3 reachability | Architecture sections 10-11; path and callback safety tests | Preserve documented boundary; no feature expansion required for handover. |
| Per-construct usage evaluation (#149) | `evidence/s6-04/report.md`, `manifest.json`; labelled usage fixtures | Issue closure confirmed. Historical report has its own analyser commit. |
| Reachability evaluation (#152) | `evidence/s6-14/report.md`, original run-01 and review-status.json | Issue closure confirmed. Preserve original figures and denominators. |
| Computed-import and MDX policy (#151) | Architecture section 19; `evidence/s6-06/`; explicit C4 comment link | Issue closure confirmed. Existing source policy retained. |
| Indirect-use decision guard (#172 / PR #179) | Architecture section 20; six labelled policy cases; `evidence/issue172/run-01/` | Record C4 agreement, C3 review and accepted merge. Copied-function precision remains deferred. |
| Plain-language limitations (#150) | README; `evidence/s6-05/final-consistency-review.md` | Final paired consistency review and accepted-main record, then closure. |

Archived evaluations and new policy regressions are not one blended accuracy
score. Cross-component audit labels under #124 remain outstanding independently.

## Controlled demo

Run from the repository root after #179 is accepted, using the documented Go
version and CGO toolchain. These commands use hand-authored synthetic inventories
and localisation policy inputs. They demonstrate analysis and the join, not live
vulnerability discovery, production localisation or real-world accuracy.

```bash
(
  set -euo pipefail
  make build
  demo=$(mktemp -d "${TMPDIR:-/tmp}/sbomber-component2-demo-XXXXXX")

  for case in direct-positive-b copied-function direct-unimported-b; do
    fixture="$PWD/testdata/fixtures/indirect-usage-172/$case"
    mkdir "$demo/$case"
    bin/sbomber usage \
      --canonical-scan "$fixture/canonical-scan.json" \
      --repo "repo-172=$fixture/app" \
      --out "$demo/$case/usage-graph.json"
    bin/sbomber decide \
      --canonical-scan "$fixture/canonical-scan.json" \
      --usage-graph "$demo/$case/usage-graph.json" \
      --localisation "$fixture/localisation.json" \
      --out "$demo/$case/decision-results.json"
  done
  echo "Saved demo outputs: $demo"
)
```

Expected outcomes after the policy is accepted:

| Case | Usage evidence | Decision |
|---|---|---|
| direct-positive-b | Resolved merge call with an application path | usage_detected |
| copied-function | Conservative unresolved-use marker; no invented later path | unknown |
| direct-unimported-b | No application import of B; dependency-internal chain outside analysis | unknown |

For a real-repository example use the saved pinned Kirill89 run in
`evidence/s6-14/run-01/kirill89-prototype-pollution-explained/` and its report.
It demonstrates measured application call paths, not paths inside Lodash.
Do not substitute the controlled demo for the integrated installation/scan demo.

## Final accepted-main verification

After #179 and the documentation have been accepted, use a new clean worktree
at the agreed final main SHA; preserve existing worktrees and historical evidence.

1. Record the full Git commit, Go version, CGO configuration and parser versions.
2. Build and run the standard required Go/contract checks with inherited GitHub
   token variables removed only from test subprocesses.
3. Run `go test -count=1 -run '^TestIssue172' ./internal/cli ./internal/decision`.
4. Re-run the six-case policy runner with a new output directory. Check the saved
   states, binary/source hashes and explicit synthetic-provenance limitation.
5. Reproduce the documented Component 2 demo. Save commands and outputs and ask
   another team member to follow the instructions.
6. If a new #149 or #152 measurement run is needed, create a separate identified
   output/worktree; never overwrite old frozen evidence. Compare source changes
   first. A decision-only guard does not require inventing new reachability rates.
7. Record reviewer agreement, exact accepted SHA and remaining limitations in a
   final validation record. Close issues only when their acceptance criteria hold.

No final-main run or second-person reproduction is claimed by this prepared
handover. No release date or completed S6-13 freeze is inferred from older plans.

## Short explanation for the presentation

“I built the JavaScript and TypeScript source-analysis component. It records
which dependency symbols the application imports and calls, and traces supported
static call paths from application entry points. When a path or use cannot be
established, it records uncertainty rather than claiming the dependency is unused.
I evaluated usage by construct and reported real-repository path resolution
separately, with coverage limits and reproducible evidence.”
