# S6-05: final limitations consistency review

Issue: [#150](https://github.com/fluxsecurity/SBOMber/issues/150).
Prepared: 24 October 2026. Updated: 26 October 2026.
PR #179 is accepted on main at `8f7adedb2e1d6425b213cbeaa6300391b4cc90ee`.
The original preparation revision remains in `completion-draft-baseline.json`.
Fresh checks and the evidence-map result are saved under `accepted-main-20261026/`.
Final review of this documentation and its merge remain pending.

This supplements `README-known-limitations-review.md`. That file is a historical
18 October review: its references to pending #151/#152 work and the pre-#172
negative decision describe earlier revisions. Do not treat them as current status.

## README evidence map

Paths are relative to the repository root. Source inspection supports a statement
of implementation scope; it does not establish accuracy for unlabelled constructs.

| README limitation | Implementation / regression evidence | Relationship to evaluation |
|---|---|---|
| Application source only; dependency-internal use is not traced | `internal/usagegraph/producer.go`; `internal/cli/indirect_usage_policy_test.go`, `TestIssue172UsageToDecide`; `internal/decision/indirect_usage_policy_test.go` | #172 reproduces transitive and direct-unimported cases through production usage -> decide. Synthetic policy cases are separate from #149/#152. |
| Copied and destructured functions preserve unresolved import-site evidence | `internal/sourceanalysis/copied_imports_test.go`, `TestCopiedImportsRemainUnresolved`; #172 copied-function and destructured-copy cases | No later call or path is invented. S6-14 marker records remain in the original denominator. |
| Dynamic member access, third-party callbacks and framework invocation | Architecture section 16; `internal/usagegraph/producer_callback_test.go`, `TestProduceCallbackReferenceRemainsUnknown`; `internal/usagegraph/route_safety_test.go`, `TestNestedCallbackInsideRouteDoesNotBecomeReachable` | Unresolved reachability is unknown, not a statement of non-execution. Framework support is limited to implemented recognisers. |
| Route factories and anonymous default exports | `internal/sourceanalysis/routes.go`, `routes_test.go`; `internal/sourceanalysis/functions.go`, `exports.go`; `internal/usagegraph/entrypoints.go` | Source review identifies boundaries. No per-construct accuracy percentage is claimed for these unsupported paths. |
| Re-exports and dynamic import promises | `internal/usagegraph/import_forms_safety_test.go`; `internal/usagegraph/dynamic_alias_test.go`, `TestDynamicImportsResolveSymbolsAndEdges`, `TestAwaitedDynamicImportRespectsBlockScope` | Static/awaited support does not imply arbitrary promise/callback/re-export resolution. |
| Syntax errors and grammar gaps | `internal/sourceanalysis/extract.go`; `internal/usagegraph/coverage.go` | Error files provide no semantic evidence. filesParsedWithErrors and partial status expose incomplete coverage; public parseFailures is not a syntax-error filename list. |
| Unsupported formats, including prose MDX | `internal/sourceanalysis/repository.go`; `internal/usagegraph/s606_scope_policy_test.go`, `TestS606MDXScope` | Included unsupported source makes analysis partial. Public counters do not expose the internal skipped-file list. |
| Root-only TypeScript alias configuration | `internal/cli/usage.go`, `readPathAliases`; `internal/usagegraph/path_aliases.go`, `alias_safety.go`; `TestParseTSConfigPaths`, `TestMissingAliasTargetCannotSupportNegative` | Missing aliases cannot be presented as resolved paths; nested configs and extends remain unsupported. |
| Repository-wide computed imports, including scripts | `internal/usagegraph/computed_import_safety_test.go`; `TestS606ComputedImportScope`, `TestS606ComputedImportRepositoryBoundary`, `TestS606ExcludedComputedImport` | #151 agreement is recorded in architecture section 19.1. This is separate from #172's absence-only decision policy. |
| Excluded directories, empty scope and minified/size limits | `internal/sourceanalysis/repository.go`, `repository_test.go`; `internal/usagegraph/empty_source_test.go`; `TestBuildPartialCoverageCountsOnlyInScopeFiles` | Directory pruning is outside the denominator. A complete status describes only the declared source scope; skipped/failed in-scope files constrain completeness. |
| Three evidence levels and honest reachability states | `internal/usagegraph/model.go`, `coverage.go`; `TestFrozenReachabilityPath`, `TestFrozenDisconnectedCallHasNoPath`, `TestProduceWithoutReachabilityUsesNotAnalysed` | Import evidence, calls and paths are distinct. There is no not_reachable result. |
| No automated negative VEX assertion | `internal/decision/results.go`; `internal/vex/`; contract validator's automated not_affected guard | Unknown and scoped negative decisions remain investigation statements under the selected VEX format. They do not establish exploitability or safety. |

## Check against the saved S6-14 results

The historical report is `docs/evidence/s6-14/report.md`; original graphs and
provenance remain under `run-01/`. Four unique pinned repository/commit pairs
serve five requested roles because the demo is also an audit case.

The README does not turn these resolution rates into product accuracy. Primary
rates count emitted contract call records, including conservative import-site
markers; records not emitted due to unsupported or excluded source are absent
from that denominator. not_analysed is reported separately. Inventory gaps and
source-analysis completeness are distinct; Juice Shop's frontend inventory gap
must not be described as a parser failure. Unknown path causes are observable
blocking conditions, not proven complete root-cause attribution.

#149 precision/recall is based on author-labelled controlled usage fixtures,
reported by construct. #152 path-resolution coverage is a different measurement.
Neither establishes whole-program vulnerability non-use.

The #172 policy changes downstream decisions, not the recorded #152 graphs.
Its missing-import guard prevents a negative in the direct-unimported case.
An observed import calling a different symbol can still produce a scoped
negative; the README explicitly retains that residual dependency-internal gap.

## Validation and closure status

The #172 validation record reports an expected failing original regression,
six passing proposed CLI cases with byte-identical usage graphs, build, full Go
tests, vet, lint, 235 contract fixture invariants, 26 contract tests and 35 script
tests. Those are the recorded #172 checks, not a fresh test run for this document.
New synthetic localisation inputs validate shape and decision-policy invariants;
production localisation provenance is explicitly not claimed for them.

This documentation change requires a whitespace and local-link check. No new
runtime test is introduced merely to restate the implementation.

Component 4 agreement for #172 is [recorded by Zane, 25 October 2026](https://github.com/fluxsecurity/SBOMber/pull/179#issuecomment-6395120754).
The fetched comment and checked head are saved in `issue172-component4-agreement.json`.
[Bob's Component 3 approval of #179](https://github.com/fluxsecurity/SBOMber/pull/179#pullrequestreview-5645862782)
and its merge are now recorded. His [#180 documentation review](https://github.com/fluxsecurity/SBOMber/pull/180#pullrequestreview-5645863494)
found no blockers and reported an independent three-case demo on the draft head.
The accepted-main record distinguishes that run from the fresh local main run;
implementation-tree equality is checked rather than claiming a new Bob run.

The #181 audit scope is now two active repositories / 46 findings (1 agree usage,
4 over-reported, 41 abstained). All 47 DVNA proposals remain provisional and
excluded. Historical 93-row evidence and the original #152 measurements are
preserved. #124 remains open; audit-set completion is not a C2 accuracy claim.

Before closing #150:

- Review the accepted-main checks, evidence map and updated handover.
- Obtain final paired approval on #180 after retargeting it to main.
- Merge #180 and confirm its reviewed documentation on main, then link the
  accepted record from #150 before closure.

#172's implementation agreement, paired approval and merge are recorded in this
handover. Its closure does not imply whole-program or dependency-internal tracing.
#124 remains shared audit work independent of Component 2 handover.
