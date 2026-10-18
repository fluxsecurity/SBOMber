# S6-05: README Known Limitations review

Issue: [#150](https://github.com/fluxsecurity/SBOMber/issues/150)
Date: 18 October 2026
Implementation baseline: `97b72cf` (merged main after PR #165)

## Change

Added a README Known Limitations section for Component 2 JavaScript/TypeScript
usage evidence and reachability. It explains application-source-only analysis,
dynamic calls/reflection, third-party callbacks, framework invocation, route
handler factories, anonymous default exports, re-exports, dynamic import
promises, syntax errors, unsupported source formats, TypeScript alias limits,
computed-import scope and incomplete coverage in plain language.

The section distinguishes imports, calls and static call paths. It states
that an unresolved path is not proof of absence, and that incomplete evidence
must not justify automated VEX `not_affected`. It also distinguishes the separate
Go `reachability` command from Component 2.

Only documentation changes. Existing computed-import and MDX behaviour stays
as implemented; policy changes remain under #151. No accuracy, precision/recall
or real-repository resolution-rate claim is introduced. #149 and #152 remain
separate evaluations; check this section again when #152 results are published.

## Implementation and regression evidence checked

Paths below are repository-relative. These are existing tests and source
checks, not new fixtures or a replacement for #152's measurements.

| README subject | Evidence checked |
|---|---|
| Application-source-only boundary, dynamic calls, framework injection | `docs/design/usage-graph-architecture.md`, section 16; application call-graph implementation in `internal/usagegraph/callgraph.go` |
| Third-party callbacks stay unknown | `TestProduceCallbackReferenceRemainsUnknown`; `TestNestedCallbackInsideRouteDoesNotBecomeReachable` |
| Static routes have limited support; factory calls are not entry points | `internal/sourceanalysis/routes.go`; `TestStaticRouteHandlerCandidates`; `TestAmbiguousOrComputedRoutesStayUnsupported` |
| Anonymous default export has no named graph target | Architecture section 16; function identities/exports in `internal/sourceanalysis/functions.go`, `exports.go` and `internal/usagegraph/entrypoints.go` |
| Re-export/import indirection is not a general resolved call path | `TestImportFormsNeverReadAsNotImported`; `TestDynamicImportsResolveSymbolsAndEdges`; `TestAwaitedDynamicImportRespectsBlockScope` |
| Syntax-error files yield no semantic evidence | Early return on `HasError` in `internal/sourceanalysis/extract.go`; partial-coverage accounting in `internal/usagegraph/coverage.go` |
| Vue/Svelte/Astro/MDX/Marko are unsupported and make coverage partial | `internal/sourceanalysis/repository.go`; `TestUnsupportedSourceFormatMakesAnalysisPartial` |
| Only root tsconfig paths; missing/ambiguous targets block negative conclusions | `internal/usagegraph/path_aliases.go`, `canonical_input.go`, `alias_safety.go`; `TestParseTSConfigPaths`; `TestMissingAliasTargetCannotSupportNegative` |
| Computed import in a build script affects unmatched packages repository-wide | `TestComputedImportDetailNamesTheLine`; `internal/usagegraph/computed_import_safety_test.go` |
| Excluded trees are outside scope; empty scope/limits cannot support a negative conclusion | `TestAnalyzeRepositoryExcludesUntrustedAndGeneratedTrees`; `TestAnalyzeRepositoryStopsAtSourceFileLimit`; `TestProduceEmptySourceScopeBlocksNegative`; `TestBuildPartialCoverageCountsOnlyInScopeFiles` |

## Validation

Executed on Go 1.26.9 with CGO enabled:

```text
go test -count=1 ./internal/sourceanalysis ./internal/usagegraph
ok github.com/Xsamsx/SBOMber/internal/sourceanalysis
ok github.com/Xsamsx/SBOMber/internal/usagegraph
```

`git diff --check` passed. Local Markdown links introduced by this change resolve.
No new tests were added because the change documents existing behaviour.
The existing full-suite results from the merged PRs are not presented as a new
full-suite run for this documentation change. Remote CI awaits publication.

Paired review: Component 3 owner (Bob), pending.
