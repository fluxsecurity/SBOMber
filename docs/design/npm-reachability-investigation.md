# npm reachability: investigation, paused pending coordination

Owner: Sadman (Component 1). Status: **paused** — not built, on purpose.

## What was asked

Scan a repo's npm dependencies, use tree-sitter to determine which
functions the application's own code actually calls, cross-reference
against a "risk chart" of known-vulnerable functions, and surface a
reachability-based risk score in the HTML vulnerability report — the same
idea as `docs/design/reachability.md`'s Go slice, but for npm/JavaScript,
which is explicitly the ecosystem that matters here.

Investigated before writing any code, per this session's standing
practice of verifying before building. Two findings changed the plan
before any implementation started.

## Finding 1: this is already someone else's in-progress work

`upstream/feature/component-2-usage-reachability` — an unmerged branch,
diverged significantly from this branch (it has its own
`internal/npm/package_lock.go`, different from the one written on this
branch this sprint) — contains `spikes/parser-bindings/DECISION.md`: a
rigorous, multi-week parser-binding selection spike. This is almost
certainly what Sprint 4's "S4-05" ticket actually was — the same ticket
this branch's `CGO_ENABLED=1` change (`docs/design/npm-identity-reconciliation.md`
predates this discovery, but the CI/Makefile CGO audit from the very start
of this sprint's work was done blind, reacting to a ticket description
rather than this decision record) was made to satisfy.

The decision, in brief (full detail in that branch's
`spikes/parser-bindings/DECISION.md`):

- Selected: the official `github.com/tree-sitter/go-tree-sitter` v0.25.0
  binding, with `tree-sitter-javascript` v0.25.0 and
  `tree-sitter-typescript` v0.23.2 — chosen over a pure-Go alternative
  (`github.com/odvcencio/gotreesitter`) that failed to parse a real,
  pinned Lodash 4.17.21 bundle (`no_stacks_alive`, an unresolved parser
  compatibility failure) despite winning on packaging (no CGO).
- Explicitly documents CGO_ENABLED=1, a dynamically-linked Linux artifact,
  and a glibc 2.34 floor as consequences **for Component 1** — i.e., this
  branch's CGO audit ticket existed because of this decision.
- Its own text: *"Component 2 must now port the proven extraction
  contract... to the Candidate A production adapter."* As of that branch's
  tip, only spike/evaluation harnesses exist under `spikes/parser-bindings/harness/{A,B}`
  — there is no production `internal/` package built on the selected
  binding yet, on that branch or this one.

Given this, building a parallel tree-sitter reachability implementation
right now risks duplicating Component 2's actual assigned scope, or
producing something that conflicts with their (already extensively
evidenced) architectural decisions once their branch merges. Decision:
**hold off, coordinate with Component 2 first**, rather than build
independently.

## Finding 2: no structured CVE-to-function data exists for npm

Go's vulnerability database (`golang.org/x/vulndb`, used by the Go
reachability slice — `docs/design/reachability.md`) gives structured,
machine-readable `affected[].ecosystem_specific.imports[].symbols` for
every entry: the exact function names a CVE affects. There is no npm
equivalent.

Verified directly against a real, well-known npm CVE rather than assumed:
[GHSA-p6mc-m468-83gw](https://github.com/advisories/GHSA-p6mc-m468-83gw)
(lodash prototype pollution, CVE-2020-8203), fetched from OSV.dev's live
API. The vulnerable function names — `pick`, `set`, `setWith`, `update`,
`updateWith`, `zipObjectDeep` — appear only in the free-text `details`
prose:

> "The functions `pick`, `set`, `setWith`, `update`, `updateWith`, and
> `zipObjectDeep` allow a malicious user to modify the prototype of
> Object..."

Not in any structured field. The `affected[].package` entries give
package name and version ranges only — no symbol-level data. Building a
"risk chart" would mean either parsing free-text advisory prose to guess
function names (unreliable, no session precedent for trusting an
unverified extraction like this), or hand-curating a small set of
well-documented CVEs one at a time. Decision: **pause the risk-chart
question rather than pick an approach under this open data gap** — this
needs more research (a better structured source, if one exists, or an
explicit decision to hand-curate and how large a set is worth maintaining)
before committing to a design.

## Not done, and not attempted

No tree-sitter dependency was added on this branch. No `internal/`
package for JS/TS parsing or usage extraction was written. Nothing in the
HTML report changed. This document exists so the investigation — which
branch owns this, and the data-availability gap — doesn't have to be
re-discovered next time this comes up.

## Before this resumes

1. Coordinate with Component 2: is `feature/component-2-usage-reachability`
   still active, when might the production adapter land, and does Component
   1's HTML-report integration wait for that or build against a stub
   contract in the meantime?
2. Resolve the CVE-to-function data source question: hand-curate a small,
   clearly-labeled set (matching this session's `SAMPLE-FIXTURE-VULN-0001`
   precedent in `docs/design/canonical-scan.md`), find a better structured
   source, or scope the feature down to package-level "does the app call
   into this vulnerable package at all" without a function-level claim.
