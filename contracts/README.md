# SBOMber contracts

**Schema versions: `canonical-scan` 1.0.0 · `usage-graph` 1.2.0 · `localisation` 1.0.0 · `decision-results` 1.1.0**

Four JSON contracts. Each component reads and writes **files**, never another component's running code — that is what lets four people build in parallel and integrate in Sprint 5 instead of queueing behind each other.

```
contracts/
  canonical-scan.schema.json        component 1 produces
  usage-graph.schema.json           component 2 produces
  localisation.schema.json          component 3 produces
  decision-results.schema.json      component 4 produces
  fixtures/                         one sample of each, all describing the same scan
  validate.py                       schema + integrity + invariant checks
```

## Who reads what

| Contract | Produced by | Read by |
|---|---|---|
| `canonical-scan.json` | 1 — inventory and CI (Sadman) | 2, 3, 4 |
| `usage-graph.json` | 2 — usage evidence and reachability (Yevhen) | 4 |
| `localisation.json` | 3 — localisation and VEX (Bob) | 4 |
| `decision-results.json` | 4 — decision and report (Zane) | 3 (VEX exporter), 1 (CI policy) |

The last row is why there are four contracts and not three. Component 3 owns the VEX exporter, but a VEX statement expresses a *decision*, and component 4 makes decisions. Fixtures break the apparent cycle: component 3 builds its exporter against `fixtures/decision-results.sample.json` long before component 4's real output exists.

## Working against fixtures

```bash
# your component reads the sample instead of real upstream output
./sbomber scan ./demo-app --usage-graph-input contracts/fixtures/usage-graph.sample.json

# check what you produce
python3 contracts/validate.py --dir ./out
```

Nobody waits. If your component reads a fixture and writes a valid file, you are done for that sprint regardless of what anyone else has finished.

## The four identities

These come from R0 and are the reason the whole pipeline can join anything to anything:

| Object | Identity |
|---|---|
| Component | exact versioned PURL |
| Package occurrence | PURL + workspace + manifest + install path |
| Vulnerability finding | vulnerability ID + component PURL |
| Usage observation | package occurrence + imported symbol + import file + import line |
| Call site | observation + file + line |

A usage observation is **not** a finding. Component 2 records what the application imports and calls without knowing which vulnerabilities exist — component 4 makes that link later.

**Reachability belongs to the call site, not the observation.** One import can be used in several places, and those places do not share a verdict: `_.template` may be reachable from a route handler at `email.js:47` and unresolved at `email.js:92`. Attaching reachability to the observation would force one answer onto both, or force the same import to be published twice.

## What the validator enforces

Schema conformance is the easy half. These are the rules a JSON Schema cannot express, and they are where the project's safety actually lives:

**Identity (R0)**
- A version field must be a resolved version, never a range or an operator
- A constraint is never stored as the version
- The same PURL at the same install path cannot be both direct and transitive — that is the reconciliation bug
- Two occurrences cannot share an identity

**Usage evidence and reachability (R1)**
- `type_only` observations carry no call sites — TypeScript `import type` is erased at compile time
- An unresolved import states its reason; an unresolved call site states its own. Nothing is dropped silently
- `resolution` on an observation describes the **import binding only**. A namespace import is `resolved` even when a computed member access through it is not — that access is an unresolved call site, not an unresolved import
- `evidenceLevel` is **derived**, not asserted: the maximum across the observation's call sites
- `reachable` requires a resolved call site, a non-empty `callPath`, and an `entryPointId` present in `entryPoints`
- A call path starts at its entry point's function and ends at the enclosing function of the call
- A call site reporting `unknown` or `not_analysed` cannot carry a call path or an entry point
- `coverage.callPathsResolved` equals the number of **reachable call sites**; `callPathsUnresolved` the number reporting `unknown`. Both count call sites, never observations
- File counts sum: discovered = parsed + parsedWithErrors + failed + skipped
- Import locations are never inside `node_modules` — only application source is parsed
- **Every occurrence in `canonical-scan.json` appears either in `observations` or in `unanalysedOccurrences`.** This is the safety-critical rule: without it, "analysed and found nothing" and "never analysed" both look like silence

**There is no `not_reachable`.** `reachability` is `reachable`, `unknown` or `not_analysed`. Within an application-source-only analysis, failing to resolve a path describes the analysis, not the code — the same reasoning that forbids automated `not_affected`. The schema makes the unsafe value unrepresentable rather than relying on anyone remembering the rule.

`unknown` and `not_analysed` are not interchangeable. `unknown` means the level-3 pass ran on this call site and no path resolved. `not_analysed` means it did not run. A resolution rate computed without that distinction is meaningless.

**Localisation (R2)**
- Every downloaded artefact records `executed: false`. Downloaded package code is never executed
- `method: unknown` cannot carry candidate symbols
- An uncorroborated LLM result cannot claim high or medium confidence

**Decision and VEX (R3, R5)**
- **`not_affected` cannot be emitted without a named manual reviewer.** Automated suppression is forbidden
- `no_usage_detected` maps to the selected VEX investigation state: OpenVEX uses `under_investigation`; CycloneDX VEX uses `in_triage`. It never maps automatically to `not_affected`
- `unknown` cannot assert `affected` or `not_affected`
- `affected` requires reliable localisation, matched symbols, and an action statement — all three
- Localisation `unknown` cannot produce `no_usage_detected`; it produces `unknown`
- Justification text cannot contain "not affected", "is safe", "no risk" or "false positive"
- Distribution counts must match the decisions
- **A negative verdict requires that component 2 actually looked.** `no_usage_detected` is forbidden where the finding's occurrence was reported unanalysed for any reason other than `not_imported_by_analysed_source`

**Honesty**
- A scan reporting `complete` cannot have skipped files, hit limits, or a truncated tree
- A non-success enrichment source should explain itself

The VEX rule is the important one. VEX consumers *suppress* findings marked `not_affected`. Application-source-only analysis cannot prove vulnerable code is outside the execution path, so an automated `not_affected` would hide a real vulnerability in the consumer's pipeline rather than merely misreport it.

## Fixture scenario

All four fixtures describe one scan of `demo-app`, chosen to exercise the cases that break naive implementations:

| Finding | Package | Outcome | Why it is in the fixture |
|---|---|---|---|
| find-001 | lodash 4.17.20 | `usage_detected` | Advisory names `template`. One import (`obs-001`), two call sites: `email.js:47` is reachable from the `postWelcome` route handler via `sendWelcome`, `email.js:92` is `unknown`. One observation, two different answers — the case the old per-observation model could not express |
| find-002 | axios 0.21.0 | `no_usage_detected` | Advisory names nothing; diff yields two candidates, neither called. `obs-005` is a **resolved** namespace import with one **unresolved** call site (computed member access) — confidence is medium, not high |
| find-003 | minimist 1.2.5 | `unknown` | Prototype pollution with no single implicated symbol. Localisation honestly fails |
| find-004 | lodash 3.10.1 | `unknown` | **The case that matters.** Nested under `legacy-reporter`. There is no observation at all — `occ-002` appears in `unanalysedOccurrences` with reason `nested_under_dependency`, which is what makes this `unknown` rather than `no_usage_detected`. The app does import `legacy-reporter` itself (`obs-007`), but its internals are not parsed |

`find-004` also exercises the nested-version requirement: lodash appears at two versions, `4.17.20` at the root and `3.10.1` under `node_modules/legacy-reporter/node_modules/`. They must remain two distinct occurrences. Collapsing them is a new bug, not a fix.

The usage graph carries two entry points, five resolved third-party call sites and one unresolved one. Reachability resolves for exactly one call site and returns `unknown` for four — a 20% resolution rate, which is the expected shape rather than a defect. It also carries one computed dynamic import (`obs-006`) that resolves to no package at all, and three occurrences declared unanalysed, one of which (`occ-006`, a dev-scope build tool) is the only kind of unanalysed occurrence that may support a negative verdict.

The scan also records `malware: timed_out` — an enrichment source that failed. An empty result is not a clean result.

## Changing a schema

1. Producer and every consumer agree.
2. Bump `schemaVersion`.
3. Update the fixture in the same commit.
4. `python3 contracts/validate.py` passes.

After Week 2, a schema change is a team decision, not an individual one.

## CI

```makefile
contracts:
	python3 contracts/validate.py
```

The validator runs 167 invariant checks over the four fixtures. Fifteen deliberate regressions — a `reachable` call site with no path, an occurrence missing from both arrays, a negative verdict on an unanalysed occurrence, a per-observation path counter — are each caught by a named rule.

Run it on every pull request. Run it against real tool output before every demo.
