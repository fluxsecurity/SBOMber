# Canonical scan schema

Owner: Sadman (Component 1). Cross-reviewed by: Component 4 (pairs 1↔4).

## Why this exists

Prior work (commit `b905a4c`) claimed to introduce "a canonical identity model
that separates component, occurrence, finding, and usage evidence" in its
message. There is no such model in the codebase — no `Canonical*`,
`Occurrence`, or `UsageObservation` types exist anywhere under `internal/`,
and `git show --stat b905a4c` shows zero files changed. That commit message
described work that was never done. This document and the schema it
describes are the actual, checkable version of that claim.

## The four identities

A single dependency graph node conflates four things that must stay
separate, or a verdict computed against the wrong one produces exactly the
false negative this project exists to prevent:

1. **Component** — an exact versioned package, identified only by its PURL
   (`pkg:npm/lodash@4.18.1`). Same name, different version = different
   component.
2. **Package occurrence** — one appearance of a component in a workspace:
   component PURL + workspace + manifest path + dependency path. The same
   component can have multiple occurrences (e.g. resolved at two different
   versions under two different `node_modules` paths — see the npm identity
   reconciliation work for a concrete case this distinction is needed for).
3. **Vulnerability finding** — keyed by (vulnerability ID, component PURL),
   not by occurrence. A finding applies to a component everywhere it occurs.
4. **Usage observation** — occurrence + imported symbol + file + line + call
   site. This is the one identity the current scanner cannot produce: there
   is no static call-site analysis anywhere in SBOMber today. The schema
   defines the shape so downstream components can build against it, but
   every real scan will emit `usageObservations: []` until that capability
   is built. Don't read an empty array as "nothing uses this component" —
   read it as "not measured yet."

## Files

- [`docs/schema/canonical-scan.schema.json`](../schema/canonical-scan.schema.json)
  — JSON Schema (draft 2020-12), `schemaVersion` field inside the document
  itself for independent versioning from the CLI. Bump the major segment on
  any breaking change to a required field or an identity key.
- [`testdata/fixtures/canonical-scan/sample.canonical-scan.json`](../../testdata/fixtures/canonical-scan/sample.canonical-scan.json)
  — one realistic sample, built from the real `testdata/fixtures/npm-basic`
  fixture (the same one used for the ground-truth verification evidence at
  `testdata/fixtures/ground-truth/npm-basic/`). The one finding in it
  (`SAMPLE-FIXTURE-VULN-0001`) is a deliberately fake ID, not a real CVE/GHSA
  — `lodash@4.18.1` does not exist on the real npm registry (see that
  fixture's `METHOD.md`), so attaching a real advisory ID to it would itself
  be an unsourced claim.

## Status: library-level, not yet wired into the CLI

`sbomber scan` / `sbomber github` / `sbomber gitlab` still emit CycloneDX and
SPDX only (see `internal/sbom/export.go`); no CLI command reads or writes
`canonical-scan.json` yet. This document and schema are the contract
Components 2, 3, and 4 build their own work against for Sprint 4; wiring an
actual exporter into the CLI is follow-up work, not part of this ticket.

What does exist as real, tested code:

- `internal/canonicalscan` — Go types for all four identities
  (`Component`, `Occurrence`, `Finding`, `UsageObservation`), a structural
  `Validate` function, and `JoinFindingsByPURL`, which matches findings to
  components by **exact** PURL — no name-only fallback, because matching on
  name while ignoring version is the false-positive/false-negative class
  this model exists to prevent.
- `internal/vulnerability` — `VulnerabilityResult` now carries `PURL`
  (previously parsed from Grype's JSON output into an internal struct field
  and then silently discarded — it was never copied into the exported
  result type, so no finding could ever be joined to anything). A
  `(VulnerabilityResult).ToFinding()` method converts a Grype match into a
  `canonicalscan.Finding`, keyed by `vulnerabilityID + "|" + PURL`, or by
  the vulnerability ID alone when Grype could not resolve a PURL for the
  affected artifact (some matchers, e.g. binary classifiers, do not).
  `PackageVersion` (the installed version) and `FixState` /
  `PatchedVersions` (fix data) were already being captured before this
  ticket — the actual gap was PURL, not version or fix data, contrary to
  what this ticket was initially filed against.

Nothing in the CLI calls `ToFinding()` or `JoinFindingsByPURL` yet — a
`sbomber scan --include-vulnerabilities` run still only produces the HTML
report via `internal/vulnerability/report.go`. Wiring the join into that
path (or a future `canonical-scan.json` exporter) is follow-up work.

## Sign-off

- [ ] Component 2 confirms they can build against the fixture
- [ ] Component 3 confirms they can build against the fixture
- [ ] Component 4 confirms they can build against the fixture (paired
      reviewer for Component 1)

These are human confirmations and cannot be marked done from this session —
tracked here so the checklist has a single place to land.
