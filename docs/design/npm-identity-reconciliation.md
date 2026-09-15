# npm identity reconciliation

Owner: Sadman (Component 1). Cross-reviewed by: Component 4 (pairs 1↔4).

## Correcting the ticket's premise

This ticket named `TestParseProjectPackageLockTransitive` as an existing
test that "asserts the current duplication" and needed correcting. That test
does not exist anywhere in this repository — `git grep` for
`PackageLock|package-lock` across `_test.go` files returns nothing before
this change. There is no test to correct; the tests added by this change
(`internal/npm/package_lock_test.go`) are new, not fixes to an existing one.
Recording this here rather than silently treating the ticket as satisfied,
per the same standard applied to the ground-truth and canonical-scan work.

## What was actually broken (verified, not assumed)

Running `sbomber scan` against `testdata/fixtures/npm-basic` (package.json
declares `lodash: ^4.17.15`, package-lock.json resolves it to `4.18.1`) and
inspecting the generated CycloneDX output directly — see
`testdata/fixtures/ground-truth/npm-basic/generated.cdx.xml`, captured
before this fix — showed:

```xml
<component type="library" bom-ref="pkg:npm/lodash@^4.17.15">
  <name>lodash</name>
  <version>^4.17.15</version>
```

`internal/npm/parse.go`'s `ParsePackageJSON` only ever reads `package.json`.
`internal/npm/yarn_lock.go`'s `EnrichFromYarnLock` reconciles against
`yarn.lock` when present, but there was no equivalent for
`package-lock.json` — confirmed by grep, not assumed from the ticket text.
Every project using plain npm (no yarn.lock) got the declared semver range
reported as the installed version.

## Fixes in this change

1. **`internal/npm/package_lock.go`** (new) — `EnrichFromPackageLock`,
   mirroring `EnrichFromYarnLock`'s shape. Reconciles `package.json`
   declarations against `package-lock.json` resolutions (lockfileVersion
   2/3's flat `packages` map only; v1's nested `dependencies` tree is not
   supported and returns an error, the same way a missing yarn.lock does).
   Wired into `internal/cli/cli.go`'s `buildRepoDependencySummary`: yarn.lock
   is tried first, package-lock.json second.
   - A direct dependency's `Version` is corrected in place to the resolved
     version and stays a single `Direct` entry — not duplicated.
   - Every other lockfile entry becomes `Transitive`, keyed by
     `name+"@"+version`, so the same name resolved to two different
     versions under two different install paths produces two distinct
     entries. Verified by `TestEnrichFromPackageLockNestedVersions`.

2. **`internal/sbom/export.go`** — `bomRefMap` was keyed by `dependency.Name`
   in both the XML and JSON CycloneDX exporters. Two components sharing a
   name (exactly the case `EnrichFromPackageLock` can now produce)
   collided: the second `bomRefMap[dep.Name] = purl` silently overwrote the
   first, so the earlier component's dependency edges in the `<dependencies>`
   section resolved to the wrong package's bom-ref. Both exporters now key
   directly by each dependency's own exact PURL (`dep.Purl()`) for its own
   bom-ref, so there is no collision at the component level.
   Verified by `TestCycloneDXBomRefNoCollisionAcrossVersions`.

3. **`internal/sbom/export.go`** — every transitive component's CycloneDX
   `scope` was hardcoded to `"optional"` regardless of its actual build
   scope, with the comment `// CycloneDX uses optional for transitive`.
   CycloneDX's `scope` values are `required`/`optional`/`excluded`, meaning
   "needed to build/run or not" — not "direct or transitive". A transitive
   runtime dependency is exactly as required as a direct one; directness is
   already carried separately via the `supplychain:dependency-type`
   property. `cycloneDXScope` now derives `required`/`optional` from
   `dep.BuildScope()` uniformly for direct and transitive components, so a
   transitive **dev/test/build-tooling** dependency still reports
   `optional` (verified by `TestCycloneDXScopeDevTransitiveStaysOptional`)
   while a transitive **runtime** dependency now correctly reports
   `required` (verified by `TestCycloneDXScopeReflectsBuildScopeNotDirectness`).

## What is fixed at the parser/exporter level but NOT fixed everywhere — a real, remaining limitation

Fixing `bomRefMap` alone does not make two same-name-different-version
occurrences visible everywhere in SBOMber, and this change does not claim
it does:

`internal/deps/model.go`'s `Summary.BuildGraph` builds
`DependencyGraph map[string]*Dependency` keyed by **name alone**:

```go
s.DependencyGraph[s.Direct[i].Name] = &s.Direct[i]
s.DependencyGraph[s.Transitive[i].Name] = &s.Transitive[i]
```

If `summary.Transitive` now legitimately contains two `lodash` entries at
different versions (which `EnrichFromPackageLock` can produce), the second
one processed silently overwrites the first in `DependencyGraph`. Every
feature that reads `DependencyGraph` by name — `sbomber trace`,
`GetDependencyTree`, `GenerateDOTGraph`, `GenerateASCIITree`,
`GetConnectionInfo`, `TraceChain`, `DetectFalsePositives` — can only ever
see one occurrence of a name-colliding package, not both. This is the
component/occurrence identity distinction from
`docs/design/canonical-scan.md` (identity 1 vs. identity 2) not yet applied
inside `internal/deps`, and it is a materially larger change than this
ticket's scope: every function above would need to key on occurrence
(name + version + dependency path), not name, and several of them
(`trace <path> <package-name>` in particular) are user-facing CLI
ergonomics built around "one name means one package." That redesign is
follow-up work, not done here — flagging it now, at discovery time, rather
than letting it surface later as a surprise.

## A second, separate bug found by the ground-truth automation (not fixed here)

Building `internal/cli/groundtruth_test.go` — an automated regression test
that reruns each committed ground-truth fixture on every `go test ./...`
— surfaced a second bug distinct from the one this document is otherwise
about. `testdata/fixtures/npm-basic` carries a `yarn.lock` alongside its
`package-lock.json`. That `yarn.lock` is a **classic Yarn v1** lockfile
(`# yarn lockfile v1`, `version "4.17.15"` with no colon), but
`EnrichFromYarnLock`'s own doc comment says it "reads a Yarn Berry
lockfile" — a different, YAML-like format. Parsing a v1 file with the
Berry-specific parser does not error (the file is well-formed text, just
not in the shape the parser expects); its `  version:` prefix check simply
never matches v1's `  version "..."` lines, so every entry's `Version`
stays empty and gets silently skipped.

The consequence: `buildRepoDependencySummary` tries
`EnrichFromYarnLock` first and only falls through to
`EnrichFromPackageLock` **on an error**:

```go
if enriched, err := npm.EnrichFromYarnLock(repoPath, npmSummary); err == nil {
    npmSummary = enriched
} else if enriched, err := npm.EnrichFromPackageLock(repoPath, npmSummary); err == nil {
    npmSummary = enriched
}
```

Since the v1 parse "succeeds" (no error, just no useful output), the
working `package-lock.json` path never runs — reproducing the exact
"reports the range, not the resolved version" symptom this whole document
is about, from a different root cause. Confirmed directly:
`groundtruth_test.go`'s regression check fails with `Version Accuracy: 0.0%`
when the test copies `yarn.lock` alongside `package-lock.json`, and passes
once it's excluded — see that test's comment for the full trace.

**Not fixed here.** The automated test copies only `package.json` and
`package-lock.json` (matching `testdata/fixtures/ground-truth/npm-basic/METHOD.md`,
which never included `yarn.lock`), so it exercises the scenario this
document's fix actually targets. Fixing the fallback order itself —
falling through to `package-lock.json` when yarn enrichment errors *or*
produces no usable data, and/or having `EnrichFromYarnLock` detect and
reject unsupported lockfile versions explicitly rather than silently
extracting nothing — is real follow-up work, tracked here rather than
fixed as a drive-by change to code this document already touches enough.

## Separate, out-of-scope limitation noticed in passing

`internal/remote/parsers.go`'s `parsePackageLockJSON` (used by
`sbomber github` / `sbomber gitlab`, which fetch and parse one manifest file
at a time via the GitHub/GitLab API rather than reading a whole checked-out
tree) explicitly **drops** any nested transitive dependency:

```go
name := strings.TrimPrefix(path, "node_modules/")
if strings.Contains(name, "node_modules/") {
    continue
}
```

That is a different, and in one sense worse, gap than the one this ticket
fixes — those packages are absent from the SBOM entirely, not merely
misclassified. It is architecturally separate from `internal/npm` (no
shared code) and out of scope for this change, which only touches the local
filesystem scan path used by `sbomber scan`. Noted here so it is not
mistaken for something this change addressed.
