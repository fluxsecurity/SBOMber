# Ground truth: npm-basic

This directory holds a real, reproducible verification run — not an illustrative
example. Every number in `verify-summary.txt` and `sbom-verify-note.txt` came
from actually running `sbomber verify` against the files committed here.

## Source fixture

`testdata/fixtures/npm-basic/` — a single `package.json` declaring
`lodash: ^4.17.15`, locked by `package-lock.json` (npm lockfile v3) to the
fixture version `lodash@4.18.1`. `lodash@4.18.1` does not exist on the real
npm registry; it is a synthetic version baked into this test fixture on
purpose, so this benchmark is stable and does not drift when the real lodash
package changes. **The resulting accuracy numbers describe SBOMber's ability
to parse this fixture correctly — they are not a general accuracy claim about
scanning arbitrary real-world npm projects.**

## How `ground-truth.cdx.json` was built

Hand-authored by reading `package-lock.json` directly: the only resolvable
entry under `packages` is `node_modules/lodash` at `"version": "4.18.1"`,
declared as a direct (non-dev) dependency of the root package. That is the
version npm would actually install, so it is the version recorded as ground
truth — not the `^4.17.15` range from `package.json`.

## How `generated.cdx.xml` was produced

Ran the built CLI, unmodified, against the fixture:

```bash
mkdir -p /tmp/gt-npm-basic/repo/.git   # .git marker only; not a real git repo
cp testdata/fixtures/npm-basic/package.json testdata/fixtures/npm-basic/package-lock.json /tmp/gt-npm-basic/repo/
./bin/sbomber scan /tmp/gt-npm-basic
```

`discovery.FindGitRepositories` only requires a directory literally named
`.git` to treat a folder as a scannable repository (see
`internal/discovery/discovery.go`); no real git history is needed. The `.git`
marker itself is not committed to this repo to avoid a nested-`.git`
directory inside SBOMber's own tree — reproduce it locally with the two
commands above if you need to regenerate `generated.cdx.xml`.

The output SBOM was copied verbatim from
`~/.sbomber/reports/repo_<hash>/sbom-cyclonedx.xml` to `generated.cdx.xml` in
this directory — nothing in it was edited by hand.

## How the verify result was captured

```bash
./bin/sbomber verify \
  testdata/fixtures/ground-truth/npm-basic/ground-truth.cdx.json \
  testdata/fixtures/ground-truth/npm-basic/generated.cdx.xml \
  > testdata/fixtures/ground-truth/npm-basic/verify-summary.txt
```

`sbom-verify-note.txt` is the scorecard `sbomber verify` writes automatically
next to the generated SBOM; both are committed unedited.

## Automated regression check

The two runs above were captured by hand. Since then,
`internal/cli/groundtruth_test.go` (`TestGroundTruthFixturesDoNotRegress`)
automates the same check: it reruns a fresh `sbomber scan` + `sbomber
verify` against this fixture on every `go test ./...` / `make test` / CI
run, and fails if any metric drops below what's committed in
`verify-summary.txt` above. It copies only `package.json` and
`package-lock.json` from `testdata/fixtures/npm-basic/`, matching the
method described above — deliberately excluding that source directory's
`yarn.lock`, which is unrelated to this fixture and would otherwise trigger
a second, separate bug (see
`docs/design/npm-identity-reconciliation.md`'s "second bug" section).
Verified to actually catch a regression, not just pass by construction: it
was run against a temporarily-reverted `EnrichFromPackageLock` and failed
with the expected `Version Accuracy: 0.0%` message before the revert was
undone.

## Provenance

This fixture was verified twice — before and after the npm package-lock
reconciliation fix (`docs/design/npm-identity-reconciliation.md`) — to show
the actual before/after effect on a real number, not a claim.

| | Run 1 (bug present) | Run 2 (fix applied) |
|---|---|---|
| Date | 2026-08-25 | 2026-08-25 |
| SBOMber version | `0.1.0` | `0.1.0` |
| Commit / tree | `36d8fac` + working tree, before `internal/npm/package_lock.go` existed | `36d8fac` + working tree, after `EnrichFromPackageLock` added and wired into `buildRepoDependencySummary` |
| Go toolchain | `go1.26.2 windows/amd64` | `go1.26.2 windows/amd64` |
| Run by | Sadman (Component 1) | Sadman (Component 1) |

Neither run is on a tagged release commit — both are working-tree states in
this branch, recorded precisely as such rather than attached to a commit
hash that would overstate their permanence.

## Result

- Precision 100.0%, Recall 100.0%, F1 100.0% in both runs — SBOMber found
  the one component that should be found, by name, in both.
- **Version Accuracy: 0.0% → 100.0%.** Run 1 reported `lodash@^4.17.15` (the
  raw semver range string from `package.json`) instead of the resolved,
  installed version `4.18.1` from `package-lock.json`, because the npm
  parser had no code path reconciling `package.json` against
  `package-lock.json` for projects without a `yarn.lock` (see
  `docs/design/npm-identity-reconciliation.md` for what was found and
  fixed). Run 2, with `EnrichFromPackageLock` wired in, resolves the exact
  version and reports `lodash@4.18.1`, matching ground truth exactly.

`verify-summary.txt` and `sbom-verify-note.txt` in this directory are Run
2's (fixed) output, committed unedited. Run 1's generated SBOM
(`lodash@^4.17.15`) is preserved in this file's git history for anyone who
wants to see the before state; it is not kept as a second committed file
here since carrying two `generated.cdx.xml` copies would invite exactly the
"which number is current" ambiguity this evidence is meant to prevent.

Note also that `sbomber verify`'s "Overall Grade" is derived from F1 Score
only (component presence/absence), so a run with a low Version Accuracy can
still be graded "A+ (Excellent)" — as Run 1 was. The grade line should
never be quoted on its own as an accuracy claim; cite Version Accuracy
alongside it.

## Known remaining scope limit of this fixture

This fixture has exactly one direct, non-nested dependency, so it cannot by
itself demonstrate the nested-version case
(`docs/design/npm-identity-reconciliation.md`'s "same package at two
versions under different node_modules paths") — that case is covered by
`internal/npm/package_lock_test.go`'s
`TestEnrichFromPackageLockNestedVersions` and
`internal/sbom/export_test.go`'s `TestCycloneDXBomRefNoCollisionAcrossVersions`
instead, both of which construct that scenario directly since no committed
fixture in this repo currently has real nested-version lockfile data.
