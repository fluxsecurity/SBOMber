# Localisation Spike (S4-08) and Evaluation Cases (S4-18)

Which source tells us the function an npm advisory implicates? Ten CVEs with
ground truth fixed before measurement, every method run on every case.
**Answer: the fix commit the advisory links to, 10/10, median two candidates;
structured metadata 0/10; the client's commit-message search 1/10.** See
`FINDINGS.md`.

## Protocol

1. Curate 8 to 10 npm CVEs (`cases/cases.json`, `cases/CASES.md`). Record the
   advisory, the functions the fix changed, the public symbol an application
   calls, and how each was established. At least three advisories must name
   no function. Drop cases without a defensible answer.
2. Commit the ground truth before the tool exists (commit `1ef9d95`).
3. Express the cases as one schema-valid `canonical-scan.json`
   (`build_canonical_scan.py`).
4. Run `sbomber localise --all-methods --client-search` so every method is
   attempted and recorded regardless of fallback order.
5. Validate `localisation.json` against `contracts/localisation.schema.json`.
6. Grade each attempt against the ground truth (`evaluate.py`): does the
   candidate set contain a changed function; does it contain the public symbol.
7. Report the unknown rate as a result.

Rules held throughout: no downloaded code is executed (`executed: false` on
every artefact), every candidate is traceable to an advisory, commit or
verified tarball, and limits are written down when hit.

## Contents

- `FINDINGS.md` — the answer, what it means for Component 4, limitations
- `cases/cases.json`, `cases/CASES.md` — ground truth (S4-18)
- `cases/FROZEN.json`, `freeze.py` — the frozen set (S5-13, tag `localisation-set-v1`): ground-truth hash, answer sources, pinned tarballs
- `cases/canonical-scan.json` — generated, schema-valid input
- `build_canonical_scan.py`, `evaluate.py`, `run.sh` — reproduce everything
- `results/localisation.json` — the contract document the tool produced
- `results/trace.json` — every method attempt with candidates, notes, provenance
- `results/evaluation.json`, `results/evaluation.md` — graded results
- `results/environment.txt` — versions at run time
- `results/provenance/` — S6-07: the same ten cases re-run with provenance
  (localisation 1.1.0), the online verification and `VERIFICATION.md`
- `verify_provenance.py` — offline check of that run against `FROZEN.json`

The tool itself is `internal/localisation/` with the `sbomber localise`
subcommand; its unit tests cover the success, failure and untrusted-input
paths for the diff parser, the function resolver, tarball handling and the
end-to-end localiser against a fake OSV/GitHub/registry.

## Provenance (S6-07)

Every candidate in localisation 1.1.0 cites the artefacts it was read from
(`candidateSymbols[].evidence`), and every artefact records how it was
verified and a checksum:

| Artefact | Checksum | Verified means |
|---|---|---|
| `advisory` (OSV record) | SHA-256 of the record in canonical JSON, because OSV reorders keys between responses. Reproduce with `curl -s <url> \| jq -S -c . \| tr -d '\n' \| shasum -a 256` | the record names the finding's vulnerability and lists the npm package |
| `source_file` (a file at a commit) | SHA-256, plus the git blob hash | the blob hash of the bytes read equals the hash GitHub reports for that path at that commit, and the hash in the commit's own file list |
| `tarball` (npm) | SHA-256, plus the registry integrity value | the bytes match the registry's integrity value |

Artefact ids are derived from their fields (`advisory`,
`github:<repo>@<full commit>:<path>`, `npm:<name>@<version>`), and a
candidate must cite the kind its method reads: `patch_reference` a source
file, `version_diff` a tarball, `advisory_*` the advisory. Online, each
candidate's symbol must also occur in the bytes it cites, so a made-up
candidate cannot borrow a real artefact (`default`, the anonymous export, has
no name to look for).

A `patch_reference` result also carries **tag checks**: is a linked fix
commit in the release the fixed npm version was published from, and absent
from the vulnerable one? The release commit is npm's `gitHead` when the
registry records one (that is the commit the tarball came from). When the
repository does not have that commit, as with lodash, the git tag is used and
`--verify` warns. A commit that is not an ancestor of the fixed release still
counts when every line it adds is in the release (`basis: content`), which is
how backports and squash merges look. Lines the commit's parent already had
are not looked for, so a generic line cannot pass a release that never got
the fix. Advisories often link fixes for several release lines, so the fixed
release passes when it carries at least one of them. The vulnerable-side
check is ancestry only: a fix cherry-picked into a release listed as
vulnerable is not detected.

Tag checks cost about ten GitHub requests per `patch_reference` finding. They
run after every finding is localised, so without a `GITHUB_TOKEN` (60 requests
an hour) they can come back `unavailable` but cannot change candidates.
`--no-tag-checks` skips them.

`results/provenance/VERIFICATION.md` has the table. On the ten frozen cases:
38/38 candidates trace to a verified artefact, all 71 artefacts re-download
with matching checksums and every candidate's symbol is in the bytes it cites,
and 19 of 20 tag checks verify (lodash's two use the git tag, see above). The
one that does not is a finding, not a broken trace: minimist 1.2.2, listed as
vulnerable, already contains linked commit `63e7ed0`, the first and incomplete
`__proto__` fix (c06).

The candidate sets are the Sprint 4 ones; localisation accuracy is not
re-measured.

The same run also fills the join-rule visibility fields from the published
vulnerable tarball (`docs/design/localisation-join-rule.md`): 3/10 candidate
sets are closed and 8/10 joinable; the reasons each open set is open are in
`VERIFICATION.md`.

    export GITHUB_TOKEN=$(gh auth token)
    make build
    ./bin/sbomber localise --canonical-scan spikes/localisation/cases/canonical-scan.json \
      --out spikes/localisation/results/provenance/localisation.json \
      --trace spikes/localisation/results/provenance/trace.json
    ./bin/sbomber localise --verify spikes/localisation/results/provenance/localisation.json \
      --online --verify-report spikes/localisation/results/provenance/verification.json
    python3 spikes/localisation/verify_provenance.py --write

CI runs the offline half: `verify_provenance.py` and
`sbomber localise --verify` without `--online`.

## Reproduce

    export GITHUB_TOKEN=$(gh auth token)
    python3 -m pip install jsonschema
    spikes/localisation/run.sh

### Verification hardening after PR #168

Offline verification checks document identity and the recorded provenance
claims. It does not independently prove that saved checksums or `verified`
flags are true; use `--online` to re-fetch evidence. Online verification now
re-checks advisory identity for each finding/package even when downloads are
cached. A synthetic `default` symbol must correspond to a parsed function or
export rather than bypassing symbol verification.

Backport checks re-read the actual fix commit, parent and changed files;
saved `content` lines are treated as claims, not authoritative patch input.
The replay compares commit identities and evidence, not just list lengths.
Content presence remains a same-file line heuristic, not proof of equivalent
runtime behaviour. Rebuilding content evidence adds requests to online
verification only; candidate selection and the normal tag-check scheduling
are unchanged for valid advisories.

An advisory that fails vulnerability/package identity checks cannot supply
metadata, prose or patch candidates. Independent version-diff fallback can
still run when the input supplies a fixed version. Verification-only flags
require `--verify`; verification and localisation inputs cannot be combined.

The pre-existing synthetic audit case under `internal/audit/testdata/` is a
hand-built decision fixture without real localisation provenance. It is not
included in the verified frozen localisation corpus and must not be used as
provenance or accuracy evidence. Its existing contract debt is separate work.

### Review corrections for PR #169

The saved 3/10 closed and 8/10 joinable counts above describe the author's
`d90adf0` run. They are historical evidence, not a measurement of the review
fixes. Re-run localisation and online verification before reporting new counts.
The review fixes retain every export alias as a join key, keep alternate
conditional exports and unparsed package files open, retain callers sharing a
source line, and keep module-initialisation references open. Online verification
now re-derives known visibility from the checksummed vulnerable tarball.

Component 2 now records an unresolved use when an imported value escapes through
an assignment, container, argument or return. For example,
`const p = lodash.merge; p()` stays unknown rather than becoming
`no_usage_detected`. This does not prove the later call or its reachability.
The fallback matches names conservatively; shadowed names may also keep a
finding unknown. Integration with PR #166's reviewed lexical-binding fixes is tested. Re-run
the known-call release gates after changes to either branch.

The provenance fixes previously packaged as the PR #168 follow-up are included
in this branch. Do not open that separate follow-up PR from the older package.
