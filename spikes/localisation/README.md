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
- `cases/canonical-scan.json` — generated, schema-valid input
- `build_canonical_scan.py`, `evaluate.py`, `run.sh` — reproduce everything
- `results/localisation.json` — the contract document the tool produced
- `results/trace.json` — every method attempt with candidates, notes, provenance
- `results/evaluation.json`, `results/evaluation.md` — graded results
- `results/environment.txt` — versions at run time

The tool itself is `internal/localisation/` with the `sbomber localise`
subcommand; its unit tests cover the success, failure and untrusted-input
paths for the diff parser, the function resolver, tarball handling and the
end-to-end localiser against a fake OSV/GitHub/registry.

## Reproduce

    export GITHUB_TOKEN=$(gh auth token)
    python3 -m pip install jsonschema
    spikes/localisation/run.sh
