# S6-08: VEX consistency on real decide output (#154)

Do SBOMber's outputs for one real run agree with each other, and does the
pinned consumer act on the VEX it writes? The answer for the committed run is
in `results/CONSISTENCY.md`.

```
demo-app/  (staged as a throwaway git repository under demo-out/s6-08; parsed, never installed or run)
  -> sbomber scan --include-vulnerabilities --canonical-scan      (Component 1's writer, #146)
  -> sbomber usage -> sbomber localise -> sbomber decide
  -> sbomber report (html, text) -> sbomber vex (application and package subject)
  -> consistency.py -> grype --vex (consumer test)
```

`demo-app` covers three decision states across four dependencies: `ini` is
imported but only `ini.stringify` is called (the vulnerable `parse`/`decode`
never are), `minimist()` and `decode-uri-component` are called, and
`lodash.template` is called while the other lodash advisories name other
functions.

## Everything in the run is the real tool

- **Scan.** `sbomber scan --include-vulnerabilities --canonical-scan` writes
  `canonical-scan.json` (Component 1, #121 / #146). The S6-01 bridge that
  stood in for it until 18 October (`build_canonical_scan.py`) is gone. The
  writer keys findings by a content hash (`find-<hash>`) and names them by
  the GHSA ID with the CVE as an alias, so finding IDs differ from the
  bridge's `find-001`..`find-010`; the vulnerability/package identities are
  the same ten. `scan` discovers git repositories, so `run.sh` stages
  `demo-app/` as one with a fixed author and date; the commit, and with it
  the `scanId`, are the same on every run.
- **Grype.** The version `scripts/versions.env` pins (`GRYPE_VERSION`),
  installed by `scripts/install-tools.sh` into `.tools/bin`, is both the
  scanner behind `scan` and the VEX consumer. The 6 September format
  decision and the 18 October run used 0.112.0, which this spike had
  hard-coded; the repository pin is the single source now, and
  `consistency.py` reads it from `versions.env` and rejects a scan or a
  consumer run made with any other version. The database is updated once
  and then frozen for the run, so the scan and the consumer runs read the
  same database (recorded in `run-metadata.json`).
- **Not produced: `findings.json`.** #154 names it, but no command writes it
  and none is planned. The decision record is `decision-results.json`, the
  human surfaces are the HTML and text reports, and the machine surface is
  the OpenVEX document. The checks cover those four; that is the treatment
  recorded on #154.

## Checks (`consistency.py`)

1. Identity: each finding has one decision, one HTML row, one text entry and
   one statement per supported finding per VEX document, for the same
   vulnerability and package. Unsupported findings remain in the human reports
   and are omitted from VEX. Nothing appears that the scan did not report.
2. State: both reports show the decision's state; statements carry the mapped
   status. Guarded positive usage can remain `under_investigation`; reliable
   positive evidence can map to `affected`; unsupported maps to `omit`.
   Automated output never asserts `not_affected`.
3. Both VEX documents validate against OpenVEX 0.2.0.
4. No finding is missing from the human report, `unknown` ones included.
5. `contracts/validate.py` passes on the run's contract files.
6. The scan is complete and was made with the pinned Grype.
7. Consumer: the pinned Grype with every finding ignored and
   `vex-add: [under_investigation]` re-adds exactly the `under_investigation`
   findings from the package-subject document. The application-subject
   document (R5 rule 1, the team's default since the #128 decision of
   18 October 2026) is reported either way.

The checker also rejects duplicate decisions, wrong HTML package headings,
foreign VEX subjects, missing scanner identities, changed consumer packages,
unmatched consumer inventories and a different database between the scan
and the consumer runs. `test_consistency.py` covers each of these with a
success case, a failure case and untrusted input.

## What the committed run shows

Revision `33aeabf`, 29 October 2026. Grype 0.120.1 with the database built
2026-10-28T06:23:30Z; scan `scan-20261018T000000Z-cf1d8d4d`, status
`complete`, every enrichment source reached (EPSS, CISA KEV, GHSA, npm
registry).

- **10 findings**: 6 `usage_detected`, 3 `unknown` (the lodash advisories
  whose candidate set stays open) and 1 `no_usage_detected` (ini,
  GHSA-qqgx-2p2h-9c37 / CVE-2020-7788). The same ten vulnerability/package
  identities and the same states as the 18 October run on Grype 0.112.0.
- Every finding has one decision, one HTML row, one text entry and one
  statement per VEX document, all with the same state. Both documents
  validate against OpenVEX 0.2.0. `contracts/validate.py` passes (703
  checks). Nothing is missing from the human report.
- **Provenance** (`localise --verify --online`): 25/25 candidates traced to a
  verified artefact, 49 artefacts, tag checks 17 verified, 1 mismatch
  (minimist 1.2.2 already contains the linked commit, a partial first fix),
  0 unavailable.
- **Consumer**: the ignore-all baseline reports nothing. The package-subject
  document re-adds exactly the 4 `under_investigation` findings (three
  lodash, ini) and leaves the 6 `affected` ones ignored. The
  application-subject document re-adds nothing. Grype 0.120.1 behaves as
  0.112.0 did on 18 October: the #128 limitation holds at the repository's
  pinned consumer.

## Reproducing

```
scripts/install-tools.sh                 # the pinned Grype into .tools/bin
export GITHUB_TOKEN=$(gh auth token)     # GHSA enrichment and localise need it
spikes/vex-format/s6-08/run.sh           # rewrites results/
```

`run.sh` needs network: Grype's database, EPSS, CISA KEV, GHSA, the npm
registry and GitHub. `scan` also writes its SBOMs and its own HTML report
under `~/.sbomber/reports/`, as it always does. The staged repository and
`scan`'s console output are left under `demo-out/s6-08/` (ignored by git).
To replay without replacing the committed evidence:

```
SBOMBER_S6_OUT=/absolute/path/to/fresh-results spikes/vex-format/s6-08/run.sh
```

`run-metadata.json` records the clean git revision, the binary checksum, the
`scanId`, the tool versions, the consumer's database and the SHA-256 of every
input and output; `consistency.py` verifies the hashes, refuses a dirty
source tree and fails if the online provenance verification did not trace
every candidate. CI re-runs `consistency.py --check` on the committed
results (offline) and its tests, so the committed `CONSISTENCY.md` cannot go
stale without CI noticing.

## Evidence scope

- The committed results are one live run on the revision `run-metadata.json`
  names. A run on another day can differ because Grype's database and the
  enrichment sources (EPSS, KEV) change; the scan itself is deterministic
  for a given database.
- The consumer runs scan the staged directory (`grype dir:`), while `scan`
  scans the SBOM it exported; `consistency.py` maps every consumer match to
  exactly one canonical finding by vulnerability aliases and package purl,
  so the two views are shown to agree rather than assumed to.
- An empty application-subject consumer result is the documented #128
  limitation, never evidence that those vulnerabilities do not matter.
