# S6-08: VEX consistency on real decide output (#154)

Do SBOMber's outputs for one real run agree with each other, and does the
pinned consumer act on the VEX it writes? The answer for the current run is in
`results/CONSISTENCY.md`.

```
demo-app/  (lockfile only; never installed or run)
  -> grype 0.112.0 -> build_canonical_scan.py (bridge) -> canonical-scan.json
  -> sbomber usage -> sbomber localise -> sbomber decide
  -> sbomber report (html, text) -> sbomber vex (application and package subject)
  -> consistency.py -> grype --vex (consumer test)
```

`demo-app` has one dependency per decision state: `ini` imported but only
`ini.stringify` called (the vulnerable `parse`/`decode` never are),
`minimist()` and `decode-uri-component` called, `lodash.template` called while
the other lodash advisories name other functions.

## What is real and what is not

- **Bridge:** no command on main writes `canonical-scan.json` from a scan yet
  (Component 1, #121 / #146). `build_canonical_scan.py` builds it from the
  lockfile and a real Grype run; it is the only stand-in. Replace its output
  with Component 1's when that lands.
- **Real:** Grype, `usage`, `localise` (with provenance and visibility),
  `decide`, `report`, `vex`, and the consumer runs.
- **Not produced:** `findings.json`. #154 names it, but no command writes it.
  The checks cover the HTML and text reports, `decision-results.json` and both
  VEX documents.

## Checks (`consistency.py`)

1. Identity: each finding has one decision, one HTML row, one text entry and
   one statement per VEX document, for the same vulnerability and package.
2. State: both reports show the decision's state; statements carry the mapped
   status (`usage_detected` -> `affected`, otherwise `under_investigation`,
   never `not_affected`).
3. Both VEX documents validate against OpenVEX 0.2.0.
4. No finding is missing from the human report, `unknown` ones included.
5. `contracts/validate.py` passes on the run's contract files.
6. Consumer: Grype with every finding ignored and
   `vex-add: [under_investigation]` re-adds exactly the `under_investigation`
   findings from the package-subject document. The application-subject
   document (R5 rule 1, the team's default since the #128 decision of
   18 October 2026) is reported either way: Grype 0.112.0 does not match it,
   which is the recorded limitation, reproduced here on real output.

CI re-runs `consistency.py --check` on the committed results (offline) and its
tests. Re-run everything with network access:

    export GITHUB_TOKEN=$(gh auth token)
    spikes/vex-format/s6-08/run.sh
