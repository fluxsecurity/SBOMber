# S5-14 labelled end-to-end cases (#124)

The audit set the Sprint 6 audit measures. Each subdirectory is one real
repository, pinned to a commit, with every vulnerability finding labelled by
hand as genuine usage or not, and the reasoning recorded.

```
testdata/audit/
  <case-id>/
    CASE.md               provenance: repo, commit, how each input was produced
    canonical-scan.json   Component 1 output for that commit, unedited
    usage-graph.json      Component 2 output, unedited
    localisation.json     Component 3 output, unedited
    labels.json           the hand labels (format below)
  _template/              copy this to start a case (ignored: no labels.json)
```

A directory is only treated as a case once it contains `labels.json`, so a
half-built case can be committed without breaking the gate.

## Running

```bash
go run ./cmd/sbomber audit                       # all cases, text report
go run ./cmd/sbomber audit --out audit-results.json
go test ./internal/audit/ -run TestCommittedCases -v
```

Exit 0: no labelled genuine usage was moved out of usage detected.
Exit 1: at least one was (MISSED USAGE), or a case's labels no longer line
up with its scan. Exit 2: input error.

## What the harness reports

Per finding: the human label, SBOMber's state, band and confidence, and an
outcome:

| Label \ state     | usage_detected      | no_usage_detected  | unknown / unsupported |
|-------------------|---------------------|--------------------|-----------------------|
| genuine_usage     | agree_usage         | **missed_usage**   | abstained             |
| no_genuine_usage  | over_reported_usage | agree_no_usage     | abstained             |

A **downgrade** is any finding SBOMber placed in "No direct usage evidence
found within the analysed scope" (`no_usage_detected`). Every downgrade is
printed in full: label, reasoning and evidence next to SBOMber's
justification, confidence criteria, matched symbols and coverage.

Results are counts, never an accuracy percentage: three to five
repositories cannot support one.

Localisation 1.1.0 is implemented. A candidate set can still be open when
visibility or public routes are incomplete, so real cases can abstain. Report
actual counts rather than predicting zero downgrades from a schema version.
The negative-verdict gate is independently exercised by the hand-built case
in `internal/audit/testdata/cases/`.

## Active and provisional labels

`labels.json` activates a case. If unresolved version/trigger evidence prevents
completion, preserve the proposals as `labels.provisional.json` and keep the
case outside discovery, following rule 6 below. Do not silently delete uncertain
findings, fabricate exact versions or treat a passing empty/partial gate as
completion of #124. The input generator refuses both active and provisional
labels so regeneration cannot overwrite their source evidence unnoticed.

Current scope: two active repositories (46 findings). DVNA's 47 provisional
proposals are excluded together. The original 93-row report is retained with
an `.original-93` name, clearly separate from the regenerated active report.
This is useful partial audit evidence, not completion of the three-to-five
repository acceptance criterion.

The source worksheet and retrospective label timing are separate strata in
`docs/evidence/s5-14/label-provenance.json`. One active vuln-app label was written
after seeing output. It remains explicitly retrospective, not blind/pre-output
evaluation; no real-world accuracy or recall percentage is claimed. These timing
classifications follow author disclosures, not an independent blinding claim.
All DVNA labels, including the uncertain Sequelize inference and version/applicability
assertions, remain excluded regardless of their proposed binary label.

## Labelling rules

1. Pin the repository to a full commit SHA. Never a branch.
2. Label from the application source at that commit, not from SBOMber's
   output. Label first, run the harness second.
3. `genuine_usage`: application code that ships calls the vulnerable
   function, or a public function that reaches it. Give `file:line` evidence.
4. `no_genuine_usage`: you read the application source and found no such
   call. Say what you searched and how (e.g. `grep -rn "\.template(" src/`).
   This records what you found, not that the vulnerability cannot be
   exploited.
5. Calls only in tests, scripts or build tooling: label by whether that code
   ships, and say so in the reasoning.
6. If you cannot decide, do not guess. Leave the case without `labels.json`
   and note why in `CASE.md`.
7. One label per finding in `canonical-scan.json`; the harness fails on an
   unlabelled finding, a label for a finding that no longer exists, or a
   label whose `vulnerabilityId` or `purl` differs from the finding its
   `findingId` names (copy all three from the scan). The three input files
   must carry the same `scanId`.
8. Label by whether code that ships executes the vulnerable code path, not by
   whether the input reaching it is attacker-controlled. A call with constant
   arguments that executes the path is `genuine_usage`. When the advisory's
   trigger needs an option or configuration the application does not set (an
   invalid `limit`, `parseNested: true`, `extended` URL encoding), label
   `no_genuine_usage`, cite the call and state which trigger is absent. When the
   advisory names one function but the fix changes shared code that a called
   function reaches, label `genuine_usage` and cite the fix lines in the
   reasoning.
