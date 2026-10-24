# Prioritisation order (S6-15, #156)

Component 4 orders `decisions[]` in `decision-results.json` so the most urgent
findings come first. The change follows the client meeting on 5 October 2026:
EPSS should inform prioritisation alongside severity, and call-path evidence
should support prioritisation where it resolves.

Implemented in `internal/decision/priority.go` (`SortDecisions`), called once
by `BuildResults`.

## The rule

Findings are ordered by these keys, in this order:

1. **Band**: `act_now`, then `insufficient_information`, then
   `lower_priority`. This is the same ranking the grouped report uses
   (`bandRank`). An undetermined finding is never listed below one SBOMber
   could assess.
2. **Severity**, as the scanner reports it: critical, high, medium (or
   `moderate`), low, negligible. Matching is case-insensitive. A missing or
   unrecognised severity sorts last in its band.
3. **EPSS**, highest first. A finding with no EPSS score sorts after every
   finding that has one, and is shown as "EPSS not reported", not as 0. A score
   that is NaN or outside [0, 1] is treated as not reported.
4. **findingId**, so the order is reproducible from run to run.

## What the order does not do

- **It never moves a finding between bands.** The band is still set by state
  and CISA KEV alone (`riskPriority` in `results.go`).
- **EPSS never changes a state or a confidence rating.** `DetermineState` and
  `Rate` do not take EPSS as input. `TestPriority_EPSSOrdersOnly` swaps the
  EPSS scores of two otherwise identical findings and checks that only their
  order changes.
- **It is not noise reduction.** Reordering a finding says nothing about
  whether it is a real issue.

## Call paths

A resolved call path is evidence, not an ordering key:

- **Method agreement.** Only a call site with reachability `reachable`, *and*
  carrying a non-blank `entryPointId` and non-empty `callPath` with non-blank
  function/file names and positive line numbers,
  counts towards `DeterministicMethodsAgree`. `unknown` (the level-3 pass ran
  and found no path) and `not_analysed` do not count. Before S6-15, `unknown`
  counted as agreement.
- **Justification.** When a matched call site has a resolved path, the
  justification names the entry point and the path. Where several call sites
  resolve, it cites the shortest (then file, then line). Paths longer than six
  steps are shortened to the first three and last three steps.

## Known limitations

- **Two orderings exist.** `decisions[]` is ordered severity-then-EPSS, while
  remediation groups (`BuildRemediationGroups`) are ordered band, KEV, EPSS,
  CVSS. The grouped report's ordering is finalised under S6-12 (#159).
- **Untrusted text in the justification.** File paths and function names in
  a call path are upstream values. A path containing a banned phrase (for
  example a file named `this is safe.js`) makes `BuildResults` fail with a
  banned-language error rather than emit it. This is the same behaviour as
  the existing unresolved-import text.
