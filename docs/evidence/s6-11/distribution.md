## S6-11: state and band distribution across the end-to-end cases

**Run:** `go run ./cmd/sbomber audit` on `main` at `ff33ace`, which includes S6-15 (#156, merged in PR #177 as `1e05852`).
**Evidence:** `docs/evidence/s6-10/audit-run.txt` and `audit-results.json` (PR #[PR]). Same run as #157.

**Cases:**
- `gitaalekhyapaul/vuln-app` @ `0ddf9bdc9672`: 32 findings
- `Kirill89/prototype-pollution-explained` @ `d7b5d98515a9`: 14 findings
- DVNA excluded (provisional labels, see #124)

### By state

| State | vuln-app | prototype-pollution | Total |
|---|---|---|---|
| `usage_detected` | 3 | 2 | **5** |
| `no_usage_detected` | 0 | 0 | **0** |
| insufficient information (unknown) | 29 | 12 | **41** |
| **Total** | 32 | 14 | **46** |

### By band

All three bands defined in `internal/decision/results.go`.

| Band | vuln-app | prototype-pollution | Total |
|---|---|---|---|
| `act_now` | 3 | 2 | **5** |
| `lower_priority` | 0 | 0 | **0** |
| `insufficient_information` | 29 | 12 | **41** |

### Against the hand labels

Context only, not an accuracy rate.

| Label | `usage_detected` | `no_usage_detected` | insufficient information |
|---|---|---|---|
| `genuine_usage` (8) | 1 | 0 | 7 |
| `no_genuine_usage` (38) | 4 | 0 | 34 |

### Reading this

- **Band follows directly from state.** In `riskPriority` (`internal/decision/results.go`), `usage_detected` → `act_now`, `no_usage_detected` → `lower_priority` unless KEV-listed, and anything else → `insufficient_information`. The band table therefore mirrors the state table. Severity and EPSS are carried in the output, but they only order findings within a band.
- **This is a distribution, not a noise-reduction figure.** 41 of 46 findings sit in `insufficient_information`, which means SBOMber abstained, not that those findings were false positives. 7 of them are labelled genuine usage.
- **`lower_priority` is empty.** It is reached only from `no_usage_detected`, and no finding reached that state (see #157). No finding was deprioritised on usage grounds.
- **All 5 `usage_detected` findings landed in `act_now`.** 4 of the 5 are labelled `no_genuine_usage`: `GHSA-rv95-896h-c2vc` and `GHSA-qw6h-vgh9-j6wx`, each appearing in both cases. The cause is explained in PR #182 (express over-reports).

### Limitations

- 46 findings across 2 repositories: counts, not rates. These shouldn't be generalised to other codebases.
- S6-15 orders findings by severity and EPSS within a band. It does not move findings between bands, so it has no effect on these counts. Its effect on ordering is checked separately in #159.
- DVNA is excluded, which leaves two cases instead of three (pending the #124 decision).
- These figures should be rechecked against the frozen #160 run before this issue is closed.
