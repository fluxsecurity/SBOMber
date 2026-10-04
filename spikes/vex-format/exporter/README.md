# S5-07 exporter evidence

`run.sh` runs the real `sbomber vex` command (internal/vex) and records three things in `results/s5-07/`.

1. **Output.** Each input is exported in both subject models:
   - `fixture.{application,package}.openvex.json`: the four-finding contract scenario (`contracts/fixtures/`).
   - `vulnerable-chat.{application,package}.openvex.json`: two decisions for the S4-09 consumer fixture, lodash 4.17.4.
2. **Schema validation.** All four documents are checked against the OpenVEX 0.2.0 JSON Schema in `../samples/` (`schema-validation.txt`).
3. **Consumer runs.** Grype 0.112.0 scans `../fixture` with both GHSA IDs ignored. It then reads each exporter document with `vex-add: [affected, under_investigation]` (`grype.jsonl`).

## Result (4 October 2026)

| Run | Document | Re-added by `openvex-matcher` |
|---|---|---|
| E0 | none, ignore rules only | none, 2 ignored |
| E1 | exporter output, `--subject package` | **GHSA-4xc9-xhrj-v574 (`affected`) and GHSA-jf85-cpcp-j695 (`under_investigation`)** |
| E2 | exporter output, `--subject application` | none, 2 still ignored |

- **All four documents are schema-valid.**
- **E1 shows the pinned consumer acting on both statuses** the exporter emits, with status handling configured.
- **E2 reproduces issue #128 on the exporter's own output.** An application-scoped product is not matched, which is the same result as SM9 in the subject-model spike.

The exporter defaults to the application subject (R5 rule 1) through `vex.DefaultSubject`. That stays until #128 is decided. `--subject package` produces the shape the consumers act on.

Grype runs with `GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_VALIDATE_AGE=false`, so all runs use the same local DB. Its build date is in `environment.txt`.

## On real Component 4 output

`run-real-decide.sh` runs the real join (`sbomber decide`, PR #142) on the
contract sample inputs and feeds its `decision-results.json` straight into
`sbomber vex`, with no adapter. Results in `results/s5-07/real-decide/`:
the decide output passes `contracts/validate.py`, and both subject modes are
valid OpenVEX 0.2.0. Under the agreed join rule (#139) `find-002` (axios) is
`unknown`, not `no_usage_detected` — its localisation set is open — so it is
exported as `under_investigation`.
