# Reviewer validation — 24 October 2026

Original reviewed PR head: `fa1bbdfe9458ab82f99f3e8e67100758175f527e`.

Build, full Go tests, vet, lint, formatting and 235 contract invariants passed. API token variables were removed from test subprocesses. Logs were captured from the validated working tree; source-hashes.json identifies the reviewed files.

Seven runner sandbox tests passed: successful publication, rejected invalid contracts, dirty/wrong cached checkouts, existing labels, preserved previous outputs/logs and uncommitted production source. These tests use fake external tools to isolate orchestration; they are not live vulnerability scans.

All 93 findings in the three original datasets were replayed through decide. Four-contract validation passed with 1,127 checks for DVNA, 4,602 for vuln-app and 1,261 for Kirill89. The committed input JSON files are unchanged. No labels were created; #124 remains incomplete until labelled cases are replayed.

## Integration after PR #177

Merged main containing #177 (`518d306`) into the review branch and
validated the combined tree. The tested commit is recorded in
integration-after-pr177/tested-head.txt.

Build, full Go tests, vet, lint and all seven audit-runner tests passed.
All 93 saved findings replayed successfully. Four-contract validation
passed: DVNA 1,127 checks; vuln-app 4,602; Kirill89 1,261.

Logs are preserved in integration-after-pr177/. Original audit input JSON
is unchanged. Labels remain outstanding under open issue #124.
