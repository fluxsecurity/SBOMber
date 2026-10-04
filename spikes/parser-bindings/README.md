# Parser Binding Spike

This spike compares Go parser options for Component 2 JavaScript, TypeScript
and TSX usage extraction.

## Decision

Selected:

- `go-tree-sitter` v0.25.0;
- `tree-sitter-javascript` v0.25.0;
- `tree-sitter-typescript` v0.23.2.

This option requires CGO and native platform builds.

Fallback: `gotreesitter` v0.51.0.

Candidate B contains the original extraction prototype. Candidate A is the
selected production parser and its semantic adapter is implemented in
`internal/sourceanalysis`.

## Contents

- `DECISION.md` — decision and limitations;
- `TEST_PROTOCOL.md` — tests and decision rule;
- `corpus/` — 13 labelled fixtures;
- `queries/usage.scm` — shared query;
- `harness/A` — selected binding tests;
- `harness/B` — extraction prototype;
- `results/` — critical raw evidence.

## Validation

From `spikes/parser-bindings`:

    (cd harness/A && CGO_ENABLED=1 go test -count=1 ./...)
    (cd harness/B && CGO_ENABLED=0 go test -count=1 ./...)
    (cd harness/B && CGO_ENABLED=0 go build -o /tmp/harness-B .)
    ./run-t2.sh

Expected: both test suites pass and Candidate B matches all 13 expected files.
