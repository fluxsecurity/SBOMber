# Parser Binding Test Protocol

## Purpose

Select a Go parser for Component 2 JavaScript, TypeScript and TSX usage
extraction using the same fixtures and fixed acceptance criteria.

## Rules

1. Fix requirements before testing.
2. Run candidates against the same fixtures.
3. A hard requirement failure eliminates a candidate.
4. Keep a reproduction for material library findings.
5. Record untested candidates and limitations honestly.

## Candidates

| ID | Candidate |
|---|---|
| A | Official `go-tree-sitter` CGO binding |
| B | Pure-Go `gotreesitter` runtime |
| C | `dcosson/treesitter-go` |
| D | Official binding with runtime-loaded grammars |
| E | WASM wrapper |
| F | `go-fast` |

A and B received the main comparison. C was not fully evaluated. D, E and F
were assessed only far enough to establish their relevant limitation.

## Hard requirements

| ID | Requirement |
|---|---|
| A1 | Parse JavaScript ESM |
| A2 | Parse TypeScript |
| A3 | Parse TSX |
| A4 | Distinguish named, default and aliased imports |
| A5 | Resolve namespace imports as bindings |
| A6 | Recognise destructured CommonJS imports |
| A7 | Preserve package subpaths |
| A8 | Distinguish type-only imports |
| A9 | Recognise static and computed dynamic imports |
| A10 | Identify member-expression calls and properties |
| A11 | Report exact byte and row/column locations |
| A12 | Identify named functions and their call sites |
| A13 | Return error nodes for invalid input without panicking |
| A14 | Never execute or evaluate source code |

## Measured signals

- tree and extraction correctness;
- hostile-input behaviour;
- memory stability;
- binary size and build matrix;
- maturity, licence and API risk;
- packaging effect on Component 1.

Performance does not decide unless the full-corpus difference exceeds 5×.

## Fixtures

`corpus/micro/` contains 13 small JS, TS and TSX fixtures.

`corpus/expected/` contains the expected semantic output. Expected files were
written before candidate output was compared.

The fixtures cover ESM, CommonJS, subpaths, dynamic imports, type-only imports,
TSX, reachability, invalid input, byte-sensitive input and an empty file.

## Main validation

Run from `spikes/parser-bindings`:

    (cd harness/A && CGO_ENABLED=1 go test -count=1 ./...)
    (cd harness/B && CGO_ENABLED=0 go test -count=1 ./...)

Build Candidate B:

    (cd harness/B && CGO_ENABLED=0 go build -trimpath -o /tmp/harness-B .)

Compare Candidate B extraction with expected output:

    ./run-t2.sh

Expected result: both test suites pass and all 13 extraction comparisons are
exact.

## Additional tests

The spike also checked:

- named-node parity between A and B;
- traversal and location agreement;
- invalid, empty, deep, binary and minified input;
- Candidate A memory with and without `Close`;
- CGO and cross-platform packaging;
- runtime grammar loading;
- repository maturity and licence.

Only critical raw evidence is retained. Other outputs can be reproduced from
the committed harnesses and fixtures.

## Decision rule

1. Eliminate candidates that fail a hard requirement.
2. Prefer exact correctness over performance.
3. If correctness ties, prefer lower project and upstream risk.
4. If risk ties, consider packaging.
5. Use throughput only for a difference greater than 5×.
6. Record a fallback and a specific switch trigger.

## Scope limitations

- Candidate A has no semantic extraction adapter yet.
- Candidate A field assignments were not directly compared.
- Candidate C did not receive the complete protocol.
- Full-corpus throughput was not measured.
- GitHub Actions matrix testing is deferred.
- Benchmarks came from one VMware guest and are comparative only.
