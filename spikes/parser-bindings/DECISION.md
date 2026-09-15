# Parser Binding Decision

## Decision

Use:

- `go-tree-sitter` v0.25.0;
- `tree-sitter-javascript` v0.25.0;
- `tree-sitter-typescript` v0.23.2.

Fallback: `gotreesitter` v0.51.0.

`Parser.SetLanguage` returned no error with the pinned binding and grammar versions, confirming ABI compatibility.

## Candidates

| ID | Candidate | Result |
|---|---|---|
| A | Official Tree-sitter Go binding | Selected |
| B | Pure-Go `gotreesitter` | Fallback |
| C | `dcosson/treesitter-go` | Not fully evaluated |
| D | Runtime-loaded grammars | Eliminated: CGO remains |
| E | WASM wrapper | Eliminated: required grammars unavailable |
| F | `go-fast` | Eliminated: required ESM parsing unavailable |

Candidate C’s tree-cursor test passed, but its earlier direct-child location
anomaly was not re-tested. The anomaly is neither confirmed nor refuted.

## Results

| Signal | Candidate A | Candidate B |
|---|---|---|
| JavaScript, TypeScript and TSX | Pass | Pass |
| Valid tree comparison | 12/12 equivalent | 12/12 |
| Location tests | Exact | Exact |
| Semantic extraction | Adapter not built | 13/13 exact |
| Invalid input | Error tree, no panic | Error tree, no panic |
| Packaging | CGO | Static CGO-free builds |
| Licence | MIT | MIT |

Candidate A extraction support is inferred from named-node parity. Field labels
were not compared directly. Its production adapter must verify query fields.

## Lodash finding

Candidate A accepted the valid Lodash 4.17.21 bundle.

Candidate B returned `no_stacks_alive`. It did not report an early safety
stop. Iteration, node, arena and depth budgets were below 4% utilisation.

Stack overrides of 16, 32 and 64 failed earlier, at byte 45,497 instead of
73,003. Diagnostics continued to report `maxStacks=8`.

This is an observed parser/recovery incompatibility. The exact internal cause
remains unresolved, so it is not described as a proven grammar defect.

## Resource safety

Candidate A requires deterministic `Close` calls.

Across 5,000 parses:

- correct closure: RSS increased by 584 KB and plateaued;
- 5,000 retained trees: RSS increased by 65,344 KB.

Production code must close all parsers, trees, cursors and queries that own C
memory. Production leak tests should use realistic JS, TS and TSX files.

## Reason for selection

Candidate B is active and well tested, but it is a young pre-1.0
reimplementation.

Candidate A uses the mature Tree-sitter C runtime with broad production use.
That lower runtime risk outweighs the CGO packaging cost.

Loading grammar shared libraries at runtime does not remove Candidate A’s CGO
requirement and adds platform-specific deployment files.

## Fallback trigger

Switch to Candidate B only if an unfixable Candidate A parser or grammar
problem blocks production work. Repeat the Lodash regression before switching.

## Packaging consequences

Component 1 must:

- enable CGO;
- use native Linux and macOS runners;
- support a tested Linux glibc floor of 2.34;
- use the exact pinned versions above.

## Limitations

- Candidate A’s semantic adapter is not yet implemented.
- This selection is confirmed when Candidate A’s adapter reproduces all 13 expected files using `queries/usage.scm`. If the required field assignments differ, the decision reopens against the recorded fallback.
- Query field assignments require direct verification.
- Candidate C was not fully evaluated.
- Full-corpus throughput and GitHub Actions matrix tests were not run.
- Planned limits are 1 MB and 5 seconds per source file.
- Skipped or unresolved files must never be silently omitted.

## Evidence

Critical raw evidence is retained under:

- `results/environment.txt`;
- `results/A/T5/`;
- `results/B/T4/lodash-cause/`;
- `results/D/`.
