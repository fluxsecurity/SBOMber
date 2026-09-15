# Candidate B T2 — Extraction Prototype Result

## Result

Candidate B passed all 13 fixed-corpus extraction fixtures.

- fixtures: 13
- exact matches: 13
- mismatches: 0
- shared query SHA-256:
  `a47429d70dcde4fcbccd760e2eae9afe6f03a8b00600b14dde36ff80575f7864`

The generated JSON matched the committed ground truth byte-for-byte.

## Supported observations

The prototype extracts:

- named, default, aliased and namespace ESM imports;
- type-only imports;
- CommonJS and destructured CommonJS imports;
- static and computed dynamic imports;
- direct, member, computed-member, chained-result and immediately-invoked calls;
- named declarations, CommonJS function expressions and exported arrow functions;
- unresolved computed constructs;
- deterministic line and byte-column locations;
- BOM-normalized first-line columns;
- syntax-error status without unreliable partial observations.

## Interpretation

T2 validates the correctness of the Candidate B extraction adapter and
demonstrates progress toward the S4-06 prototype acceptance criteria.

It is not, by itself, evidence that Candidate B is better than Candidate A.
Cross-candidate evidence comes from T2b tree parity, T3 location accuracy,
representability gates and the remaining operational tests.
