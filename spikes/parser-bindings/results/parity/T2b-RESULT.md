# T2b S-expression Parity Result

Date: 2026-08-21
Candidates: A (native Tree-sitter with CGO) and B (pure-Go Tree-sitter)

## Method

Both candidates parsed the same 13 byte-fixed fixtures.

Candidate A's `Node.ToSexp()` output includes Tree-sitter field labels.
Candidate B's `SExpr()` output omits those labels. Candidate A output was
therefore normalised by removing field labels only. Named node types, tree
nesting and parentheses were retained.

The shared query was frozen before this comparison at:

`a47429d70dcde4fcbccd760e2eae9afe6f03a8b00600b14dde36ff80575f7864`

## Result

- Total fixtures: 13
- Identical normalised trees: 12
- Different normalised trees: 1
- All required valid JavaScript, TypeScript and TSX fixtures: identical
- BOM, CRLF and UTF-8 edge fixture: identical
- Empty fixture: identical
- Invalid JavaScript fixture: different error-recovery tree

For `11-invalid.js`, Candidate A retained a `program` root containing an
`ERROR` node. Candidate B returned an `ERROR` root with a different recovery
subtree.

## Interpretation

The candidates provide equivalent named-node structures for every valid
construct in the formal corpus. A separate Candidate A semantic extractor is
therefore not required for valid-construct comparison.

The invalid-source difference is retained as a genuine research finding. It
does not by itself eliminate either candidate because both identify malformed
input. Their invalid-input behaviour will be evaluated separately under T4.

T2 extraction diffs are treated as adapter and prototype correctness checks.
T2b structural parity, T3 locations, and Gate A representability are the
candidate-comparison evidence.

## Field-label limitation

Candidate A's s-expression field labels were removed during normalisation
because Candidate B's `SExpr()` output did not include them.

T2b therefore proves parity of named-node types, nesting and parentheses. It
does not independently prove parity of field assignments such as `function:`,
`source:` or `object:`.

Candidate A's extraction-related Gate A results are consequently labelled as
inferred from structural parity rather than directly measured through a
Candidate A semantic adapter. The production Candidate A adapter must verify
the field assignments used by `queries/usage.scm`.
