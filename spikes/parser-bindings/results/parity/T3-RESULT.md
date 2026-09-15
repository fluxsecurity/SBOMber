# T3 — Location and Traversal Agreement

## Result

Candidate A and Candidate B passed T3.

Both candidates reported identical byte ranges and source locations through:

1. direct child traversal;
2. named-child traversal;
3. tree-cursor traversal.

For the `require("node:path")` call in `04-cjs-require.js`, every route
reported:

- bytes: 42–62
- start: line 2, column 13
- end: line 2, column 33

## Edge fixture

Both candidates also agreed on the byte and location information for the
BOM, CRLF, and UTF-8 fixture `12-edge.js`.

Raw first-line columns include the three-byte UTF-8 BOM. The adapter therefore
subtracts three from first-line columns when the fixture starts with a BOM.
Later lines require no BOM adjustment.

Columns are UTF-8 byte columns, consistent with Tree-sitter points.

Candidate B additionally verified that the fixture is exactly 92 bytes and
matches SHA-256:

`5ede488bbef4d6e50ccf5210cdfcc876ef66cb603928739579f5e18450875eac`

## Decision relevance

T3 does not distinguish Candidate A from Candidate B: both provide accurate,
consistent locations across the required traversal routes.

This result validates the location normalization contract that the extraction
adapter must apply.
