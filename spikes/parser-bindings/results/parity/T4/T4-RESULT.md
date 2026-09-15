# T4 — Robustness Against Hostile Input

## Safety result

Both Candidate A and Candidate B terminated normally on:

- invalid JavaScript;
- an empty file;
- the pinned Lodash 4.17.21 minified bundle;
- 5,000 nested calls;
- 1,000,000 bytes of random binary input.

Neither candidate panicked or exceeded the 10-second test ceiling.

Both candidates reported errors for invalid JavaScript and random binary input.
Both accepted the empty file and deeply nested valid JavaScript.

## Valid Lodash difference

Candidate A parsed the pinned 73,015-byte Lodash bundle without an error.

Candidate B reported an error and produced deeply nested `ERROR` nodes covering
most of the otherwise valid file. Candidate B's root error state was confirmed
independently through both extraction output and direct node traversal.

This is parser-level evidence and not an extraction-adapter difference.

Minified and generated files are normally excluded under R1, but this remains
a known limitation because filename-based exclusions can be incomplete.

## Matched s-expression measurements

| Input | Candidate A | Candidate B |
|---|---:|---:|
| Lodash | 0.21 s, 15,052 KB | 0.91 s, 74,648 KB |
| Deep nesting | 0.10 s, 13,980 KB | 0.21 s, 51,036 KB |
| Random binary | 3.01 s, 253,168 KB | 0.11 s, 17,688 KB |

The binary comparison is influenced by different error-recovery tree shapes:
Candidate A retained and serialized a much larger recovery tree, while
Candidate B collapsed most input into error nodes.

## Candidate B extraction measurements

| Input | Elapsed | Peak RSS |
|---|---:|---:|
| Lodash | 0.90 s | 75,484 KB |
| Deep nesting | 0.50 s | 77,020 KB |
| Random binary | 0.26 s | 17,688 KB |

## R9 defaults

Based on the tested hostile input:

- maximum individual source-file size: **1,000,000 bytes**;
- per-file processing timeout: **5 seconds**.

The size limit is the largest input directly tested. The timeout is above the
largest matched valid-source observation and above Candidate A's 3.01-second
binary recovery time, while remaining below the 10-second safety ceiling.

Files exceeding either limit must be reported as skipped or unresolved rather
than silently omitted.

## Lodash cause-isolation follow-up

A later `ParseStrict` diagnostic refined the Candidate B finding.

Candidate B reported `ParseStoppedEarly() == false` and stop reason
`no_stacks_alive`. Iteration, node, arena and depth budgets were below 4%
utilisation, so those measured limits were not implicated. Raising
`GOT_PARSE_NODE_LIMIT_SCALE` changed the node budget but not the outcome.

Attempts to set `GOT_GLR_MAX_STACKS` to 16, 32 and 64 produced identical,
earlier failures at byte 45,497 instead of the default byte 73,003, while the
diagnostic continued to report `maxStacks=8`.

Candidate B exhausted its viable parse stacks. The result is recorded as an
observed parser/recovery incompatibility rather than a proven grammar defect
because the exact cause of the stack exhaustion remains unresolved.

Evidence: `results/B/T4/lodash-cause/`.
