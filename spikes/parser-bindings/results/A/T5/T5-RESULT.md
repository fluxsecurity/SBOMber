# Candidate A T5 — Resource Safety

## Method

Candidate A parsed the 332-byte valid reachability fixture 5,000 times in one
process. RSS was sampled every 500 parses after forcing Go garbage collection
and returning unused Go-managed memory to the operating system.

Two runs were performed:

1. every returned tree was closed immediately;
2. trees were deliberately retained without calling `Close`.

The same parser was reused in both runs and closed at process exit.

## Correct-close result

- parses: 5,000;
- parse errors: 0;
- initial RSS: 5,332 KB;
- final RSS: 5,916 KB;
- RSS change: +584 KB;
- peak RSS: 5,932 KB;
- elapsed time reported by the harness: 514 ms.

RSS reached approximately 5.9 MB after the first 1,000 parses and then
remained flat within measurement noise.

Candidate A passes T5 when the required `Close` discipline is followed.

## Deliberate-leak result

- parses: 5,000;
- parse errors: 0;
- deliberately retained trees: 5,000;
- initial RSS: 5,304 KB;
- final RSS: 70,648 KB;
- RSS change: +65,344 KB;
- peak RSS: 70,648 KB;
- elapsed time reported by the harness: 500 ms.

RSS increased consistently at each sample, corresponding to approximately
13.1 KB per retained unclosed tree.

## Design rule

Every Candidate A object that owns C memory must be closed deterministically.
In particular, production code must close parsers, trees, tree cursors,
queries, query cursors and lookahead iterators.

A production leak test must parse thousands of files in one process and assert
that RSS reaches a plateau.

This spike used a small 332-byte fixture. It clearly demonstrates the native
memory cost of retaining unclosed trees, but the production leak test must
also use realistic file sizes and a mixture of JavaScript, TypeScript and TSX
inputs.

## Additional evidence

`Parser.SetLanguage` returned no error with the pinned binding and grammar versions, confirming ABI compatibility.25.0;
- `tree-sitter-javascript` v0.25.0;
- `tree-sitter-typescript` v0.23.2.

This demonstrates compatibility of the pinned parser and grammar ABI versions
for the tested JavaScript input.
