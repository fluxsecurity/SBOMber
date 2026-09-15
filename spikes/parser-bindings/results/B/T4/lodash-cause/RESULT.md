# Candidate B Lodash Cause Isolation

## Fixture

- Lodash version: 4.17.21
- bytes: 73,015
- SHA-256:
  `a9705dfc47c0763380d851ab1801be6f76019f6b67e40e9b873f8b4a0603f7a9`

## Default result

`ParseStrict` returned a tree without `ErrParseStoppedEarly`.

The tree reported:

- `ParseStoppedEarly()`: false;
- stop reason: `no_stacks_alive`;
- root type: `program`;
- root contained errors;
- root ended at byte 73,003 rather than byte 73,015.

The runtime diagnostic reported a truncated parse, but not a strict
early-stop safety reason.

## Limit tests

The default diagnostic recorded:

| Budget | Used | Limit | Utilisation |
|---|---:|---:|---:|
| Iterations | 43,815 | 2,190,450 | 2.0% |
| Nodes | 112,006 | 3,796,780 | 3.0% |
| Arena memory | 20,695,224 bytes | 536,870,912 bytes | 3.9% |
| Peak depth | 49 | 146,030 | 0.03% |

Setting `GOT_PARSE_NODE_LIMIT_SCALE=3` increased the node budget to
11,390,340. It did not change the result.

Attempts with `GOT_GLR_MAX_STACKS` set to 16, 32 and 64 also did not produce a
successful parse. All three overrides produced byte-identical reports and a
worse outcome:

| Run | Tokens | Root end byte |
|---|---:|---:|
| Default | 41,455 | 73,003 |
| Stack override 16, 32 or 64 | 26,593 | 45,497 |

The combined node-scale and stack override also did not succeed. The override
runs continued to report `maxStacks=8`, so the effective stack-limit behaviour
remains unresolved.

## Interpretation

The measured iteration, node, arena and depth budgets were all below 4%
utilisation. The public strict-parsing diagnostics also did not classify the
result as an early parser safety stop. These measured resource limits were
therefore not implicated.

Candidate B exhausted its viable parse stacks and failed to accept a valid
bundle that Candidate A accepted. This is recorded as an observed
parser/recovery incompatibility. It is not described as a proven grammar
defect because the exact cause of the stack exhaustion remains unresolved.

The formal fixture comparison remains a correctness tie. This real-world
finding is considered under Gate C as reimplementation and operational risk.
