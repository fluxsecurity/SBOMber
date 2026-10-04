# Design Note: Joining Localisation Candidates to Application Usage

Date: 2026-10-04 · Status: **proposed, needs Component 4 sign-off** (Bob → Zane)

Relates to #119 (S5-08, join rule 6), #117 (S5-06), #121 (S5-10), and the
frozen evaluation set `localisation-set-v1` (#123).

## The problem

Component 3 tells Component 4 which functions an advisory implicates.
Component 2 tells Component 4 which package symbols the application imports
and calls. Component 4 joins the two. The join only works if both sides speak
the same names, and they often do not:

- the fix usually lands in a **private helper** (`safeGet`, `parseObject`,
  `setKey`);
- the application calls a **public export** (`merge`, `qs.parse`, `minimist()`).

On the frozen set, measured from `spikes/localisation/results/`:

| Join keys | Cases whose keys contain a public symbol the app would call |
|---|---|
| Selected candidate set as-is | **5/10** (c01, c04, c05, c08, c09) |
| Plus symbols the advisory prose names | **7/10** (adds c02, c03) |
| Remaining | c06 `setKey` nested in the anonymous export; c07 `parseObject` behind `lib/index.js`'s `parse`; c10 helpers behind the anonymous export |

#119 rule 6 already says a private-helper mismatch must not produce
`no_usage_detected`. But `localisation.json` 1.0.0 gives Component 4 **no way
to tell** a private helper from a public export: `safeGet` and `template` look
identical. Component 4's draft join (`internal/decision/fixtures.go`, PR #109)
matches `candidateSymbols[].symbol` against `calledSymbol` directly. On c02,
with the analysis otherwise complete, that join would report an application
calling `_.merge` as `no_usage_detected`.

Advisory names do not fix this on their own. On c02 the prose extractor
returns `mergeWith` and `defaultsDeep` but not `merge`, so adding them still
leaves `_.merge` unmatched. Prose can add join keys. It cannot prove the key
set is complete.

## Proposed rule

**A name match can prove usage. Only a closed candidate set can support a
negative.**

1. **Join keys.** For each localisation result, the join keys are:
   - every candidate whose `visibility` is `public`;
   - every name in `exposedVia` of an `internal` candidate;
   - symbols the advisory names, marked as prose-derived (positive-only).
2. **Positive.** If any join key equals a resolved `calledSymbol` (or
   `importedSymbol` for whole-module bindings, per #119 rule 8) on an
   occurrence of the same purl, the finding may be `usage_detected`, subject
   to Component 4's other conditions.
3. **Closed set.** The candidate set is *closed* when every candidate is
   either `public`, or `internal` with an `exposedVia` derived from the
   package's own code (export resolution), not from prose.
4. **Negative.** `no_usage_detected` additionally requires a closed set. An
   open set (any candidate `internal` with no code-derived `exposedVia`, or
   `visibility` absent or `unknown`) produces `unknown` with the
   criterion *"localised to an internal function with no resolved public
   entry point"*.
5. **Backward compatibility.** A 1.0.0 document has no `visibility`, so every
   set is open. That is the conservative reading: positives still join,
   negatives fall back to `unknown`.

On the frozen set, this rule never produces a negative from a name mismatch
alone. Every case is either joinable by a public name or falls back to
`unknown`.

## Contract change (localisation 1.0.0 → 1.1.0, additive)

Two optional fields on `candidateSymbols[]`:

```json
{
  "symbol": "safeGet",
  "modulePath": "_baseMergeDeep.js",
  "changeKind": "modified",
  "visibility": "internal",
  "exposedVia": ["merge", "mergeWith", "defaultsDeep"],
  "exposedViaSource": "export_resolution"
}
```

| Field | Values | Meaning |
|---|---|---|
| `visibility` | `public` · `internal` · `unknown` | `public` = exported by the package's entry module under this name, or `default` for the module function itself |
| `exposedVia` | public names | exports through which the internal candidate is reached |
| `exposedViaSource` | `export_resolution` · `advisory_text` | only `export_resolution` can close a set |

New `contracts/validate.py` invariant: a `decision-results.json`
`no_usage_detected` whose localisation result has an open candidate set is
rejected.

## How Component 3 fills the fields

Cheapest first, all from the vulnerable tarball the localiser already reads
in memory (never executed):

1. **Entry-module exports.** Read `package.json` `main`/`exports` and list
   the names the entry module exports, including `module.exports = fn`
   (`default`) and alias assignments (`exports.parse = decode`). A candidate
   with an exported name is `public`. This closes c01, c04, c09.
2. **Anonymous-export nesting.** A candidate nested inside the function
   assigned to `module.exports` is reached via `default` (c06, c10).
3. **One-hop re-export.** `module.exports = { parse: require('./parse') }`
   maps the target module's exported function to the public name (c07).
4. **Bounded caller walk.** For lodash-style helpers, walk callers inside
   the package up to a fixed depth and record exports reached (c02, c03).
   If the depth limit is hit, stop and leave the set open.

Steps 1–3 are about a day of work and should take the frozen set to 9–10/10
joinable. Step 4 is optional for Sprint 6. Until any step lands, the rule's
fallback keeps Component 4 safe.

## Decisions needed from Component 4

- Accept rule 4 (open set → `unknown`) as the S5-08 implementation of #119
  rule 6.
- Accept the 1.1.0 field names, or propose others before Component 3
  implements them.
- Agree that prose-derived names are positive-only.
