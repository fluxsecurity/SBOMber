# Design Note: Joining Localisation Candidates to Application Usage

Date: 2026-10-04 · Status: **accepted** by Component 4 on 2026-10-04 with
three conditions, folded in below; implemented in `internal/decision/join.go`
by #142. The localisation 1.1.0 schema change is still to do (Component 3).

Relates to #119 (S5-08, join rule 6), #140, #142, #117 (S5-06), #121 (S5-10),
and the frozen evaluation set `localisation-set-v1` (#123).

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
matched `candidateSymbols[].symbol` against `calledSymbol` directly. On c02,
with the analysis otherwise complete, that join reported an application
calling `_.merge` as `no_usage_detected` (#140, fixed by #142).

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
   - the candidate's own symbol when `visibility` is absent (1.0.0) or
     `unknown`;
   - names from advisory text (an `advisory_text` result, or an `exposedVia`
     with `exposedViaSource: advisory_text`) are prose-derived:
     positive-only, and a `usage_detected` resting only on them is capped at
     `medium` confidence, with the justification saying so.
2. **Positive.** If any join key equals a resolved `calledSymbol` on an
   occurrence of the same purl, the finding may be `usage_detected`, subject
   to Component 4's other conditions. Per #119 rule 8, Component 2 emits
   `calledSymbol: "default"` for a direct call on a whole-module binding and
   the property name for member access, so a `public` candidate named
   `default` matches (c06, c09, c10). There is no `importedSymbol` fallback.
3. **Closed set.** The candidate set is *closed* when every candidate is
   either `public`, or `internal` with a non-empty `exposedVia`,
   `exposedViaSource: export_resolution` and `exposedViaComplete: true`.
   An `advisory_text` or `llm_suggested` result is never closed.
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

Four optional fields on `candidateSymbols[]`:

```json
{
  "symbol": "safeGet",
  "modulePath": "_baseMergeDeep.js",
  "changeKind": "modified",
  "visibility": "internal",
  "exposedVia": ["merge", "mergeWith", "defaultsDeep"],
  "exposedViaSource": "export_resolution",
  "exposedViaComplete": true
}
```

| Field | Values | Meaning |
|---|---|---|
| `visibility` | `public` · `internal` · `unknown` | `public` = exported by the package's entry module under this name, or `default` for the module function itself |
| `exposedVia` | public names | exports through which the internal candidate is reached |
| `exposedViaSource` | `export_resolution` · `advisory_text` | only `export_resolution` can close a set |
| `exposedViaComplete` | `true` · `false` | `true` only when resolution was exhaustive; a partial caller walk is `false` and leaves the set open |

`internal/decision` already reads these fields (#142). `contracts/localisation.schema.json`
is still 1.0.0 with `additionalProperties: false` on `candidateSymbols[]`, so a
document carrying them fails `contracts/validate.py` until Component 3 ships
the 1.1.0 schema.

Proposed, not yet on main: a `contracts/validate.py` invariant rejecting a
`decision-results.json` `no_usage_detected` whose localisation result has an
open candidate set.

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
   If the depth limit is hit, stop and set `exposedViaComplete: false`.

Steps 1–3 are about a day of work and should take the frozen set to 9–10/10
joinable. Step 4 is optional for Sprint 6. Until any step lands, the rule's
fallback keeps Component 4 safe.

## Component 4 decisions (2026-10-04, review on #139)

- Accepted: rule 4 (open set → `unknown`) as the S5-08 implementation of
  #119 rule 6; the 1.1.0 field names; prose-derived names are positive-only.
- Conditions, now in rules 1–3 above: `exposedViaComplete` gates closing a
  set; rule 2 follows #119 rule 8; prose-only matches cap confidence at
  `medium`.

Until localisation 1.1.0 ships every set is open, so no finding can be
`no_usage_detected`: those findings show under "Insufficient information".
