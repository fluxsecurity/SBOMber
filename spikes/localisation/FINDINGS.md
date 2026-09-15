# Localisation Spike Findings (S4-08)

**Question.** Of three sources, which actually tells us the function an npm
advisory implicates: structured advisory metadata, the maintainer's patch or
security-commit references, or a diff of the vulnerable and fixed versions?
The client also described the method he expected: search the package's
GitHub repository for the CVE number in commit messages, read the patch, and
use GitHub Advisories for their diff and patch links.

**Method.** Ten CVEs curated in S4-18 with ground truth fixed before any
measurement (`cases/cases.json`, committed in `1ef9d95` ahead of the tool).
`sbomber localise --all-methods --client-search` ran every method on every
case and recorded each attempt independently (`results/trace.json`).
`evaluate.py` graded each attempt on two questions: does the candidate set
contain a function the fix changed, and does it contain the public symbol an
application would call. Full tables: `results/evaluation.md`.

## Answer

| Source | Produced candidates | Named a changed function | Named the public symbol | Median set size |
|---|---|---|---|---|
| Structured advisory metadata | **0/10** | – | – | – |
| Patch reference (fix commit or PR linked by the advisory) | **10/10** | 10/10 | 5/10 | 2 |
| Advisory prose | 6/10 | 1/6 | 4/6 | 1 |
| Vulnerable-vs-fixed tarball diff | 10/10 | 10/10 | 4/10 | 7 |
| Client's method: CVE ID in a commit message | 1/10 | – | – | – |

**Unknown rate: 0/10.** Every case was localised; nine at high confidence,
one (semver, a refactor-sized fix touching 20 functions) at low.

1. **Structured metadata does not exist for npm.** No OSV record carried an
   `ecosystem_specific` block for the npm package, and no reference was typed
   `FIX`; every fix link was an untyped `WEB` reference. The issue's warning
   ("do not design around structured fields existing") was correct. The
   contract fixture's `find-001` labels a prose mention as `advisory_metadata`;
   under this tool it is `advisory_text`.
2. **The patch reference is the source that works.** All ten advisories link
   the fix commit or its pull request. Reading the commit's per-file patches
   and resolving each changed line to its enclosing function with Component 2's
   tree-sitter grammar found a function the fix changed in every case, with a
   median of two candidates. Pull-request links had to be resolved to commits
   in four cases (lodash #4336, semver #564/#585/#593, qs #428, node-fetch #1453).
3. **The client's method rarely works as described, but the intent is right.**
   Only lodash's CVE-2021-23337 fix mentions its CVE in a commit message
   (1/10). Maintainers fix first and receive the CVE later. The
   *advisory's* links to the commit are what carry the information, and
   GitHub Advisories does publish them, so the method works when read as
   "follow the advisory to the patch" rather than "grep the log for the CVE".
   The minimist repository has since moved (`substack` to `minimistjs`), which
   made the commit search fail outright (HTTP 422).
4. **The tarball diff always finds the change but says too much.** It is the
   only source that needs no GitHub access, and it found the changed function
   10/10. It also reports every other change in the release: lodash 4.17.21
   bundles the CVE-2020-28500 ReDoS fix (`toNumber`, `trim`, `trimEnd`,
   `baseTrim`) with the `template` fix; 4.17.4 to 4.17.11 spans 26 source files
   and 19 symbols; qs ships a `dist/` bundle that folds in a dependency's
   changes. It is the right fallback, not the right first choice.
5. **Advisory prose names the public API, the fix lands in a private helper.**
   Prose found the public symbol in 4/6 hits but a changed function in only
   1/6; the patch found a changed function 10/10 but the public symbol only
   5/10. The five misses are exactly the private-helper cases from S4-18:
   `safeGet` behind `merge`/`defaultsDeep` (c02, c03), `setKey` inside
   minimist's default export (c06), `parseObject` behind `qs.parse` in another
   file (c07), and two helpers behind decode-uri-component's anonymous export
   (c10). Prose extraction also produced noise: `are`, `vulnerable` (c02),
   `Polluted` (c06), and the header names `authorization`, `cookie` (c08).

## What this means for Component 4

The `candidateSymbols` set describes **changed code**, and `notes` says what
else was seen. Component 4 should join on it like this:

- A candidate that is also the symbol Component 2 observed at a call site is
  strong evidence (c01 `template`, c04 `parse`, c08 `fetch`/`default`, c09
  `default`).
- When the candidate is a private helper (note "not exported from this
  file"), the observed public symbol will not match it. That is not a
  negative result; it means the localisation is package-internal and the
  decision must fall back to package level, as `unknown` localisation does.
- The `default` symbol means the module itself is the function
  (`module.exports = function`, `export default`). Component 2 records such
  calls as a call on the whole-module binding; the two sides should agree to
  join on `default`.
- Export aliases are emitted as separate candidates with note "export alias
  of X" (c04: `decode` and `parse`), so `ini.parse` matches without Component
  4 knowing about the alias.

## Limitations recorded when discovered

- All ten cases are JavaScript. The TypeScript and TSX grammars are wired in
  but were not exercised by a case; add a TS package in Sprint 5.
- Comment-only and blank changed lines are ignored; a fix that only changes a
  string constant or regex at module level is reported under "non-function
  changes", not as a candidate (lodash's `reForbiddenIdentifierChars`, semver's
  `safeRe`). Component 4 cannot match those to a call site anyway.
- Minified files (`*.min.js`, or any line over 4,000 bytes) are skipped and
  noted. Bundled `lib/index.js`, `lib/index.mjs`, `lib/index.es.js` triplets
  (node-fetch) produce the same symbols three times; they are de-duplicated by
  symbol and path, so the count is per file.
- Attribution of a private helper to the public API that calls it would need
  a call graph inside the package. That is deliberately out of scope
  (Requirements v8: application-source-only usage analysis) and is the single
  biggest gap in the numbers above.
- The GitHub API is required for patch_reference (60 requests/hour without a
  token, 5,000 with). Commit patches over roughly 1 MB are not inlined by the
  API and are reported as not attributable. Repositories that were renamed
  break the commit search but not the commit fetch.
- When several referenced commits belong to different release lines and the
  registry publishes no `gitHead` for the fixed version (ansi-regex, minimist),
  candidates from all of them are merged and the note says so. For ansi-regex
  this adds `ansiRegex` from the 6.x line to `default` from the 5.x line.
- `llm_suggested` is not implemented. The contract already forbids it from
  supporting any negative conclusion.
- Confidence criteria are published in `internal/localisation/localise.go`
  (`confidenceFor`) and are categorical, not a formula.
- Run time for the ten cases was about 70 seconds, dominated by network
  requests; nothing was executed and nothing was written to disk except the
  two output files.

## Recommendation for Sprint 5

Keep `patch_reference` first and `version_diff` as the fallback, exactly as
the contract orders them. Add one refinement: when advisory prose names a
public symbol and the tarball for the fixed version contains an exported
function of that name, attach it to the result as a corroborated public
candidate. On these ten cases that lifts public-symbol coverage from 5/10 to
7/10 without adding any of the prose noise, because the noise words are not
exported functions.
