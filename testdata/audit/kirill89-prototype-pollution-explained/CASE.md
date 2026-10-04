# kirill89-prototype-pollution-explained

- Repository: <https://github.com/Kirill89/prototype-pollution-explained>
- Commit: `d7b5d98515a95f9a8cb0fedef034010ee083a6a9`
- Ecosystem / language: npm / JavaScript
- Why this repository: the README documents CVE-2018-16487 in lodash@4.17.4 via
  `_.merge()`, and `index.js` calls `_.merge` on request input. Same repository and
  commit as the Component 2 evaluation (docs/evaluation/component2-public-evaluation-repository.md).

## How each input was produced

| File | Produced by | Command / branch / commit of SBOMber used |
|---|---|---|
| canonical-scan.json | Component 1 | pending: no command on main writes it yet |
| usage-graph.json | Component 2 | pending: `sbomber usage` (feature/s5-10-usage-cli, not merged) |
| localisation.json | Component 3 (`sbomber localise`) | pending |

The three files are committed exactly as produced. Do not edit them by hand;
if one is wrong, regenerate it and record the new command here.

## Labelling notes

Labels were written from the application source and the lodash package source
before any SBOMber command was run on this repository. They are keyed below by
package and advisory; `findingId`s are mapped once canonical-scan.json exists.
Any finding in the scan that is not listed here is labelled by the same method
and listed under "Added after the scan listing".

Source at the pinned commit: `README.md`, `index.js`, `package.json` (`git ls-files`).
Direct dependencies, exact pins: lodash 4.17.4, express 4.16.4, body-parser 1.18.3.

### Searches (run from the repository root at the pinned commit)

| # | Command | Result |
|---|---|---|
| S1 | `grep -rnE "require\(['\"](lodash\|express\|body-parser)" --include=*.js .` | index.js:9 express, :10 body-parser, :11 lodash (`const _ = require('lodash')`) |
| S2 | `grep -rnoE "\b_\.[A-Za-z]+" --include=*.js . \| sort \| uniq -c` | one call: index.js:55 `_.merge` |
| S3 | `grep -rnwE "defaultsDeep\|mergeWith\|zipObjectDeep\|pick\|set\|setWith\|update\|updateWith\|template\|toNumber\|trim\|trimEnd\|words\|camelCase\|kebabCase\|snakeCase\|startCase\|lowerCase\|upperCase\|unset\|omit" --include=*.js .` | no matches |
| S4 | `grep -rnE "\.(redirect\|location)\(" --include=*.js .` | no matches |
| S5 | `grep -rnoE "bodyParser\.[A-Za-z]+\([^)]*\)" --include=*.js .` | index.js:34 `bodyParser.json()` |
| S6 | `grep -rn "limit" --include=*.js .` | no matches |

### Dependency-side check (lodash tarballs from registry.npmjs.org)

| # | Command | Result |
|---|---|---|
| L1 | `grep -n "function safeGet" -A8 4.17.12/package/lodash.js` | 6609: 4.17.12 adds a `constructor` check to `safeGet` (the CVE-2019-10744 fix) |
| L2 | `grep -n "safeGet(" 4.17.12/package/lodash.js` | used at 3607 (`baseMerge`), 3634-3635 (`baseMergeDeep`) |
| L3 | `grep -n "var merge = createAssigner" -A2 4.17.12/package/lodash.js` | 13437-13438: `merge` calls `baseMerge` |
| L4 | `grep -c safeGet 4.17.4/package/lodash.js` | 0: the pinned version has no such check |
| L5 | `grep -n "baseSet(" 4.17.4/package/lodash.js` | callers at 3782 (`basePickBy`), 4337 (`baseUpdate`), 13652 (`set`), 13681 (`setWith`); none in `baseMerge`/`baseMergeDeep` |

### Worksheet

| Package | Advisory | Symbols the advisory names | Label | Evidence / reasoning |
|---|---|---|---|---|
| lodash 4.17.4 | GHSA-fvqr-27wr-82fm / CVE-2018-3721 | merge, mergeWith, defaultsDeep | genuine_usage | index.js:55 `_.merge(message, req.body.message, {...})` in the PUT / handler; req.body.message is request input |
| lodash 4.17.4 | GHSA-4xc9-xhrj-v574 / CVE-2018-16487 | merge, mergeWith, defaultsDeep | genuine_usage | index.js:55, as above; the repository README names this CVE |
| lodash 4.17.4 | GHSA-jf85-cpcp-j695 / CVE-2019-10744 | defaultsDeep | genuine_usage (decision: see below) | index.js:55 calls `_.merge`, which reaches the code the fix changed (L1-L4) |
| lodash 4.17.4 | GHSA-p6mc-m468-83gw / CVE-2020-8203 | pick, set, setWith, update, updateWith, zipObjectDeep | no_genuine_usage | S2, S3: none called; the fix is in `baseSet`, which is not on the `merge` path (L5) |
| lodash 4.17.4 | GHSA-35jh-r3h4-6jhm / CVE-2021-23337 | template | no_genuine_usage | S2, S3: not called |
| lodash 4.17.4 | GHSA-r5fr-rjxr-66jc | template (imports option) | no_genuine_usage | S2, S3: not called |
| lodash 4.17.4 | GHSA-29mw-wpgm-hmr9 / CVE-2020-28500 | toNumber, trim, trimEnd | no_genuine_usage | S2, S3: not called |
| lodash 4.17.4 | GHSA-x5rq-j2xg-h7qm / CVE-2019-1010266 | none named; lodash#3359 identifies words and the case functions | no_genuine_usage | S2, S3: not called. NVD describes a "date handler"; the referenced lodash issue #3359 is the `words` regex; labelled against #3359 |
| lodash 4.17.4 | GHSA-xxjr-mmjv-4gpg | unset, omit | no_genuine_usage | S2, S3: not called |
| lodash 4.17.4 | GHSA-f23m-r3pf-42rh | unset | no_genuine_usage | S2, S3: not called |
| express 4.16.4 | GHSA-qw6h-vgh9-j6wx / CVE-2024-43796 | res.redirect | no_genuine_usage | S4: not called |
| express 4.16.4 | GHSA-rv95-896h-c2vc / CVE-2024-29041 | res.location, res.redirect | no_genuine_usage | S4: not called |
| body-parser 1.18.3 | GHSA-qwcr-r2fm-qrc7 / CVE-2024-45590 | urlencoded (extended) | no_genuine_usage | S5: only `bodyParser.json()` is used (index.js:34) |
| body-parser 1.18.3 | GHSA-v422-hmwv-36x6 / CVE-2026-12590 | `limit` option with an invalid value | no_genuine_usage (rule 8) | index.js:34 calls `bodyParser.json()` with no options (S5, S6); the advisory's trigger is an invalid `limit` value, which is not set |

### Decision: CVE-2019-10744

The advisory names only `defaultsDeep`, which the application does not call. The
fix in 4.17.12 is a `constructor` check in `safeGet`, used by `baseMerge` and
`baseMergeDeep` (L1, L2); `_.merge` calls `baseMerge` (L3), and 4.17.4 has no such
check (L4). The code path the fix changed is therefore executed by index.js:55, so
this is labelled genuine_usage under rule 3 ("a public function that reaches it").
If SBOMber matches only the advisory's named symbol, this label is where a
missed_usage would show.

### Added after the scan listing

(none yet)

## Known limitations of this case

- No committed lockfile: transitive packages (e.g. qs via express/body-parser) are not in the scan.
- Single source file; no TypeScript; no nested same-package versions.
- Advisory list above comes from the GitHub Advisory Database; the findings in
  canonical-scan.json are what the labels are finally keyed to.
