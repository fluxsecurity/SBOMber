# Localisation Spike Results (S4-08)

Ten cases, ground truth fixed before measurement (`cases/cases.json`). Tool: `sbomber localise --all-methods --client-search`, trace in `results/trace.json`.

## Headline numbers

| Measure | Value |
|---|---|
| Cases | 10 |
| Selected method produced a candidate | 10/10 |
| **Unknown rate** (no method produced a candidate) | **0/10** |
| Selected candidate set contains a function the fix changed | 10/10 |
| Selected candidate set contains the public symbol an app would call | 5/10 |
| Client's method: vulnerability ID found in a commit message | 1/10 repositories searched |

## Per method

| Method | Attempted | Hit | Empty | Error / non-code / skipped | Contains a changed function | Contains the public symbol | Median candidates |
|---|---|---|---|---|---|---|---|
| `advisory_metadata` | 10 | 0 | 10 | 0 | 0/0 | 0/0 | - |
| `patch_reference` | 10 | 10 | 0 | 0 | 10/10 | 5/10 | 2 |
| `advisory_text` | 10 | 6 | 4 | 0 | 1/6 | 4/6 | 1 |
| `version_diff` | 10 | 10 | 0 | 0 | 10/10 | 4/10 | 7 |

Hit = at least one candidate. A hit that names the wrong function is still a hit; the two right-hand columns say whether it was useful.

## Per case

| Case | Advisory | Names a fn? | Selected | Conf. | Selected candidates | Changed fn found | Public symbol found | metadata | patch | text | version_diff |
|---|---|---|---|---|---|---|---|---|---|---|---|
| c01 | CVE-2021-23337 lodash | yes | `patch_reference` | high | template | yes | yes | empty | 1 (CP) | 1 (CP) | 7 (CP) |
| c02 | CVE-2018-16487 lodash | yes | `patch_reference` | high | safeGet | yes | no | empty | 1 (C) | 4 (P) | 19 (C) |
| c03 | CVE-2019-10744 lodash | yes | `patch_reference` | high | safeGet | yes | no | empty | 1 (C) | 1 (P) | 8 (C) |
| c04 | CVE-2020-7788 ini | yes | `patch_reference` | high | decode, parse | yes | yes | empty | 2 (CP) | 1 (P) | 2 (CP) |
| c05 | CVE-2022-25883 semver | yes | `patch_reference` | low | makeSafeRe, parse, SemVer, default, Comparator +18 | yes | yes | empty | 20 (CP) | empty | 13 (C) |
| c06 | CVE-2020-7598 minimist | no | `patch_reference` | high | setKey | yes | no | empty | 1 (C) | 1 (miss) | 1 (C) |
| c07 | CVE-2022-24999 qs | no | `patch_reference` | high | parseObject, parseObjectRecursive | yes | no | empty | 2 (C) | empty | 15 (C) |
| c08 | CVE-2022-0235 node-fetch | no | `patch_reference` | high | isDomainOrSubdomain, fetch, default | yes | yes | empty | 3 (CP) | 3 (miss) | 3 (CP) |
| c09 | CVE-2021-3807 ansi-regex | no | `patch_reference` | high | default, ansiRegex | yes | yes | empty | 2 (CP) | empty | 1 (CP) |
| c10 | CVE-2022-38900 decode-uri-component | no | `patch_reference` | high | decodeComponents, decode | yes | no | empty | 2 (C) | empty | 2 (C) |

Method cells: candidate count, then C = contains a changed function, P = contains the public symbol.

## Notes recorded per case

### c01 CVE-2021-23337 (lodash)

Expected changed: `template`. Expected public: `template`.

- `advisory_metadata`: empty
  - OSV record has no ecosystem_specific block for this npm package; no structured function field exists
- `patch_reference`: hit -> `template`
  - lodash.js: 3 changed line(s) at module level outside any function
  - lodash.js: 1 changed line(s) at module level outside any function
- `advisory_text`: hit -> `template`
- `version_diff`: hit -> `baseTrim`, `default`, `template`, `toNumber`, `trim`, `trimEnd`, `trimmedEndIndex`; non-function changes: trimmedEndIndex (_baseTrim.js), reTrimStart (_baseTrim.js), reWhitespace (_trimmedEndIndex.js), INVALID_TEMPL_VAR_ERROR_TEXT (template.js), reForbiddenIdentifierChars (template.js), baseTrim (toNumber.js)
  - 12 source file(s) differ between 4.17.20 and 4.17.21
  - _baseTrim.js: 1 changed line(s) at module level outside any function
  - _trimmedEndIndex.js: 1 changed line(s) at module level outside any function
  - core.js: 1 changed line(s) at module level outside any function
  - core.js: 1 changed line(s) at module level outside any function
  - core.min.js: minified, not attributed
- client method: searched `lodash/lodash` for `GHSA-35jh-r3h4-6jhm CVE-2021-23337 CVE-2026-4800 GHSA-r5fr-rjxr-66jc` -> 1 commit(s)

### c02 CVE-2018-16487 (lodash)

Expected changed: `safeGet`. Expected public: `merge`, `mergeWith`, `defaultsDeep`.

- `advisory_metadata`: empty
  - OSV record has no ecosystem_specific block for this npm package; no structured function field exists
- `patch_reference`: hit -> `safeGet`
- `advisory_text`: hit -> `are`, `defaultsDeep`, `mergeWith`, `vulnerable`
  - 4 identifiers extracted from prose; heuristic extraction is over-inclusive
- `version_diff`: hit -> `addMapEntry`, `addSetEntry`, `baseClone`, `baseConvert`, `baseMerge`, `baseMergeDeep`, `cloneByPath`, `cloneMap`, `cloneSet`, `customDefaultsAssignIn`, `default`, `initCloneArray` (+7); non-function changes: isMap (_baseClone.js), isSet (_baseClone.js), keysIn (_baseMerge.js), safeGet (_baseMerge.js), safeGet (_baseMergeDeep.js), addMapEntry (_cloneMap.js)
  - 26 source file(s) differ between 4.17.4 and 4.17.11
  - _addMapEntry.js: 1 changed line(s) at module level outside any function
  - _addSetEntry.js: 1 changed line(s) at module level outside any function
  - _cloneMap.js: 1 changed line(s) at module level outside any function
  - _cloneSet.js: 1 changed line(s) at module level outside any function
  - _safeGet.js: 1 changed line(s) at module level outside any function
- client method: searched `lodash/lodash` for `GHSA-4xc9-xhrj-v574 CVE-2018-16487` -> 0 commit(s)

### c03 CVE-2019-10744 (lodash)

Expected changed: `safeGet`. Expected public: `defaultsDeep`.

- `advisory_metadata`: empty
  - OSV record has no ecosystem_specific block for this npm package; no structured function field exists
- `patch_reference`: hit -> `safeGet`
  - pull request lodash/lodash#4336 resolved to 1 commit(s)
- `advisory_text`: hit -> `defaultsDeep`
- `version_diff`: hit -> `baseClone`, `baseMerge`, `createRound`, `debounced`, `default`, `runInContext`, `safeGet`, `template`; non-function changes: nativeIsFinite (_createRound.js), nativeMin (_createRound.js), fs (org.js), path (org.js), _ (org.js), glob (org.js)
  - 11 source file(s) differ between 4.17.11 and 4.17.12
  - core.js: 1 changed line(s) at module level outside any function
  - core.js: 1 changed line(s) at module level outside any function
  - core.min.js: minified, not attributed
  - core.min.js: minified, not attributed
  - lodash.js: 1 changed line(s) at module level outside any function
- client method: searched `lodash/lodash` for `GHSA-jf85-cpcp-j695 CVE-2019-10744` -> 0 commit(s)

### c04 CVE-2020-7788 (ini)

Expected changed: `decode`. Expected public: `parse`, `decode`.

- `advisory_metadata`: empty
  - OSV record has no ecosystem_specific block for this npm package; no structured function field exists
- `patch_reference`: hit -> `decode`, `parse`
- `advisory_text`: hit -> `parse`
- `version_diff`: hit -> `decode`, `parse`
  - 1 source file(s) differ between 1.3.5 and 1.3.6
- client method: searched `npm/ini` for `GHSA-qqgx-2p2h-9c37 CVE-2020-7788` -> 0 commit(s)

### c05 CVE-2022-25883 (semver)

Expected changed: `Range`, `format`, `parseRange`, `replaceTildes`, `replaceCarets`, `replaceXRanges`, `Comparator`. Expected public: `Range`.

- `advisory_metadata`: empty
  - OSV record has no ecosystem_specific block for this npm package; no structured function field exists
- `patch_reference`: hit -> `Comparator`, `Range`, `SemVer`, `coerce`, `constructor`, `createToken`, `default`, `format`, `hyphenReplace`, `makeSafeRe`, `parse`, `parseRange` (+8); non-function changes: MAX_SAFE_BUILD_LENGTH (semver.js), safeRe (semver.js), LETTERDASHNUMBER (semver.js), safeRegexReplacements (semver.js), safeRe (internal/re.js)
  - pull request npm/node-semver#564 resolved to 1 commit(s)
  - pull request npm/node-semver#585 resolved to 1 commit(s)
  - pull request npm/node-semver#593 resolved to 1 commit(s)
  - commit b717044e57 changes no source code (release or docs commit)
  - semver.js: 7 changed line(s) at module level outside any function
  - semver.js: 3 changed line(s) at module level outside any function
- `advisory_text`: empty
  - advisory prose names no function-like identifier
- `version_diff`: hit -> `constructor`, `createToken`, `default`, `diff`, `format`, `hyphenReplace`, `inc`, `parseRange`, `replaceCarets`, `replaceGTE0`, `replaceStars`, `replaceTildes` (+1); non-function changes: safeRe (internal/re.js)
  - 6 source file(s) differ between 7.5.1 and 7.5.2
  - classes/comparator.js: 1 changed line(s) at module level outside any function
  - classes/comparator.js: 1 changed line(s) at module level outside any function
  - classes/range.js: 1 changed line(s) at module level outside any function
  - classes/range.js: 1 changed line(s) at module level outside any function
  - classes/semver.js: 1 changed line(s) at module level outside any function
- client method: searched `npm/node-semver` for `GHSA-c2qf-rxjj-qqgw CVE-2022-25883` -> 0 commit(s)

### c06 CVE-2020-7598 (minimist)

Expected changed: `setKey`. Expected public: `default`.

- `advisory_metadata`: empty
  - OSV record has no ecosystem_specific block for this npm package; no structured function field exists
- `patch_reference`: hit -> `setKey`
  - commit 4cf1354839 changes no source code (release or docs commit)
  - 3 commits attributed and merged: minimistjs/minimist@10bd4cdf49, minimistjs/minimist@38a4d1caea, minimistjs/minimist@63e7ed05aa
- `advisory_text`: hit -> `Polluted`
- `version_diff`: hit -> `setKey`
  - 2 source file(s) differ between 1.2.2 and 1.2.3
- client method: searched `substack/minimist` for `` -> 0 commit(s); error: HTTP 422 for https://api.github.com/search/commits?per_page=10&q=repo%3Asubstack%2Fminimist+GHSA-vh95-rmgr-6w4m

### c07 CVE-2022-24999 (qs)

Expected changed: `parseObject`. Expected public: `parse`.

- `advisory_metadata`: empty
  - OSV record has no ecosystem_specific block for this npm package; no structured function field exists
- `patch_reference`: hit -> `parseObject`, `parseObjectRecursive`
  - pull request ljharb/qs#428 resolved to 1 commit(s)
  - 9 commits attributed and merged: ljharb/qs@4310742efb, ljharb/qs@727ef5d346, ljharb/qs@7320525993, ljharb/qs@8b4cc14cda, ljharb/qs@ba24e74dd1, ljharb/qs@e799ba57e5, ljharb/qs@ed0f5dcbef, ljharb/qs@f945393cfe, ljharb/qs@fc36827766
- `advisory_text`: empty
  - advisory prose names no function-like identifier
- `version_diff`: hit -> `addNumericSeparator`, `arrObjKeys`, `collectionOf`, `default`, `getIndent`, `indentedJoin`, `inspect`, `inspectString`, `inspect_`, `lowbyte`, `nameOf`, `normalizeStringifyOptions` (+3)
  - 4 source file(s) differ between 6.10.2 and 6.10.3
  - dist/qs.js: 13 changed line(s) at module level outside any function
  - dist/qs.js: 2 changed line(s) at module level outside any function
- client method: searched `ljharb/qs` for `GHSA-hrpp-h998-j3pp CVE-2022-24999` -> 0 commit(s)

### c08 CVE-2022-0235 (node-fetch)

Expected changed: `fetch`, `isDomainOrSubdomain`. Expected public: `default`.

- `advisory_metadata`: empty
  - OSV record has no ecosystem_specific block for this npm package; no structured function field exists
- `patch_reference`: hit -> `default`, `fetch`, `isDomainOrSubdomain`; non-function changes: URL (src/index.js), resolve_url (src/index.js)
  - pull request node-fetch/node-fetch#1453 resolved to 2 commit(s)
  - commit 1ef4b560a1 is the registry gitHead of node-fetch@2.6.7; other referenced commits ignored
  - src/index.js: 7 changed line(s) at module level outside any function
  - src/index.js: 6 changed line(s) at module level outside any function
- `advisory_text`: hit -> `authorization`, `cookie`, `cookie2`
- `version_diff`: hit -> `default`, `fetch`, `isDomainOrSubdomain`; non-function changes: URL$1 (lib/index.es.js), resolve_url (lib/index.es.js), URL$1 (lib/index.js), resolve_url (lib/index.js), URL$1 (lib/index.mjs), resolve_url (lib/index.mjs)
  - 3 source file(s) differ between 2.6.6 and 2.6.7
- client method: searched `node-fetch/node-fetch` for `GHSA-r683-j2x4-v87g CVE-2022-0235` -> 0 commit(s)

### c09 CVE-2021-3807 (ansi-regex)

Expected changed: `default`. Expected public: `default`.

- `advisory_metadata`: empty
  - OSV record has no ecosystem_specific block for this npm package; no structured function field exists
- `patch_reference`: hit -> `ansiRegex`, `default`
  - 4 commits attributed and merged: chalk/ansi-regex@419250fa51, chalk/ansi-regex@75a657da7a, chalk/ansi-regex@8d1d7cdb58, chalk/ansi-regex@c3c0b3f273
- `advisory_text`: empty
  - advisory prose names no function-like identifier
- `version_diff`: hit -> `default`
  - 1 source file(s) differ between 5.0.0 and 5.0.1
- client method: searched `chalk/ansi-regex` for `GHSA-93q8-gq69-wqmw CVE-2021-3807` -> 0 commit(s)

### c10 CVE-2022-38900 (decode-uri-component)

Expected changed: `decodeComponents`, `decode`. Expected public: `default`.

- `advisory_metadata`: empty
  - OSV record has no ecosystem_specific block for this npm package; no structured function field exists
- `patch_reference`: hit -> `decode`, `decodeComponents`
- `advisory_text`: empty
  - advisory prose names no function-like identifier
- `version_diff`: hit -> `decode`, `decodeComponents`
  - 1 source file(s) differ between 0.2.0 and 0.2.1
- client method: searched `SamVerschueren/decode-uri-component` for `GHSA-w573-4hg7-7wgq CVE-2022-38900` -> 0 commit(s)

