# Localisation Evaluation Cases (S4-18)

Ten npm CVEs, ground truth fixed on 2026-09-06 **before** the localisation
tool was run against them. The machine-readable file is `cases.json`; this
page is the human summary. Five of the ten advisories name no function,
which is what justifies diff-based localisation at all.

How each expectation was established: the maintainer's fix commit was read
in full and the enclosing function of every changed non-test line written
down by hand. Two layers are recorded per case, because they differ more
often than not:

- **changed functions** — what the fix actually modified (often a private
  helper);
- **public symbols** — what an application imports or calls, which is what
  Component 2 observes and Component 4 joins on. `default` means the module
  itself is the function.

| # | Advisory | Package | Names a function? | Changed by the fix | Public symbol | What it tests |
|---|---|---|---|---|---|---|
| c01 | CVE-2021-23337 | lodash 4.17.20 → 4.17.21 | yes: `template` | `template` | `template` | baseline; fix lands in the named function |
| c02 | CVE-2018-16487 | lodash 4.17.4 → 4.17.11 | yes: `merge`, `mergeWith`, `defaultsDeep` | `safeGet` (private) | `merge`, `mergeWith`, `defaultsDeep` | the S4-20 evaluation repo case; fix in a private helper |
| c03 | CVE-2019-10744 | lodash 4.17.11 → 4.17.12 | yes: `defaultsDeep` | `safeGet` (private) | `defaultsDeep` | advisory links a PR, not a commit |
| c04 | CVE-2020-7788 | ini 1.3.5 → 1.3.6 | yes: `ini.parse` | `decode` | `parse` (alias of `decode`) | export alias between advisory name and changed name |
| c05 | CVE-2022-25883 | semver 7.5.1 → 7.5.2 | yes: `new Range` | `Range`, `format`, `parseRange`, `replaceTildes`, `replaceCarets`, `replaceXRanges`, `Comparator` | `Range` | refactor-sized fix across five files |
| c06 | CVE-2020-7598 | minimist 1.2.2 → 1.2.3 | **no** | `setKey` (nested) | `default` | function nested inside the anonymous export; two release lines referenced |
| c07 | CVE-2022-24999 | qs 6.10.2 → 6.10.3 | **no** | `parseObject` | `parse` | doubly-named function expression; public entry in another file |
| c08 | CVE-2022-0235 | node-fetch 2.6.6 → 2.6.7 | **no** | `fetch`, `isDomainOrSubdomain` | `default` | three referenced commits, one with no code; tarball ships a compiled bundle |
| c09 | CVE-2021-3807 | ansi-regex 5.0.0 → 5.0.1 | **no** | `default` | `default` | whole package is one anonymous arrow function |
| c10 | CVE-2022-38900 | decode-uri-component 0.2.0 → 0.2.1 | **no** | `decodeComponents`, `decode` | `default` | two private helpers behind an anonymous export |

## Dropped

| Advisory | Package | Why |
|---|---|---|
| CVE-2020-7774 | y18n | fixes across three release lines with different internals; no single defensible set |
| CVE-2021-32803 | tar | three-commit fix to a directory-cache state machine; expected set not defensible |
| CVE-2020-28168 | axios | already the contract fixture case (find-002); the fixture must not grade itself |

## Observations made while curating

- None of the ten OSV records carries `ecosystem_specific` or any structured
  function field for npm, and none types its commit links as `FIX`; every fix
  commit URL is an untyped `WEB` reference. Structured-metadata localisation
  therefore cannot work for npm today, exactly as the S4-08 issue warned.
- GitHub's diff hunk headers were empty for all three lodash commits because
  every function is indented inside an IIFE. Function attribution has to
  parse the file.
- Advisories that name a function usually name the **public** one; the fix
  usually lands in a **private** one (c02, c03, c04, c07, c10). Diff-based
  methods find the private function; joining it to application usage needs
  either the advisory's public name or export-alias resolution.
