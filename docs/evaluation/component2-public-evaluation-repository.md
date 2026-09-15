# Component 2 Public Evaluation Repository

## Selection

- Repository: `Kirill89/prototype-pollution-explained`
- Pinned commit: `d7b5d98515a95f9a8cb0fedef034010ee083a6a9`
- Language: JavaScript
- Ecosystem: npm

The pinned commit must be used for evaluation rather than the moving master branch.

## Rationale

The repository is small enough to inspect and hand-label. At the pinned commit it contains only `index.js`, `package.json`, and `README.md`.

Its npm dependencies include `body-parser` 1.18.3, `express` 4.16.4, and `lodash` 4.17.4.

The application genuinely uses Lodash: `index.js` imports it with `require("lodash")` and calls `_.merge(...)`.

## Historical CVE

The repository README identifies `CVE-2018-16487` for `lodash@4.17.4` through the `_.merge()` function.

This gives Component 2 a real dependency import and dependency-call case associated with a historical CVE.

Component 2 provides import, call-site, and later reachability evidence. It does not make the final vulnerability decision.

## Limitations

- No committed npm lockfile, so exact installed-version reconciliation cannot be demonstrated.
- No nested same-package multiple-version case.
- No TypeScript or TSX coverage.
- No large-repository performance evidence.
- This single repository cannot support a general accuracy percentage.

## S4-20 Decision

This selection satisfies S4-20: a public JavaScript repository with real npm dependencies and a historical CVE is named, pinned by commit SHA, and its rationale and limitations are documented.

The client will be informed of this selection rather than asked to choose the repository.
