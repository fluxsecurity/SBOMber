# S6-06 validation — Issue #151

Validated on 20 October 2026.

- All 15 policy scenarios passed across five test functions.
- Tests exercise production parsing, graph generation, JSON conversion
  and Component 4's join/results path.
- make build, full Go tests, go vet and golangci-lint passed.
- Contract validation passed: 235 invariant checks.
- Formatting and git diff whitespace checks passed.
- Go checks ran with GITHUB_TOKEN and GH_TOKEN unset in a subshell.

Changes are limited to documentation, regression tests and saved logs.
Production behaviour, schemas and defaults remain unchanged.
Issue #152 measurements are unaffected.

Component 3 paired-owner review approved PR #175: https://github.com/fluxsecurity/SBOMber/pull/175#pullrequestreview-5583045843
PR #175 merged. Component 4 agreement was recorded by Zane (XUZANE) on
22 October 2026: https://github.com/fluxsecurity/SBOMber/pull/176#issuecomment-6331298063
The agreement covers repository-wide uncertainty within analysed source,
including scripts; Zane also accepted unsupported/partial MDX handling.
Issue #151 can close when this agreement record merges through PR #176.
