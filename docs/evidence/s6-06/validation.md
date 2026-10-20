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
PR #175 merged. Component 4 agreement on computed-import scope remains
pending. Keep #151 open until agreement is explicitly recorded.
