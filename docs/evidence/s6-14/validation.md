# Validation — Issue #152

Validated on 20 October 2026.

| Check | Result |
|---|---|
| make build | PASS before measurement |
| Full Go suite | PASS |
| go vet | PASS |
| golangci-lint | PASS — 0 issues |
| Contract invariants | PASS — 235 checks |
| Contract regression tests | PASS — 25 tests |
| Python script tests | PASS — 28 tests |
| gofmt | PASS — no files listed |
| git diff --check | PASS |
| Four frozen reachability fixtures | PASS |
| Per-repository canonical/usage schema and invariants | PASS |
| Repeated usage output | Byte-identical for all four repositories |

The first full Go run failed TestNewClient because NewClient("")
reads GITHUB_TOKEN from the environment while the existing test expects
no token. The full suite passed with GITHUB_TOKEN and GH_TOKEN unset
inside a subshell. Both the original failure and successful rerun logs
are preserved. No production code was changed for this condition.

Paired-owner review and PR merge remain pending. Issue #152 stays open
until its acceptance criteria and review requirements are satisfied.
