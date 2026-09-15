# T10 — Maturity Review

## Result

Candidate A has stronger established downstream adoption. Candidate B has much
higher recent activity and a larger test suite, but is young, pre-1.0 and
strongly dependent on one maintainer.

## Evidence

| Signal | Candidate A | Candidate B |
|---|---|---|
| Pinned version | v0.25.0 | v0.51.0 |
| Licence | MIT | MIT |
| Repository created | August 2024 | February 2026 |
| Commits in last 90 days | 0 | 2,428 |
| Open non-PR issues | 6 | 3 |
| Oldest zero-comment issue | January 2026 | None |
| pkg.go.dev importers | 174 | 26 |
| Pinned module test files | 8 | 737 |
| Pinned module test functions | 164 | 4,587 |
| Current checkout test files | 9 | 916 |
| Current checkout test functions | 165 | 5,198 |
| Changelog | None found | Detailed changelog |
| Version status | Pre-1.0 | Pre-1.0 |

## Candidate A

Candidate A is maintained under the official Tree-sitter organisation and has
substantially more known downstream importers.

Its binding repository has no commits in the measured 90-day period. GitHub
exposed tags through v0.24.0, while the pinned module and pkg.go.dev expose
v0.25.0. No changelog or GitHub releases were found.

The published module's complete test run could not pass independently because
a repository fixture under the Tree-sitter submodule was omitted. A complete
current repository checkout with its submodule passed 165 test functions.

Most checked-out repository commits came from one contributor, although the
official Tree-sitter organisation provides broader institutional context.

## Candidate B

Candidate B has a very large test suite, frequent releases, a detailed
changelog and active responses to all currently open issues.

Its five latest releases occurred between 4 and 16 August 2026. This shows
active maintenance but also substantial pre-1.0 change frequency.

Approximately 98% of commits in the measured 90-day period were authored
under identities belonging to the primary maintainer. This creates a material
single-maintainer continuity risk.

The full suite could not complete on the spike VM because compilation exceeded
the disk quota. The run reached approximately 1.43 GB peak RSS. This is an
environmental limitation and is not recorded as a test failure. The focused
SBOMber harness and all 13 extraction fixtures passed separately.

No explicitly labelled public API breaking change was found. However, the
project remains at version 0.x, and the rapid minor-release cadence requires
SBOMber to pin and deliberately review upgrades.

## Decision relevance

Maturity favours Candidate A because of official ownership and stronger
downstream adoption.

Candidate A still carries low-activity, release-record and CGO ecosystem
risks. Candidate B carries larger pre-1.0 churn, resource-demand and
single-maintainer risks.

Neither candidate is risk-free, so the final selection must also apply the
correctness, robustness and packaging evidence.

## Runtime-maturity clarification

Candidate A's primary maturity advantage is the official Tree-sitter C runtime
beneath its thin Go binding. That runtime has broad production exposure across
editors and code-intelligence tooling. Low activity in the thin binding is
less concerning when SBOMber pins parser and grammar versions.

Candidate B's high activity, large test suite and detailed changelog are
strengths. However, it remains a young from-scratch runtime reimplementation
whose parity is primarily demonstrated by its own suite and whose maintenance
is concentrated around one maintainer.

For SBOMber's evidence-producing parser, mature runtime behaviour outweighs
binding-repository activity.
