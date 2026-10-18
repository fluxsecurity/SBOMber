# Vulnerability reachability (Go)

Owner: Sadman (Component 1).

## What this is, and what it isn't

This implements the "is the vulnerable function actually called, not just
present" idea from the reachability spec — for **Go only**, as a narrow,
real, tested slice rather than the spec's full multi-language engine.
It is exposed as its own command, `sbomber reachability [path]` (see
[Risk score](#risk-score-called-functions-only) below); `sbomber
scan`/`github`/`gitlab` do not call it yet.

## Why govulncheck, not a hand-built call-graph engine

The spec calls for an AST parser and call-graph builder per language. The
first version of this work started down that path for Go using
`golang.org/x/tools/go/ssa` + `go/callgraph` directly. That was abandoned
in favor of shelling out to `govulncheck`
(`golang.org/x/vuln/cmd/govulncheck`) once it became clear this is
literally the Go team's own reference implementation of the same idea,
already built on that same SSA/call-graph machinery, already fed by the
official Go vulnerability database, and already maintained. Reimplementing
it would have meant a worse, less-tested version of a tool that already
ships. `internal/reachability` shells out to it exactly the way
`internal/vulnerability` already shells out to Grype —
`govulncheck -json`'s output is govulncheck's documented, stable
integration contract; the packages it's built from internally are not part
of Go's public API, so wrapping the CLI is the sanctioned integration
point, not a shortcut around a "real" library API that doesn't exist.

## The govulncheck `-json` output shape (verified directly, not assumed)

`govulncheck -json` was undocumented enough in practice that its exact
shape was worth confirming by running it against two hand-built probe
modules (one calling a known-vulnerable `golang.org/x/text/language`
symbol, `ParseAcceptLanguage`, from CVE-2022-32149 / GO-2022-1059; one
importing it but never calling it) before writing any classification code.
Findings from that probe:

- It emits a stream of top-level JSON objects, not one JSON array:
  `{"config":...}`, `{"SBOM":...}`, `{"progress":...}`, `{"osv":...}`,
  `{"finding":...}`, decodable in sequence with a plain
  `json.Decoder.Decode` loop.
- For an OSV with no confirmed call, only coarse `finding` entries appear
  (module-only, or module+package, but no `function` field) — this is the
  "imported but not called" signal.
- For an OSV that **is** called, a `finding` entry appears whose `trace`
  array starts with the vulnerable function itself
  (`module`/`package`/`function`/`position`) and continues outward through
  each caller, ending at the entry point. A 2-frame trace
  (`[vulnerableFunc, main]`) means the scanned module's own code calls it
  directly. A longer trace where frame 1 (the direct caller) belongs to a
  *different* module means a dependency calls it on the app's behalf.
- The first guess at which symbol was "the vulnerable one" for the probe
  was wrong (`language.Parse` isn't listed as affected; `ParseAcceptLanguage`
  and `MatchStrings` are) — confirmed by reading the actual OSV entry in
  govulncheck's own output rather than guessing twice.

## Tier mapping (derived from the verified shape above)

| Tier | Condition |
|---|---|
| CRITICAL (100) | A function-level trace exists and its direct-caller frame (`trace[1]`) belongs to the module being scanned — app code calls the vulnerable function itself. |
| HIGH (85) | A function-level trace exists but `trace[1]` belongs to a different module — a dependency calls it, and that dependency is itself reachable from the app. |
| MEDIUM (50) | `govulncheck`'s own `config.scan_level` isn't `"symbol"` — it fell back to a coarser scan (e.g. the module didn't build cleanly), so reachability genuinely couldn't be confirmed either way. This is a real signal from the tool, not an invented heuristic. |
| LOW (5) | The vulnerable package/module is present in a `finding`, but no `function`-level trace was found for it — imported, never (as far as static analysis can tell) called. |

This does **not** implement the spec's dynamic-dispatch-specific MEDIUM
case (`eval`, reflection, interface calls whose concrete type can't be
resolved statically) as its own detected condition — govulncheck doesn't
expose that distinction directly in `-json` output the way it exposes
`scan_level`. What's implemented is a real, verified, honestly-scoped
subset: MEDIUM fires on "the analysis itself was less confident," not on
every kind of ambiguity the spec describes.

The scanned module is the unversioned entry in `SBOM.modules` that
contains `SBOM.roots[0]`. `roots` lists root **packages**, not the module:
they only coincide for a single-package module like the fixtures. Using
`roots[0]` directly made every direct call in a multi-package repo (this
one included) classify as HIGH instead of CRITICAL;
`TestMainModuleFromMultiPackageRoots` guards against that.

## Risk score (called functions only)

`sbomber reachability` scores each vulnerable function the call graph
shows is **called** (CRITICAL or HIGH above) from 0 to 100%. Vulnerable
code that is with no resolved call path (LOW, MEDIUM) is listed but not
scored. The parts add up to exactly 100:

| Part | Formula | Max | Source |
|---|---|---|---|
| Severity | CVSS base score ÷ 10 × 40 | 40 | NVD CVE API 2.0 (v3.1 → v3.0 → v4.0 → v2, NVD's Primary score first) |
| Exploit chance | EPSS probability × 25 | 25 | FIRST.org EPSS |
| Known exploited | listed in CISA KEV | 20 | CISA KEV catalog |
| Call proximity | app code calls it directly (CRITICAL) = 15, via a dependency (HIGH) = 8 | 15 | the call graph |

Bands: **0–20% Minimal priority**, **21–39% Low**, **40–69% Medium**, **70–100% High**.
The project's overall risk is its riskiest called function.

- govulncheck reports Go IDs (`GO-YYYY-NNNN`); the OSV entry's `CVE-`
  aliases are what CVSS/EPSS/KEV are looked up by. With several aliases,
  the highest CVSS and EPSS are used, and KEV counts if any alias is in it.
- CVSS comes from NVD, not GHSA: GHSA's reviewed advisories don't cover
  most recent Go standard-library CVEs (checked directly for
  CVE-2026-33814: GHSA returned `[]`, NVD returned 7.5). NVD allows 5
  requests per 30s without a key, so lookups are paced and cached for 24h
  in `~/.sbomber/nvd_cache.json`; set `NVD_API_KEY` to go faster.
- When no CVSS is found (e.g. a CVE NVD hasn't analyzed yet), severity
  assumes 5.0 rather than 0 and the output says so, so an unrated
  vulnerability is never reported as harmless.

## Fixture: fully offline, no network dependency

`testdata/fixtures/reachability/` is a small, self-contained scenario:

- `vendorpkg/` — a fake dependency module (`example.com/sbomber-reachability/vendorpkg`)
  with `Vulnerable()`, `Wrapper()` (which calls `Vulnerable()`), and `Safe()`
  (which doesn't).
- `app/critical/`, `app/high/`, `app/low/` — three tiny main modules
  requiring that dependency: `critical` calls `Vulnerable()` directly,
  `high` calls `Wrapper()`, `low` calls only `Safe()`.
- `proxy/` — a hand-built [GOPROXY protocol](https://go.dev/ref/mod#goproxy-protocol)
  directory (`@v/list`, `.info`, `.mod`, `.zip`) serving `vendorpkg` as a
  real, versioned, fetchable module, so the three app modules `require` it
  normally rather than via a `replace` directive. This matters: a plain
  local-filesystem `replace` was tried first and doesn't work for this —
  govulncheck's SBOM reports a replaced local module's identity as its
  *filesystem replace path* rather than its declared module name, which
  breaks vulnerability-database matching entirely (verified directly: the
  CRITICAL scenario silently reported "no vulnerabilities found" until
  switched to a real proxy-served module).
- `vulndb/` — a local, offline vulnerability database in the same format
  `golang.org/x/vuln`'s own tests use (`ID/<id>.json`,
  `index/{db,modules,vulns}.json` — confirmed by reading
  `golang.org/x/vuln`'s own `cmd/govulncheck/testdata` fixtures directly
  rather than guessing the schema), declaring one fake vulnerability
  (`GO-9999-0001`, following the same `GO-9999-*` fake-ID convention
  `x/vuln`'s own tests use) against `vendorpkg`'s `Vulnerable` symbol.

Tests point `GOPROXY` and `-db` at these local paths (`t.Setenv`, restored
automatically), so `go test ./...` needs no network access and gets the
same result every run — no dependency on the live `vuln.go.dev` database
changing over time.

## The CGO / CVE dataset dead end (recorded so it isn't retried)

An external Java-focused ground-truth dataset (`VAScanner/VAScanner`,
backing a real published paper on vulnerable-API detection) was suggested
as a possible ground-truth source. Verified directly rather than taken on
description: the repo is real and its `Database/` directory does contain
substantial real per-CVE ground-truth data (~979k labeled vulnerable APIs),
but two things rule it out for this work: it carries **no license** on
GitHub (`license: null` — default all-rights-reserved, not something to
vendor into this repo without explicit permission), and it's Java/Maven
API-level, not Go. `golang.org/x/vulndb` (the real, structured,
machine-readable CVE-to-symbol data `govulncheck` itself reads) and
`golang.org/x/vuln`'s own BSD-3-Clause-licensed, well-tested reachability
tool were the actually-applicable resources for the Go slice — used above
— rather than that dataset. If Java reachability is ever built, VAScanner's
data is a real candidate ground-truth source, but the licensing question
would need resolving first — not assumed away.

## Requirements

`govulncheck` must be on `PATH` or in the Go bin directory (`$GOBIN`, else
`$GOPATH/bin`, default `~/go/bin`, which `go install` writes to but which
often isn't on `PATH`, especially on Windows) (`IsGovulncheckAvailable`); if it isn't,
`Analyze` returns a clear error rather than a silent skip, matching how
missing Grype is now handled (CO-1). Install with
`go install golang.org/x/vuln/cmd/govulncheck@latest`. CI installs it the
same way alongside golangci-lint so `TestAnalyze*` actually runs in CI
rather than being silently skipped.
