# Demonstration and handover guide

How to install SBOMber, run the demonstration, run each command on its own,
and read what it writes. Everything here is reproducible from a clean
checkout on the official demonstration machine.

## The official demonstration setup

| | |
|---|---|
| Operating system | **Ubuntu 24.04 LTS** (x86-64). CI runs the same demonstration on `ubuntu-24.04` on every pull request. |
| Go | **1.26.9**, from <https://go.dev/dl/> |
| Grype | **v0.120.1**, installed by `scripts/install-tools.sh` |
| govulncheck | **v1.9.0**, installed by `scripts/install-tools.sh` (Go reachability only) |
| Demo repository | [Kirill89/prototype-pollution-explained](https://github.com/Kirill89/prototype-pollution-explained) at `d7b5d98515a95f9a8cb0fedef034010ee083a6a9` |
| Network | Required: Grype's vulnerability database, EPSS, CISA KEV, GHSA, the npm registry, GitHub |

All versions live in [`scripts/versions.env`](../scripts/versions.env); the
install script, the demo script and CI read them from there. Other systems
(macOS, Windows with Git Bash) work for development, but the demonstration is
only checked on Ubuntu 24.04.

The demo repository is a small Express application whose README documents
CVE-2018-16487 in lodash 4.17.4 (`_.merge`), and whose `index.js` calls
`_.merge` on request input. It is cloned and parsed, never built, installed or
run.

## Install

```bash
sudo apt-get install -y build-essential git curl python3 python3-pip   # gcc for CGO (tree-sitter)
# Go 1.26.9: https://go.dev/dl/  (then make sure `go version` says go1.26.9)

git clone https://github.com/fluxsecurity/SBOMber.git
cd SBOMber
scripts/install-tools.sh                # Grype and govulncheck into ./.tools/bin
export PATH="$PWD/.tools/bin:$PATH"
python3 -m pip install -r contracts/requirements.txt   # optional: schema checks in the validator
gh auth login                           # or: export GITHUB_TOKEN=<a token with no scopes>
```

`scripts/install-tools.sh --check` reports what is installed against the
pins without installing anything.

A GitHub token is needed: `localise` looks up advisories and their patch
commits on GitHub, and without a token GitHub allows 60 requests an hour,
fewer than one run makes. A token with no scopes is enough.

## Run the demonstration

```bash
scripts/demo.sh            # one run, artefacts in demo-out/run/
scripts/demo.sh --twice    # two runs, and check they are identical
```

The script builds SBOMber, checks the pinned tools, checks out the demo
repository at its pinned commit, updates Grype's database once and freezes
it, then runs the six commands below and validates every contract file with
`contracts/validate.py`. With `--twice` it runs the pipeline again into
`demo-out/run2/` and fails if any file differs.

Every timestamp SBOMber writes is set from `SOURCE_DATE_EPOCH`, which the
script sets to the demo commit's time. That, the frozen database and
content-derived identifiers are what make two runs identical. Runs on
different days can differ: the database and the enrichment sources (EPSS,
KEV) change. `canonical-scan.json` records the Grype database each run used
(`scan.toolVersions["grype-db"]`).

Expected result on the demo repository (database of October 2026):
14 findings, 2 under "Update first" (express, used from `index.js`) and 12
under "Insufficient information". The scan is `partial` because the
repository has no lockfile: the versions are as declared in `package.json`
and transitive dependencies are not listed.

## The pipeline, one command at a time

```bash
out=demo-out/run
sbomber scan --include-vulnerabilities --canonical-scan $out/canonical-scan.json -- <repo>
sbomber usage --allow-partial --canonical-scan $out/canonical-scan.json --out $out/usage-graph.json
sbomber localise --canonical-scan $out/canonical-scan.json --out $out/localisation.json
sbomber decide --canonical-scan $out/canonical-scan.json --usage-graph $out/usage-graph.json \
  --localisation $out/localisation.json --out $out/decision-results.json
sbomber report --decision-results $out/decision-results.json --usage-graph $out/usage-graph.json \
  --out $out/remediation-report.html
sbomber vex --decisions $out/decision-results.json --canonical-scan $out/canonical-scan.json \
  --out $out/vex.openvex.json
python3 contracts/validate.py --dir $out --vex-decision contracts/fixtures/vex-decision.json
```

| Step | Component | Reads | Writes |
|---|---|---|---|
| `scan` | 1, inventory | the repository | SBOMs and an HTML vulnerability report (under `~/.sbomber/reports/`), and `canonical-scan.json` |
| `usage` | 2, usage evidence | `canonical-scan.json`, the repository's JS/TS source | `usage-graph.json` |
| `localise` | 3, localisation | `canonical-scan.json`, advisories and patches online | `localisation.json` |
| `decide` | 4, decision | the three files above | `decision-results.json` |
| `report` | 4, report | `decision-results.json`, `usage-graph.json` | `remediation-report.html` |
| `vex` | 3, VEX | `decision-results.json`, `canonical-scan.json` | `vex.openvex.json` |

Exit codes, for every command: `0` success, `1` a policy result
(`scan --fail-on-vuln` found vulnerabilities), `2` a tool or input error. A
repository that could not be scanned makes `scan` exit `2`; it still writes
`canonical-scan.json`, with the failure in `scan.statusDetail`. `usage` exits
`2` on a partial analysis unless `--allow-partial` is given.

## Reading the outputs

- **`remediation-report.html`**: start here. "Update first" lists packages
  with usage evidence, most urgent first, with the version to update to.
  "Insufficient information" lists findings SBOMber could not decide, and
  why, with the analysis coverage at the top. "No direct usage evidence found
  within the analysed scope" is not a statement that a package is safe.
- **`canonical-scan.json`**: the inventory. `scan.status` is `complete` only
  when nothing was skipped; `scan.statusDetail.limitsHit` says what was not
  done (no lockfile, an ecosystem the contract cannot represent, a failed
  vulnerability scan). `scan.enrichment` gives each online source's outcome:
  a source that failed says so instead of looking like a clean result.
- **`usage-graph.json`**: what the application imports and calls, per
  package occurrence, with `coverage` counting what was and was not analysed.
  Every occurrence is either observed or listed in `unanalysedOccurrences`
  with a reason.
- **`localisation.json`**: per finding, the functions the advisory
  implicates and the method that found them.
- **`decision-results.json`**: per finding, the decision state, band,
  confidence and justification.
- **`vex.openvex.json`**: OpenVEX statements. SBOMber never asserts
  `not_affected` automatically; undecided findings export as
  `under_investigation`.

## Known limitations of the inventory (`canonical-scan.json`)

- **No lockfile, no resolved versions.** Without `package-lock.json` or
  `yarn.lock`, a dependency declared as a range is written with
  `versionKnown: false`, its range in `declaredConstraint`, and no transitive
  dependencies. The scan is `partial` and says so.
- **yarn.lock has no install paths.** Packages resolved from `yarn.lock` get
  exact versions but no `installPath` or `dependencyPath`; nested copies of
  one package are not told apart.
- **Ecosystems the contract cannot represent.** canonical-scan 1.0.0 lists
  npm, PyPI, Maven, RubyGems and Go. Cargo, Composer and NuGet packages are
  counted in `limitsHit`, not listed.
- **Findings the inventory does not list.** A Grype finding for a package the
  inventory does not contain is added as a component with no occurrence, so
  it is never dropped; usage evidence cannot be attached to it.

## Recording

A recording of `scripts/demo.sh --twice` on the demonstration machine is the
fallback if the live demonstration cannot run. Where it is published is
agreed with the client (#147) and recorded here once it is.
