# VEX Format Decision (S4-09)

## Decision

| Item | Selection |
|---|---|
| Format | **OpenVEX**, spec v0.2.0 (`@context: https://openvex.dev/ns/v0.2.0`) |
| Investigation-state token | **`under_investigation`** |
| Affected-state token | `affected`, with a mandatory `action_statement` |
| Validator | OpenVEX JSON Schema 0.2.0 (`samples/openvex_json_schema_0.2.0.json`, sha256 `93735977…3238`) run by `jsonschema` 4.19.2 in `validate.py` |
| Consumer | **Grype 0.112.0** (`--vex`, `vex-add`); Trivy 0.70.0 verified as a second consumer of the same document |
| Product identity | the package PURL from `canonical-scan.json`, e.g. `pkg:npm/lodash@4.17.4`. **This is a package-level subject, not the R5 application-level subject — see "R5 subject model: unresolved" below.** |
| Vulnerability identity | `vulnerability.name` = the primary ID, `aliases` = every other ID (CVE and GHSA both listed, because Grype reports GHSA and Trivy reports CVE) |

CycloneDX VEX was the D5 preference because it matches the SBOM format
SBOMber already produces. It **loses the spike** on the decision rule fixed
in the issue: the pinned consumer must recognise and act on both the
affected state and the investigation state.

## Mapping from `decision-results.json` to OpenVEX

| Component 4 `state` | `vexMapping.statement` | OpenVEX `status` | Required fields |
|---|---|---|---|
| `usage_detected` | `affected` | `affected` | `action_statement` (the remediation) |
| `no_usage_detected` | `under_investigation` | `under_investigation` | none |
| `unknown` | `under_investigation` | `under_investigation` | none |
| `unsupported` | `omit` | no statement emitted | |
| manual review only | `not_affected` | `not_affected` | `justification`, `impact_statement`, named reviewer in `decision-results.json` |

`no_usage_detected` never maps to `not_affected`. Both consumers suppress
`not_affected` findings (runs G1, T1, T3, T4), so an automated
`not_affected` would hide a real vulnerability in the consumer's pipeline.
The contract validator already enforces this (`contracts/validate.py`,
rule "no automated not_affected").

This is the vocabulary Component 2's format-aware validator (PR #104) maps
for `format: openvex`, so no validator change is needed. The machine-
readable record is `contracts/fixtures/vex-decision.json`.

## Why OpenVEX, not CycloneDX

The rule from the issue: *"consumed successfully" means the consumer
recognises and acts on the statements with status handling explicitly
configured, not that it exited zero.*

| Test | OpenVEX | CycloneDX VEX |
|---|---|---|
| Schema-valid sample committed | yes (`samples/sample.openvex.json`) | yes (`samples/sample.cdx-vex.json`, 1.6 strict) |
| Grype 0.112.0 reads the document on a directory scan | **yes** (G1: `not_affected` statement suppressed one match) | **no** (G3: exit 1, "unable to detect document format"; Grype supports OpenVEX only) |
| Grype acts on `under_investigation` | **yes** (G5d: with `vex-add: [under_investigation]` the statement re-adds a match an ignore rule had removed; the match carries the `openvex-matcher` detail) | n/a, document not read |
| Grype acts on `affected` | **yes** (G5c: `vex-add: [affected, under_investigation]` re-adds both) | n/a |
| Trivy 0.70.0 reads the document on a filesystem scan | yes (T1) | **no** (T2: fatal "CycloneDX VEX can be used with CycloneDX SBOM") |
| Trivy reads the document when scanning a CycloneDX SBOM | yes (T4) | yes, only with BOM-Link `affects.ref` bound to that SBOM's `serialNumber` (T3) |
| Trivy acts on the investigation state | passive only: `under_investigation` findings stay visible, unannotated | passive only: `in_triage` findings stay visible, unannotated |
| Trivy acts on `not_affected` | yes, suppressed and listed under `ExperimentalModifiedFindings` with the justification | yes, same |

CycloneDX VEX fails the rule twice. Grype, the scanner SBOMber already
shells out to, does not read it at all. Trivy reads it only when the scan
input is a CycloneDX SBOM and every statement references that specific
SBOM by serial number and version, which means a VEX document produced for
one SBOM export is not usable against a rescan of the repository. Neither
consumer does anything with `in_triage` beyond leaving the finding visible.

OpenVEX passes on Grype: the document is read on directory, SBOM and image
sources, `not_affected` suppresses, and `affected` and `under_investigation`
are actively recognised through `vex-add`. Trivy reads the same document on
both filesystem and SBOM scans, which gives a second independent consumer
for free.

## What "acts on the investigation state" means in practice

Neither consumer renders `under_investigation` or `in_triage` in its default
output. The observable behaviours are:

1. The finding is **not suppressed**. This is the safety property the project
   needs, and both consumers deliver it for both formats.
2. In Grype, `vex-add: [under_investigation]` makes the statement override an
   ignore rule (G5d re-added `GHSA-jf85-cpcp-j695` while `GHSA-4xc9-xhrj-v574`,
   whose statement is `affected`, stayed ignored). That is the only place
   where a consumer distinguishes the investigation state from silence, and it
   exists only for OpenVEX.

SBOMber's own report is therefore still the primary surface for the
investigation state. The VEX document communicates it to downstream tools
without ever suppressing anything.

## Limitations recorded when discovered

- Grype's `vex-add` only re-adds matches that a Grype ignore rule removed. It
  does not add findings absent from the scan.
- Grype matched the `not_affected` statement written against `CVE-2020-8203`
  to its own `GHSA-p6mc-m468-83gw` match (G1), so alias matching works in
  this version. Both IDs are still listed in every statement in case a future
  version narrows this.
- Trivy's `--vex` flag is marked experimental in 0.70.0. Trivy did not
  annotate kept findings; only suppressed findings appear in
  `ExperimentalModifiedFindings`.
- CycloneDX VEX's BOM-Link requirement was tested only with Trivy's own SBOM
  of the fixture. SBOMber's exporter emits a different `serialNumber` per
  export, which is exactly the coupling that makes the format awkward here.
- The `not_affected` statement in both samples is a **probe**. It exists to
  prove the consumer reads the document. Production never emits it without a
  named manual reviewer.
- Both consumers match a statement's product `@id` against the vulnerable
  package's purl on directory and filesystem scans; an application-scoped
  product is not matched. Found 13 September 2026 on Yevhen's PR #110 review,
  after the original runs. See "R5 subject model: unresolved".
- Consumer versions are pinned to what the team has installed (Grype 0.112.0,
  Trivy 0.70.0). A newer Grype may add CycloneDX VEX; re-run `run.sh` before
  re-opening this decision.

## R5 subject model: unresolved

Raised by the paired Component 2 review (Yevhen, PR #110, 12 September 2026)
and reproduced here on 13 September 2026 at the same pinned versions.

**R5 rule 1** requires the scanned application to be the VEX product, with the
vulnerable package named as a versioned subcomponent:

> The scanned application or repository needs a stable product identifier and
> a version or commit SHA; the vulnerable package is identified as a versioned
> subcomponent.

The consumer evidence above was gathered with the **package** as the product
(`pkg:npm/lodash@4.17.4`) and no subcomponent. That shape is consumed, but it
is not the R5 subject model. The runs below test the R5 shape directly.

`samples/sample.openvex.subcomponent.json` is the R5-shaped document. It is
**schema-valid** — the spec accepts it; the consumers do not act on it.
Reproduce with `run-subject-model.sh`; evidence in `results/subject-model.jsonl`.

| Run | Product | Subcomponent | Grype suppressed | Trivy suppressed |
|---|---|---|---|---|
| SM1 | `pkg:npm/lodash@4.17.4` | none | 1 | 1 |
| SM2 | `pkg:npm/lodash@4.17.4` | `pkg:npm/lodash@4.17.4` | 1 | 1 |
| SM3 | `pkg:generic/vulnerable-chat@1.0.0` | `pkg:npm/lodash@4.17.4` | **0** | **0** |
| SM4 | `pkg:generic/vulnerable-chat@1.0.0` | none | **0** | **0** |
| SM5 | `.` | `pkg:npm/lodash@4.17.4` | **0** | **0** |
| SM6 | `dir:.` | `pkg:npm/lodash@4.17.4` | **0** | **0** |
| SM7 | absolute fixture path | `pkg:npm/lodash@4.17.4` | **0** | **0** |

**The subcomponent field is not what breaks it — the product identifier is.**
SM2 adds a subcomponent while leaving the product matching, and both consumers
still act on the statement. SM4 removes the subcomponent while leaving the
application as the product, and both stop. At these versions Grype 0.112.0 and
Trivy 0.70.0 resolve a statement's product `@id` against the **vulnerable
package's own purl** on directory and filesystem scans. An application-scoped
product never matches, with or without subcomponents, and no alternative
spelling of the application identifier helped (SM5–SM7).

Grype's `under_investigation` re-addition — the one behaviour in the whole
spike where a consumer distinguishes the investigation state from silence —
also stops under the R5 shape:

| Run | Document | `GHSA-jf85-cpcp-j695` re-added | Matcher |
|---|---|---|---|
| SM8 | package-level | yes | `openvex-matcher` |
| SM9 | R5 subcomponent | **no** | none — stays ignored |

This is not explained by the SBOM lacking an application identity. SM10 and
SM11 rebuild the fixture SBOM with a root component carrying
`purl: pkg:generic/vulnerable-chat@1.0.0`, then rescan; neither consumer
applies the R5-shaped document (`applied: false` in both).

### What this does and does not change

- **The format decision stands.** OpenVEX over CycloneDX VEX was decided on
  which format the pinned consumers read at all, and nothing here touches that
  comparison. The investigation-state token, the validator, the mapping table
  and the `no_usage_detected` → `under_investigation` rule are all unaffected.
- **The consumer evidence is now scoped.** Runs G1–G5d and T1–T4 are valid as a
  **package-level consumer probe**. They must not be cited as showing that
  SBOMber's VEX output satisfies R5 with the application as the subject.
- **R5's acceptance criteria and R5 rule 1 cannot both be met at these pinned
  versions.** The acceptance criteria require statements "recognised and acted
  on by one pinned third-party tool"; rule 1 requires an application-scoped
  subject. Package-level satisfies the first and fails the second; the R5 shape
  does the reverse. This is a requirements conflict, not an implementation bug,
  and it needs a client/supervisor decision before the S5 exporter is built.

### Options for the exporter (not decided here)

1. **Emit the R5 subject model and accept that the pinned consumers ignore it.**
   Standards-correct and honest about the subject; loses the only demonstrated
   third-party consumption, so R5's acceptance criteria fail.
2. **Emit package-level statements only.** Keeps demonstrated consumption;
   fails rule 1, and asserts a judgement about the lodash package itself that
   SBOMber has not made. SBOMber's finding is *"this application does not reach
   the vulnerable function"*, which is not a property of lodash.
3. **Emit both subjects in one document.** Rejected as the default here: an
   application-scoped reachability decision does not transfer to the package,
   so duplicating the statement at package level would publish a claim about
   lodash that the evidence does not support. Yevhen raised this explicitly in
   the PR #110 review and the same objection applies.
4. **Emit the R5 document and carry the investigation state in SBOMber's own
   report and `findings.json`.** Consistent with the spike's existing
   conclusion that SBOMber's report is the primary surface for the
   investigation state, with the VEX document as the standards-conformant
   record. Currently the least-bad option, but it is a scope call, not a
   Component 3 call.

Tracked as an open production-integration decision; it blocks the S5 VEX
exporter's subject model, not the format selection.

## Handover to S4-21

Component 2's validator (`contracts/validate.py`, PR #104) reads
`contracts/fixtures/vex-decision.json` and requires `under_investigation`
for `format: openvex`. The committed decision record selects exactly that,
so `decision-results.sample.json` is unchanged and all invariant checks still
pass (169 as of 13 September 2026; the count tracks main, not this spike).

The record gained `subjectModel`, `subjectModelR5Conformant` and
`subjectModelNote` on 13 September. `load_vex_policy` reads only `format` and
`investigationState`, so the added fields change no check.
