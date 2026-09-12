# VEX Format Spike (S4-09)

Which VEX format should SBOMber emit, and which consumer reads it? Both
candidates were generated, validated and fed to the pinned scanners with
status handling explicitly configured. **Decision: OpenVEX 0.2.0,
`under_investigation`, consumed by Grype 0.112.0.** See `DECISION.md`.

## Protocol

Fixed before the runs:

1. One fixture: the manifest of the S4-20 evaluation repository
   (`Kirill89/prototype-pollution-explained` @ `d7b5d98`) with a generated
   lockfile, so the spike, Component 2's evaluation and Component 3's
   localisation cases all describe the same lodash 4.17.4.
2. One statement of each status that matters, on the same product:
   `affected` (CVE-2018-16487), the investigation state (CVE-2019-10744) and a
   `not_affected` probe (CVE-2020-8203). The probe exists only to prove the
   consumer read the file.
3. A format wins only if the pinned consumer recognises **and acts on** both
   the affected and the investigation state. Exit code zero is not success.
4. The consumer is run on a directory source (how SBOMber scans repositories)
   and on a CycloneDX SBOM source (how SBOMber's export would be consumed).

## Contents

- `DECISION.md` — decision, mapping table, evidence, limitations
- `fixture/` — `package.json`, generated `package-lock.json`, and
  `fixture.cdx.json` (Trivy's CycloneDX 1.6 SBOM of the fixture; its
  `serialNumber` is what the CycloneDX VEX sample's BOM-Links reference)
- `samples/sample.openvex.json` — schema-valid OpenVEX 0.2.0 sample
- `samples/sample.cdx-vex.json` — schema-valid CycloneDX 1.6 VEX sample
- `samples/openvex_json_schema_0.2.0.json` — the OpenVEX schema, committed
  for reproducibility (source: github.com/openvex/spec, `main`, fetched
  2026-09-06)
- `consumers/` — Grype configs for the ignore / `vex-add` experiments
- `validate.py` — validates both samples against their official schemas
- `run.sh` — reproduces every consumer run
- `results/runs.jsonl` — one summary line per run (counts and IDs)
- `results/environment.txt` — tool and database versions at run time

## Reproduce

    python3 -m pip install jsonschema 'cyclonedx-python-lib[json-validation]'
    python3 spikes/vex-format/validate.py
    spikes/vex-format/run.sh > spikes/vex-format/results/runs.jsonl

## Run key

| Run | Source | Document | Consumer config |
|---|---|---|---|
| G0 / T0 | directory | none | baseline, 23 findings |
| G1 / T1 | directory | OpenVEX | default |
| G3 / T2 | directory | CycloneDX VEX | default |
| G4 / T4 | CycloneDX SBOM | OpenVEX | default |
| T3 | CycloneDX SBOM | CycloneDX VEX (BOM-Link) | default |
| G5a | directory | none | ignore `GHSA-jf85-cpcp-j695`, `GHSA-4xc9-xhrj-v574` |
| G5b | directory | OpenVEX | same ignore rules |
| G5c | directory | OpenVEX | ignore rules + `vex-add: [affected, under_investigation]` |
| G5d | directory | OpenVEX | ignore rules + `vex-add: [under_investigation]` |

Grype reports findings by GHSA ID, Trivy by CVE ID. Every statement lists
both as `name` and `aliases`.
