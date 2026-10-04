#!/usr/bin/env bash
# S4-09 VEX format spike: consumer experiments against pinned Grype and Trivy.
#
# Reproduces every run recorded in results/. Each run writes a small summary
# JSON (counts and vulnerability IDs) rather than the full scanner output, so
# the evidence stays reviewable. Requires grype 0.112.0, trivy 0.70.0, jq.
#
# The probe documents contain ONE not_affected statement (CVE-2020-8203).
# It exists only to prove a consumer reads the file. Production SBOMber never
# emits not_affected automatically (Requirements v8 R5, contracts/README.md).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX="$HERE/fixture"
SBOM="$FIX/fixture.cdx.json"
OV="$HERE/samples/sample.openvex.json"
CDX="$HERE/samples/sample.cdx-vex.json"
OUT="$HERE/results"
mkdir -p "$OUT"
cd "$FIX"

{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  grype version | grep -E 'Version|Syft Version|GoVersion'
  grype db status | grep -E 'Schema|Built'
  trivy --version | tr '\n' ' '; echo
  echo "fixture sbom serialNumber: $(jq -r .serialNumber "$SBOM")"
} > "$OUT/environment.txt"

gsum() { # id, file
  jq -c --arg id "$1" '{run:$id, matches:(.matches|length), ignored:(.ignoredMatches|length),
    ignoredIds:[.ignoredMatches[]?|.vulnerability.id],
    ignoreRules:[.ignoredMatches[]?|.appliedIgnoreRules],
    lodashMatches:[.matches[]|select(.artifact.name=="lodash")|.vulnerability.id]|sort,
    matchersOnReadded:[.matches[]|select(.vulnerability.id=="GHSA-jf85-cpcp-j695")|.matchDetails[].matcher]}' "$2"
}
tsum() { # id, file
  jq -c --arg id "$1" '{run:$id, findings:([.Results[]?.Vulnerabilities[]?]|length),
    lodashFindings:([.Results[]?.Vulnerabilities[]?|select(.PkgName=="lodash")|.VulnerabilityID]|sort),
    modified:[.Results[]?.ExperimentalModifiedFindings[]?|{id:.Finding.VulnerabilityID,type:.Type,status:.Status,statement:.Statement,source:(.Source|split("/")|last)}]}' "$2"
}

T="$(mktemp -d)"
# ---- Grype -----------------------------------------------------------------
grype dir:. -o json -q > "$T/g0.json";                                                   gsum G0-baseline "$T/g0.json"
grype dir:. --vex "$OV" -o json -q > "$T/g1.json";                                       gsum G1-dir-openvex "$T/g1.json"
if grype dir:. --vex "$CDX" -o json > "$T/g3.json" 2> "$T/g3.err"; then
  gsum G3-dir-cyclonedx "$T/g3.json"
else
  jq -nc --arg err "$(grep -o 'merging vex documents:.*' "$T/g3.err" | head -1 | sed -E 's#/[^ ]*/samples/#samples/#g; s#\x1b\[[0-9;]*m##g' | cut -c1-220)" '{run:"G3-dir-cyclonedx", exit:1, error:$err}'
fi
grype "sbom:$SBOM" --vex "$OV" -o json -q > "$T/g4.json";                                gsum G4-sbom-openvex "$T/g4.json"
grype dir:. -c "$HERE/consumers/grype-ignore.yaml" -o json -q > "$T/g5a.json";            gsum G5a-ignore-only "$T/g5a.json"
grype dir:. -c "$HERE/consumers/grype-ignore.yaml" --vex "$OV" -o json -q > "$T/g5b.json"; gsum G5b-ignore-openvex "$T/g5b.json"
grype dir:. -c "$HERE/consumers/grype-ignore-vexadd.yaml" --vex "$OV" -o json -q > "$T/g5c.json"; gsum G5c-ignore-openvex-vexadd-both "$T/g5c.json"
grype dir:. -c "$HERE/consumers/grype-ignore-vexadd-under-investigation.yaml" --vex "$OV" -o json -q > "$T/g5d.json"; gsum G5d-ignore-openvex-vexadd-under-investigation "$T/g5d.json"

# ---- Trivy -----------------------------------------------------------------
trivy fs --quiet --scanners vuln --format json --output "$T/t0.json" . ;                                          tsum T0-baseline "$T/t0.json"
trivy fs --quiet --scanners vuln --format json --show-suppressed --vex "$OV" --output "$T/t1.json" . ;            tsum T1-fs-openvex "$T/t1.json"
if trivy fs --quiet --scanners vuln --format json --show-suppressed --vex "$CDX" --output "$T/t2.json" . 2> "$T/t2.err"; then
  tsum T2-fs-cyclonedx "$T/t2.json"
else
  jq -nc --arg err "$(grep -o 'unable to load VEX.*' "$T/t2.err" | head -1 | cut -c1-160)" '{run:"T2-fs-cyclonedx", exit:1, error:$err}'
fi
trivy sbom --quiet --format json --show-suppressed --vex "$CDX" --output "$T/t3.json" "$SBOM";                   tsum T3-sbom-cyclonedx-bomlink "$T/t3.json"
trivy sbom --quiet --format json --show-suppressed --vex "$OV" --output "$T/t4.json" "$SBOM";                    tsum T4-sbom-openvex "$T/t4.json"
rm -rf "$T"
