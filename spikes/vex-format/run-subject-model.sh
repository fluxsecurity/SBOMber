#!/usr/bin/env bash
# S4-09 follow-up: does either pinned consumer act on the R5 subject model?
#
# R5 rule 1 requires the scanned application to be the VEX product and the
# vulnerable package to be a versioned subcomponent. The original spike used
# the package itself as the product, so it never tested that shape.
#
# This harness varies ONE thing at a time -- product identifier, and presence
# of subcomponents -- so the failure can be attributed. Requires grype 0.112.0,
# trivy 0.70.0, jq, python3.
#
# Writes results/subject-model.jsonl. It deliberately does NOT touch
# results/runs.jsonl, which is the committed 6 September format-decision
# evidence.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX="$HERE/fixture"
OUT="$HERE/results"
SUB="$HERE/samples/sample.openvex.subcomponent.json"
mkdir -p "$OUT"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
cd "$FIX"

# One not_affected statement is the cleanest probe: if the consumer applies the
# document the finding is suppressed, and suppression is unambiguous in both
# tools' JSON. Generates a doc with the given product id and optional subcomponent.
probe() { # $1 product id, $2 subcomponent id (empty for none), $3 outfile
python3 - "$1" "$2" "$3" <<'PY'
import json, sys
pid, sub, out = sys.argv[1], sys.argv[2], sys.argv[3]
product = {"@id": pid}
if sub:
    product["subcomponents"] = [{"@id": sub}]
json.dump({
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": "https://github.com/fluxsecurity/SBOMber/spikes/vex-format/subject-model-probe",
    "author": "SBOMber Component 3 (S4-09 subject-model probe)",
    "role": "Document Creator",
    "timestamp": "2026-09-13T00:00:00Z",
    "version": 1,
    "statements": [{
        "vulnerability": {"name": "CVE-2020-8203", "aliases": ["GHSA-p6mc-m468-83gw"]},
        "products": [product],
        "status": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path",
        "impact_statement": "SPIKE PROBE ONLY.",
    }],
}, open(out, "w"), indent=1)
PY
}

matrix() { # $1 run id, $2 product, $3 subcomponent
  probe "$2" "$3" "$T/p.json"
  local g t
  g=$(grype dir:. --vex "$T/p.json" -o json -q 2>/dev/null | jq '.ignoredMatches|length')
  t=$(trivy fs --quiet --scanners vuln --format json --show-suppressed --vex "$T/p.json" . 2>/dev/null \
      | jq '[.Results[]?.ExperimentalModifiedFindings[]?]|length')
  jq -nc --arg run "$1" --arg p "$2" --arg s "${3:-none}" --argjson g "$g" --argjson t "$t" \
    '{run:$run, product:$p, subcomponent:$s, grypeIgnored:$g, trivyModified:$t,
      applied:(($g>0) and ($t>0))}'
}

{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  grype version | grep -E '^Version|Syft Version'
  trivy --version | tr '\n' ' '; echo
} > "$OUT/subject-model-environment.txt"

{
# Controls: the shape the 6 Sep decision actually shipped.
matrix SM1-product-package-no-sub        "pkg:npm/lodash@4.17.4"             ""
# Isolates the subcomponent field: same matching product, subcomponent added.
matrix SM2-product-package-with-sub      "pkg:npm/lodash@4.17.4"             "pkg:npm/lodash@4.17.4"
# The R5 shape.
matrix SM3-product-app-with-sub          "pkg:generic/vulnerable-chat@1.0.0" "pkg:npm/lodash@4.17.4"
# Isolates the product id: app product, no subcomponent at all.
matrix SM4-product-app-no-sub            "pkg:generic/vulnerable-chat@1.0.0" ""
# Alternative product identifiers a directory scan might plausibly match.
matrix SM5-product-dot-with-sub          "."                                 "pkg:npm/lodash@4.17.4"
matrix SM6-product-dirtarget-with-sub    "dir:."                             "pkg:npm/lodash@4.17.4"
matrix SM7-product-abspath-with-sub      "$FIX"                              "pkg:npm/lodash@4.17.4"

# Does Grype's under_investigation re-add survive the R5 shape? SM8 is the
# package-level control for G5d, SM9 the same run against the R5 document.
# matchersOnReadded containing openvex-matcher is the observable effect.
for pair in "SM8-vexadd-UI-package-level:$HERE/samples/sample.openvex.json" \
            "SM9-vexadd-UI-subcomponent:$SUB"; do
  id="${pair%%:*}"; doc="${pair#*:}"
  grype dir:. -c "$HERE/consumers/grype-ignore-vexadd-under-investigation.yaml" \
        --vex "$doc" -o json -q > "$T/v.json" 2>/dev/null
  jq -c --arg run "$id" '{run:$run,
    ignoredIds:[.ignoredMatches[]?|.vulnerability.id]|sort,
    matchersOnReadded:[.matches[]|select(.vulnerability.id=="GHSA-jf85-cpcp-j695")|.matchDetails[].matcher],
    reAdded:([.matches[]|select(.vulnerability.id=="GHSA-jf85-cpcp-j695")|.matchDetails[].matcher]|index("openvex-matcher")!=null)}' "$T/v.json"
done

# Trivy on an SBOM whose root component carries a real purl, to rule out
# "the SBOM had no application identity to match" as the explanation.
python3 - "$FIX/fixture.cdx.json" "$T/rooted.cdx.json" <<'PY'
import json, sys
b = json.load(open(sys.argv[1]))
b["metadata"]["component"].update(
    {"name": "vulnerable-chat", "version": "1.0.0", "purl": "pkg:generic/vulnerable-chat@1.0.0"})
json.dump(b, open(sys.argv[2], "w"), indent=1)
PY
trivy sbom --quiet --format json --show-suppressed --vex "$SUB" "$T/rooted.cdx.json" 2>/dev/null \
  | jq -c '{run:"SM10-trivy-sbom-rooted-app-product",
            modified:[.Results[]?.ExperimentalModifiedFindings[]?|.Finding.VulnerabilityID],
            applied:([.Results[]?.ExperimentalModifiedFindings[]?]|length>0)}'
grype "sbom:$T/rooted.cdx.json" --vex "$SUB" -o json -q 2>/dev/null \
  | jq -c '{run:"SM11-grype-sbom-rooted-app-product",
            ignored:(.ignoredMatches|length), applied:((.ignoredMatches|length)>0)}'
} > "$OUT/subject-model.jsonl"

cat "$OUT/subject-model.jsonl"
