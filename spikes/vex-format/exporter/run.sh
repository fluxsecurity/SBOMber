#!/usr/bin/env bash
# S5-07 exporter evidence: real `sbomber vex` output, validated against the
# OpenVEX 0.2.0 schema and fed to pinned Grype with status handling configured.
#
# Inputs:
#   contracts/fixtures/*.sample.json          the four-finding contract scenario
#   spikes/vex-format/exporter/*.json          two decisions for the S4-09
#                                              vulnerable-chat fixture (lodash 4.17.4)
# Requires: go, grype 0.112.0, jq, python3 with jsonschema 4.19.2.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPIKE="$(dirname "$HERE")"
ROOT="$(cd "$SPIKE/../.." && pwd)"
OUT="$SPIKE/results/s5-07"
PY="${PYTHON:-python3}"
mkdir -p "$OUT"

BIN="$(mktemp -d)/sbomber"
(cd "$ROOT" && go build -o "$BIN" ./cmd/sbomber)

for subject in application package; do
  "$BIN" vex --subject "$subject" \
    --decisions "$ROOT/contracts/fixtures/decision-results.sample.json" \
    --canonical-scan "$ROOT/contracts/fixtures/canonical-scan.sample.json" \
    --out "$OUT/fixture.$subject.openvex.json"
  "$BIN" vex --subject "$subject" \
    --decisions "$HERE/decision-results.json" \
    --canonical-scan "$HERE/canonical-scan.json" \
    --out "$OUT/vulnerable-chat.$subject.openvex.json"
done

# Schema validation of everything the exporter wrote.
"$PY" - "$SPIKE/samples/openvex_json_schema_0.2.0.json" "$OUT"/*.openvex.json <<'EOF' | tee "$OUT/schema-validation.txt"
import json, sys
from jsonschema import Draft202012Validator
v = Draft202012Validator(json.load(open(sys.argv[1])))
bad = 0
for p in sys.argv[2:]:
    doc = json.load(open(p))
    errs = list(v.iter_errors(doc))
    name = p.rsplit("/", 1)[-1]
    print(f"{name}: {'VALID' if not errs else 'INVALID'}; statuses {sorted({s['status'] for s in doc['statements']})}")
    for e in errs:
        bad += 1
        print("  -", "/".join(map(str, e.path)), e.message)
sys.exit(1 if bad else 0)
EOF

# Consumer: Grype with both GHSA IDs ignored, then each exporter document with
# vex-add [affected, under_investigation]. A re-added match carrying the
# openvex-matcher detail is Grype acting on the statement.
gsum() { # run id, grype json
  jq -c --arg id "$1" '{run:$id, matches:(.matches|length), ignored:(.ignoredMatches|length),
    readded:[.matches[]|select(.vulnerability.id=="GHSA-4xc9-xhrj-v574" or .vulnerability.id=="GHSA-jf85-cpcp-j695")
      |{id:.vulnerability.id, matchers:[.matchDetails[].matcher]|unique}]|sort_by(.id)}' "$2"
}
T="$(mktemp -d)"
cd "$SPIKE/fixture"
# Keep the local DB rather than refreshing it mid-run, so every run below sees
# the same advisory data; its build date is recorded in environment.txt.
export GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_VALIDATE_AGE=false
{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  grype version | grep -E '^Version'
  grype db status | grep -E 'Schema|Built'
} > "$OUT/environment.txt"
grype dir:. -c "$SPIKE/consumers/grype-ignore.yaml" -o json -q > "$T/e0.json"
gsum E0-ignore-only "$T/e0.json" > "$OUT/grype.jsonl"
grype dir:. -c "$SPIKE/consumers/grype-ignore-vexadd.yaml" --vex "$OUT/vulnerable-chat.package.openvex.json" -o json -q > "$T/e1.json"
gsum E1-exporter-package-subject-vexadd "$T/e1.json" >> "$OUT/grype.jsonl"
grype dir:. -c "$SPIKE/consumers/grype-ignore-vexadd.yaml" --vex "$OUT/vulnerable-chat.application.openvex.json" -o json -q > "$T/e2.json"
gsum E2-exporter-application-subject-vexadd "$T/e2.json" >> "$OUT/grype.jsonl"
cat "$OUT/grype.jsonl"
