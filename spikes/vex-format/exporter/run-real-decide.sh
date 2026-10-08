#!/usr/bin/env bash
# S5-07 on real Component 4 output: sbomber decide -> sbomber vex.
#
# Inputs are the contract sample files (canonical-scan, usage-graph,
# localisation). decision-results.json is produced by the real join
# (internal/decision, PR #142), not the hand-written sample. Both subject
# modes are exported and validated against the OpenVEX 0.2.0 schema, and the
# decide output against contracts/validate.py.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
PY="${PYTHON:-python3}"
F="$ROOT/contracts/fixtures"
OUT="$ROOT/spikes/vex-format/results/s5-07/real-decide"
mkdir -p "$OUT"
cd "$ROOT"
go build -o bin/sbomber ./cmd/sbomber

./bin/sbomber decide --canonical-scan "$F/canonical-scan.sample.json" \
  --usage-graph "$F/usage-graph.sample.json" --localisation "$F/localisation.sample.json" \
  --out "$OUT/decision-results.json"
for subject in application package; do
  ./bin/sbomber vex --decisions "$OUT/decision-results.json" \
    --canonical-scan "$F/canonical-scan.sample.json" --subject "$subject" \
    --out "$OUT/demo-app.$subject.openvex.json"
done

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cp "$F/canonical-scan.sample.json" "$TMP/canonical-scan.json"
cp "$F/usage-graph.sample.json" "$TMP/usage-graph.json"
cp "$F/localisation.sample.json" "$TMP/localisation.json"
cp "$OUT/decision-results.json" "$TMP/decision-results.json"
{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "sbomber: $(git rev-parse --short HEAD)"
  echo -n "contracts/validate.py on decide output: "
  "$PY" contracts/validate.py --dir "$TMP" --vex-decision "$F/vex-decision.json" | tail -1
  for subject in application package; do
    "$PY" - "$OUT/demo-app.$subject.openvex.json" <<PYEOF
import json, sys
from jsonschema import validators
schema = json.load(open("spikes/vex-format/samples/openvex_json_schema_0.2.0.json"))
doc = json.load(open(sys.argv[1]))
errs = list(validators.validator_for(schema)(schema).iter_errors(doc))
print(sys.argv[1].split("/")[-1] + ":", "VALID" if not errs else f"{len(errs)} error(s)",
      "statuses", sorted({s["status"] for s in doc["statements"]}))
PYEOF
  done
} | tee "$OUT/validation.txt"
