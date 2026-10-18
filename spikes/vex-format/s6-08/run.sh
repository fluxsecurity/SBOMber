#!/usr/bin/env bash
# S6-08 (#154): VEX consistency on real decide output.
#
#   demo-app -> grype -> canonical-scan.json (bridge, see build_canonical_scan.py)
#            -> sbomber usage -> sbomber localise -> sbomber decide
#            -> sbomber report (html, text) -> sbomber vex (both subjects)
#            -> consistency.py (identity, state, schema, nothing missing)
#            -> grype --vex (does the pinned consumer act on the statements?)
#
# Needs network (OSV, GitHub, npm) and Grype 0.112.0. Set GITHUB_TOKEN.
# The demo app is never installed or run; Grype reads its lockfile.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
PY="${PYTHON:-python3}"
OUT="$HERE/results"
APP="$HERE/demo-app"
mkdir -p "$OUT"
cd "$ROOT"
make build >/dev/null
S=./bin/sbomber

grype version | grep -q '^Version: *0.112.0$' || { echo "Grype 0.112.0 is the pinned consumer" >&2; exit 2; }
grype "dir:$APP" -o json -q > "$OUT/grype.json"
"$PY" "$HERE/build_canonical_scan.py" "$APP" "$OUT/grype.json" "$OUT/canonical-scan.json"

$S usage --canonical-scan "$OUT/canonical-scan.json" --repo "repo-demo-app=$APP" \
  --entry "repo-demo-app=src/index.js:main" --out "$OUT/usage-graph.json"
$S localise --canonical-scan "$OUT/canonical-scan.json" --out "$OUT/localisation.json" --trace "$OUT/localisation-trace.json"
$S decide --canonical-scan "$OUT/canonical-scan.json" --usage-graph "$OUT/usage-graph.json" \
  --localisation "$OUT/localisation.json" --out "$OUT/decision-results.json"
$S report --decision-results "$OUT/decision-results.json" --usage-graph "$OUT/usage-graph.json" \
  --format html --out "$OUT/report.html"
$S report --decision-results "$OUT/decision-results.json" --usage-graph "$OUT/usage-graph.json" \
  --format text --out "$OUT/report.txt"
# The demo app is not a git repository of its own, so the application
# subject is its own purl.
$S vex --decisions "$OUT/decision-results.json" --canonical-scan "$OUT/canonical-scan.json" \
  --subject application --product "pkg:npm/s6-08-demo-app@1.0.0" --out "$OUT/demo-app.application.openvex.json"
$S vex --decisions "$OUT/decision-results.json" --canonical-scan "$OUT/canonical-scan.json" \
  --subject package --out "$OUT/demo-app.package.openvex.json"
(cd "$HERE" && "$ROOT/bin/sbomber" localise --verify results/localisation.json > results/localisation-verify.txt) || true

# The pinned consumer. Every finding is ignored by rule; with vex-add:
# [under_investigation], Grype re-adds a finding only if a statement for it
# matches. So the output changes because of the statements, or it does not.
"$PY" - "$OUT/grype.json" > "$OUT/grype-ignore-all.yaml" <<'PYEOF'
import json, sys
ids = sorted({m["vulnerability"]["id"] for m in json.load(open(sys.argv[1]))["matches"]})
print("ignore:")
for i in ids:
    print(f"  - vulnerability: {i}")
print("vex-add:\n  - under_investigation")
PYEOF
grype "dir:$APP" -c "$OUT/grype-ignore-all.yaml" -o json -q > "$OUT/grype-consumer-baseline.json"
for subject in application package; do
  grype "dir:$APP" -c "$OUT/grype-ignore-all.yaml" --vex "$OUT/demo-app.$subject.openvex.json" -o json -q \
    > "$OUT/grype-consumer-$subject.json"
done

# Grype records the absolute scan path and its cache path; keep the
# committed evidence free of local paths.
"$PY" - "$ROOT" "$OUT"/grype*.json <<'PYEOF'
import json, os, sys
root, home = sys.argv[1], os.path.expanduser("~")
def scrub(v):
    if isinstance(v, dict):
        return {k: scrub(x) for k, x in v.items()}
    if isinstance(v, list):
        return [scrub(x) for x in v]
    if isinstance(v, str):
        return v.replace(root, ".").replace(home, "~")
    return v
for p in sys.argv[2:]:
    d = scrub(json.load(open(p)))
    with open(p, "w") as f:
        json.dump(d, f, indent=1)
        f.write("\n")
PYEOF

"$PY" "$HERE/consistency.py" "$OUT" | tee "$OUT/CONSISTENCY.md"
