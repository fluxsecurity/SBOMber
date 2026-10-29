#!/usr/bin/env bash
# S6-08 (#154): VEX consistency on real decide output.
#
#   demo-app (staged as a throwaway git repository under demo-out/s6-08)
#     -> sbomber scan --include-vulnerabilities --canonical-scan   (Component 1's writer, #146)
#     -> sbomber usage -> sbomber localise -> sbomber decide
#     -> sbomber report (html, text) -> sbomber vex (application and package subject)
#     -> consistency.py (identity, state, schema, nothing missing)
#     -> grype --vex (does the pinned consumer act on the statements?)
#
# Tools: the Grype the repository pins in scripts/versions.env, installed by
# scripts/install-tools.sh into .tools/bin, the same binary the demo and CI
# use. Needs network (Grype's database, EPSS, KEV, GHSA, the npm registry,
# GitHub) and GITHUB_TOKEN, or `gh auth login`. The demo app is parsed, never
# installed or run.
#
#   spikes/vex-format/s6-08/run.sh                          # rewrite results/
#   SBOMBER_S6_OUT=/abs/dir spikes/vex-format/s6-08/run.sh  # replay elsewhere
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
# shellcheck source=../../../scripts/versions.env
. "$ROOT/scripts/versions.env"
PY="${PYTHON:-python3}"
OUT="${SBOMBER_S6_OUT:-$HERE/results}"
WORK="${SBOMBER_S6_WORK:-$ROOT/demo-out/s6-08}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
cd "$ROOT"

# The pinned consumer, from scripts/versions.env.
export PATH="$ROOT/.tools/bin:$PATH"
scripts/install-tools.sh --check >/dev/null || { echo "Run scripts/install-tools.sh first" >&2; exit 2; }
PIN="${GRYPE_VERSION#v}"
grype version | grep -q "^Version: *${PIN}\$" || { echo "Grype $PIN is the pinned consumer (scripts/versions.env)" >&2; exit 2; }

if [ -z "${GITHUB_TOKEN:-}" ] && command -v gh >/dev/null 2>&1; then
  GITHUB_TOKEN=$(gh auth token 2>/dev/null || true)
fi
[ -n "${GITHUB_TOKEN:-}" ] || { echo "Set GITHUB_TOKEN or run 'gh auth login': the GHSA enrichment and localise need it" >&2; exit 2; }
export GITHUB_TOKEN

make build >/dev/null
S=./bin/sbomber

# `sbomber scan` discovers git repositories, so the demo app is staged as
# one. Fixed author and date: the commit, and with it the scanId, are the
# same on every run.
APP="$WORK/demo-app"
rm -rf "$WORK"
mkdir -p "$WORK"
cp -R "$HERE/demo-app" "$APP"
git -c init.defaultBranch=main -C "$APP" init -q
git -C "$APP" add -A
GIT_AUTHOR_NAME=sbomber GIT_AUTHOR_EMAIL=sbomber@example.invalid \
GIT_COMMITTER_NAME=sbomber GIT_COMMITTER_EMAIL=sbomber@example.invalid \
GIT_AUTHOR_DATE=2026-10-18T00:00:00Z GIT_COMMITTER_DATE=2026-10-18T00:00:00Z \
  git -C "$APP" -c commit.gpgsign=false commit -q -m "S6-08 demo app"
# Every timestamp SBOMber writes is the staged commit's time.
SOURCE_DATE_EPOCH=$(git -C "$APP" log -1 --format=%ct)
export SOURCE_DATE_EPOCH

# One vulnerability database for the whole run: update once, then freeze
# it, so the scan and the consumer runs read the same database.
grype db update >/dev/null
export GRYPE_DB_AUTO_UPDATE=false

# Component 1's canonical-scan writer. Written next to the staged app so the
# repository path is recorded as "demo-app"; scan's SBOMs and its own HTML
# report go under ~/.sbomber/reports as usual.
$S scan --include-vulnerabilities --format both --no-color \
  --canonical-scan "$WORK/canonical-scan.json" -- "$APP" > "$WORK/scan.txt"
cp "$WORK/canonical-scan.json" "$OUT/canonical-scan.json"

$S usage --canonical-scan "$OUT/canonical-scan.json" --repo "repo-demo-app=$APP" \
  --entry "repo-demo-app=src/index.js:main" --out "$OUT/usage-graph.json"
$S localise --canonical-scan "$OUT/canonical-scan.json" --out "$OUT/localisation.json" --trace "$OUT/localisation-trace.json"
$S decide --canonical-scan "$OUT/canonical-scan.json" --usage-graph "$OUT/usage-graph.json" \
  --localisation "$OUT/localisation.json" --out "$OUT/decision-results.json"
$S report --decision-results "$OUT/decision-results.json" --usage-graph "$OUT/usage-graph.json" \
  --format html --out "$OUT/report.html"
$S report --decision-results "$OUT/decision-results.json" --usage-graph "$OUT/usage-graph.json" \
  --format text --out "$OUT/report.txt"
# The staged repository has no remote, so the application subject is the
# demo app's own purl.
$S vex --decisions "$OUT/decision-results.json" --canonical-scan "$OUT/canonical-scan.json" \
  --subject application --product "pkg:npm/s6-08-demo-app@1.0.0" --out "$OUT/demo-app.application.openvex.json"
$S vex --decisions "$OUT/decision-results.json" --canonical-scan "$OUT/canonical-scan.json" \
  --subject package --out "$OUT/demo-app.package.openvex.json"
# Verified from the results directory with a relative path: the text report
# names the file it was given, and the committed evidence carries no local path.
(cd "$OUT" && "$ROOT/bin/sbomber" localise --verify localisation.json --online --timeout 10m \
  --verify-report localisation-verify.json > localisation-verify.txt)

# The pinned consumer. grype.json is the consumer's own view of the app;
# every finding in it is ignored by rule, and with vex-add:
# [under_investigation] Grype re-adds a finding only if a statement for it
# matches. So the output changes because of the statements, or it does not.
grype "dir:$APP" -o json -q > "$OUT/grype.json"
"$PY" - "$OUT/grype.json" > "$OUT/grype-ignore-all.yaml" <<'PYEOF'
import json, sys

ids = sorted(
    {m["vulnerability"]["id"] for m in json.load(open(sys.argv[1]))["matches"]}
)
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
if grep -rlF "$HOME" "$OUT" >/dev/null; then
  echo "a local path leaked into $OUT:" >&2
  grep -rlF "$HOME" "$OUT" >&2
  exit 1
fi

# Record the revision, tools, inputs and bytes of this run. Do not mix
# old consumer outputs with regenerated documents.
"$PY" - "$ROOT" "$HERE" "$OUT" <<'METADATA'
import hashlib, importlib.util, json, subprocess, sys
from pathlib import Path

root, here, out = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location("consistency", here / "consistency.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
code = [
    "cmd",
    "internal",
    "go.mod",
    "go.sum",
    "Makefile",
    "contracts",
    "scripts/versions.env",
    "scripts/install-tools.sh",
    "spikes/vex-format/samples",
    "spikes/vex-format/s6-08/run.sh",
    "spikes/vex-format/s6-08/consistency.py",
    "spikes/vex-format/s6-08/demo-app",
]
status = subprocess.check_output(
    ["git", "status", "--porcelain", "--", *code], cwd=root, text=True
)
scan = json.loads((out / "canonical-scan.json").read_text())
grype = json.loads((out / "grype.json").read_text())["descriptor"]
meta = {
    "mode": "live",
    "sbomberRevision": subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip(),
    "sourceDirty": bool(status.strip()),
    "binarySha256": hashlib.sha256((root / "bin/sbomber").read_bytes()).hexdigest(),
    "scanId": scan["scan"]["scanId"],
    "toolVersions": scan["scan"]["toolVersions"],
    "consumer": {
        "grype": grype["version"],
        "db": grype.get("db", {}).get("status", {}).get("built"),
    },
    "inputSha256": {
        str(f.relative_to(here)): hashlib.sha256(f.read_bytes()).hexdigest()
        for f in sorted((here / "demo-app").rglob("*"))
        if f.is_file()
    },
    "sha256": {
        name: hashlib.sha256((out / name).read_bytes()).hexdigest()
        for name in module.ARTIFACTS
    },
}
(out / "run-metadata.json").write_text(json.dumps(meta, indent=2) + "\n")
METADATA

"$PY" "$HERE/consistency.py" "$OUT" | tee "$OUT/CONSISTENCY.md"
