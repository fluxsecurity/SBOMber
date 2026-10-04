#!/usr/bin/env bash
# S4-08 localisation spike: reproduce the evaluation end to end.
#
#   1. build canonical-scan.json from the ten curated cases
#   2. run `sbomber localise` with every method enabled
#   3. validate the produced localisation.json against the contract schema
#   4. grade every method attempt against the pre-committed ground truth
#
# Needs network access to api.osv.dev, api.github.com and registry.npmjs.org.
# Set GITHUB_TOKEN (e.g. `export GITHUB_TOKEN=$(gh auth token)`) or the
# GitHub API rate limit (60/hour unauthenticated) will be exhausted.
# No downloaded package code is executed at any step.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PY="${PYTHON:-python3}"

cd "$ROOT"
make build >/dev/null
"$PY" "$HERE/build_canonical_scan.py"
./bin/sbomber localise \
  --canonical-scan "$HERE/cases/canonical-scan.json" \
  --out "$HERE/results/localisation.json" \
  --trace "$HERE/results/trace.json" \
  --all-methods --client-search --timeout 12m
"$PY" - <<PYEOF
import json, sys
from jsonschema import Draft202012Validator
schema = json.load(open("$ROOT/contracts/localisation.schema.json"))
doc = json.load(open("$HERE/results/localisation.json"))
errs = list(Draft202012Validator(schema).iter_errors(doc))
print("localisation.json schema:", "VALID" if not errs else f"{len(errs)} error(s)")
for e in errs: print(" -", "/".join(map(str, e.path)), e.message)
sys.exit(1 if errs else 0)
PYEOF
"$PY" "$HERE/evaluate.py" >/dev/null
{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "sbomber: $(git -C "$ROOT" rev-parse --short HEAD)"
  go version
  echo "tree-sitter: $(grep tree-sitter/go-tree-sitter "$ROOT/go.mod" | awk '{print $2}')"
} > "$HERE/results/environment.txt"
echo "wrote $HERE/results/{localisation.json,trace.json,evaluation.json,evaluation.md,environment.txt}"
