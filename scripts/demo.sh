#!/usr/bin/env bash
# The SBOMber demonstration: the whole pipeline on the pinned demo repository.
#
#   scripts/demo.sh                  # run once, artefacts in ./demo-out/run
#   scripts/demo.sh --twice          # run twice and check the artefacts match
#   scripts/demo.sh --repo DIR       # use an existing checkout instead of cloning
#
# Steps: build SBOMber, check the pinned tools, check out the demo repository
# at its pinned commit, then
#   scan -> canonical-scan.json -> usage, localise -> decide -> report, vex
# and validate every contract file with contracts/validate.py (when Python
# and jsonschema are available).
#
# Network: Grype's database, the enrichment sources (EPSS, CISA KEV, GHSA,
# npm registry) and localise's advisory and patch lookups are online. Set
# GITHUB_TOKEN, or log in with `gh auth login`: without a token GitHub allows
# 60 requests an hour, which one run uses up.
#
# The demo repository is untrusted input: it is cloned and parsed, never
# built, installed or executed.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=versions.env
. "$root/scripts/versions.env"

out="$root/demo-out"
repo=""
twice=false
while [ $# -gt 0 ]; do
	case "$1" in
		--twice) twice=true ;;
		--repo) repo=$2; shift ;;
		--out) out=$2; shift ;;
		-h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
	shift
done

step() { printf '\n== %s\n' "$*"; }

step "Tools"
export PATH="$root/.tools/bin:$PATH"
if ! "$root/scripts/install-tools.sh" --check; then
	echo "Run scripts/install-tools.sh first (and install Go $GO_VERSION)." >&2
	exit 2
fi
if [ -z "${GITHUB_TOKEN:-}" ] && command -v gh >/dev/null 2>&1; then
	GITHUB_TOKEN=$(gh auth token 2>/dev/null || true)
fi
if [ -n "${GITHUB_TOKEN:-}" ]; then
	export GITHUB_TOKEN
	echo "  GitHub token   set"
else
	echo "  GitHub token   not set: localise will hit GitHub's 60-requests-an-hour limit" >&2
	if [ -z "${ALLOW_NO_TOKEN:-}" ]; then
		echo "Set GITHUB_TOKEN or run 'gh auth login' (ALLOW_NO_TOKEN=1 to run anyway)." >&2
		exit 2
	fi
fi

step "Build"
(cd "$root" && make build)
sbomber="$root/bin/sbomber"
"$sbomber" version

step "Demo repository"
if [ -z "$repo" ]; then
	repo="$out/repos/prototype-pollution-explained"
	if [ ! -d "$repo/.git" ]; then
		mkdir -p "$(dirname "$repo")"
		git clone --quiet --no-checkout "$DEMO_REPO_URL" "$repo"
	fi
	git -C "$repo" -c advice.detachedHead=false checkout --quiet --force "$DEMO_REPO_COMMIT"
fi
commit=$(git -C "$repo" rev-parse HEAD)
echo "$repo at $commit"
if [ "$commit" != "$DEMO_REPO_COMMIT" ] && [ -z "${ALLOW_OTHER_COMMIT:-}" ]; then
	echo "warning: not the pinned demo commit $DEMO_REPO_COMMIT" >&2
fi

# Every timestamp SBOMber writes is the demo commit's time, so two runs over
# the same repository and vulnerability database write identical files.
SOURCE_DATE_EPOCH=$(git -C "$repo" log -1 --format=%ct)
export SOURCE_DATE_EPOCH

step "Vulnerability database"
# Update once, then freeze it for the run: a database update mid-demo would
# change the findings between the two runs.
grype db update >/dev/null
export GRYPE_DB_AUTO_UPDATE=false
grype db status | sed -n '1,4p'

# run_pipeline <dir>: the six commands, each writing into <dir>.
run_pipeline() {
	local dir=$1
	rm -rf "$dir"
	mkdir -p "$dir"
	# scan also writes the SBOMs and its HTML report under ~/.sbomber/reports
	# and prints where.
	"$sbomber" scan --include-vulnerabilities --format both --no-color \
		--canonical-scan "$dir/canonical-scan.json" -- "$repo"
	"$sbomber" usage --allow-partial --canonical-scan "$dir/canonical-scan.json" --out "$dir/usage-graph.json"
	"$sbomber" localise --canonical-scan "$dir/canonical-scan.json" --out "$dir/localisation.json"
	"$sbomber" decide --canonical-scan "$dir/canonical-scan.json" --usage-graph "$dir/usage-graph.json" \
		--localisation "$dir/localisation.json" --out "$dir/decision-results.json"
	"$sbomber" report --decision-results "$dir/decision-results.json" --usage-graph "$dir/usage-graph.json" \
		--out "$dir/remediation-report.html"
	"$sbomber" vex --decisions "$dir/decision-results.json" --canonical-scan "$dir/canonical-scan.json" \
		--out "$dir/vex.openvex.json"
}

artefacts="canonical-scan.json usage-graph.json localisation.json decision-results.json remediation-report.html vex.openvex.json"

step "Pipeline"
run_pipeline "$out/run"

step "Contract validation"
if command -v python3 >/dev/null 2>&1; then
	python3 "$root/contracts/validate.py" --dir "$out/run" --vex-decision "$root/contracts/fixtures/vex-decision.json"
else
	echo "python3 not found: skipped (CI runs contracts/validate.py on this output)"
fi

if $twice; then
	step "Second run"
	run_pipeline "$out/run2"
	step "Reproducibility"
	differ=0
	for f in $artefacts; do
		if cmp -s "$out/run/$f" "$out/run2/$f"; then
			echo "  identical  $f"
		else
			echo "  DIFFERENT  $f"
			differ=1
		fi
	done
	[ $differ -eq 0 ] || { echo "The two runs differ." >&2; exit 1; }
fi

step "Done"
for f in $artefacts; do
	[ -f "$out/run/$f" ] && echo "  $out/run/$f"
done
echo "Open remediation-report.html in a browser to see what to update first."
