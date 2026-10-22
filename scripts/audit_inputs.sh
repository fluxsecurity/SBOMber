#!/usr/bin/env bash
# Produce the three pipeline inputs for each S5-14 audit case (#124):
#
#   scripts/audit_inputs.sh                 # every case below
#   scripts/audit_inputs.sh appsecco-dvna   # one case
#
# For each case: check out the repository at its pinned commit (the commit
# recorded in testdata/audit/<case>/CASE.md), then run
#   scan -> canonical-scan.json, usage -> usage-graph.json,
#   localise -> localisation.json
# and write the three files into testdata/audit/<case>/ exactly as produced.
# It never writes labels.json: labels are written by hand from the source.
#
# Reproducibility follows scripts/demo.sh: SOURCE_DATE_EPOCH is the case
# commit's time, and Grype's database is updated once and frozen for the run.
# A log of every command, the SBOMber commit and the Grype database status is
# written to docs/evidence/s5-14/<case>.log for the CASE.md provenance table.
#
# Network: Grype's database, enrichment (EPSS, KEV, GHSA, npm registry) and
# localise's advisory and patch lookups are online. Set GITHUB_TOKEN or run
# `gh auth login` first.
#
# The case repositories are untrusted input: cloned and parsed, never built,
# installed or executed.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=versions.env
. "$root/scripts/versions.env"

# case-id  repository  commit   (must match each CASE.md)
cases=(
	"kirill89-prototype-pollution-explained https://github.com/Kirill89/prototype-pollution-explained.git d7b5d98515a95f9a8cb0fedef034010ee083a6a9"
	"appsecco-dvna https://github.com/appsecco/dvna.git 9ba473add536f66ac9007966acb2a775dd31277a"
	"gitaalekhyapaul-vuln-app https://github.com/gitaalekhyapaul/vuln-app.git 0ddf9bdc9672cc53ebd66cb829382bd702a98876"
)

only=${1:-}
work="$root/audit-work"
evidence="$root/docs/evidence/s5-14"
mkdir -p "$work" "$evidence"

export PATH="$root/.tools/bin:$PATH"
"$root/scripts/install-tools.sh" --check || {
	echo "Run scripts/install-tools.sh first (and install Go $GO_VERSION)." >&2
	exit 2
}
if [ -z "${GITHUB_TOKEN:-}" ] && command -v gh >/dev/null 2>&1; then
	GITHUB_TOKEN=$(gh auth token 2>/dev/null || true)
fi
[ -n "${GITHUB_TOKEN:-}" ] || { echo "Set GITHUB_TOKEN or run 'gh auth login'." >&2; exit 2; }
export GITHUB_TOKEN

(cd "$root" && make build)
sbomber="$root/bin/sbomber"
sbomber_commit=$(git -C "$root" rev-parse HEAD)
sbomber_dirty=$(git -C "$root" status --porcelain -- cmd internal go.mod go.sum | wc -l)

grype db update >/dev/null
export GRYPE_DB_AUTO_UPDATE=false

ran=0
for entry in "${cases[@]}"; do
	read -r id url commit <<<"$entry"
	[ -n "$only" ] && [ "$only" != "$id" ] && continue
	ran=1
	dest="$root/testdata/audit/$id"
	[ -f "$dest/CASE.md" ] || { echo "$dest/CASE.md missing" >&2; exit 2; }
	grep -q "$commit" "$dest/CASE.md" || { echo "$id: commit $commit is not the one in CASE.md" >&2; exit 2; }

	# The workspace holds only this repository, so scan finds exactly one.
	ws="$work/$id"
	repo="$ws/$(basename "$url" .git)"
	if [ ! -d "$repo/.git" ]; then
		mkdir -p "$ws"
		git clone --quiet --no-checkout "$url" "$repo"
	fi
	git -C "$repo" -c advice.detachedHead=false checkout --quiet --force "$commit"
	[ "$(git -C "$repo" rev-parse HEAD)" = "$commit" ] || { echo "$id: checkout failed" >&2; exit 1; }

	SOURCE_DATE_EPOCH=$(git -C "$repo" log -1 --format=%ct)
	export SOURCE_DATE_EPOCH

	out="$ws/out"
	rm -rf "$out"
	mkdir -p "$out"
	log="$evidence/$id.log"
	{
		echo "case:            $id"
		echo "repository:      $url"
		echo "commit:          $commit"
		echo "sbomber commit:  $sbomber_commit (uncommitted source changes: $sbomber_dirty)"
		echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
		echo "date run:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "--- grype db status"
		grype db status 2>&1 | sed -n '1,6p'
		echo "--- commands"
	} >"$log"

	run() {
		echo "+ $*" | sed "s#$root/##g; s#$work/##g" >>"$log"
		set +e
		"$@" >>"$log" 2>&1
		local rc=$?
		set -e
		echo "  exit $rc" >>"$log"
		return $rc
	}

	echo "== $id"
	run "$sbomber" scan --include-vulnerabilities --no-color \
		--canonical-scan "$out/canonical-scan.json" -- "$repo" ||
		{ echo "$id: scan failed, see $log" >&2; exit 1; }
	# usage exits 2 on a partial analysis without --allow-partial; partial is
	# an honest result here (e.g. no lockfile) and is recorded in the file.
	run "$sbomber" usage --allow-partial --canonical-scan "$out/canonical-scan.json" \
		--out "$out/usage-graph.json" ||
		{ echo "$id: usage failed, see $log" >&2; exit 1; }
	run "$sbomber" localise --canonical-scan "$out/canonical-scan.json" \
		--out "$out/localisation.json" ||
		{ echo "$id: localise failed, see $log" >&2; exit 1; }

	for f in canonical-scan.json usage-graph.json localisation.json; do
		cp "$out/$f" "$dest/$f"
	done
	if command -v python3 >/dev/null 2>&1; then
		run python3 "$root/contracts/validate.py" --dir "$out" || echo "$id: contract validation reported problems, see $log" >&2
	fi

	findings=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["findings"]))' "$dest/canonical-scan.json" 2>/dev/null || echo "?")
	echo "  $findings findings -> $dest"
	echo "  log -> $log"
done

[ $ran -eq 1 ] || { echo "no case named $only" >&2; exit 2; }
echo
echo "Next: write labels.json for each case from the source (testdata/audit/README.md),"
echo "then: go run ./cmd/sbomber audit --out audit-results.json"
