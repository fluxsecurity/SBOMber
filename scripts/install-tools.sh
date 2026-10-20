#!/usr/bin/env bash
# Install the pinned Grype and govulncheck into ./.tools/bin.
#
#   scripts/install-tools.sh            # install
#   scripts/install-tools.sh --check    # only report what is installed
#
# Go itself is not installed here: install Go $GO_VERSION from
# https://go.dev/dl/ (the official demonstration runs on Ubuntu 24.04 LTS;
# see docs/demo.md). Nothing is installed system-wide.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=versions.env
. "$root/scripts/versions.env"
bin="$root/.tools/bin"

check_only=false
[ "${1:-}" = "--check" ] && check_only=true

status=0
report() { printf '  %-14s %s\n' "$1" "$2"; }

echo "Pinned versions (scripts/versions.env):"
go_line=$(awk '$1 == "go" { print $2 }' "$root/go.mod")
if [ "$go_line" != "$GO_VERSION" ]; then
	echo "error: go.mod says go $go_line but versions.env pins $GO_VERSION" >&2
	exit 2
fi

if command -v go >/dev/null 2>&1; then
	have=$(go env GOVERSION 2>/dev/null || true)
	if [ "$have" = "go$GO_VERSION" ]; then
		report go "go$GO_VERSION (ok)"
	else
		report go "$have installed, go$GO_VERSION pinned: install it from https://go.dev/dl/"
		status=1
	fi
else
	report go "not installed: install go$GO_VERSION from https://go.dev/dl/"
	status=1
fi

grype_installed() {
	[ -x "$bin/grype" ] && "$bin/grype" version 2>/dev/null | awk '/^Version:/ { print "v" $2 }'
}

if [ "$(grype_installed)" = "$GRYPE_VERSION" ]; then
	report grype "$GRYPE_VERSION (ok)"
elif $check_only; then
	report grype "not installed at $bin (pinned $GRYPE_VERSION)"
	status=1
else
	case "$GRYPE_VERSION" in
		v[0-9]*.[0-9]*.[0-9]*) ;;
		*) echo "error: GRYPE_VERSION must be a release tag like v0.120.1" >&2; exit 2 ;;
	esac
	mkdir -p "$bin"
	# The install script is fetched from the same release tag; it checks the
	# release's checksums before installing.
	curl -sSfL "https://raw.githubusercontent.com/anchore/grype/${GRYPE_VERSION}/install.sh" \
		| sh -s -- -b "$bin" "$GRYPE_VERSION"
	[ "$(grype_installed)" = "$GRYPE_VERSION" ] || { echo "error: grype $GRYPE_VERSION did not install" >&2; exit 2; }
	report grype "$GRYPE_VERSION (installed)"
fi

govulncheck_installed() {
	[ -x "$bin/govulncheck" ] && "$bin/govulncheck" -version 2>/dev/null | awk -F@ '/^Scanner:/ { print $2 }'
}

if [ "$(govulncheck_installed)" = "$GOVULNCHECK_VERSION" ]; then
	report govulncheck "$GOVULNCHECK_VERSION (ok)"
elif $check_only; then
	report govulncheck "not installed at $bin (pinned $GOVULNCHECK_VERSION)"
	status=1
else
	GOBIN="$bin" go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"
	report govulncheck "$GOVULNCHECK_VERSION (installed)"
fi

if $check_only; then
	exit $status
fi
echo
echo "Add the tools to PATH for this shell:"
echo "  export PATH=\"$bin:\$PATH\""
exit $status
