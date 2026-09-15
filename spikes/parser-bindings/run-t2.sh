#!/usr/bin/env bash

set -uo pipefail

harness="${HARNESS_B:-/tmp/harness-B}"
expected_query_sha="a47429d70dcde4fcbccd760e2eae9afe6f03a8b00600b14dde36ff80575f7864"

if [[ ! -x "$harness" ]]; then
  echo "FAIL: Candidate B harness is not executable: $harness" >&2
  exit 2
fi

actual_query_sha="$(sha256sum queries/usage.scm | awk '{print $1}')"

if [[ "$actual_query_sha" != "$expected_query_sha" ]]; then
  echo "FAIL: shared query SHA-256 has changed" >&2
  echo "expected=$expected_query_sha" >&2
  echo "actual=$actual_query_sha" >&2
  exit 2
fi

mkdir -p results/B/extract results/B/diff

fixtures=0
matches=0
mismatches=0

echo "=== Candidate B T2 Extraction ==="
date -Is
echo "harness=$harness"
echo "querySHA256=$actual_query_sha"
echo

for expected in corpus/expected/[0-9][0-9]-*.json
do
  stem="$(basename "$expected" .json)"
  fixture=""

  for extension in js ts tsx
  do
    candidate="corpus/micro/$stem.$extension"

    if [[ -f "$candidate" ]]; then
      fixture="$candidate"
      break
    fi
  done

  if [[ -z "$fixture" ]]; then
    echo "MISMATCH: $stem — fixture not found"
    mismatches=$((mismatches + 1))
    continue
  fi

  output="results/B/extract/$stem.json"
  diff_file="results/B/diff/$stem.diff"

  fixtures=$((fixtures + 1))

  if ! CGO_ENABLED=0 "$harness" extract "$fixture" > "$output"
  then
    echo "MISMATCH: $stem — extractor failed"
    mismatches=$((mismatches + 1))
    continue
  fi

  if diff -u "$expected" "$output" > "$diff_file"
  then
    echo "PASS: $stem"
    matches=$((matches + 1))
  else
    echo "MISMATCH: $stem"
    mismatches=$((mismatches + 1))
  fi
done

echo
echo "fixtures=$fixtures"
echo "matches=$matches"
echo "mismatches=$mismatches"

if (( mismatches > 0 )); then
  exit 1
fi
