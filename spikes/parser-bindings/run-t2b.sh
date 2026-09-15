#!/usr/bin/env bash

set -euo pipefail

script_dir="$(
  CDPATH= cd -- "$(dirname -- "$0")" &&
    pwd
)"

harness_a="${HARNESS_A:-/tmp/harness-A}"
harness_b="${HARNESS_B:-/tmp/harness-B}"

expected_query_sha="a47429d70dcde4fcbccd760e2eae9afe6f03a8b00600b14dde36ff80575f7864"

actual_query_sha="$(
  sha256sum "$script_dir/queries/usage.scm" |
    awk '{print $1}'
)"

if [[ "$actual_query_sha" != "$expected_query_sha" ]]; then
  echo "FAIL: shared query SHA does not match frozen value"
  echo "expected=$expected_query_sha"
  echo "actual=$actual_query_sha"
  exit 1
fi

if [[ ! -x "$harness_a" ]]; then
  echo "FAIL: Candidate A harness is unavailable: $harness_a"
  exit 1
fi

if [[ ! -x "$harness_b" ]]; then
  echo "FAIL: Candidate B harness is unavailable: $harness_b"
  exit 1
fi

mkdir -p \
  "$script_dir/results/A/sexp" \
  "$script_dir/results/B/sexp" \
  "$script_dir/results/parity"

mapfile -t fixtures < <(
  find "$script_dir/corpus/micro" \
    -maxdepth 1 \
    -type f \
    \( -name '*.js' -o -name '*.ts' -o -name '*.tsx' \) \
    -print |
    sort
)

mismatches=0

for fixture in "${fixtures[@]}"; do
  base="$(basename "$fixture")"

  "$harness_a" \
    sexp "$fixture" \
    > "$script_dir/results/A/sexp/$base.txt"

  "$harness_b" \
    sexp "$fixture" \
    > "$script_dir/results/B/sexp/$base.txt"

  if diff -u \
    "$script_dir/results/A/sexp/$base.txt" \
    "$script_dir/results/B/sexp/$base.txt" \
    > "$script_dir/results/parity/$base.diff"
  then
    echo "PASS: $base"
  else
    echo "MISMATCH: $base"
    mismatches=$((mismatches + 1))
  fi
done

{
  echo "=== T2b Named-Node S-expression Parity ==="
  date -Is
  echo "fixtures=${#fixtures[@]}"
  echo "mismatches=$mismatches"
  echo "candidateA=$harness_a"
  echo "candidateB=$harness_b"
  echo "querySHA256=$actual_query_sha"
  echo "normalization=Candidate A field labels removed"
} > "$script_dir/results/parity/T2b-summary.txt"

cat "$script_dir/results/parity/T2b-summary.txt"

if ((mismatches > 0)); then
  exit 1
fi

echo "PASS: all T2b named-node structures are identical"
