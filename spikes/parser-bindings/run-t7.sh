#!/usr/bin/env bash

set -uo pipefail

targets=(
  "linux amd64"
  "linux arm64"
  "darwin amd64"
  "darwin arm64"
  "windows amd64"
)

echo "=== T7 Packaging Matrix ==="
date -Is
go version
echo

for candidate in A B
do
  echo "=== Candidate $candidate ==="

  for target in "${targets[@]}"
  do
    read -r target_os target_arch <<< "$target"

    for cgo in 0 1
    do
      output="/tmp/h-$candidate-$target_os-$target_arch-cgo$cgo"
      log="results/$candidate/T7/build-$target_os-$target_arch-cgo$cgo.log"

      if (
        cd "harness/$candidate"

        env \
          CGO_ENABLED="$cgo" \
          GOOS="$target_os" \
          GOARCH="$target_arch" \
          go build \
            -trimpath \
            -ldflags='-s -w' \
            -o "$output" \
            .
      ) > "$log" 2>&1
      then
        echo "PASS Candidate $candidate $target_os/$target_arch CGO=$cgo"
      else
        echo "FAIL Candidate $candidate $target_os/$target_arch CGO=$cgo"
      fi
    done
  done

  echo
done
