(
  set -euo pipefail
  make build
  demo="$C2_DEMO_OUT"

  for case in direct-positive-b copied-function direct-unimported-b; do
    fixture="$PWD/testdata/fixtures/indirect-usage-172/$case"
    mkdir "$demo/$case"
    bin/sbomber usage \
      --canonical-scan "$fixture/canonical-scan.json" \
      --repo "repo-172=$fixture/app" \
      --out "$demo/$case/usage-graph.json"
    bin/sbomber decide \
      --canonical-scan "$fixture/canonical-scan.json" \
      --usage-graph "$demo/$case/usage-graph.json" \
      --localisation "$fixture/localisation.json" \
      --out "$demo/$case/decision-results.json"
  done
  echo "Saved demo outputs: $demo"
)
