# Issue #172: labelled synthetic indirect-use policy cases

These are author-labelled policy fixtures, not CVE evidence or a real-repository
accuracy dataset. `expected.json` was written before any analyser execution on
these cases. `expectedOriginalState` is a source-derived prediction to verify on
the original binary; it is not a claimed measured result until a run succeeds.

| Fixture | Source label | Original expected verdict | Proposed verdict |
|---|---|---|---|
| transitive-b | app index.js:2 -> A index.js:2 -> B merge; B transitive | unknown | unknown |
| direct-unimported-b | same chain; B additionally declared directly | no_usage_detected | unknown |
| direct-positive-b | app index.js:2 directly calls B.merge | usage_detected | usage_detected |
| copied-function | app index.js:2 copies B.merge, later calls f | unknown | unknown |
| destructured-copy | app index.js:2 destructures B.merge | unknown | unknown |
| observed-other-symbol | app calls B.other; no merge call in labelled implementation | no_usage_detected | no_usage_detected |

`dependency-source/` supplies the implementation for manual labels. It is outside
`app/`, the root analysed by the CLI. No packages are installed and no fixture code
is executed. The synthetic package names and finding IDs identify no real advisory.
Canonical inventories are hand-authored contract fixtures, not scan output.
Localisation files supply a public candidate for a controlled decision-policy test;
they are not output of localise and contain no claimed verified provenance.

The CLI regression invokes production usage -> decide. The evidence runner also
validates all four JSON shapes plus canonical, usage and decision invariants. It
intentionally does not validate synthetic localisation provenance: that separate
production gate requires genuine upstream artefacts, which these cases do not have.
The normal full contract fixture validator and its regression suite remain required.

From repository root after building:

```sh
python3 -B scripts/run_issue172_policy.py --binary bin/sbomber --out docs/evidence/issue172/proposed
```

The output directory must be new. To verify original behaviour, run the harness
against an archive of the original commit with its original binary and validator,
using `--expect-original --source-commit <full-sha>`. Never run the fixed validator
against an original absence-only negative and call that a baseline pass.

The runner preserves commands, source/binary/input/output hashes and Git status.
Go tests cover the production CLI path, absent-import guard, repeated reasons and
positive evidence despite an absence-only occurrence. Existing copied-import alias
and shadow cases remain required. Original #152 evidence must not be overwritten.
