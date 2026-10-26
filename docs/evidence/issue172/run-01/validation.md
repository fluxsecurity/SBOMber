# Issue #172 policy validation

Original commit: `f0eda3fe558902e24ecae19ad7fd618d596cecf4`.

The original guard regression failed with the expected absence-only negative.
All six source-derived baseline predictions were reproduced. The proposed
policy passed the same six labelled CLI cases, preserving byte-identical usage
graphs. Only the direct-unimported-B case changed state (negative to unknown).
Positive evidence, copied-use uncertainty and the observed-other-symbol scoped
negative control were retained. This is not whole-program non-use evidence.

Build, focused policy tests, full Go tests, vet, lint, full existing contract
fixture validation, Python contract regressions, Python script regressions,
formatting and whitespace checks passed. Commands and exit codes are saved.
Original S6-14 run-01 evidence is unchanged.

The six new cases use synthetic inventories and synthetic localisation inputs.
They validate four JSON schemas and canonical/usage/decision invariants, but
NOT production localisation provenance. No verified upstream artefacts or real
vulnerability accuracy is claimed. Baseline source was a committed archive
augmented only with the labelled test harness. Source/binary hashes are saved.

Component 4 policy agreement and Component 3 paired review remain pending.
No commit, push, review submission, issue closure or merge was performed.
