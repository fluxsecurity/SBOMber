# PR #181 reviewer findings — 25 October 2026

Reviewed head: `1de5ba6270c8ec852833c4aaab74111f87695b5d`.

All 93 label identities, recorded label reasoning/evidence, scan IDs and outcome
classifications match the saved report. All nine generated upstream inputs match
base `f0eda3fe558902e24ecae19ad7fd618d596cecf4` byte-for-byte.
Recomputed: 2 agree usage, 4 over-reported usage, 87 abstained, zero negatives.
Of 21 genuine-use labels, only 2 are usage_detected and 19 abstained.

## Definite wording correction

The original renderer claimed no genuine usage was moved out of usage detected,
although genuine-use labels also abstain. A regression reproduced that overclaim.
The corrected renderer says only that no genuine-use finding was classified
no_usage_detected and explicitly distinguishes abstentions from detections.
Full checks passed; the corrected audit JSON is semantically identical to the
saved original. Original labels and generated evidence were not edited.

## Label-methodology issues requiring owner resolution before #124 closure

1. DVNA has 43 labelled findings without an exact component version. Twenty-nine
   labels explicitly assume the package.json range floor; 17 use floor-specific
   dependency implementation behaviour. A permitted floor is not evidence of the
   installed version. Either establish a reproducible labelled version context
   with new, separately identified inputs, or mark affected labels conditional /
   not evaluable and exclude them from any validated usage-measurement denominator.
   Do not overwrite the existing raw inputs or silently relabel from tool output.
2. The sequelize GHSA-8c25-f3mj-v6h8 no_genuine_usage label explicitly infers a
   trigger from another advisory sharing fixes. Shared fixes alone do not establish
   equivalent vulnerable paths. Supply direct fix/source reasoning or leave it
   unresolved under labelling rule 6; a definitive binary label is not justified
   by the current weakest-label explanation alone.
3. Separate label timing: the worksheet-origin stratum has 63 labels (2 agree
   usage, 4 over-reported, 57 abstained); the 30 retrospective labels all abstain.
   Retrospective source review is not blind/pre-output evaluation. Timing is
   honestly disclosed; preserve that distinction in machine-readable evidence and
   S6-10/S6-11 reporting, not just one aggregate result.
4. Twelve floor-labelled negatives concern advisory applicability/version
   exclusion, not absence of a called symbol. Verify the actual affected ranges
   against declarations and report them as a separate applicability stratum.
   Absence from one bulk API response alone is not proof of an unaffected range.

The associated API responses and dependency tarball bytes/checksums are not in
this review bundle. References and line numbers are recorded, but the reviewer
has not independently verified every external source/trigger claim. The primary
GHSA-8c25-f3mj-v6h8 advisory is broad and names no precise function/option.

## Acceptance status

The negative-decision gate passes, with zero negatives to inspect. This does not
establish successful usage detection or validate uncertain labels. No accuracy or
recall percentage is claimed here. Keep #124 open until a fully evaluable labelled
set satisfies its criteria; replace the PR body's automatic closing claim while
those issues remain unresolved. This reviewer change does not alter binary labels
or claim to have resolved the methodological questions.

No review submission, commit, push, approval or merge was performed.
