# PR #181: resolved evaluation scope

The audit renderer correction distinguishes abstention from passing the negative-
verdict gate. This follow-up resolves uncertain-label inclusion conservatively:
DVNA proposals move unchanged to labels.provisional.json and the entire case is
excluded by the existing discovery contract. The original 93-row evidence is
retained unchanged with explicit original-93 filenames.

The active audit contains 46 findings from two repositories: 1 agree usage,
4 over-reported usage, 41 abstained and zero negatives. The worksheet-origin
stratum has 45 rows (1 agree usage, 4 over-reported, 40 abstained); one
retrospective row abstains. No blind/accuracy/recall claim is made.

DVNA's 43 unversioned findings, 29 floor-conditioned proposals, speculative
Sequelize trigger and 12 applicability exclusions have not been magically
resolved. They are excluded pending verifiable evidence. All 47 proposals and
source reasoning remain available; no binary label or package version was guessed.

Issue #124 remains open: two active repositories do not satisfy its three-to-five
requirement. This change can merge as a partial deliverable without claiming the
labelled-set task is complete. Future promotion must establish versions/trigger
reasoning and run the complete case through the unchanged audit gate.

The provenance script checks case discovery, row identities, binary outcomes,
active totals and disclosed timing. It rejects reintroducing a provisional case
or tampered report identities. It does not establish independent label truth.
