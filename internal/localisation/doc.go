// Package localisation works out which function an advisory actually
// implicates in a vulnerable npm package, and records how it knows.
//
// It is Component 3 of SBOMber (Requirements v8 R2). The output is the
// localisation.json contract in contracts/localisation.schema.json, read by
// Component 4 to decide whether the application's observed usage touches the
// implicated code.
//
// Methods run in the schema's fallback order, cheapest and most reliable
// first:
//
//	advisory_metadata  structured fields in OSV / GHSA that name a function
//	patch_reference    the fix commit or pull request the advisory links to
//	advisory_text      function-like identifiers in the advisory prose
//	version_diff       the diff between the vulnerable and fixed npm tarballs
//	unknown            an honest outcome; the finding falls back to package level
//
// Two rules hold everywhere in this package:
//
//   - Downloaded package code is never executed. Tarballs are read in memory,
//     only text files are inspected, and every artefact records
//     executed: false.
//   - A function changed by a security patch is a CANDIDATE, not a proven
//     culprit. Patches routinely bundle refactoring with the fix, and a public
//     API is often fixed inside a private helper it calls.
package localisation
