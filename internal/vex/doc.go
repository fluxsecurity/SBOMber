// Package vex turns component 4's decision-results.json into an OpenVEX
// 0.2.0 document.
//
// It is the VEX exporter of Component 3 (Requirements v8 R5, task S5-07).
// The format, the investigation-state token and the consumer evidence come
// from the S4-09 spike (spikes/vex-format/DECISION.md).
//
// The mapping lives in one policy layer, Map:
//
//	usage_detected     affected, with a mandatory action_statement, or
//	                   under_investigation when component 4 maps it so
//	no_usage_detected  under_investigation
//	unknown            under_investigation
//	unsupported        no statement; counted as omitted so the report can show it
//
// Three rules hold everywhere in this package:
//
//   - not_affected is not emitted by the committed exporter. VEX consumers
//     suppress not_affected findings, and application-source-only analysis
//     cannot prove vulnerable code is outside the execution path.
//   - One vocabulary per document. OpenVEX uses under_investigation; a
//     decision carrying CycloneDX's in_triage rejects the whole document
//     rather than being silently translated.
//   - No text field may carry the phrases contracts/validate.py bans.
//
// The subject model is an open decision (issue #128), so both shapes are
// available. SubjectApplication follows R5 rule 1: the scanned application at
// a commit is the product and the vulnerable package is a subcomponent.
// SubjectPackage makes the package purl the product, which is the shape Grype
// 0.112.0 and Trivy 0.70.0 actually act on.
package vex
