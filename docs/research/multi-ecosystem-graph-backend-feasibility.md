# Multi-ecosystem graph backend feasibility review

Issue: #101  
Component: 2  
Status: research only; no production parser change

## Question

Can an existing multi-language graph backend produce SBOMber's required
usage evidence for a second ecosystem without executing analysed source
code, cheaply enough to justify a later proof of concept?

SBOMber requires more than language support. A usable backend must support
a defensible join from an exact installed SBOM component/PURL to:

1. an external module or package;
2. an imported or referenced symbol;
3. a source location;
4. call-site evidence.

## Candidate 1: Code-Graph-RAG

### Strengths

- multi-language static source analysis;
- graph representation of packages, modules and functions;
- dependency and call relationships;
- retains source locations.

### Gap for SBOMber

Its package model is primarily code-structure oriented. It does not
directly provide SBOMber's canonical installed PURL/occurrence identity.

An adapter would still be required to reconcile graph packages with
`canonical-scan.json` before usage evidence could safely refer to the
correct installed dependency occurrence.

It also introduces additional graph/database infrastructure compared
with the current Component 2 design.

### Decision

Not recommended as the first proof-of-concept candidate.

## Candidate 2: Joern

### Strengths

- static analysis without executing the analysed application;
- mature Code Property Graph model;
- AST, control-flow and data-flow information;
- explicit call nodes and graph queries;
- support for multiple languages.

### Gap for SBOMber

Joern provides strong semantic and call-graph analysis, but its graph
does not directly provide SBOMber's canonical PURL/occurrence join.

A package-identity adapter would therefore still be required.

Its JDK/CPG-based analysis platform also introduces substantially more
packaging and CI complexity than the current Component 2 parser.

### Decision

Technically capable of useful call-graph analysis, but not the preferred
low-cost proof-of-concept candidate.

## Candidate 3: SCIP

### Strengths

- language-independent code-intelligence protocol;
- symbols contain package manager, package name and package version;
- occurrences contain source ranges;
- external symbols are represented;
- indexers exist for multiple ecosystems.

### Gap for SBOMber

SCIP represents symbols and references rather than a complete application
reachability graph.

A symbol reference cannot automatically be treated as a runtime call.

Its package manager/name/version identity is close to SBOMber's PURL
model, but a proof of concept must still demonstrate deterministic
conversion to the canonical PURL and occurrenceId from
`canonical-scan.json`.

### Decision

SCIP is the preferred candidate for a separately scheduled proof of
concept.

## Acceptance-criteria comparison

| Candidate | Graph / external evidence | Exact PURL mapping | Licence | Maintenance | Packaging / CI impact | Decision |
|---|---|---|---|---|---|---|
| Code-Graph-RAG (`vitali87/code-graph-rag`) | Unified Tree-sitter/Memgraph graph with dependency and call relationships | No native SBOMber PURL/occurrence join; adapter required | MIT | Active; release v0.0.996 published 26 Sep 2026 | Python 3.12+, Memgraph/Docker and additional graph-service dependencies | Reject as first PoC |
| Joern (`joernio/joern`) | Code Property Graph with explicit call-site nodes plus control/data-flow information | No native SBOMber PURL/occurrence join; adapter required | Apache-2.0 | Very active; release v4.0.650 published 7 Oct 2026 | Large platform distributions and Java/sbt or container tooling increase CI/integration cost | Secondary candidate |
| SCIP (`scip-code/scip`) | Protocol records external symbols, source occurrences and package manager/name/version identity | Closest match, but still requires deterministic conversion to canonical PURL/occurrenceId | Apache-2.0 | Active; release v0.10.0 published 3 Sep 2026 | Core CLI can be built as Go binary; a language-specific indexer is still required | Preferred future PoC |

None of the candidates currently demonstrates the complete SBOMber join:

`canonical installed occurrence/PURL -> external module -> symbol -> actual call site`

without an adapter or separately evaluated proof of concept.

## Feasibility decision

None of the reviewed backends is a drop-in replacement for Component 2.

SCIP is the preferred candidate for a future proof of concept because
its package/version identity and source-occurrence model most closely
match SBOMber's required evidence.

A future proof of concept would need to demonstrate:

- deterministic package-manager/name/version to canonical PURL mapping;
- association with the exact canonical SBOM occurrence;
- external-symbol identification;
- source-location evidence;
- reliable distinction between references and actual calls;
- conservative `unknown` handling when the join is ambiguous.

Joern remains a possible secondary option if richer inter-procedural
call analysis later becomes more important than integration cost.

Code-Graph-RAG is not recommended as the first candidate because it does
not remove the package-identity problem and adds additional graph
infrastructure.

## Unknowns

This review does not establish adoption readiness.

Remaining unknowns include:

- consistency of dependency versions produced by individual SCIP indexers;
- whether a chosen indexer exposes enough information to distinguish
  runtime calls from general references;
- reconciliation of nested or duplicated dependency versions;
- runtime and CI cost in SBOMber's supported environment.

These questions require a separately scheduled proof of concept.

## Scope boundary

No analysed application source was executed.

No second ecosystem was implemented.

The production JavaScript/TypeScript parser was not changed.

Any proof of concept or second-ecosystem implementation requires separate
scheduling and approval.

## Evidence reviewed

Public project documentation reviewed on 8 October 2026:

- `vitali87/code-graph-rag`: README, architecture, packaging metadata and releases;
- `joernio/joern`: repository documentation, Code Property Graph documentation,
  call-node documentation and releases;
- `scip-code/scip`: repository documentation, `scip.proto`, generated protocol
  documentation and releases.

The comparison records only documented capabilities. No candidate was installed
or executed, so runtime behaviour, performance and SBOMber-specific integration
remain unknown until a separately approved proof of concept.

## Quality-rule evidence

**Success path:** SCIP documents package manager/name/version identity,
external symbols and source occurrences.

**Failure / unknown path:** none of the candidates demonstrates the full
canonical-PURL-to-call-site join required by SBOMber without an adapter
or proof of concept.

**Boundary:** this work is a feasibility review only. Production parsing
and the committed JS/TS pipeline remain unchanged.
