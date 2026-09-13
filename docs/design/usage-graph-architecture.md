# Component 2 — JavaScript/TypeScript Usage Graph Architecture

## 1. Purpose

Component 2 analyses JavaScript, TypeScript and TSX application source and
produces function-usage evidence describing which third-party packages and
symbols the application imports and calls.

It also supports the project's narrowly scoped level-3 reachability analysis:
where statically resolvable, a call path may connect a recognised application
entry point to a third-party call site.

Component 2 consumes the agreed `canonical-scan.json` contract and produces
the agreed `usage-graph.json` 1.2.0 contract.

It does not consume vulnerability findings or localisation results and does
not decide whether a vulnerability affects the application. Those joins and
decisions are performed by downstream components.


## 2. Contract boundary

The project uses versioned JSON contract fixtures so that components can be
developed independently.

Component 2 consumes `canonical-scan.json` 1.0.0 and produces
`usage-graph.json` 1.2.0.

Component 2 can therefore work against the agreed canonical-scan fixture
without waiting for the production Component 1 exporter.

### Input

Component 2 reads the canonical information needed to identify the scan,
repository and installed package occurrences, including:

- `scan.scanId`;
- `scan.repositories[].repositoryId`;
- `occurrences[].occurrenceId`;
- `occurrences[].purl`;
- repository, workspace, manifest, dependency-path and install-path
  information where required for package resolution.

`occurrenceId` is the canonical cross-component identity for a specific
installed package occurrence. Component 2 does not invent or regenerate it.

Component 2 does not require vulnerability findings, severity, EPSS, KEV,
fixed versions or vulnerable-function localisation.

### Output

Component 2 produces `usage-graph.json` schema version `1.2.0`.

The root output contains:

- `schemaVersion`;
- `scanId`;
- `analysis`;
- `analyser`;
- `entryPoints`;
- `coverage`;
- `observations`;
- `unanalysedOccurrences`;
- `parseFailures`.

One observation represents one third-party import binding.

An observation records the import identity, package occurrence where known,
import resolution, source location, derived evidence level and its
`callSites[]`.

Reachability belongs to an individual call site rather than to the whole
observation. Each call site may therefore contain:

- `resolution`;
- `unresolvedReason`;
- `reachability`;
- `entryPointId`;
- `callPath`.

This permits two calls through the same import to have different reachability
results.

Runtime metadata such as parser and grammar versions must report the versions
actually used by the analyser rather than blindly copying fixture values.
## 3. Two-layer design

Component 2 separates parser-specific extraction from the public JSON
contract.

### Layer 1 — parser adapter

The parser adapter converts parser-specific syntax into an internal
parser-independent representation of:

- imports;
- local bindings and aliases;
- calls;
- named application functions;
- source locations;
- parse status;
- unresolved constructs.

Tree-sitter node names, capture labels, S-expressions and parser-specific
objects remain internal.

### Layer 2 — usage graph producer

The usage-graph producer resolves extracted imports against package
occurrences supplied by `canonical-scan.json` and converts the internal
representation into the agreed `usage-graph.json` 1.2.0 structure.

This separation allows the parser implementation to change without requiring
Component 4 to change its input contract.

## 4. Current implementation status

### Verified

- The parser binding spike is complete.
- Candidate A is `github.com/tree-sitter/go-tree-sitter` v0.25.0.
- JavaScript grammar: `tree-sitter-javascript` v0.25.0.
- TypeScript/TSX grammar: `tree-sitter-typescript` v0.23.2.
- Candidate B, `gotreesitter` v0.51.0, is the documented fallback.
- Candidate A parses JavaScript, TypeScript and TSX.
- Candidate A reports invalid input without panic.
- Candidate B's extraction adapter reproduced all 13 expected parser fixtures.
- CGO is required for Candidate A.

### Current implementation boundary

Candidate A's semantic extraction adapter has reproduced the 13 labelled
parser fixtures exactly.

The following are still not claimed complete by this architecture document:

- production usage-graph generation;
- production level-3 reachability implementation.

Candidate A remains the selected binding. Its parser field assignments were
verified before the production adapter work.


## 5. Parser decision and packaging

The selected parser integration is:

- `github.com/tree-sitter/go-tree-sitter` v0.25.0;
- `tree-sitter-javascript` v0.25.0;
- `tree-sitter-typescript` v0.23.2.

The selected binding requires CGO. The tested Linux glibc floor is 2.34.
Component 1 has already been informed of the packaging consequence.

`gotreesitter` v0.51.0 is retained as the fallback. The fallback is used only
if an unfixable Candidate A parser or grammar problem blocks production work.
The recorded Lodash regression must be repeated before switching.

Candidate A's parser behaviour is verified, but its semantic extraction
adapter is not yet claimed complete. In particular, query field assignments
must be verified directly before the Candidate A adapter is accepted.

## 6. Import and alias representation

Component 2 records imports using the public representation defined by
`usage-graph.json` 1.2.0.

Supported import kinds are:

- `esm_named`;
- `esm_default`;
- `esm_namespace`;
- `esm_type_only`;
- `cjs_require`;
- `cjs_destructured`;
- `dynamic_static_literal`;
- `dynamic_computed`.

The original package specifier is preserved in `importedSpecifier`.

For package subpaths, for example:

    lodash/merge
    @scope/package/subpath

the source spelling is preserved and the subpath may also be recorded
separately in `subpath`.

Aliases are represented explicitly.

For example:

    import { get as httpGet } from "axios";

is represented with:

- `importedSymbol` = `get`;
- `localAlias` = `httpGet`.

A namespace import such as:

    import * as _ from "lodash";

is a resolved package binding. A later computed member call such as
`_[name](...)` may still be unresolved, but the namespace import itself must
not be classified as unresolved.

TypeScript `import type` declarations are retained as type-only evidence.
They do not produce runtime-call evidence because they are removed by the
TypeScript compiler.

### Whole-module calls

When a whole-module binding is called directly, Component 2 records
`calledSymbol` as `default`.

For example:

    const minimist = require("minimist");
    minimist(process.argv);

produces `calledSymbol: "default"`.

When a member of the whole-module binding is called, the property name is
recorded instead. For example, `_.merge(...)` produces
`calledSymbol: "merge"`.

The application's local binding name is never used as the package-side
symbol.

## 7. Package occurrence resolution

Component 2 joins source imports to package occurrences from the agreed
`canonical-scan.json` contract.

The cross-component identity is `occurrenceId`. Component 2 must preserve the
canonical occurrence identity rather than construct a competing identity.

Package resolution considers the repository and package installation context
so that nested versions remain distinct.

For example, root Lodash and a different Lodash version nested beneath
another dependency are different occurrences even though their package names
are the same.

If an import cannot safely be associated with a canonical occurrence,
Component 2 does not guess.

Every canonical occurrence must be accounted for in exactly one of two ways:

1. it is represented by one or more observations; or
2. it appears in `unanalysedOccurrences`.

`unanalysedOccurrences` distinguishes "analysis completed and no import was
found" from "this occurrence was never or could not be analysed".

Supported reasons are:

- `nested_under_dependency`;
- `not_imported_by_analysed_source`;
- `ecosystem_unsupported`;
- `import_site_parse_failed`;
- `excluded_by_limits`.

Only `not_imported_by_analysed_source` represents a completed application
source check that found no import. The other reasons describe unsupported or
incomplete analysis and cannot support a negative conclusion downstream.

## 8. Call-site resolution

Call sites belong to their import observation.

This is important because one import may be used at several source locations
and those calls may have different reachability results.

A resolved third-party call site records:

- source file;
- line and optional column;
- `calledSymbol`;
- enclosing application function where available;
- `resolution: resolved`;
- its own reachability result.

An unresolved call site remains present rather than being silently dropped.

Supported call-site unresolved reasons are:

- `computed_member_access`;
- `call_through_variable`;
- `reexport_chain`;
- `outside_supported_syntax`.

For example, a namespace import may be fully resolved while a later computed
member access through that binding remains an unresolved call site.

Component 2 must not fabricate the target of a computed member access,
dynamic dispatch or another unsupported construct.

## 9. Evidence levels

`evidenceLevel` is derived from the evidence contained in an observation. It
is not an independent claim.

### Level 1 — import evidence

The application imports the package or symbol but no resolved runtime call
site has been established.

Type-only imports remain level 1 and contain no runtime call sites.

An observation whose only calls are unresolved also remains level 1.

### Level 2 — call evidence

At least one call site is statically resolved to a named third-party symbol.

Level 2 is function-usage evidence. It is not by itself reachability
analysis.

### Level 3 — reachability evidence

At least one resolved call site has:

- `reachability: reachable`;
- a valid `entryPointId`;
- a non-empty ordered `callPath`.

The observation's evidence level is the maximum evidence level supported by
its call sites.

One observation can therefore be level 3 while still containing another call
site whose reachability is `unknown`.

There is deliberately no `not_reachable` result.

## 10. Entry points and reachability boundary

The committed reachability design and analysis boundary are deliberately narrow.

The public entry-point kinds are:

- `declared`;
- `package_bin`;
- `package_main`;
- `exported_module`;
- `route_handler`.

These represent configured entry points, `package.json` bin/main entries,
exported application modules or functions, and statically recognisable route
handlers.

Within the committed scope, paths follow statically resolvable direct calls
between named application functions, including intra-file and cross-file
calls where the target resolves without inference.

The following are outside the committed scope:

- dynamic dispatch;
- computed member target inference;
- calls through variables holding function references;
- callbacks invoked from inside third-party libraries;
- dependency-injection and lifecycle framework invocation;
- paths through dependency source;
- transitive reachability through dependencies;
- full taint or data-flow analysis.

A call site outside this boundary reports `unknown` when reachability analysis
ran but could not resolve a path, or `not_analysed` when that pass did not run.

Failure to resolve a path is never reported as proof of unreachability.

## 11. Reachability path representation

Reachability is recorded per call site.

A call site with `reachability: reachable` references an entry point through
`entryPointId` and contains an ordered `callPath`.

For the Sprint 4 labelled reachability case the intended application path is:

    entry point
        -> intermediate application function
        -> application function containing the dependency call

The first `callPath` element must correspond to the referenced entry point.

The final path element must correspond to the application function containing
the third-party call.

A call site reporting `unknown` or `not_analysed` does not carry a call path
or entry-point ID.

`coverage.entryPointsDetected`, `coverage.callPathsResolved` and
`coverage.callPathsUnresolved` make reachability measurable.

Reachability counters count call sites rather than observations.

## 12. Parse failures

Source files are untrusted input.

A parse problem in one file must not stop analysis of the remaining
repository and must not silently disappear from coverage.

The public coverage distinguishes:

- `filesParsed` — usable tree with no parser error nodes;
- `filesParsedWithErrors` — usable tree containing error nodes;
- `filesFailed` — no usable tree;
- `filesSkipped` — intentionally excluded or excluded by policy/limits.

Files with no usable tree are also recorded in `parseFailures`.

The coverage invariant is:

    filesDiscovered
      = filesParsed
      + filesParsedWithErrors
      + filesFailed
      + filesSkipped

Missing evidence from failed, partially parsed or skipped files cannot be
treated as proof that a package or function is unused.

## 13. Unresolved constructs

Unsupported or ambiguous constructs remain visible rather than being silently
dropped.

Import-binding unresolved reasons are:

- `computed_specifier`;
- `reexport_chain`;
- `not_in_inventory`;
- `parse_failure`;
- `outside_supported_syntax`.

A computed member access is not an unresolved import. It is an unresolved
call site on a potentially resolved import binding.

Call-site unresolved reasons are:

- `computed_member_access`;
- `call_through_variable`;
- `reexport_chain`;
- `outside_supported_syntax`.

For example:

    import(name)

is an unresolved import with reason `computed_specifier`.

By contrast:

    import * as _ from "lodash";
    _[method](value);

has a resolved namespace import and an unresolved call site with reason
`computed_member_access`.

This distinction keeps import-resolution coverage separate from call-site
resolution coverage.

## 14. Coverage

Coverage is part of the public Component 2 contract, not diagnostic logging.

### File coverage

- `filesDiscovered`;
- `filesParsed`;
- `filesParsedWithErrors`;
- `filesFailed`;
- `filesSkipped`.

### Third-party import coverage

- `thirdPartyImportsResolved`;
- `thirdPartyImportsTypeOnly`;
- `thirdPartyImportsUnresolved`.

These counters count observations.

### Third-party call-site coverage

- `thirdPartyCallSitesResolved`;
- `thirdPartyCallSitesUnresolved`.

These counters count individual call sites.

### Reachability coverage

- `entryPointsDetected`;
- `callPathsResolved`;
- `callPathsUnresolved`.

`callPathsResolved` equals the number of call sites reporting
`reachability: reachable`.

`callPathsUnresolved` equals the number of call sites reporting
`reachability: unknown`.

A call site reporting `not_analysed` is not counted as an unresolved path
because the reachability pass did not run for it.

Coverage may also contain `limitsHit` and per-repository file counters.

Component 4 may use these measured values when determining analysis
confidence, so incomplete analysis must remain visible.
## 15. Security and resource boundaries

Component 2 parses source code but never executes it.

The selected Sprint 4 resource defaults are:

- maximum individual source file size: 1,000,000 bytes;
- per-file parse timeout: 5 seconds.

Files outside a configured bound must be reported as skipped or unresolved,
never silently omitted.

Repository-relative source locations should be emitted rather than
machine-specific absolute paths where contract portability is required.

The public usage graph contains source locations and symbols but should not
contain unnecessary source-code snippets.

All Candidate A objects owning native resources must be closed
deterministically.

Files excluded because they are oversized, minified or vendored are counted
in `filesSkipped`, not `filesParsed`. They cannot support a negative
usage conclusion.

## 16. Known limitations

The current design intentionally does not claim support for:

- dependency-internal source analysis;
- transitive dependency reachability;
- dynamic dispatch;
- computed member target resolution;
- callback indirection through third-party code;
- framework-injected invocation;
- full taint/data-flow analysis;
- remote source-code analysis without a local checkout.

The application-source-only boundary is particularly important.

A path such as:

    application -> dependency A -> vulnerable function in dependency B

is not visible to Component 2 and must not lead to a negative safety
conclusion.


## 17. Contract compatibility

Component 2 targets the agreed project contracts:

- `canonical-scan.json` 1.0.0 as its upstream identity contract;
- `usage-graph.json` 1.2.0 as its public output contract.

The shared fixtures define the interface used during independent Sprint 4
development. Component 2 does not wait for another component's production
implementation before working against that interface.

The 1.2.0 usage graph keeps reachability on individual call sites and requires
canonical package occurrences to be explicitly accounted for through either
`observations` or `unanalysedOccurrences`.

A breaking contract change requires producer/consumer agreement, a schema
version bump, an updated fixture and successful contract validation.
## 18. Evidence

Parser-selection evidence is retained under:

- `spikes/parser-bindings/DECISION.md`;
- `spikes/parser-bindings/TEST_PROTOCOL.md`;
- `spikes/parser-bindings/PROVENANCE.md`;
- `spikes/parser-bindings/queries/usage.scm`;
- `spikes/parser-bindings/corpus/`;
- `spikes/parser-bindings/results/`.

The parser selection was merged in PR #71 at merge commit `e9e6b2e`.

The Candidate A semantic adapter, production usage-graph generation and
production reachability implementation are tracked separately and are not
claimed complete by this architecture document.
