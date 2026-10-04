# Component 2 — JavaScript/TypeScript Usage Graph Architecture

## 1. Purpose

Component 2 analyses JavaScript, TypeScript and TSX application source and
produces function-usage evidence describing which third-party packages and
symbols the application imports and calls.

It also supports the project's narrowly scoped level-3 reachability analysis:
where statically resolvable, a call path may connect a recognised application
entry point to a third-party call site.

Component 2 consumes the agreed `canonical-scan.json` contract and produces
the agreed `usage-graph.json` 1.4.0 contract.

It does not consume vulnerability findings or localisation results and does
not decide whether a vulnerability affects the application. Those joins and
decisions are performed by downstream components.


## 2. Contract boundary

The project uses versioned JSON contract fixtures so that components can be
developed independently.

Component 2 consumes `canonical-scan.json` 1.0.0 and produces
`usage-graph.json` 1.4.0.

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

Component 2 produces `usage-graph.json` schema version `1.4.0`.

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
representation into the agreed `usage-graph.json` 1.4.0 structure.

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

Production usage-graph generation and the committed level-3 reachability
slice (R1.3) are implemented. Measured precision, recall and reachability
resolution rates are Sprint 6 work and are not claimed here.

Candidate A remains the selected binding. Its parser field assignments were
verified before the production adapter work.

### Command

`sbomber usage` produces `usage-graph.json` from a real run:

    sbomber usage --canonical-scan canonical-scan.json --out usage-graph.json

- It reads `canonical-scan.json` using the contract's field names (`purl`,
  `manifest`, `relationship`, `repositoryId`), not the internal
  `canonicalscan` Go types, whose names differ.
- It analyses every repository in `scan.repositories` whose source is local.
  Relative paths are resolved from the directory holding
  `canonical-scan.json`; `--repo [repositoryId=]path` overrides a path or
  supplies source for a remote repository.
- Remote (manifest-only) repositories are not analysed. Their npm packages are
  listed as `excluded_by_limits`. If no repository has local source, the graph
  has status `unsupported` with reason code `no_local_source`.
- Packages from other ecosystems are listed as `ecosystem_unsupported`.
- A repository with no discovered JavaScript or TypeScript source files makes
  analysis `partial` and lists its npm packages as `no_source_files`. The CLI
  writes the graph and exits 2, or exits 0 with `--allow-partial`. The status
  and reason remain partial and blocking even when that flag is used.
- The root `tsconfig.json` `compilerOptions.paths` (and `baseUrl`) are read.
  An import that matches an alias and no inventory package is the
  application's own code: it is not reported as a package, and call edges
  follow it like a relative import. An alias can never hide a real package.
- `--entry [repositoryId=]file:function[:line]` declares an entry point;
  `<module>` means a file's top-level code. The root `package.json` supplies
  `main` and `bin` entry points automatically.
- Exit codes: 0 for a complete analysis; 2 for bad input, a missing source
  directory, or a partial, failed or unsupported analysis. A partial graph is
  still written. `--allow-partial` returns 0 for a partial analysis.
- Input is bounded: `canonical-scan.json` (64 MiB by default), each source
  file (`--max-file-bytes`), source files per repository (`--max-files`) and
  the root `package.json` (1 MiB).


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
`usage-graph.json` 1.4.0.

Supported import kinds are:

- `esm_named`;
- `esm_default`;
- `esm_namespace`;
- `esm_type_only`;
- `cjs_require`;
- `cjs_destructured`;
- `dynamic_static_literal`;
- `dynamic_computed`;
- `esm_reexport`;
- `esm_side_effect`.

Every import form the parser recognises produces an observation; none is
dropped. The less common forms are handled as follows:

| Source | Recorded as |
|---|---|
| `import "pkg"` | `esm_side_effect`, no binding, level 1 |
| `export { a } from "pkg"`, `export * from "pkg"` | `esm_reexport` with one unresolved call site, reason `reexport_chain` |
| `require(name)`, `` require(`x${y}`) `` | `dynamic_computed`, like `import(name)` |
| `` require(`pkg`) `` (no substitutions) | treated as the literal `"pkg"` |
| `require("pkg");` as a statement | `cjs_require`, no binding, level 1 |
| `const m = require("pkg").merge` | `cjs_destructured`, `importedSymbol` = `merge` |
| `require("pkg").merge(x)` | `cjs_require` with a resolved call site, `calledSymbol` = `merge` |
| `require("pkg")(x)`, e.g. `require("debug")("app")` | `cjs_require` with a resolved call site, `calledSymbol` = `default` |
| `x = require("pkg")` | `cjs_require`, `localAlias` = `x` |
| `foo(require("pkg"))`, `module.exports = require("pkg")`, array or nested patterns | `cjs_require` with one unresolved call site at the import, reason `outside_supported_syntax` |
| `import x = require("pkg")` (TypeScript) | `cjs_require`, `localAlias` = `x` |
| `const m = await import("pkg")` | `dynamic_static_literal`, `localAlias` = `m`, member calls resolve by name |
| `const { merge } = await import("pkg")` | `dynamic_static_literal`, `importedSymbol` = `merge` |
| `import("pkg").then(...)`, `const p = import("pkg")` | `dynamic_static_literal` with one unresolved call site, reason `outside_supported_syntax` |

The unresolved call site is what keeps an escaped import honest: the package
is imported, something may call it, and the analysis cannot say what.

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
- `ambiguous_occurrence`;
- `computed_specifier`;
- `not_imported_by_analysed_source`;
- `no_source_files`;
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

The implementation accepts explicit declarations through
`ProduceOptions.DeclaredEntryPoints`. A declaration names a repository,
analysed source file and unique named function; it may give a line to
disambiguate duplicate names. Declaring `<module>` selects that file's
top-level execution. Missing or ambiguous targets add no entry point.

Root `package.json` contents are supplied as `RepositoryInput.PackageJSON`.
`main` and string or object `bin` paths become entry points only when a path
uniquely resolves to an analysed application source file. There is no inferred
default file. These entry points use a synthetic `<module>` node at line 1.
Only statically resolved top-level direct calls create edges from that node.

A conventional exported `index` module supplies `exported_module` entries.
Static `app.*` and `router.*` calls supply `route_handler` entries when the
handler can be identified uniquely. An inline handler uses the synthetic
`<route_handler>` name at its actual source location. Its entry point and
first path step use the same name, file and line. Synthetic nodes are internal
to the usage graph and are not added to the parser's public `Functions` array.

A path has one element when a resolved third-party call is inside the entry
function or directly at module top level. Relative cross-file calls use the
exported symbol name; a default import resolves against the exported name
`default`. Repeated runs select the same shortest path.

A bare function reference does not create a call edge. Calls nested inside
ordinary anonymous callbacks do not inherit the containing route or module
entry. Unsupported dynamic dispatch, computed targets, dependency injection,
framework lifecycle calls and dependency-source paths remain `unknown`.
When the pass did not run, call sites report `not_analysed`. No
`not_reachable` value is produced.

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
- `filesSkipped` — an in-scope source candidate intentionally not parsed
  because of file-level policy or limits.

Pruned directory trees such as `node_modules`, `dist` and `build` are outside
the declared application-source scope. Their contents are not traversed merely
to inflate the denominator and a directory entry is not counted as one skipped
file. The internal repository result retains the scope exclusion for audit.

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

### Analysis status derived from coverage

The producer derives status from measured coverage rather than accepting a
caller-supplied claim:

- `complete` requires every discovered in-scope file to parse cleanly, with no
  partially parsed, failed or skipped file and no limit or traversal failure;
- `partial` is emitted when any in-scope file is partially parsed, failed or
  skipped, or when a bound or repository traversal prevents complete analysis;
- `failed` means no usable Component 2 analysis was produced;
- `unsupported` means the source ecosystem is outside Component 2 support.

An unresolved import or call is counted separately and does not automatically
make the repository parse partial. A package-relevant unresolved observation
still blocks `no_usage_detected` in Component 4. Positive resolved evidence may
remain `usage_detected` on a partial scan; missing evidence may not.

Parse coverage percentage is cleanly parsed files divided by discovered
in-scope files. A zero denominator reports zero and cannot support a negative
usage decision.
## 15. Security and resource boundaries

Component 2 parses source code but never executes it.

The selected Sprint 4 resource defaults are:

- maximum source files analysed per repository: 10,000;
- maximum individual source file size: 1,000,000 bytes;
- minified-line threshold: 4,000 bytes;
- per-file parse timeout: 5 seconds.

Files outside a configured bound must be reported as skipped or unresolved,
never silently omitted.

Repository discovery does not descend into `.git`, `node_modules`, `dist`,
`build`, `coverage`, `.next`, `out`, `generated` or `vendor` directories.
Generated and minified filename patterns such as `*.bundle.js`, `*.min.js`
and `*.generated.{js,ts,tsx}` are skipped. A source line longer than the
minified-line threshold is also treated as a minified bundle. Directory scope
exclusions are retained internally but stay outside the public file counters;
in-scope file exclusions are counted in `filesSkipped`. Every exclusion is
recorded with its reason.

The repository walker does not follow symbolic links or read other
non-regular files. This prevents source discovery from escaping through a
linked tree or blocking on a device or named pipe.

Repository-relative source locations should be emitted rather than
machine-specific absolute paths where contract portability is required.

The public usage graph contains source locations and symbols but should not
contain unnecessary source-code snippets.

All Candidate A objects owning native resources must be closed
deterministically.

In-scope files excluded because they are oversized, generated or minified are
counted in `filesSkipped`, not `filesParsed`. Pruned vendored directory trees
are outside the denominator. Neither case can support a negative usage
conclusion.

## 16. Known limitations

The current design intentionally does not claim support for:

- dependency-internal source analysis;
- transitive dependency reachability;
- dynamic dispatch;
- computed member target resolution;
- callback indirection through third-party code;
- framework-injected invocation;
- full taint/data-flow analysis;
- remote source-code analysis without a local checkout;
- Vue, Svelte, Astro, MDX and Marko files. These are counted as skipped with
  reason `unsupported_source_format`, which makes the analysis `partial`, so
  an import that exists only in such a file cannot support a negative.

Also not handled, and stated here so results are read correctly:

- Files with syntax errors contribute no usage evidence at all. They are
  counted as parsed with errors and make the analysis `partial`.
- One computed import anywhere in a repository, including a build script,
  keeps every unmatched package in that repository from reading as unused.
  The `unanalysedOccurrences` detail names the line responsible.
- A path alias without a unique analysed source target blocks negative
  findings for unmatched packages in that repository.
- Only the root `tsconfig.json` is read; `extends` and nested tsconfig files
  (for example a separate frontend project) are not followed.
- Route handlers passed as factory calls (`app.use(path, route())`) are not
  entry points, and default-exported anonymous functions
  (`export default async () => {}`) have no name for a call edge to reach.
- An `import()` binding is limited to its lexical block and enclosing
  function; a call outside that block cannot inherit its module identity.
  A module kept as a promise (`const p = import("x")`, `.then(...)`) is
  reported as an unresolved use.

Call-graph edges are not added through a name that a parameter or local
declaration (`const`/`let`/`var`, `for...of`, `catch`, generator or class)
could shadow in any enclosing function. Tracked helpers declared directly
in that function body (`function helper()`, `const helper = () => ...`,
`const helper = function helper()`) can receive a call path. Declarations
inside a deeper function or block still block a same-named call outside
their scope; a same-named module function also leaves the target ambiguous.
A same-file call only resolves to a function that is in scope at the call:
a function nested inside another function is a candidate only when the call
is inside that enclosing function, so `other()` cannot reach a helper
declared inside `main()`.
This is deliberately over-conservative: a shadowing check that misses a
case would fabricate a path, while an extra check only turns a path into
`unknown`.

The application-source-only boundary is particularly important.

A path such as:

    application -> dependency A -> vulnerable function in dependency B

is not visible to Component 2 and must not lead to a negative safety
conclusion.


## 17. Contract compatibility

Component 2 targets the agreed project contracts:

- `canonical-scan.json` 1.0.0 as its upstream identity contract;
- `usage-graph.json` 1.4.0 as its public output contract.

The shared fixtures define the interface used during independent Sprint 4
development. Component 2 does not wait for another component's production
implementation before working against that interface.

The 1.4.0 usage graph keeps reachability on individual call sites and requires
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

The Candidate A semantic adapter and bounded repository discovery are in
production code. Coverage aggregation derives file, import, call-site and
reachability counters plus parser metadata for the public usage graph.
Production package-occurrence resolution and reachability implementation are
tracked separately and are not claimed complete by this architecture document.

### Empty source scope (PR #135 review)

A repository with zero discovered in-scope source files makes the analysis
`partial`; unmatched direct occurrences in that repository use `no_source_files`.
This reason always blocks a negative finding. If the whole scan discovers zero
files, `analysis.reasonCode` is also `no_source_files`. No file counts or scan
limits are invented. A clean repository alongside an empty one cannot hide the
empty scope. The additive reason changes the usage-graph contract to 1.4.0.

The reachability safety tests exercise the production multi-source path index.
The per-target search remains a reference for explicit equivalence tests only.
