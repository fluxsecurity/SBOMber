# Parser Spike Ground-Truth Conventions

These conventions were fixed before Candidate A or Candidate B was run
against the formal micro-fixture corpus.

## Coordinates

- Lines are 1-based.
- Columns are 0-based UTF-8 byte columns.
- `startByte` is inclusive.
- `endByte` is exclusive.
- Byte offsets refer to the original file bytes.
- CRLF is two bytes in byte-offset calculations but represents one line ending.
- The UTF-8 BOM in `12-edge.js` is included in byte offsets.
- The BOM is not treated as a visible source-code column. Therefore, columns
  on the first line of `12-edge.js` are normalised by subtracting the
  three-byte BOM.
- Non-ASCII characters count according to their UTF-8 byte length.

## Import locations

- For ESM named, default and namespace imports, the location is the beginning
  of the local binding.
- For an aliased import, the location is the beginning of the local alias.
- For CommonJS imports, the location is the beginning of the local binding.
- For destructured CommonJS imports, each destructured binding is a separate
  import observation.
- For dynamic imports, the location is the beginning of the `import` keyword.
- A literal dynamic import has its literal package specifier.
- A computed dynamic import preserves its source expression as the specifier
  and is also recorded in `unresolved`. Placeholder values such as
  `<computed>` are not used by the production contract.
- A TypeScript `import type` is retained with kind `esm_type_only` and
  `typeOnly: true`.
- Type-only imports do not create runtime-call evidence.

The S5 production adapter uses the public usage-graph import-kind names:
`cjs_require`, `dynamic_static_literal` and `dynamic_computed`. This is a
contract-normalisation correction to the labels, not a change to the source
constructs or their expected locations. The original S4 research labels
remain preserved at tag `s4-05-research-history`.

## Call locations

- A call location is the beginning of the complete call expression.
- All syntactic call expressions are recorded, including nested calls.
- An immediately invoked result is a separate call expression.
- `require(...)` is both a CommonJS import and a call expression.
- `import(...)` is both a dynamic-import observation and a call expression.
- For `object.property(...)`, `receiver` is the object and `callee` is the
  property.
- For a simple `name(...)` call, `receiver` is null and `callee` is the name.
- For a computed member call such as `_[method](...)`, the receiver is known
  but the property is unresolved.
- Calls through the result of another call are retained with a note explaining
  that the callee is an immediately invoked or chained result.

## Functions

- Named function declarations are recorded.
- Named function expressions are recorded.
- An arrow function assigned to a named exported variable is recorded using
  the variable name.
- Anonymous callback functions are not added to the named-functions list.
- The function location is the beginning of its recorded name.

## Unresolved constructs

The following formal corpus cases are unresolved:

1. Computed member call `_[method](src)` in `03-esm-namespace.js`.
2. Computed dynamic import `import(NAME)` in `07-dynamic-import.js`.

They must be reported rather than silently dropped.

An immediately invoked result is represented as a call with a null callee and
a note. It is not classified as an unresolved dependency construct.

The comment below fixture `03-esm-namespace.js` in the protocol mentions A5
and A9. The fixture actually tests namespace binding resolution and computed
member access. Formal dynamic-import Gate A9 is tested by
`07-dynamic-import.js`. This clarification does not change either gate.

## Invalid and empty files

- `11-invalid.js` must set `hasError: true` and must not panic.
- Partial nodes recovered from `11-invalid.js` are not compared during T2.
- `13-empty.js` must set `hasError: false`, return empty result lists and not
  panic. A parser-specific nil root is acceptable if the adapter normalises it
  to this empty result.

## Ordering
Every output list is sorted deterministically by:

1. line;
2. column;
3. when two call expressions begin at the same location, the inner call is
   listed before the outer call;
4. name, imported symbol, callee or unresolved expression as applicable.

## Comparison rule

Expected results describe the source code, not a particular parser's AST.
They must not be changed merely because Candidate A or Candidate B produces a
different result. A genuine error or ambiguity in the ground truth must be
documented and corrected for every candidate before comparison continues.
