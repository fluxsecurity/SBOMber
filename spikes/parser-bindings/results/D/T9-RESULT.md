# T9 — Runtime Grammar Loading

## Result

Runtime grammar loading does not remove Candidate A's CGO requirement.

The official README documents using the external `ebitengine/purego` package
to load a grammar shared library and obtain its language pointer.

`NewLanguage` then converts that existing pointer to `*C.TSLanguage`. It does
not replace the parser runtime.

The binding itself embeds the Tree-sitter C runtime through `lib.c`, imports
`C`, and calls functions such as `C.ts_parser_new` and
`C.ts_parser_parse_with_options`.

A binding-only program compiled with `CGO_ENABLED=0` failed because
`tree_sitter.NewParser` was unavailable.

## Decision relevance

Runtime loading moves each grammar into a platform-specific shared library,
but the official parser binding remains CGO-based. Deployment would require
the native parser runtime plus separate grammar libraries.

Candidate D therefore does not improve packaging over Candidate A and remains
eliminated.
