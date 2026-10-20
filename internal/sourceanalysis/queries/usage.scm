; ESM imports
(import_statement
  source: (string) @import.source) @import.statement

; ESM re-exports: export { x } from "pkg", export * from "pkg"
(export_statement
  source: (string) @reexport.source) @reexport.statement

; CommonJS require, any argument. Non-literal arguments become
; dynamic_computed imports rather than being dropped.
(call_expression
  function: (identifier) @_require
  arguments: (arguments) @require.arguments
  (#eq? @_require "require")) @require.statement

; Dynamic import
(call_expression
  function: (import)
  arguments: (arguments) @dynamic.arguments) @dynamic.statement

; Direct function calls
(call_expression
  function: (identifier) @call.name) @call.site

; Member-expression calls
(call_expression
  function: (member_expression
    object: (identifier) @call.receiver
    property: (property_identifier) @call.property)) @call.site

; Immediately invoked result of another call
(call_expression
  function: (call_expression) @call.iife_function) @call.iife_site

; Named function declarations
(function_declaration
  name: (identifier) @function.name) @function.decl
