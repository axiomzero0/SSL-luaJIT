// CEP:FILE: cold/src/lib.rs
// CEP:WHAT: Library root of the cold crate; declares the Lua frontend, the assembler airlock, the JIT driver, and run reporting.
// CEP:WHY: Cold orchestration is separated from hot execution per section 7.1 so the fast path never depends on cold code; both frontends land here.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: none; module declarations only.
// CEP:ASSUMES: none
// CEP:COST: cold; declarations only.
// CEP:EVIDENCE: driver differential tests; Lua frontend program tests.

pub mod assembler;
pub mod driver;
pub mod lua_ast;
pub mod lua_codegen;
pub mod lua_frontend;
pub mod lua_lex;
pub mod lua_parse;
