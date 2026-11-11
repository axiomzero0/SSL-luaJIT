// CEP:FILE: tools/cep_lint/src/lib.rs
// CEP:WHAT: Library root of the cep_lint engine; exposes every mechanism for the unit and integration suites.
// CEP:WHY: Section 50.6 requires cargo test suites over the engine; a library target makes each check primitive independently testable.
// CEP:CLASS: CEP-2
// CEP:STATUS: complete
// CEP:FAILURE: none; declarations only.
// CEP:ASSUMES: none
// CEP:COST: cold; declarations only.
// CEP:EVIDENCE: cargo test -p cep-lint.

pub mod blocks;
pub mod checks_code;
pub mod checks_comment;
pub mod checks_doc;
pub mod checks_func;
pub mod checks_topology;
pub mod engine;
pub mod json;
pub mod limits;
pub mod model;
pub mod regex_lite;
pub mod report;
pub mod selftest;
pub mod source;
