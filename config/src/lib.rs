// CEP:FILE: config/src/lib.rs
// CEP:WHAT: Root module of the ssl-config crate; declares the configuration namespaces.
// CEP:WHY: Central configuration entry point keeps limits, target facts, and cost facts in one crate so no downstream file invents numeric constants.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: none; this module holds declarations only and cannot fail.
// CEP:ASSUMES: none
// CEP:COST: cold; compile-time constants only, no runtime work.
// CEP:EVIDENCE: unit test ssl-tests::unit_config_nameconstants.
pub mod bytecode_consts;
pub mod cost_model;
pub mod limits;
pub mod target_model;
