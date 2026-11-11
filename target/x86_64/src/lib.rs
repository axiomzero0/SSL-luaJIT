// CEP:FILE: target/x86_64/src/lib.rs
// CEP:WHAT: Library root of the x86-64 backend; declares ISA, encoder, isel classes, register allocation, emission, and disassembly.
// CEP:WHY: Target-specific code is isolated in target directories per section 32.5 with versioned, deterministic interfaces.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: none; module declarations only.
// CEP:ASSUMES: none
// CEP:COST: cold; declarations only.
// CEP:EVIDENCE: golden disassembly and differential codegen tests.
// CEP:TARGET: x86-64

pub mod disasm;
pub mod emit;
pub mod isel;
pub mod isel_control;
pub mod isel_memory;
pub mod isel_scalar;
pub mod isel_simd;
pub mod isa_def;
pub mod isa_enc;
pub mod machine;
pub mod regalloc;
