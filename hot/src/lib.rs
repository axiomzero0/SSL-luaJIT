// CEP:FILE: hot/src/lib.rs
// CEP:WHAT: Library root of the SSL-LuaJIT hot core; declares every CEP-0 and HPC-0 module of the tracing JIT.
// CEP:WHY: One no_std root proves the allocation and std bans of section 25.3 at compile time for the whole hot tree.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: none; module declarations only.
// CEP:ASSUMES: none
// CEP:COST: cold; declarations only.
// CEP:EVIDENCE: cargo build -p ssl-hot; self-lint gate over hot/src.
#![no_std]

pub mod bytecode;
pub mod deopt;
pub mod gc;
pub mod heap;
pub mod ir;
pub mod ir_build;
pub mod ir_print;
pub mod ir_verify;
pub mod interp_run;
pub mod interp_step;
pub mod math_ffi;
pub mod mir;
pub mod mir_build;
pub mod pass_licm;
pub mod pass_pdce;
pub mod pass_pea;
pub mod pass_pre;
pub mod profile;
pub mod record;
pub mod runtime;
pub mod vec_loop;
pub mod vec_reduction;
pub mod vec_slp;
pub mod vm_state;
pub mod vm_table;
pub mod vm_value;
