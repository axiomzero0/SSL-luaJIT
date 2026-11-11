// CEP:FILE: ffi/src/lib.rs
// CEP:WHAT: Library root of the FFI boundary crate; declares the mmap manager and the trace entry protocol.
// CEP:WHY: FFI code lives in dedicated directories per section 32.6 with validation, layout documentation, and no business logic.
// CEP:CLASS: FFI
// CEP:STATUS: complete
// CEP:FAILURE: none; module declarations only.
// CEP:ASSUMES: none
// CEP:COST: cold; declarations only.
// CEP:EVIDENCE: ffi tests in tests/.
#![allow(clippy::result_unit_err)]

pub mod ffi_exec;
pub mod ffi_math;
pub mod ffi_mmap;
