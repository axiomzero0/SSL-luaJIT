// CEP:FILE: ffi/src/ffi_exec.rs
// CEP:WHAT: Typed entry into emitted traces: the trace function pointer protocol and the sealed-memory call wrapper.
// CEP:WHY: design.md Part 10 executes installed traces from the interpreter loop; the call boundary validates the seal state and keeps the unsafe call in one auditable place.
// CEP:CLASS: FFI
// CEP:STATUS: complete
// CEP:FAILURE: Returns FfiError::ProtectFailed when the region is not sealed; the call itself cannot fail after validation.
// CEP:ASSUMES: emitted code follows the SysV call convention with the VmState pointer in rdi and returns the exit id in eax; enforced by the encoder contract in the target crate and layout tests.
// CEP:COST: one indirect call per trace activation; documented as the sanctioned measured indirect call (25.6 exception for emitted dispatch).
// CEP:EVIDENCE: differential JIT execution in tests; ffi lifecycle tests.
// CEP:SECURITY: the code pointer comes from a sealed region only; no untrusted code can enter through this wrapper.
// CEP:UNSAFE: casting sealed executable memory to a function pointer and calling it with a validated state pointer.

use crate::ffi_mmap::{CodeMemory, FfiError};
use ssl_hot::vm_state::VmState;

/// Protocol of one emitted trace: state pointer in rdi, exit id returned in eax.
pub type TraceFn = unsafe extern "C" fn(state: *mut VmState) -> u32;

/// Computes the function pointer for a trace entry at the given byte offset.
///
/// # Safety
/// The region must be sealed and the offset must be inside the sealed bytes.
pub unsafe fn entry_at(code: &CodeMemory, offset: usize) -> Result<TraceFn, FfiError> {
    if offset >= code.used_bytes() {
        return Err(FfiError::ProtectFailed);
    }
    let base = code.base() as *mut u8;
    let entry = base.add(offset);
    Ok(core::mem::transmute::<*mut u8, TraceFn>(entry))
}

/// Calls one sealed trace entry with the VM state; returns the exit id.
///
/// # Safety
/// The entry must come from `entry_at` on a sealed region.
pub unsafe fn call_trace(entry: TraceFn, state: *mut VmState) -> u32 {
    entry(state)
}
