// CEP:FILE: tests/tests/dbg_exec.rs
// CEP:WHAT: Executable-region smoke tests: hand-assembled traces execute through the sealed-memory call protocol and return the documented exit id.
// CEP:WHY: The ffi entry and call wrappers are the audited unsafe boundary; these tests prove the minimum contract (entry resolution, state passing, eax exit id) before any compiler-emitted code is trusted.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: Panics through test assertions and expect on mapping or sealing failures.
// CEP:ASSUMES: the SysV call convention with the VmState pointer in rdi and the exit id in eax; W^X region lifecycle works on the host kernel.
// CEP:COST: cold; milliseconds per case.
// CEP:EVIDENCE: cargo test -p ssl-tests --test dbg_exec.

use ssl_ffi::ffi_mmap::CodeMemory;
use ssl_ffi::ffi_exec::{entry_at, call_trace};
use ssl_hot::vm_state::VmState;

// CEP:WHAT: Executes a hand-assembled nop-plus-return trace and verifies the exit id equals the encoded immediate.
// CEP:WHY: The minimum trace function (entry resolution, no state access, eax return) pins the call protocol end to end.
// CEP:STATUS: complete
// CEP:FAILURE: Panics through test assertions and expect on mapping or sealing failures.
// CEP:ASSUMES: the trace ABI passes the state pointer in rdi and returns the exit id in eax.
// CEP:COST: cold; milliseconds.
// CEP:EVIDENCE: cargo test -p ssl-tests --test dbg_exec minimal_trace_executes.
#[test]
fn minimal_trace_executes() {
    let mut code = CodeMemory::new(4096).expect("map");
    {
        let stage = code.stage();
        stage[0] = 0x90;
        stage[1] = 0xB8; stage[2] = 42; stage[3] = 0x00; stage[4] = 0x00; stage[5] = 0x00;
        stage[6] = 0xC3;
    }
    code.mark_used(7);
    code.seal().expect("seal");
    let entry = unsafe { entry_at(&code, 0) }.expect("entry");
    let mut state = Box::new(VmState::new());
    let ptr: *mut VmState = &mut *state;
    let id = unsafe { call_trace(entry, ptr) };
    assert_eq!(id, 42);
}

// CEP:WHAT: Executes a state-touching trace that reads the state pointer from rdi into another register and verifies the exit id.
// CEP:WHY: Traces must read VmState through the rbx convention established by the prologue; this case pins the state-pointer handoff.
// CEP:STATUS: complete
// CEP:FAILURE: Panics through test assertions and expect on mapping or sealing failures.
// CEP:ASSUMES: the state pointer arrives in rdi per the trace ABI.
// CEP:COST: cold; milliseconds.
// CEP:EVIDENCE: cargo test -p ssl-tests --test dbg_exec state_touching_trace_executes.
#[test]
fn state_touching_trace_executes() {
    let mut code = CodeMemory::new(4096).expect("map");
    {
        let stage = code.stage();
        let program: [u8; 15] = [
            0x48, 0x89, 0xFB,
            0x4C, 0x8B, 0xBB, 0x10, 0x10, 0x00, 0x00,
            0xB8, 0x07, 0x00, 0x00, 0x00,
        ];
        stage[..15].copy_from_slice(&program);
        stage[15] = 0xC3;
    }
    code.mark_used(16);
    code.seal().expect("seal");
    let entry = unsafe { entry_at(&code, 0) }.expect("entry");
    let mut state = Box::new(VmState::new());
    let ptr: *mut VmState = &mut *state;
    let id = unsafe { call_trace(entry, ptr) };
    assert_eq!(id, 7);
}
