use ssl_ffi::ffi_mmap::CodeMemory;
use ssl_ffi::ffi_exec::{entry_at, call_trace};
use ssl_hot::vm_state::VmState;

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
