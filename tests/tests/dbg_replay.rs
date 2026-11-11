use ssl_ffi::ffi_mmap::CodeMemory;
use ssl_ffi::ffi_exec::{entry_at, call_trace};
use ssl_hot::vm_state::VmState;
use ssl_config::limits as L;

extern "C" {
    fn sigaction(signum: i32, act: *const SigAction, oldact: *mut SigAction) -> i32;
}

#[repr(C)]
struct SigAction {
    handler: usize,
    mask: [u64; 16],
    flags: i32,
    restorer: usize,
}

extern "C" {
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
}

extern "C" fn on_segv(sig: i32, info: *mut usize, ctx: *mut usize) {
    let addr = unsafe { *info.add(2) };
    let rip = unsafe { *ctx.add(21) };
    let msg = format!("SIGSEGV sig={} fault_addr={:#x} rip={:#x}\n", sig, addr, rip);
    unsafe {
        write(2, msg.as_ptr(), msg.len());
    }
    std::process::exit(9);
}

fn install_handler() {
    let act = SigAction {
        handler: on_segv as *const () as usize,
        mask: [0; 16],
        flags: 4,
        restorer: 0,
    };
    let rc = unsafe { sigaction(11, &act, std::ptr::null_mut()) };
    let msg = format!("sigaction rc={}\n", rc);
    unsafe {
        write(2, msg.as_ptr(), msg.len());
    }
}

fn run_truncated(cut: usize) -> u32 {
    let bytes = std::fs::read("/tmp/ssl_code.bin").expect("code bytes");
    let mut code = CodeMemory::new(bytes.len() + 64).expect("map");
    {
        let stage = code.stage();
        stage[..bytes.len()].copy_from_slice(&bytes);
        if cut > 0 {
            stage[cut] = 0xB8;
            stage[cut + 1] = 77;
            stage[cut + 2] = 0x00;
            stage[cut + 3] = 0x00;
            stage[cut + 4] = 0x00;
            stage[cut + 5] = 0xC3;
        }
    }
    code.mark_used(bytes.len());
    code.seal().expect("seal");
    {
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
        for line in maps.lines() {
            if line.contains("r-xp") || line.contains("--xp") {
                let msg = format!("MAPS {}\n", line);
                unsafe { write(2, msg.as_ptr(), msg.len()); }
            }
        }
        let base_ptr = code.base_ptr();
        let msg = format!("CODEBASE {:p}\n", base_ptr);
        unsafe { write(2, msg.as_ptr(), msg.len()); }
    }
    let entry = unsafe { entry_at(&code, 22) }.expect("entry");
    let mut state = Box::new(VmState::new());
    state.eden_end = ssl_hot::heap::survivor_base();
    state.barrier_capacity = L::BARRIER_BYTES / 4;
    state.barrier_base = ssl_hot::gc::barrier_base();
    state.set_slot(0, ssl_hot::vm_value::SslValue::integer(0));
    state.set_slot(1, ssl_hot::vm_value::SslValue::integer(65));
    state.set_slot(3, ssl_hot::vm_value::SslValue::integer(200));
    let ptr: *mut VmState = &mut *state;
    let msg = format!("size={} ptr={:p} heapbase_field={:p}\n",
        std::mem::size_of::<VmState>(), ptr,
        unsafe { *(ptr as *const u8).add(0x1010) as *const u8 });
    unsafe { write(2, msg.as_ptr(), msg.len()); }
    unsafe { call_trace(entry, ptr) }
}

#[test]
fn replay_bisect() {
    install_handler();
    let bytes = std::fs::read("/tmp/ssl_code.bin").expect("code bytes");
    for cut in [27usize, 48, 106, 133, 178, 184, 0] {
        let id = run_truncated(cut);
        let msg = format!("CUT {} -> exit {}\n", cut, id);
        unsafe {
            write(2, msg.as_ptr(), msg.len());
        }
        assert_eq!(id, 77, "cut {} should hit the probe", cut);
    }
}
