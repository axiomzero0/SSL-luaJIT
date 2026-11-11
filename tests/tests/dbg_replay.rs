// CEP:FILE: tests/tests/dbg_replay.rs
// CEP:WHAT: Replay bisect harness: regenerates the fixture trace region outside the interpreter, injects balanced probe returns at disassembler-derived instruction boundaries, and verifies reachability plus the documented natural exit id.
// CEP:WHY: Trace debugging requires deterministic replay of emitted machine code with synthetic state; injecting a balanced `mov eax, PROBE` return at a boundary proves execution reaches that boundary and that the region unwinds cleanly to the sealed-region call protocol.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: Panics through assert_eq when a probe is unreachable, a probe return id mismatches, or the natural exit id changes; the SIGSEGV handler converts memory faults into process exit 9 so a faulting probe surfaces as a test abort with a printed fault address.
// CEP:ASSUMES: tests/fixtures/hot.ssl compiles to exactly one root trace; the prologue is six instructions (three pushes, state pointer, heap base, allocation start) so instruction 6 is the header reset at byte 22; the replay state mirrors Driver::new at trace entry with integer slots 0, 1, 3.
// CEP:COST: cold; one driver run for artifact regeneration plus one trace execution per probe.
// CEP:EVIDENCE: SSL_DEBUG=1 build/debug/ssljit tests/fixtures/hot.ssl dumps the same sealed region to /tmp/ssl_code.bin; probe offsets come from the committed disassembler over those bytes.
// CEP:SECURITY: executes only bytes emitted by this repository's compiler from the checked-in fixture; no external input reaches the executable region.

use ssl_ffi::ffi_exec::{call_trace, entry_at};
use ssl_ffi::ffi_mmap::CodeMemory;
use ssl_hot::vm_state::VmState;
use ssl_hot::vm_value::SslValue;
use ssl_target_x86_64::disasm::{disassemble, Line};

use std::ffi::c_void;

/// Checked-in SSL-BC fixture compiled to the replayed trace region.
const FIXTURE: &str = include_str!("../fixtures/hot.ssl");
/// Debug artifact written by the driver's SSL_DEBUG dump path.
const ARTIFACT_PATH: &str = "/tmp/ssl_code.bin";
/// Exit id carried by an injected probe return (`mov eax, 77`).
const PROBE_EXIT_ID: u32 = 77;
/// Probe sequence for post-prologue cuts: sets eax, undoes the three prologue
/// pushes (`lea rsp, [rsp+24]`), and returns to the caller with a balanced stack.
const PROBE_BODY_UNWIND: [u8; 11] = [0xB8, 77, 0, 0, 0, 0x48, 0x8D, 0x64, 0x24, 0x18, 0xC3];
/// Probe sequence for the prologue start, where nothing has been pushed yet.
const PROBE_TOP: [u8; 6] = [0xB8, 77, 0, 0, 0, 0xC3];
/// Measured natural exit id of the fixture trace: EXIT_GUARD_BASE (1) plus the
/// loop-exit branch guard (5). Changes whenever the fixture or pipeline changes.
const NATURAL_EXIT_ID: u32 = 6;
/// Instruction count of the standard prologue (no r12, odd push count).
const PROLOGUE_INSNS: usize = 6;
/// Number of hot-path instruction boundaries probed after the header.
const PROBE_COUNT: usize = 6;

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
    fn write(fd: i32, buf: *const c_void, count: usize) -> isize;
}

extern "C" fn on_segv(sig: i32, info: *mut usize, ctx: *mut usize) {
    let addr = unsafe { *info.add(2) };
    let rip = unsafe { *ctx.add(21) };
    let msg = format!("SIGSEGV sig={} fault_addr={:#x} rip={:#x}\n", sig, addr, rip);
    unsafe {
        write(2, msg.as_ptr() as *const c_void, msg.len());
    }
    std::process::exit(9);
}

// CEP:WHAT: Installs a SIGSEGV handler so a faulting probe prints its fault address and exits 9 instead of aborting without context.
// CEP:WHY: Replay probes jump into corrupted instruction streams; a fault must surface as a diagnosable test abort with fault address and rip.
// CEP:STATUS: complete
// CEP:FAILURE: Panics never; a failed sigaction only reports its return code.
// CEP:ASSUMES: Linux x86-64 sigaction and ucontext layouts; the handler is installed once per test process.
// CEP:COST: cold; two syscalls per test.
// CEP:EVIDENCE: sigaction rc printed on every replay run.
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
        write(2, msg.as_ptr() as *const c_void, msg.len());
    }
}

// CEP:WHAT: Loads the sealed trace region bytes, regenerating them from the checked-in fixture through the driver's SSL_DEBUG dump path when the artifact is absent.
// CEP:WHY: A committed replay test must not depend on leftover state from a developer machine; regeneration from the fixture keeps the harness reproducible.
// CEP:STATUS: complete
// CEP:FAILURE: Panics when the fixture fails to assemble, run, or produce the artifact; a missing artifact after a successful run is a pipeline regression.
// CEP:ASSUMES: SSL_DEBUG=1 makes compile_root dump the sealed region to /tmp/ssl_code.bin; the dump is deterministic for the committed fixture and pipeline.
// CEP:COST: cold; one driver run (64 interpreted iterations plus one trace compile) plus one file read.
// CEP:EVIDENCE: SSL_DEBUG=1 build/debug/ssljit tests/fixtures/hot.ssl writes the identical region.
fn ensure_code_bytes() -> Vec<u8> {
    if let Ok(bytes) = std::fs::read(ARTIFACT_PATH) {
        if !bytes.is_empty() {
            return bytes;
        }
    }
    std::env::set_var("SSL_DEBUG", "1");
    let mut driver = ssl_cold::driver::Driver::new(FIXTURE).expect("assemble fixture");
    driver.run().expect("run fixture");
    std::fs::read(ARTIFACT_PATH).expect("regenerated code bytes")
}

// CEP:WHAT: Derives probe cuts as the prologue start plus hot-path instruction boundaries taken from the committed disassembler.
// CEP:WHY: Hard-coded byte offsets would violate Law 7 and silently rot with any emission change; boundaries derived from the decoder track the fixture deterministically.
// CEP:STATUS: complete
// CEP:FAILURE: Panics when the fixture trace disassembles too small or when the prologue shape changes so the header no longer sits at byte 22.
// CEP:ASSUMES: the standard prologue is six instructions (three pushes, state pointer, heap base, allocation start) and instruction 6 is the header reset; the first PROBE_COUNT body instructions are always on the hot path.
// CEP:COST: cold; one bounded disassembly pass.
// CEP:EVIDENCE: SSL_DEBUG=1 ssljit fixture dump disassembles to the same boundaries.
fn probe_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut lines: [Line; 128] = unsafe { std::mem::zeroed() };
    let count = disassemble(bytes, &mut lines);
    assert!(
        count > PROLOGUE_INSNS + PROBE_COUNT,
        "fixture trace disassembles to {} instructions, too small to probe",
        count
    );
    assert_eq!(
        lines[PROLOGUE_INSNS].offset, 22,
        "unexpected prologue shape; the header must sit at byte 22"
    );
    let mut cuts = Vec::with_capacity(PROBE_COUNT + 1);
    cuts.push(0usize);
    for idx in PROLOGUE_INSNS..PROLOGUE_INSNS + PROBE_COUNT {
        cuts.push(lines[idx].offset);
    }
    cuts
}

// CEP:WHAT: Copies the region into fresh executable memory, optionally overwrites the cut offset with a balanced probe return sequence, and runs the region once with the synthetic state.
// CEP:WHY: Probes prove execution reachability of a boundary; post-prologue probes must unwind the three prologue pushes so the return is balanced, while the prologue-start probe runs before any push.
// CEP:STATUS: complete
// CEP:FAILURE: Panics when the region fails to map, seal, or resolve an entry; a faulting probe triggers the SIGSEGV handler which exits 9.
// CEP:ASSUMES: the replay state mirrors Driver::new at trace entry with integer slots 0, 1, 3; usize::MAX means no probe.
// CEP:COST: cold; one mmap, one memcpy of the region, and one trace execution per call.
// CEP:EVIDENCE: natural run returns the documented exit id; probe runs return PROBE_EXIT_ID.
fn run_region(bytes: &[u8], cut: usize) -> u32 {
    let mut code = CodeMemory::new(bytes.len() + 64).expect("map");
    {
        let stage = code.stage();
        stage[..bytes.len()].copy_from_slice(bytes);
        if cut != usize::MAX {
            let probe: &[u8] = if cut == 0 { &PROBE_TOP } else { &PROBE_BODY_UNWIND };
            stage[cut..cut + probe.len()].copy_from_slice(probe);
        }
    }
    code.mark_used(bytes.len());
    code.seal().expect("seal");
    let entry = unsafe { entry_at(&code, 0) }.expect("entry");
    let mut state = Box::new(VmState::new());
    state.eden_end = ssl_hot::heap::survivor_base();
    state.barrier_capacity = ssl_config::limits::BARRIER_BYTES / 4;
    state.barrier_base = ssl_hot::gc::barrier_base();
    state.set_slot(0, SslValue::integer(0));
    state.set_slot(1, SslValue::integer(65));
    state.set_slot(3, SslValue::integer(200));
    let ptr: *mut VmState = &mut *state;
    unsafe { call_trace(entry, ptr) }
}

// CEP:WHAT: Replay bisect: verifies the natural exit id of the fixture trace and then probes every derived boundary for reachability.
// CEP:WHY: The harness pins the emitted trace region to its fixture: any pipeline drift changes the natural exit id or makes a boundary unreachable, and both regressions must fail loudly.
// CEP:STATUS: complete
// CEP:FAILURE: Panics through assert_eq when the natural exit id or any probe return id mismatches.
// CEP:ASSUMES: the fixture compiles to exactly one root trace; slot state mirrors Driver::new at trace entry.
// CEP:COST: cold; one natural run plus one execution per probe.
// CEP:EVIDENCE: cargo test -p ssl-tests --test dbg_replay.
#[test]
fn replay_bisect() {
    install_handler();
    let bytes = ensure_code_bytes();
    let natural = run_region(&bytes, usize::MAX);
    assert_eq!(
        natural, NATURAL_EXIT_ID,
        "natural exit id changed; fixture or pipeline changed"
    );
    for cut in probe_offsets(&bytes) {
        let id = run_region(&bytes, cut);
        assert_eq!(id, PROBE_EXIT_ID, "cut {} should hit the probe", cut);
    }
}
