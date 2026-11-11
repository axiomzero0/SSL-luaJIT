// CEP:FILE: cold/src/driver.rs
// CEP:WHAT: The JIT driver: owns the VM state and arena, orchestrates the interpreter loop, trace recording, compilation, installation, execution, guard exits, side-trace patching, and garbage collection.
// CEP:WHY: design.md Part 10 defines the end-to-end flow; the driver is the cold orchestrator that hands validated state to hot code and machine code and owns every heap allocation of the run.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: Returns DriverError from the airlock, the run engine, compilation, or the code memory stage; never panics.
// CEP:ASSUMES: one driver per program run; the machine code protocol is the SysV convention implemented by the target crate.
// CEP:COST: cold orchestration around hot execution; compilation bounded by per-trace budgets.
// CEP:EVIDENCE: differential tests; determinism tests; budget tests.
// CEP:SECURITY: the arena, code memory, and scratch are allocated here once and never reallocated during the run.

use ssl_config::limits as L;
use ssl_config::target_model::jit_state_layout as layout;
use ssl_hot::bytecode as bc;
use ssl_hot::bytecode::Program;
use ssl_hot::deopt;
use ssl_hot::gc;
use ssl_hot::interp_run::{run_until_event, RunOutcome};
use ssl_hot::ir;
use ssl_hot::ir_build;
use ssl_hot::ir_verify::{verify_full, IssueSink, VerifyIssue as VerifyIssueSentry};

/// Verifier sink capacity per compiled trace.
const VERIFIER_SINK_CAP: usize = 64;
use ssl_hot::mir_build::{build_mir, ReductionExit};
use ssl_hot::pass_licm::run_licm;
use ssl_hot::pass_pdce::run_pdce;
use ssl_hot::pass_pea::run_pea;
use ssl_hot::pass_pre::entry_guard_duplicated;
use ssl_hot::profile::MAX_LOOP_HEADERS;
use ssl_hot::record::record_iteration;
use ssl_hot::runtime::Runtime;
use ssl_hot::vec_loop::run_loop_vectorization;
use ssl_hot::vec_reduction::run_reduction;
use ssl_hot::vec_slp::run_slp;
use ssl_hot::vm_state::VmState;
use ssl_target_x86_64::emit::emit_trace;
use ssl_target_x86_64::isel::select_instructions;
use ssl_target_x86_64::machine::MachineFunction;
use ssl_target_x86_64::regalloc::allocate;
use ssl_ffi::ffi_exec::{call_trace, entry_at};
use ssl_ffi::ffi_mmap::{CodeMemory, FfiError};

/// Driver failure enumeration.
#[derive(Debug)]
pub enum DriverError {
    /// Assembler failure.
    Assemble(String),
    /// Runtime failure from the interpreter.
    Run(String),
    /// Compilation failure.
    Compile(String),
    /// Code memory failure.
    Memory(String),
    /// Bytecode validator rejection (should be unreachable after the airlock).
    Validate(String),
}

/// One installed root trace with its compiled body and IR for deopt and PRE.
struct RootTrace {
    header_pc: u32,
    entry_offset: usize,
    stub_rets: [u16; L::EXIT_GUARD_LIMIT as usize],
    code: CodeMemory,
    guard_count: u16,
    exit_counts: Vec<u32>,
    patched: Vec<bool>,
    body: Box<ssl_hot::mir::MirBody>,
    trace_ir: Box<ir::IrTrace>,
    slot_nodes: Box<[u16; L::MAX_SLOTS as usize]>,
}

/// Full JIT run container.
pub struct Driver {
    program: Assembled,
    state: Box<VmState>,
    heap: Vec<u8>,
    rt: Runtime,
    scratch_worklist: Vec<u32>,
    scratch_remap: Vec<(u32, u32)>,
    roots: Vec<RootTrace>,
    steps: u64,
    traces_compiled: u32,
    side_traces: u32,
    guards_merged: u32,
}

/// Internally assembled program view.
struct Assembled {
    words: Vec<u32>,
    consts: Vec<bc::Const>,
    slot_count: u32,
}

impl Driver {
    /// Creates a driver from assembled text; interns strings and initializes the arena.
    pub fn new(text: &str) -> Result<Driver, DriverError> {
        if std::env::var("SSL_DEBUG").is_ok() {
            if let Ok(assembled) = crate::assembler::assemble(text) {
                eprintln!("DBG words={:?}", assembled.words);
            }
        }
        let assembled = ssl_cold_intern_stage(text)?;
        let heap_len = gc::arena_bytes() as usize;
        let heap = vec![0u8; heap_len];
        let mut state = Box::new(VmState::new());
        state.bump_ptr = ssl_config::target_model::heap_layout::CELL_BYTES;
        state.eden_end = ssl_hot::heap::survivor_base();
        state.barrier_capacity = L::BARRIER_BYTES / 4;
        state.barrier_base = ssl_hot::gc::barrier_base();
        Ok(Driver {
            program: assembled,
            state,
            heap,
            rt: Runtime::new(),
            scratch_worklist: vec![0u32; L::MAX_TABLES as usize],
            scratch_remap: vec![(0, 0); L::MAX_TABLES as usize],
            roots: Vec::new(),
            steps: 0,
            traces_compiled: 0,
            side_traces: 0,
            guards_merged: 0,
        })
    }

    /// Runs the program to completion with the JIT enabled.
    pub fn run(&mut self) -> Result<RunReport, DriverError> {
        loop {
            let outcome = {
                let view = Program {
                    words: &self.program.words,
                    consts: &self.program.consts,
                    slot_count: self.program.slot_count,
                };
                let mut scratch = gc::GcScratch {
                    worklist: &mut self.scratch_worklist,
                    remap: &mut self.scratch_remap,
                };
                run_until_event(&mut self.state, &view, &mut self.heap, &mut self.rt, &mut scratch)
                    .map_err(|e| DriverError::Run(format!("{:?}", e)))?
            };

            if std::env::var("SSL_DEBUG").is_ok() {
                eprintln!("DBG outcome={:?} pc={} slot1={:?}", outcome, self.state.pc,
                    self.state.slot(1).map(|v| v.as_int()));
            }
            match outcome {
                RunOutcome::Returned => break,
                RunOutcome::BudgetSpent => break,
                RunOutcome::HotLoop(header) => {
                    self.compile_root(header)?;
                }
                RunOutcome::AtInstalledTrace(header) => {
                    self.enter_trace(header)?;
                }
            }
        }
        Ok(self.report())
    }

    fn view(&self) -> Program {
        Program {
            words: &self.program.words,
            consts: &self.program.consts,
            slot_count: self.program.slot_count,
        }
    }

    fn enter_trace(&mut self, header: u32) -> Result<(), DriverError> {
        let root_index = match self.roots.iter().position(|root| root.header_pc == header) {
            Some(index) => index,
            None => return Ok(()),
        };
        loop {
            if std::env::var("SSL_NOEXEC").is_ok() {
                return Ok(());
            }
            let entry = self.roots[root_index].entry_offset;
            let entry_fn = {
                let code = &self.roots[root_index].code;
                unsafe { entry_at(code, entry) }
            }
            .map_err(|e| DriverError::Memory(format!("{:?}", e)))?;
            let state_ptr: *mut VmState = &mut *self.state;
            if std::env::var("SSL_DEBUG").is_ok() {
                eprintln!("DBG entering trace entry={} state={:?}", entry, state_ptr as usize);
            }
            let exit_id = unsafe { call_trace(entry_fn, state_ptr) };
            if std::env::var("SSL_DEBUG").is_ok() {
                eprintln!("DBG exit_id={} pc={} slot0={:?} slot1={:?}", exit_id, self.state.pc,
                    self.state.slot(0).map(|v| v.as_int()), self.state.slot(1).map(|v| v.as_int()));
            }
            if exit_id == L::EXIT_ALLOC {
                let mut scratch = gc::GcScratch {
                    worklist: &mut self.scratch_worklist,
                    remap: &mut self.scratch_remap,
                };
                gc::minor_collect(&mut self.state, &mut self.heap, &mut self.rt, &mut scratch)
                    .map_err(|e| DriverError::Run(format!("{:?}", e)))?;
                continue;
            }
            if exit_id >= L::EXIT_GUARD_BASE && exit_id < L::EXIT_GUARD_BASE + L::EXIT_GUARD_LIMIT {
                let guard = exit_id - L::EXIT_GUARD_BASE;
                let body = &self.roots[root_index].body;
                let resume = deopt::prepare_resume(&mut self.state, body, guard as u16);
                let slot = guard as usize;
                if let Some(pc) = resume {
                    let root = &mut self.roots[root_index];
                    let mut hot = false;
                    while root.exit_counts.len() <= slot {
                        root.exit_counts.push(0);
                    }
                    let counter = root.exit_counts.get_mut(slot);
                    if let Some(counter) = counter {
                        *counter = counter.saturating_add(1);
                        hot = *counter >= L::SIDE_HOT_THRESHOLD && !root.patched.get(slot).copied().unwrap_or(true);
                    }
                    let _ = hot;
                    if hot {
                        let resume_pc = pc;
                        self.compile_side(root_index, guard, resume_pc)?;
                    }
                }
                return Ok(());
            }
            return Ok(());
        }
    }

    fn compile_root(&mut self, header: u32) -> Result<(), DriverError> {
        let Driver {
            state,
            program,
            heap,
            rt,
            roots,
            traces_compiled,
            ..
        } = self;
        if roots.iter().any(|root| root.header_pc == header) {
            return Ok(());
        }
        if rt.traces.count >= L::MAX_TRACES {
            return Ok(());
        }
        let view = Program {
            words: &program.words,
            consts: &program.consts,
            slot_count: program.slot_count,
        };
        let buffer = match record_iteration(state, &view, heap, rt, header) {
            Ok(buffer) => {
                if std::env::var("SSL_DEBUG").is_ok() {
                    eprintln!("DBG recorded {} ops header={}", buffer.count, header);
                }
                buffer
            }
            Err(err) => {
                if std::env::var("SSL_DEBUG").is_ok() {
                    eprintln!("DBG record err={:?}", err);
                }
                return Ok(());
            }
        };
        let built = match ir_build::build_trace(&buffer) {
            Ok(built) => built,
            Err(err) => {
                if std::env::var("SSL_DEBUG").is_ok() {
                    eprintln!("DBG build err={:?}", err);
                }
                return Ok(());
            }
        };
        let mut trace = built.trace;
        let reductions = match optimize_trace(&mut trace, buffer.vec_hint) {
            Ok(reductions) => reductions,
            Err(_) => return Ok(()),
        };
        if std::env::var("SSL_DEBUG").is_ok() {
            let mut buf = [0u8; 8192];
            let len = ssl_hot::ir_print::render(&trace, &mut buf);
            eprintln!("DBG IR:\n{}", String::from_utf8_lossy(&buf[..len]));
        }
        let mut issues = [VerifyIssueSentry { node: 0, code: 0 }; VERIFIER_SINK_CAP];
        let issue_count = {
            let mut sink = IssueSink::new(&mut issues);
            verify_full(&trace, &mut sink);
            sink.len
        };
        if issue_count > 0 {
            if std::env::var("SSL_DEBUG").is_ok() {
                eprintln!("DBG verify issues={:?}", &issues[..issue_count.min(4)]);
            }
            return Ok(());
        }
        let mut body = match build_mir(&trace, &built.slot_nodes, &reductions) {
            Ok(body) => body,
            Err(err) => {
                if std::env::var("SSL_DEBUG").is_ok() {
                    eprintln!("DBG mir err={:?}", err);
                }
                return Ok(());
            }
        };
        if std::env::var("SSL_DEBUG").is_ok() {
            eprintln!("DBG mir insns={} vregs={} snaps={}", body.count, body.vreg_count, body.snapshot_count);
            for si in 0..body.snapshot_count as usize {
                let snap = &body.snapshots[si];
                let entries: Vec<String> = body.snap_entries[snap.start as usize..(snap.start as usize + snap.len as usize)]
                    .iter()
                    .map(|e| format!("s{}=v{} k{}", e.slot, e.vreg, e.kind))
                    .collect();
                eprintln!("DBG snap guard={} pc={} [{}]", snap.guard, snap.resume_pc, entries.join(" "));
            }
            for i in 0..body.count as usize {
                eprintln!("DBG mir[{}] op={} dst={} s0={} s1={} imm={} aux={}", i, body.insns[i].op, body.insns[i].dst, body.insns[i].src0, body.insns[i].src1, body.insns[i].imm, body.insns[i].aux);
            }
        }
        let mut machine = MachineFunction::new(&body);
        if let Err(err) = select_instructions(&body, &mut machine) {
            debug_fail(format!("isel {:?}", err));
            return Ok(());
        }
        let allocation = match allocate(&machine, &body) {
            Ok(allocation) => allocation,
            Err(err) => {
                debug_fail(format!("regalloc {:?}", err));
                return Ok(());
            }
        };
        let emitted = match emit_trace(&machine, &allocation, &body, &program.consts) {
            Ok(emitted) => emitted,
            Err(err) => {
                if std::env::var("SSL_DEBUG").is_ok() {
                    eprintln!("DBG emit err={:?}", err);
                }
                return Ok(());
            }
        };
        if std::env::var("SSL_DEBUG").is_ok() {
            dump_code(&emitted.code, &emitted.labels, emitted.entry);
        }
        let guard_count = body.snapshot_count;
        if std::env::var("SSL_DEBUG").is_ok() {
            eprintln!("DBG root installed header={} guards={}", header, guard_count);
        }
        rt.traces.install(header);
        *traces_compiled += 1;
        roots.push(RootTrace {
            header_pc: header,
            entry_offset: emitted.entry,
            stub_rets: emitted.stub_rets,
            code: emitted.code,
            guard_count,
            exit_counts: vec![0; guard_count as usize],
            patched: vec![false; guard_count as usize],
            body: Box::new(body),
            trace_ir: Box::new(trace),
            slot_nodes: Box::new(built.slot_nodes),
        });
        Ok(())
    }


    fn compile_side(&mut self, root_index: usize, guard: u32, resume_pc: u32) -> Result<(), DriverError> {
        let Driver {
            state,
            program,
            heap,
            rt,
            roots,
            side_traces,
            guards_merged,
            ..
        } = self;
        let view = Program {
            words: &program.words,
            consts: &program.consts,
            slot_count: program.slot_count,
        };
        if *side_traces >= L::MAX_SIDE_TRACES {
            return Ok(());
        }
        let header = roots[root_index].header_pc;
        let buffer = match record_side(state, &view, heap, rt, resume_pc, header) {
            Ok(buffer) => buffer,
            Err(_) => return Ok(()),
        };
        let built = match ir_build::build_trace(&buffer) {
            Ok(built) => built,
            Err(err) => {
                if std::env::var("SSL_DEBUG").is_ok() {
                    eprintln!("DBG build err={:?}", err);
                }
                return Ok(());
            }
        };
        let mut trace = built.trace;
        let reductions = match optimize_trace(&mut trace, false) {
            Ok(reductions) => reductions,
            Err(_) => return Ok(()),
        };
        let root_ir = &roots[root_index].trace_ir;
        if entry_guard_duplicated(&trace, root_ir) {
            *guards_merged += 1;
        }
        if std::env::var("SSL_DEBUG").is_ok() {
            let mut buf = [0u8; 8192];
            let len = ssl_hot::ir_print::render(&trace, &mut buf);
            eprintln!("DBG IR:\n{}", String::from_utf8_lossy(&buf[..len]));
        }
        let mut issues = [VerifyIssueSentry { node: 0, code: 0 }; VERIFIER_SINK_CAP];
        let issue_count = {
            let mut sink = IssueSink::new(&mut issues);
            verify_full(&trace, &mut sink);
            sink.len
        };
        if issue_count > 0 {
            if std::env::var("SSL_DEBUG").is_ok() {
                eprintln!("DBG verify issues={:?}", &issues[..issue_count.min(4)]);
            }
            return Ok(());
        }
        let mut body = match build_mir(&trace, &built.slot_nodes, &reductions) {
            Ok(body) => body,
            Err(err) => {
                if std::env::var("SSL_DEBUG").is_ok() {
                    eprintln!("DBG mir err={:?}", err);
                }
                return Ok(());
            }
        };
        if std::env::var("SSL_DEBUG").is_ok() {
            eprintln!("DBG mir insns={} vregs={} snaps={}", body.count, body.vreg_count, body.snapshot_count);
            for si in 0..body.snapshot_count as usize {
                let snap = &body.snapshots[si];
                let entries: Vec<String> = body.snap_entries[snap.start as usize..(snap.start as usize + snap.len as usize)]
                    .iter()
                    .map(|e| format!("s{}=v{} k{}", e.slot, e.vreg, e.kind))
                    .collect();
                eprintln!("DBG snap guard={} pc={} [{}]", snap.guard, snap.resume_pc, entries.join(" "));
            }
            for i in 0..body.count as usize {
                eprintln!("DBG mir[{}] op={} dst={} s0={} s1={} imm={} aux={}", i, body.insns[i].op, body.insns[i].dst, body.insns[i].src0, body.insns[i].src1, body.insns[i].imm, body.insns[i].aux);
            }
        }
        let mut machine = MachineFunction::new(&body);
        if let Err(err) = select_instructions(&body, &mut machine) {
            debug_fail(format!("isel {:?}", err));
            return Ok(());
        }
        let allocation = match allocate(&machine, &body) {
            Ok(allocation) => allocation,
            Err(err) => {
                debug_fail(format!("regalloc {:?}", err));
                return Ok(());
            }
        };
        let emitted = match emit_trace(&machine, &allocation, &body, &program.consts) {
            Ok(emitted) => emitted,
            Err(err) => {
                if std::env::var("SSL_DEBUG").is_ok() {
                    eprintln!("DBG emit err={:?}", err);
                }
                return Ok(());
            }
        };
        let root = &mut roots[root_index];
        let ret_offset = root.stub_rets[guard as usize] as usize;
        let target = emitted.code.address_at(emitted.entry);
        let patch = jump_thunk(target);
        if root.code.retarget(ret_offset, &patch).is_ok() {
            root.patched[guard as usize] = true;
            *side_traces += 1;
        }
        Ok(())
    }

    fn report(&self) -> RunReport {
        RunReport {
            steps: self.steps,
            traces_compiled: self.traces_compiled,
            side_traces: self.side_traces,
            guards_merged: self.guards_merged,
            minor_gcs: self.rt.gc.minor_count,
            major_gcs: self.rt.gc.major_count,
            out: self.rt.out[..self.rt.out_len as usize].to_vec(),
        }
    }
}

/// Records a side trace from a guard resume point until it rejoins the root header.
fn record_side(
    state: &mut VmState,
    prog: &Program,
    heap: &mut [u8],
    rt: &mut Runtime,
    resume_pc: u32,
    header: u32,
) -> Result<ssl_hot::record::TraceBuffer, ssl_hot::record::RecordError> {
    let mut buffer = ssl_hot::record::TraceBuffer::new(resume_pc, false);
    state.pc = resume_pc;
    let mut steps = 0u32;
    loop {
        if steps >= L::MAX_TRACE_OPS {
            return Err(ssl_hot::record::RecordError::TraceTooLong);
        }
        steps += 1;
        let record = ssl_hot::interp_step::step(
            state,
            prog,
            heap,
            &mut rt.survivor_bump,
            &mut rt.out_len,
            ssl_hot::runtime::OUT_CAP,
        )
        .map_err(ssl_hot::record::RecordError::Execution)?;
        let mut op = ssl_hot::record::TraceOp {
            bc_op: record.op,
            a: record.dst,
            b: record.lhs,
            c: record.rhs,
            imm: record.imm,
            lhs_ty: obs(record.lhs_val),
            rhs_ty: obs(record.rhs_val),
            res_ty: obs(record.result),
            pc: record.pc,
            taken: false,
            is_backedge: false,
        };
        if bc::uses_condition_slot(record.op) && state.pc != record.pc + 2 {
            op.taken = true;
        }
        if state.pc == header {
            op.is_backedge = true;
            push_op(&mut buffer, op)?;
            buffer.exit_pc = header;
            return Ok(buffer);
        }
        push_op(&mut buffer, op)?;
    }
}

fn push_op(
    buffer: &mut ssl_hot::record::TraceBuffer,
    op: ssl_hot::record::TraceOp,
) -> Result<(), ssl_hot::record::RecordError> {
    if buffer.count >= L::MAX_TRACE_OPS {
        return Err(ssl_hot::record::RecordError::TraceTooLong);
    }
    buffer.ops[buffer.count as usize] = op;
    buffer.count += 1;
    Ok(())
}

fn obs(value: ssl_hot::vm_value::SslValue) -> u8 {
    use ssl_hot::record::*;
    use ssl_hot::vm_value::*;
    if value.is_int() {
        OBS_INT
    } else if value.is_num() {
        OBS_NUM
    } else if value.tag == TAG_BOOL {
        OBS_BOOL
    } else if value.is_table() {
        OBS_TBL
    } else {
        OBS_NONE
    }
}

/// Applies the optimization pipeline in pipeline order per docs/compiler/pass_pipeline.md.
fn optimize_trace(
    trace: &mut ir::IrTrace,
    vec_hint: bool,
) -> Result<Vec<ReductionExit>, DriverError> {
    if std::env::var("SSL_DEBUG").is_ok() {
        eprintln!("DBG opt in count={}", trace.count);
    }
    run_pea(trace);
    if std::env::var("SSL_DEBUG").is_ok() {
        eprintln!("DBG opt after-pea count={}", trace.count);
    }
    run_licm(trace, 0);
    let mut reductions = Vec::new();
    if vec_hint {
        if let Some(reduction) = run_reduction(trace, 0) {
            reductions.push(ReductionExit {
                slot: reduction.slot,
                hadd: reduction.hadd,
            });
        } else if run_loop_vectorization(trace, 0) {
        } else {
            run_slp(trace, 0);
        }
    }
    run_pdce(trace);
    Ok(reductions)
}

/// Run summary returned to the CLI and tests.
pub struct RunReport {
    /// Interpreted step count.
    pub steps: u64,
    /// Root traces compiled.
    pub traces_compiled: u32,
    /// Side traces compiled.
    pub side_traces: u32,
    /// Guards merged by PRE.
    pub guards_merged: u32,
    /// Minor collections.
    pub minor_gcs: u32,
    /// Major collections.
    pub major_gcs: u32,
    /// Printed output values in order.
    pub out: Vec<ssl_hot::vm_value::SslValue>,
}

/// Interning stage separated to keep borrow chains simple.
fn ssl_cold_intern_stage(text: &str) -> Result<Assembled, DriverError> {
    let assembled = crate::assembler::assemble(text)
        .map_err(|e| DriverError::Assemble(format!("{:?}", e)))?;
    let mut consts = assembled.consts.clone();
    for entry in consts.iter_mut() {
        if let bc::Const::Str(index) = entry {
            let text = assembled
                .strings
                .get(*index as usize)
                .cloned()
                .unwrap_or_default();
            *entry = bc::Const::Str(hash_string(&text));
        }
    }
    Ok(Assembled {
        words: assembled.words,
        consts,
        slot_count: assembled.slot_count,
    })
}

/// Dumps the sealed code region through the deterministic disassembler for evidence.
fn dump_code(code: &CodeMemory, labels: &ssl_target_x86_64::emit::LabelTable, entry: usize) {
    let bytes = code.bytes_view();
    eprintln!("DBG code bytes={} entry={}", bytes.len(), entry);
    for idx in 0..labels.debug_count() {
        let (label, offset) = labels.debug_entries()[idx];
        eprintln!("DBG label {} -> {}", label, offset);
    }
    let mut lines: [ssl_target_x86_64::disasm::Line; 64] = unsafe { std::mem::zeroed() };
    let count = ssl_target_x86_64::disasm::disassemble(&bytes[entry..], &mut lines);
    eprintln!("DBG code bytes={} entry={}", bytes.len(), entry);
    for idx in 0..labels.debug_count() {
        let (label, offset) = labels.debug_entries()[idx];
        eprintln!("DBG label {} -> {}", label, offset);
    }
    for idx in 0..count {
        let text = std::str::from_utf8(&lines[idx].text[..lines[idx].len]).unwrap_or("?");
        eprintln!("DBG +{} {}", lines[idx].offset, text);
    }
    let _ = bytes.len();
    let _ = std::fs::write("/tmp/ssl_code.bin", bytes);
    let stop = bytes.len();
    let mut hex = String::new();
    for (idx, byte) in bytes[entry..stop].iter().enumerate() {
        if idx % 16 == 0 {
            hex.push_str(&format!("
DBG hex+{}: ", idx));
        }
        hex.push_str(&format!("{:02x} ", byte));
    }
    eprintln!("{}", hex);
}

/// Prints a compilation failure when SSL_DEBUG is set; silent skip otherwise.
fn debug_fail(detail: String) {
    if std::env::var("SSL_DEBUG").is_ok() {
        eprintln!("DBG compile-skip: {}", detail);
    }
}

/// Builds the absolute jump thunk patched over a stub ret: movabs rax, addr; jmp rax.
fn jump_thunk(target: usize) -> Vec<u8> {
    let mut bytes = vec![0x48u8, 0xB8];
    bytes.extend_from_slice(&(target as u64).to_le_bytes());
    bytes.push(0xFF);
    bytes.push(0xE0);
    bytes
}

/// Deterministic FNV-1a string handle used for interned string identity.
fn hash_string(text: &str) -> u32 {
    let mut hash: u32 = 0x811C_9DC5;
    for byte in text.bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

const _: () = assert!(MAX_LOOP_HEADERS <= 128);
