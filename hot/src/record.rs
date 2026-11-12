// CEP:FILE: hot/src/record.rs
// CEP:WHAT: The trace recorder: executes one loop iteration through the shared step engine while capturing a flat TraceOp buffer with observed types, guards, and allocation counts.
// CEP:WHY: design.md Part 2 requires decoupled recording; the buffer is linear by construction so graphification stays a single pass.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns RecordError on capacity exhaustion, execution errors, boundary operations that cannot be traced, or traces that never return to their own header; partial traces are discarded by the caller.
// CEP:ASSUMES: recording executes real program effects exactly once; the iteration executed during recording counts as program execution, so the interpreter resumes after the backedge; a trace closes only when execution lands back on its own header, so nested-loop backedges are recorded as ordinary path markers and never close a foreign trace.
// CEP:COST: one step engine dispatch plus one buffer append per instruction; no allocation.
// CEP:EVIDENCE: unit tests ssl-tests::unit_record; differential tests; nested-loop regression (the recorder previously closed inner-loop traces on the outer backedge, producing machine traces without progress).

use crate::bytecode as bc;
use crate::interp_step::{self, RunError};
use crate::runtime::Runtime;
use crate::vm_state::VmState;
use ssl_config::limits as L;

/// Observed type tag for recorder fields.
pub const OBS_NONE: u8 = 0;
/// Observed integer operand.
pub const OBS_INT: u8 = 1;
/// Observed double operand.
pub const OBS_NUM: u8 = 2;
/// Observed boolean operand.
pub const OBS_BOOL: u8 = 3;
/// Observed table operand.
pub const OBS_TBL: u8 = 4;

/// One recorded instruction with observed operand types.
#[derive(Copy, Clone)]
pub struct TraceOp {
    /// Bytecode opcode.
    pub bc_op: u8,
    /// a field.
    pub a: u8,
    /// b field.
    pub b: u8,
    /// c field.
    pub c: u8,
    /// Immediate word.
    pub imm: i32,
    /// Observed left operand type.
    pub lhs_ty: u8,
    /// Observed right operand type.
    pub rhs_ty: u8,
    /// Observed result type.
    pub res_ty: u8,
    /// Bytecode word index of this instruction.
    pub pc: u32,
    /// Recorded branch polarity for conditional jumps.
    pub taken: bool,
    /// Recorded backedge marker: this jump closes the loop.
    pub is_backedge: bool,
}

impl TraceOp {
    pub const fn empty() -> TraceOp {
        TraceOp {
            bc_op: 0,
            a: 0,
            b: 0,
            c: 0,
            imm: 0,
            lhs_ty: OBS_NONE,
            rhs_ty: OBS_NONE,
            res_ty: OBS_NONE,
            pc: 0,
            taken: false,
            is_backedge: false,
        }
    }
}

/// Flat linear trace buffer produced by one recording pass.
pub struct TraceBuffer {
    /// Recorded operations in execution order.
    pub ops: [TraceOp; L::MAX_TRACE_OPS as usize],
    /// Recorded operation count.
    pub count: u32,
    /// Word index of the loop header.
    pub header_pc: u32,
    /// Bytecode word after the loop header (resume point for side exits).
    pub exit_pc: u32,
    /// Total allocation bytes requested by TNEW ops in the trace.
    pub alloc_bytes: u32,
    /// Vectorization hint from the profiler.
    pub vec_hint: bool,
}

impl TraceBuffer {
    pub fn new(header_pc: u32, vec_hint: bool) -> TraceBuffer {
        TraceBuffer {
            ops: [TraceOp::empty(); L::MAX_TRACE_OPS as usize],
            count: 0,
            header_pc,
            exit_pc: header_pc,
            alloc_bytes: 0,
            vec_hint,
        }
    }
}

/// Recorder failure enumeration.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum RecordError {
    /// Trace exceeded the operation budget.
    TraceTooLong,
    /// The loop body hit a boundary op (RET or PRINT) and cannot form a closed trace.
    BoundaryOp,
    /// The step engine reported an execution error during recording.
    Execution(RunError),
    /// Recording started at a word that is not a backward jump target.
    BadHeader,
}

/// Records one iteration of the loop starting at header_pc by executing it once through the step engine.
pub fn record_iteration(
    state: &mut VmState,
    prog: &bc::Program,
    heap: &mut [u8],
    rt: &mut Runtime,
    header_pc: u32,
) -> Result<TraceBuffer, RecordError> {
    let vec_hint = rt
        .profile
        .entry(header_pc)
        .map(|entry| entry.vec_hint)
        .unwrap_or(false);
    let mut buffer = TraceBuffer::new(header_pc, vec_hint);
    state.pc = header_pc;
    let mut steps = 0u32;
    loop {
        if steps >= L::MAX_TRACE_OPS {
            return Err(RecordError::TraceTooLong);
        }
        steps += 1;
        let pc_before = state.pc;
        let record = interp_step::step(
            state,
            prog,
            heap,
            &mut rt.survivor_bump,
            &mut rt.out_len,
            crate::runtime::OUT_CAP,
        )
        .map_err(RecordError::Execution)?;
        if record.op == bc::OP_PRINT {
            let _ = rt.push_out(record.result);
            return Err(RecordError::BoundaryOp);
        }
        if record.op == bc::OP_RET {
            return Err(RecordError::BoundaryOp);
        }
        if record.op == bc::OP_TNEW {
            buffer.alloc_bytes = buffer
                .alloc_bytes
                .saturating_add(record.imm as u32)
                .saturating_add(ssl_config::target_model::heap_layout::HEADER_BYTES);
        }
        let mut op = TraceOp {
            bc_op: record.op,
            a: record.dst,
            b: record.lhs,
            c: record.rhs,
            imm: record.imm,
            lhs_ty: obs_type(record.lhs_val),
            rhs_ty: obs_type(record.rhs_val),
            res_ty: obs_type(record.result),
            pc: record.pc,
            taken: false,
            is_backedge: false,
        };
        if bc::uses_condition_slot(record.op) {
            op.taken = state.pc != pc_before + 2;
        }
        // A trace closes only when execution lands back on its OWN header.
        // Closing on any backward jump (the old rule) let a nested loop's
        // backedge close a foreign trace: the compiled machine code then
        // looped without executing the real body and never terminated.
        if bc::is_jump(record.op) && state.pc == header_pc {
            op.is_backedge = true;
            append(&mut buffer, op)?;
            buffer.exit_pc = pc_before;
            return Ok(buffer);
        }
        append(&mut buffer, op)?;
    }
}

/// Appends one operation to the buffer with bounds checking.
fn append(buffer: &mut TraceBuffer, op: TraceOp) -> Result<(), RecordError> {
    if buffer.count >= L::MAX_TRACE_OPS {
        return Err(RecordError::TraceTooLong);
    }
    buffer.ops[buffer.count as usize] = op;
    buffer.count += 1;
    Ok(())
}

/// Maps one observed value to a recorder type tag.
fn obs_type(value: crate::vm_value::SslValue) -> u8 {
    use crate::vm_value::*;
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
