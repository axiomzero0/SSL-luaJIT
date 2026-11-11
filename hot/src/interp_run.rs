// CEP:FILE: hot/src/interp_run.rs
// CEP:WHAT: The interpreter run loop: hot-loop detection, installed-trace entry points, GC quantum interleaving, and bounded step budgets.
// CEP:WHY: design.md Part 10 puts profiling, recording triggers, and trace entry in the interpreter loop; every loop here is bounded by named budgets per section 38.12.
// CEP:CLASS: CEP-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns RunError from the step engine, BudgetSpent when the step budget is spent, and OutputOverflow on print overflow; never panics.
// CEP:ASSUMES: program, heap, and runtime are validated by the cold airlock before the loop starts; the vectorization hint is coarse (float and table votes) and is re-proven by the vectorizer before any SIMD emission.
// CEP:COST: one dispatch plus one backward-edge bookkeeping update per instruction; no allocation, no formatting.
// CEP:EVIDENCE: differential tests interpreter versus JIT; budget tests in tests.

use crate::bytecode as bc;
use crate::interp_step::{self, RunError};
use crate::runtime::Runtime;
use crate::vm_state::VmState;
use ssl_config::limits as L;

/// Terminal outcomes of the interpreter loop.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RunOutcome {
    /// Program returned normally.
    Returned,
    /// A loop header reached the hot threshold and should be recorded.
    HotLoop(u32),
    /// An installed trace header was reached and machine code should run.
    AtInstalledTrace(u32),
    /// The interpreter stopped because the step budget was spent.
    BudgetSpent,
}

/// Runs bytecode until the program returns, a loop becomes hot, or an installed trace is reached.
pub fn run_until_event(
    state: &mut VmState,
    prog: &bc::Program,
    heap: &mut [u8],
    rt: &mut Runtime,
    scratch: &mut crate::gc::GcScratch,
) -> Result<RunOutcome, RunError> {
    let mut executed = 0u32;
    loop {
        if executed >= L::MAX_RUN_STEPS {
            return Ok(RunOutcome::BudgetSpent);
        }
        executed += 1;
        let pc_before = state.pc;
        let record = interp_step::step(
            state,
            prog,
            heap,
            &mut rt.survivor_bump,
            &mut rt.out_len,
            crate::runtime::OUT_CAP,
        )?;
        if record.op == bc::OP_PRINT && !rt.push_out(record.result) {
            return Err(RunError::OutputOverflow);
        }
        if record.op == bc::OP_RET {
            return Ok(RunOutcome::Returned);
        }
        if bc::is_jump(record.op) && state.pc < pc_before {
            let header = state.pc;
            if rt.traces.is_installed(header) {
                return Ok(RunOutcome::AtInstalledTrace(header));
            }
            if rt.profile.tick_backedge(header) {
                return Ok(RunOutcome::HotLoop(header));
            }
        }
        if record.op == bc::OP_TGETI || record.op == bc::OP_TSETI {
            rt.profile.vote_shape(pc_before);
        }
        if record.op == bc::OP_ADD || record.op == bc::OP_SUB || record.op == bc::OP_MUL {
            rt.profile.vote_float(pc_before);
        }
        maybe_hint(rt, pc_before);
        rt.gc.steps_since_quantum += 1;
        if rt.gc.steps_since_quantum >= L::GC_QUANTUM_STEPS {
            rt.gc.steps_since_quantum = 0;
            crate::gc::collector_quantum(state, heap, rt, scratch)?;
        }
    }
}

/// Raises the vectorization hint when a loop body combines float arithmetic with table traffic.
fn maybe_hint(rt: &mut Runtime, pc: u32) {
    if let Some(entry) = rt.profile.entry_mut(pc) {
        if entry.float_votes >= L::HINT_FLOAT_VOTES && entry.shape_votes >= L::HINT_SHAPE_VOTES {
            entry.vec_hint = true;
        }
    }
}
