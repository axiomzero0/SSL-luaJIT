// CEP:FILE: hot/src/deopt.rs
// CEP:WHAT: Deoptimization planning: maps guard exits to resume points and snapshot entry ranges for stub emission and interpreter resumption.
// CEP:WHY: design.md Part 9 requires perfect state reconstruction; emitted exit stubs restore vregs into slots from these ranges and the interpreter resumes at the recorded bytecode pc.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns None for unknown guard ids; the caller routes the exit to the trace header instead.
// CEP:ASSUMES: snapshots were written by mir_build in guard order; exit stubs restore vreg payloads before the interpreter resumes.
// CEP:COST: O(G) guard scan per exit; G is bounded by MAX_GUARDS.
// CEP:EVIDENCE: differential tests exercise guard exits on every corpus program.

use crate::mir::MirBody;
use crate::vm_state::VmState;

/// One guard exit plan consumed by the emitter and the driver.
#[derive(Copy, Clone)]
pub struct ExitPlan {
    /// Bytecode word where the interpreter resumes.
    pub resume_pc: u32,
    /// First snapshot entry index in the pool.
    pub entry_start: u16,
    /// Number of snapshot entries.
    pub entry_len: u16,
}

/// Resolves the exit plan for one guard id.
pub fn exit_plan(body: &MirBody, guard_id: u16) -> Option<ExitPlan> {
    for idx in 0..body.snapshot_count as usize {
        let snapshot = &body.snapshots[idx];
        if snapshot.guard == guard_id {
            return Some(ExitPlan {
                resume_pc: snapshot.resume_pc,
                entry_start: snapshot.start,
                entry_len: snapshot.len,
            });
        }
    }
    None
}

/// Prepares the interpreter resume state after a guard failure; stubs already restored slot payloads.
pub fn prepare_resume(state: &mut VmState, body: &MirBody, guard_id: u16) -> Option<u32> {
    let plan = exit_plan(body, guard_id)?;
    state.pc = plan.resume_pc;
    Some(plan.resume_pc)
}
