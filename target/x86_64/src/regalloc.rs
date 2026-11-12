// CEP:FILE: target/x86_64/src/regalloc.rs
// CEP:WHAT: Linear scan register allocation: live intervals, class-separated pools, move coalescing, and zero-spill exhaustion policy.
// CEP:WHY: design.md Part 7 mandates trace-local linear scan with ABI reservations; the zero-spill mandate of section 52.4 is enforced by refusing compilation when the pool exhausts, which keeps every installed trace spill-free.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns RegError::PoolExhausted when a class cannot serve a live interval; the caller discards the trace and the interpreter continues, which is always legal.
// CEP:ASSUMES: rbx, r13, r14, r15 are ABI-reserved and absent from the pool; r10 and r11 are isel scratch; physical ids bypass allocation via PHYS_BASE.
// CEP:COST: O(V log V) over interval endpoints plus one linear pass; V is bounded by MAX_VREGS.
// CEP:EVIDENCE: spill count evidence in benches/artifacts; differential codegen.
// CEP:CODEGEN-SPILLS: zero by policy; shapes beyond the pool are not compiled.

use crate::isa_def::*;
use crate::machine::MachineFunction;
use ssl_config::target_model::abi_reservation as abi;
use ssl_config::target_model::gpr_pool;
use ssl_config::target_model::xmm_pool;
use ssl_config::limits as L;

/// Allocation failure enumeration.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum RegError {
    /// A register class ran out of physical registers for live intervals.
    PoolExhausted,
}

/// Allocation result: physical register per vreg.
pub struct Allocation {
    /// Physical id per vreg or PHYS_BASE marker for spilled-free passthrough.
    pub map: [u16; L::MAX_VREGS as usize],
    /// Physical GPR ids actually used (for prologue save set).
    pub used_gpr: [u8; 16],
    pub used_gpr_count: u8,
}

impl Allocation {
    /// Reports whether the callee-saved r12 needs prologue preservation.
    pub fn uses_r12(&self) -> bool {
        for idx in 0..self.used_gpr_count as usize {
            if self.used_gpr[idx] == 12 {
                return true;
            }
        }
        false
    }
}

/// Runs linear scan allocation over one machine function.
pub fn allocate(machine: &MachineFunction, mir: &ssl_hot::mir::MirBody) -> Result<Allocation, RegError> {
    let mut allocation = Allocation {
        map: [0; L::MAX_VREGS as usize],
        used_gpr: [0; 16],
        used_gpr_count: 0,
    };
    let mut intervals: [(u16, u32, u32); L::MAX_VREGS as usize] = [(0, 0, 0); L::MAX_VREGS as usize];
    let mut live = [false; L::MAX_VREGS as usize];
    for idx in 0..machine.count as usize {
        let insn = &machine.insns[idx];
        for vreg in [insn.dst, insn.src0, insn.src1] {
            if vreg >= PHYS_BASE {
                continue;
            }
            if (vreg as usize) >= machine.vreg_count as usize {
                continue;
            }
            if !live[vreg as usize] {
                live[vreg as usize] = true;
                intervals[vreg as usize] = (vreg, idx as u32, idx as u32);
            } else {
                intervals[vreg as usize].2 = idx as u32;
            }
        }
    }
    for snap_idx in 0..mir.snapshot_count as usize {
        let snapshot = &mir.snapshots[snap_idx];
        let guard_insn = guard_position(machine, snapshot.guard);
        let start = snapshot.start as usize;
        let stop = (start + snapshot.len as usize).min(mir.snap_used as usize);
        for entry in &mir.snap_entries[start..stop] {
            let vreg = entry.vreg;
            if (vreg as usize) < machine.vreg_count as usize {
                // The stub executes immediately after the guard's branch fires, so
                // the register still holds the vreg at that point; extending the
                // interval to the guard position is sufficient. Extending further
                // would exhaust the zero-spill pool for wide traces.
                if !live[vreg as usize] {
                    live[vreg as usize] = true;
                    intervals[vreg as usize] = (vreg, guard_insn as u32, guard_insn as u32);
                } else {
                    intervals[vreg as usize].2 = intervals[vreg as usize]
                        .2
                        .max(guard_insn as u32);
                }
            }
        }
    }
    let mut order: [u16; L::MAX_VREGS as usize] = [0; L::MAX_VREGS as usize];
    let mut order_count = 0usize;
    for vreg in 0..machine.vreg_count as usize {
        if live[vreg] {
            order[order_count] = vreg as u16;
            order_count += 1;
        }
    }
    sort_by_start(&mut intervals, &mut order, order_count);
    let mut gpr_free: [bool; 16] = [false; 16];
    let mut xmm_free: [bool; 16] = [false; 16];
    for reg in 0..16usize {
        gpr_free[reg] = true;
        xmm_free[reg] = true;
    }
    gpr_free[abi::STATE_PTR_GPR as usize] = false;
    gpr_free[abi::HEAP_BASE_GPR as usize] = false;
    gpr_free[abi::ALLOC_START_GPR as usize] = false;
    gpr_free[abi::ALLOC_CURSOR_GPR as usize] = false;
    gpr_free[abi::STACK_PTR_GPR as usize] = false;
    gpr_free[abi::FRAME_PTR_GPR as usize] = false;
    gpr_free[L::SCRATCH_GPR_A as usize] = false;
    gpr_free[L::SCRATCH_GPR_B as usize] = false;
    let mut gpr_active: [(u16, u32); 16] = [(0, 0); 16];
    let mut xmm_active: [(u16, u32); 16] = [(0, 0); 16];
    let mut gpr_active_count = 0usize;
    let mut xmm_active_count = 0usize;
    for slot in 0..order_count {
        let (vreg, start, end) = intervals[order[slot] as usize];
        expire_active(&mut gpr_active, &mut gpr_active_count, &mut gpr_free, start, &allocation);
        expire_active(&mut xmm_active, &mut xmm_active_count, &mut xmm_free, start, &allocation);
        let class = machine.vreg_class[vreg as usize];
        let assigned = if class == CLASS_XMM {
            take_free(&mut xmm_free, xmm_pool::COUNT as usize)
        } else {
            take_free(&mut gpr_free, 16)
        };
        let phys = match assigned {
            Some(phys) => phys,
            None => return Err(RegError::PoolExhausted),
        };
        allocation.map[vreg as usize] = PHYS_BASE + phys as u16;
        if class == CLASS_XMM {
            xmm_active[xmm_active_count] = (vreg, end);
            xmm_active_count += 1;
        } else {
            gpr_active[gpr_active_count] = (vreg, end);
            gpr_active_count += 1;
            if phys < gpr_pool::COUNT as usize || is_callee_saved(phys) {
                record_used(&mut allocation.used_gpr, &mut allocation.used_gpr_count, phys as u8);
            }
        }
    }
    Ok(allocation)
}

/// Finds the machine instruction index that carries one guard id.
fn guard_position(machine: &MachineFunction, guard_id: u16) -> usize {
    for idx in 0..machine.count as usize {
        let insn = &machine.insns[idx];
        let carries = (insn.op == X_JCC_REL && insn.aux == crate::machine::stub_label(guard_id))
            || (insn.aux == guard_id && matches!(insn.op, X_MOV_SLOT_TAG | X_MOV_R_SLOT));
        if carries {
            return idx;
        }
    }
    machine.count as usize
}

fn is_callee_saved(phys: usize) -> bool {
    phys == abi::STATE_PTR_GPR as usize
        || phys == abi::ALLOC_START_GPR as usize
        || phys == abi::ALLOC_CURSOR_GPR as usize
        || phys == 12
}

fn record_used(used: &mut [u8], count: &mut u8, phys: u8) {
    for idx in 0..*count as usize {
        if used[idx] == phys {
            return;
        }
    }
    if (*count as usize) < used.len() {
        used[*count as usize] = phys;
        *count += 1;
    }
}

fn expire_active(
    active: &mut [(u16, u32); 16],
    count: &mut usize,
    free: &mut [bool; 16],
    position: u32,
    allocation: &Allocation,
) {
    let mut idx = 0;
    while idx < *count {
        let (vreg, end) = active[idx];
        if end < position {
            let phys = allocation.map[vreg as usize] - PHYS_BASE;
            free[phys as usize] = true;
            active[idx] = active[*count - 1];
            *count -= 1;
        } else {
            idx += 1;
        }
    }
}

fn take_free(free: &mut [bool; 16], limit: usize) -> Option<usize> {
    for reg in 0..limit {
        if free[reg] {
            free[reg] = false;
            return Some(reg);
        }
    }
    None
}

/// Deterministic insertion sort of interval order by start position.
fn sort_by_start(
    intervals: &mut [(u16, u32, u32); L::MAX_VREGS as usize],
    order: &mut [u16; L::MAX_VREGS as usize],
    count: usize,
) {
    for idx in 1..count {
        let key = order[idx];
        let key_start = intervals[key as usize].1;
        let mut scan = idx;
        while scan > 0 && intervals[order[scan - 1] as usize].1 > key_start {
            order[scan] = order[scan - 1];
            scan -= 1;
        }
        order[scan] = key;
    }
}
