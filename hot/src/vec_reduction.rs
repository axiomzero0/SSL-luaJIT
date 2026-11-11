// CEP:FILE: hot/src/vec_reduction.rs
// CEP:WHAT: Reduction vectorization: a scalar float sum accumulated through one load becomes a packed vector accumulator with a horizontal add on the exit path.
// CEP:WHY: design.md Part 6.9 requires vector reduction for accumulations; the init vector packs the identity into lane zero and zero into lane one so the horizontal add yields init plus the true sum.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns None when the loop shape or capacity does not permit the transform; the trace stays scalar, which is always legal.
// CEP:ASSUMES: the strengthened exit guard bounds vector loads to in-range lanes; the interpreter completes at most one remainder iteration after a side exit.
// CEP:COST: O(N) pattern scan plus bounded rewrites.
// CEP:EVIDENCE: golden IR tests reduce_01; differential tests with reduction traces.
// CEP:CODEGEN-UOPS: per iteration, one movapd load, one addpd, one add, one compare; one unpckhpd plus one addsd at exit.
// CEP:CODEGEN-VECTOR: SSE2 128-bit two-lane accumulator; horizontal combine at loop exit.

use crate::ir::*;
use crate::vec_loop::find_induction;

/// Exit-path product of a vectorized reduction.
pub struct ReductionResult {
    /// Slot whose exit value is the reduced scalar.
    pub slot: u8,
    /// The horizontal-add node holding the reduced scalar.
    pub hadd: u16,
}

/// Vectorizes one float sum-reduction loop; returns the exit mapping when successful.
pub fn run_reduction(trace: &mut IrTrace, body_start: u16) -> Option<ReductionResult> {
    let induction = find_induction(trace, body_start)?;
    let phi = find_accumulator(trace, body_start)?;
    let feed = trace.in1[phi as usize];
    if feed == NO_OPERAND || trace.op[feed as usize] != OP_ADD_F {
        return None;
    }
    if trace.in0[feed as usize] != phi {
        return None;
    }
    let load = trace.in1[feed as usize];
    if load == NO_OPERAND || trace.op[load as usize] != OP_TGETI {
        return None;
    }
    if trace.in1[load as usize] != induction.phi {
        return None;
    }
    if trace.refcount[phi as usize] != 1 {
        return None;
    }
    if trace.remaining() < 8 {
        return None;
    }
    strengthen_exit_guard_for_vector(trace, body_start, induction.phi);
    let table = trace.in0[load as usize];
    let param = trace.in0[phi as usize];
    let zero = trace.push(OP_CONST_I, TY_INT, NO_OPERAND, NO_OPERAND, NO_OPERAND, 0, 0, 0)?;
    let splat = trace.push(OP_VPACK, TY_VEC, param, zero, NO_OPERAND, 0, 0, FLAG_HOISTED)?;
    add_use(trace, param);
    add_use(trace, zero);
    let vphi = trace.push(OP_PHI, TY_VEC, splat, NO_OPERAND, NO_OPERAND, 0, trace.aux[phi as usize], 0)?;
    add_use(trace, splat);
    let vload = trace.push(OP_VLOAD_F, TY_VEC, table, induction.phi, NO_OPERAND, 0, 0, FLAG_MEMORY | FLAG_VECTORIZED)?;
    add_use(trace, table);
    add_use(trace, induction.phi);
    let vadd = trace.push(OP_VADD_F, TY_VEC, vphi, vload, NO_OPERAND, 0, 0, FLAG_VECTORIZED)?;
    add_use(trace, vphi);
    add_use(trace, vload);
    trace.in1[vphi as usize] = vadd;
    add_use(trace, vadd);
    let hadd = trace.push(OP_HADD_F, TY_NUM, vphi, NO_OPERAND, NO_OPERAND, 0, 0, FLAG_SIDE_EFFECT)?;
    add_use(trace, vphi);
    drop_use(trace, feed);
    drop_use(trace, load);
    drop_use(trace, phi);
    drop_use(trace, param);
    trace.in0[feed as usize] = NO_OPERAND;
    trace.in1[feed as usize] = NO_OPERAND;
    trace.in2[feed as usize] = NO_OPERAND;
    trace.op[feed as usize] = OP_NOP;
    trace.in0[load as usize] = NO_OPERAND;
    trace.in1[load as usize] = NO_OPERAND;
    trace.in2[load as usize] = NO_OPERAND;
    trace.op[load as usize] = OP_NOP;
    trace.in0[phi as usize] = NO_OPERAND;
    trace.in1[phi as usize] = NO_OPERAND;
    trace.in2[phi as usize] = NO_OPERAND;
    trace.op[phi as usize] = OP_NOP;
    rebuild_mem_chain(trace);
    Some(ReductionResult {
        slot: trace.aux[vphi as usize] as u8,
        hadd,
    })
}

/// Finds one scalar float accumulator phi fed by exactly one in-loop add.
fn find_accumulator(trace: &IrTrace, body_start: u16) -> Option<u16> {
    for idx in body_start..trace.count {
        if trace.op[idx as usize] != OP_PHI || trace.ty[idx as usize] != TY_NUM {
            continue;
        }
        let feed = trace.in1[idx as usize];
        if feed == NO_OPERAND || trace.op[feed as usize] != OP_ADD_F {
            continue;
        }
        if trace.in0[feed as usize] != idx as u16 {
            continue;
        }
        return Some(idx as u16);
    }
    None
}

/// Strengthens the exit guard so vector loads stay inside the logical range.
fn strengthen_exit_guard_for_vector(trace: &mut IrTrace, body_start: u16, phi: u16) {
    let mut guard_idx = NO_OPERAND;
    for idx in body_start..trace.count {
        if trace.op[idx as usize] == OP_GUARD_BOOL {
            guard_idx = idx as u16;
        }
    }
    if guard_idx == NO_OPERAND {
        return;
    }
    let cond = trace.in0[guard_idx as usize];
    if cond == NO_OPERAND || trace.op[cond as usize] != OP_LT_I {
        return;
    }
    if trace.in0[cond as usize] != phi {
        return;
    }
    let one = match trace.push(OP_CONST_I, TY_INT, NO_OPERAND, NO_OPERAND, NO_OPERAND, 1, 0, 0) {
        Some(node) => node,
        None => return,
    };
    let plus_one = match trace.push(OP_ADD_I, TY_INT, phi, one, NO_OPERAND, 0, 0, 0) {
        Some(node) => node,
        None => return,
    };
    add_use(trace, phi);
    add_use(trace, one);
    add_use(trace, plus_one);
    drop_use(trace, phi);
    trace.in0[cond as usize] = plus_one;
}
