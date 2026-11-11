// CEP:FILE: hot/src/pass_licm.rs
// CEP:WHAT: Loop invariant code motion: one backward sweep marking guards over loop-invariant operands for hoisting into the pre-header.
// CEP:WHY: design.md Part 5.3 hoists type and shape checks out of the hot loop in O(N); scheduling emits hoisted nodes before the loop body, which trivializes dominance for a single-entry trace.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: none; the pass is conservative and only marks nodes, never rewrites indices.
// CEP:ASSUMES: body_start marks the first loop-body node; nodes before it are pre-header or hoisted material.
// CEP:COST: O(N) backward sweep.
// CEP:EVIDENCE: golden IR tests licm_01; unit tests ssl-tests::unit_pass_licm.

use crate::ir::*;

/// Runs LICM over one trace; returns the number of hoisted nodes.
pub fn run_licm(trace: &mut IrTrace, body_start: u16) -> u32 {
    let mut hoisted = 0u32;
    let mut idx = trace.count;
    while idx > body_start {
        idx -= 1;
        if trace.op[idx as usize] == OP_NOP {
            continue;
        }
        if !is_guard(trace.op[idx as usize]) {
            continue;
        }
        if invariant_operands(trace, idx as usize, body_start) {
            trace.flags[idx as usize] |= FLAG_HOISTED;
            hoisted += 1;
        }
    }
    hoisted
}

fn is_guard(op: u16) -> bool {
    matches!(
        op,
        OP_GUARD_INT | OP_GUARD_NUM | OP_GUARD_SHAPE
    )
}

fn invariant_operands(trace: &IrTrace, idx: usize, body_start: u16) -> bool {
    for operand in [trace.in0[idx], trace.in1[idx], trace.in2[idx]] {
        if operand == NO_OPERAND {
            continue;
        }
        if operand >= body_start {
            return false;
        }
        if trace.op[operand as usize] == OP_PHI || trace.op[operand as usize] == OP_PARAM {
            return false;
        }
    }
    true
}
