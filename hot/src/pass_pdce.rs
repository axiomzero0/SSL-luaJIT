// CEP:FILE: hot/src/pass_pdce.rs
// CEP:WHAT: Partial dead code elimination: one backward refcount sweep turning unreferenced pure nodes into placeholders and cascading their operands.
// CEP:WHY: design.md Part 5.5 requires a contiguous refcount scan at memory-bandwidth speed; guards and memory nodes are side-effecting and survive by contract.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: none; the pass only deletes value nodes with zero references.
// CEP:ASSUMES: refcounts are recomputed at entry so prior passes leave consistent state.
// CEP:COST: O(N) recomputation plus one O(N) backward sweep.
// CEP:EVIDENCE: golden IR tests pdce_01; unit tests ssl-tests::unit_pass_pdce.

use crate::ir::*;

/// Runs PDCE over one trace; returns the number of eliminated nodes.
pub fn run_pdce(trace: &mut IrTrace) -> u32 {
    recompute_refcounts(trace);
    let mut eliminated = 0u32;
    let mut idx = trace.count;
    while idx > 0 {
        idx -= 1;
        if trace.op[idx as usize] == OP_NOP {
            continue;
        }
        if trace.is_memory(idx as u16) || trace.is_side_effect(idx as u16) {
            continue;
        }
        if trace.refcount[idx as usize] == 0 {
            eliminate(trace, idx as usize);
            eliminated += 1;
        }
    }
    rebuild_mem_chain(trace);
    eliminated
}

/// Recomputes every refcount from operand and memory edges.
pub fn recompute_refcounts(trace: &mut IrTrace) {
    for idx in 0..trace.count as usize {
        trace.refcount[idx] = 0;
    }
    for idx in 0..trace.count as usize {
        if trace.op[idx] == OP_NOP {
            continue;
        }
        for operand in [trace.in0[idx], trace.in1[idx], trace.in2[idx]] {
            if operand != NO_OPERAND {
                trace.refcount[operand as usize] =
                    trace.refcount[operand as usize].saturating_add(1);
            }
        }
        if trace.is_memory(idx as u16) && trace.mem_in[idx] != NO_OPERAND {
            trace.refcount[trace.mem_in[idx] as usize] =
                trace.refcount[trace.mem_in[idx] as usize].saturating_add(1);
        }
    }
}

/// Turns one node into a no-op record and releases its operand references.
fn eliminate(trace: &mut IrTrace, idx: usize) {
    for operand in [trace.in0[idx], trace.in1[idx], trace.in2[idx]] {
        if operand != NO_OPERAND {
            trace.refcount[operand as usize] = trace.refcount[operand as usize].saturating_sub(1);
        }
    }
    trace.in0[idx] = NO_OPERAND;
    trace.in1[idx] = NO_OPERAND;
    trace.in2[idx] = NO_OPERAND;
    trace.op[idx] = OP_NOP;
}
