// CEP:FILE: hot/src/pass_pre.rs
// CEP:WHAT: Partial redundancy elimination across trace boundaries: compares a side-trace entry guard against root-trace guards by signature.
// CEP:WHY: design.md Part 5.4 trivializes PRE in a trace world; when the root trace already checked the same guard condition, the side trace skips the duplicate check.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: none; the predicate is pure and conservative.
// CEP:ASSUMES: guard identity is the triple of guard opcode, slot, and expected value; operands resolve to the same slot semantics on both sides.
// CEP:COST: O(G) over root guards per side-trace entry.
// CEP:EVIDENCE: unit tests ssl-tests::unit_pass_pre.

use crate::ir::*;

/// Reports whether the side trace's first guard already exists in the root trace.
pub fn entry_guard_duplicated(side: &IrTrace, root: &IrTrace) -> bool {
    let side_guard = first_guard(side);
    match side_guard {
        None => false,
        Some((op, aux, imm)) => root_has_guard(root, op, aux, imm),
    }
}

fn first_guard(trace: &IrTrace) -> Option<(u16, u16, i32)> {
    for idx in 0..trace.count as usize {
        let op = trace.op[idx];
        if matches!(op, OP_GUARD_INT | OP_GUARD_NUM | OP_GUARD_SHAPE | OP_GUARD_BOOL) {
            return Some((op, trace.aux[idx], trace.imm[idx]));
        }
    }
    None
}

fn root_has_guard(root: &IrTrace, op: u16, aux: u16, imm: i32) -> bool {
    for idx in 0..root.count as usize {
        if root.op[idx] == op && root.aux[idx] == aux && root.imm[idx] == imm {
            return true;
        }
    }
    false
}
