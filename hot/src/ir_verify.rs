// CEP:FILE: hot/src/ir_verify.rs
// CEP:WHAT: IR verifier: operand validity, type agreement, phi structure, memory chain order, and refcount consistency.
// CEP:WHY: Chapter 38.18 requires verification after every HPC-0 pass; the cheap mode runs after each pass and the full mode runs in CI.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns VerifyIssue lists rather than aborting; a non-empty list is a pass failure by contract.
// CEP:ASSUMES: node indices are u16 and NO_OPERAND marks absent operands.
// CEP:COST: cheap mode O(N); full mode O(N) with one extra refcount scan.
// CEP:EVIDENCE: verifier tests in tests/unit; golden tests run the full verifier.

use crate::ir::*;

/// One verifier issue.
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct VerifyIssue {
    /// Node index the issue refers to.
    pub node: u16,
    /// Issue code.
    pub code: u16,
}

/// Bounded issue sink backed by a caller-provided slice.
pub struct IssueSink<'a> {
    /// Issue storage.
    pub items: &'a mut [VerifyIssue],
    /// Number of issues written.
    pub len: usize,
}

impl<'a> IssueSink<'a> {
    pub fn new(items: &'a mut [VerifyIssue]) -> IssueSink<'a> {
        IssueSink { items, len: 0 }
    }

    pub fn push(&mut self, issue: VerifyIssue) {
        if self.len < self.items.len() {
            self.items[self.len] = issue;
            self.len += 1;
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Issue code: operand references a dead or missing node.
pub const V_BAD_OPERAND: u16 = 1;
/// Issue code: operand type disagrees with the consumer opcode.
pub const V_BAD_TYPE: u16 = 2;
/// Issue code: phi structure malformed.
pub const V_BAD_PHI: u16 = 3;
/// Issue code: memory chain order violated.
pub const V_BAD_MEM: u16 = 4;
/// Issue code: refcount inconsistent with operand uses.
pub const V_BAD_REFCOUNT: u16 = 5;

/// Runs the cheap verifier: operands and types.
pub fn verify_cheap(trace: &IrTrace, issues: &mut IssueSink) {
    for idx in 0..trace.count as usize {
        if trace.op[idx] == OP_NOP {
            continue;
        }
        check_operands(trace, idx, issues);
        check_types(trace, idx, issues);
        if trace.op[idx] == OP_PHI {
            if trace.in0[idx] == NO_OPERAND || trace.in1[idx] == NO_OPERAND {
                issues.push(VerifyIssue { node: idx as u16, code: V_BAD_PHI });
            }
        }
    }
}

/// Runs the full verifier: cheap checks plus memory chain and refcount consistency.
pub fn verify_full(trace: &IrTrace, issues: &mut IssueSink) {
    verify_cheap(trace, issues);
    let mut last_mem: u16 = NO_OPERAND;
    for idx in 0..trace.count as usize {
        if trace.op[idx] == OP_NOP {
            continue;
        }
        if trace.is_memory(idx as u16) {
            if last_mem != NO_OPERAND && trace.mem_in[idx] != last_mem {
                issues.push(VerifyIssue { node: idx as u16, code: V_BAD_MEM });
            }
            last_mem = idx as u16;
        }
    }
    let mut counts = [0u16; ssl_config::limits::MAX_IR_NODES as usize];
    for idx in 0..trace.count as usize {
        if trace.op[idx] == OP_NOP {
            continue;
        }
        for operand in [trace.in0[idx], trace.in1[idx], trace.in2[idx]] {
            if operand != NO_OPERAND {
                counts[operand as usize] = counts[operand as usize].saturating_add(1);
            }
        }
        if trace.is_memory(idx as u16) && trace.mem_in[idx] != NO_OPERAND {
            counts[trace.mem_in[idx] as usize] =
                counts[trace.mem_in[idx] as usize].saturating_add(1);
        }
    }
    for idx in 0..trace.count as usize {
        if trace.op[idx] == OP_NOP {
            continue;
        }
        if counts[idx] != trace.refcount[idx] {
            issues.push(VerifyIssue { node: idx as u16, code: V_BAD_REFCOUNT });
        }
    }
}

fn check_operands(trace: &IrTrace, idx: usize, issues: &mut IssueSink) {
    for operand in [trace.in0[idx], trace.in1[idx], trace.in2[idx]] {
        if operand == NO_OPERAND {
            continue;
        }
        if operand as usize >= trace.count as usize || trace.op[operand as usize] == OP_NOP {
            issues.push(VerifyIssue { node: idx as u16, code: V_BAD_OPERAND });
        }
    }
    if trace.is_memory(idx as u16)
        && trace.mem_in[idx] != NO_OPERAND
        && (trace.mem_in[idx] as usize >= trace.count as usize
            || trace.op[trace.mem_in[idx] as usize] == OP_NOP)
    {
        issues.push(VerifyIssue { node: idx as u16, code: V_BAD_OPERAND });
    }
}

fn check_types(trace: &IrTrace, idx: usize, issues: &mut IssueSink) {
    let op = trace.op[idx];
    let expect = match op {
        OP_ADD_I | OP_SUB_I | OP_MUL_I => [TY_INT, TY_INT],
        OP_ADD_F | OP_SUB_F | OP_MUL_F | OP_DIV_F => [TY_NUM, TY_NUM],
        OP_LT_I | OP_LE_I | OP_EQ_I | OP_NE_I => [TY_INT, TY_INT],
        OP_LT_F | OP_LE_F | OP_EQ_F | OP_NE_F => [TY_NUM, TY_NUM],
        OP_INT2F => [TY_INT, TY_ANY],
        OP_VADD_F | OP_VSUB_F | OP_VMUL_F => [TY_VEC, TY_VEC],
        OP_HADD_F => [TY_VEC, TY_ANY],
        _ => return,
    };
    for slot in 0..2usize {
        let operand = [trace.in0[idx], trace.in1[idx]][slot];
        if operand == NO_OPERAND || expect[slot] == TY_ANY {
            continue;
        }
        let produced = trace.ty[operand as usize];
        if produced != expect[slot] && produced != TY_ANY {
            issues.push(VerifyIssue { node: idx as u16, code: V_BAD_TYPE });
        }
    }
}
