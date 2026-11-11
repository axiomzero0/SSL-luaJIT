// CEP:FILE: hot/src/vec_slp.rs
// CEP:WHAT: Superword level parallelism: packs adjacent scalar float load, arithmetic, and store pairs into packed SSE2 nodes.
// CEP:WHY: design.md Part 6.1 requires SLP for straight-line isomorphic float operations; adjacent constant-index pairs from one table pack into single vector nodes with no loop restructuring.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns the number of packed pairs; pattern mismatch leaves the trace scalar, which is always legal.
// CEP:ASSUMES: packed semantics read or write lanes base and base plus one; pairs must share one table node and adjacent constant indices.
// CEP:COST: O(N) window scan plus bounded rewrites.
// CEP:EVIDENCE: golden IR tests slp_01; differential tests.
// CEP:CODEGEN-VECTOR: SSE2 128-bit pairs.

use crate::ir::*;

/// Node budget required by one SLP pair transform.
pub const SLP_NODE_BUDGET: u16 = 8;

/// Runs SLP over the trace; returns the number of packed pairs.
pub fn run_slp(trace: &mut IrTrace, body_start: u16) -> u32 {
    let mut packed = 0u32;
    let mut idx = body_start;
    while (idx as usize) < trace.count as usize {
        let pair = find_slp_pair(trace, idx, body_start);
        match pair {
            Some((first, second, store_first, store_second)) => {
                if trace.remaining() < SLP_NODE_BUDGET {
                    return packed;
                }
                pack_pair(trace, first, second, store_first, store_second);
                packed += 1;
                idx += 1;
            }
            None => idx += 1,
        }
    }
    packed
}

/// Locates one adjacent-index load pair feeding isomorphic arithmetic into adjacent stores.
fn find_slp_pair(
    trace: &IrTrace,
    from: u16,
    body_start: u16,
) -> Option<(u16, u16, u16, u16)> {
    let first = scalar_store(trace, from, body_start)?;
    let chain1 = trace.in2[first as usize];
    let load1 = arith_load_operand(trace, chain1)?;
    let second = adjacent_store(trace, first, body_start)?;
    let chain2 = trace.in2[second as usize];
    let load2 = arith_load_operand(trace, chain2)?;
    if !same_table_adjacent(trace, load1, load2) {
        return None;
    }
    if arith_op_of(trace, chain1) != arith_op_of(trace, chain2) {
        return None;
    }
    if !other_operands_compatible(trace, chain1, chain2, load1, load2) {
        return None;
    }
    Some((load1, load2, first, second))
}

fn scalar_store(trace: &IrTrace, from: u16, body_start: u16) -> Option<u16> {
    let _ = body_start;
    let mut idx = from;
    while (idx as usize) < trace.count as usize {
        if trace.op[idx as usize] == OP_TSETI {
            let value = trace.in2[idx as usize];
            if value != NO_OPERAND && IrTrace::is_float_arith(trace.op[value as usize]) {
                return Some(idx as u16);
            }
        }
        idx += 1;
    }
    None
}

fn adjacent_store(trace: &IrTrace, first: u16, body_start: u16) -> Option<u16> {
    let _ = body_start;
    let mut idx = first + 1;
    while (idx as usize) < trace.count as usize {
        if trace.op[idx as usize] == OP_TSETI {
            let value = trace.in2[idx as usize];
            if value != NO_OPERAND && IrTrace::is_float_arith(trace.op[value as usize]) {
                return Some(idx as u16);
            }
        }
        idx += 1;
    }
    None
}

fn arith_load_operand(trace: &IrTrace, chain: u16) -> Option<u16> {
    if chain == NO_OPERAND || !IrTrace::is_float_arith(trace.op[chain as usize]) {
        return None;
    }
    let lhs = trace.in0[chain as usize];
    let rhs = trace.in1[chain as usize];
    if lhs != NO_OPERAND && trace.op[lhs as usize] == OP_TGETI {
        return Some(lhs);
    }
    if rhs != NO_OPERAND && trace.op[rhs as usize] == OP_TGETI {
        return Some(rhs);
    }
    None
}

fn same_table_adjacent(trace: &IrTrace, load1: u16, load2: u16) -> bool {
    let i1 = load1 as usize;
    let i2 = load2 as usize;
    if trace.in0[i1] != trace.in0[i2] {
        return false;
    }
    let idx1 = trace.in1[i1];
    let idx2 = trace.in1[i2];
    if idx1 == NO_OPERAND || idx2 == NO_OPERAND {
        return false;
    }
    if trace.op[idx1 as usize] != OP_CONST_I || trace.op[idx2 as usize] != OP_CONST_I {
        return false;
    }
    let (v1, v2) = (trace.imm[idx1 as usize], trace.imm[idx2 as usize]);
    v2 == v1 + 1
}

fn arith_op_of(trace: &IrTrace, chain: u16) -> u16 {
    if chain == NO_OPERAND {
        return OP_NOP;
    }
    trace.op[chain as usize]
}

fn other_operands_compatible(
    trace: &IrTrace,
    chain1: u16,
    chain2: u16,
    load1: u16,
    load2: u16,
) -> bool {
    let other1 = other_operand(trace, chain1, load1);
    let other2 = other_operand(trace, chain2, load2);
    match (other1, other2) {
        (Some(a), Some(b)) => same_table_adjacent(trace, a, b),
        (None, None) => true,
        _ => false,
    }
}

fn other_operand(trace: &IrTrace, chain: u16, load: u16) -> Option<u16> {
    if chain == NO_OPERAND {
        return None;
    }
    let lhs = trace.in0[chain as usize];
    let rhs = trace.in1[chain as usize];
    if lhs == load {
        return Some(rhs);
    }
    if rhs == load {
        return Some(lhs);
    }
    None
}

/// Emits the packed load, arithmetic, and store pair and deletes the scalar originals.
fn pack_pair(trace: &mut IrTrace, load1: u16, load2: u16, store1: u16, store2: u16) {
    let table = trace.in0[load1 as usize];
    let idx_node = trace.in1[load1 as usize];
    let vload = match trace.push(
        OP_VLOAD_F,
        TY_VEC,
        table,
        idx_node,
        NO_OPERAND,
        0,
        0,
        FLAG_MEMORY | FLAG_VECTORIZED,
    ) {
        Some(node) => node,
        None => return,
    };
    add_use(trace, table);
    add_use(trace, idx_node);
    let other1 = other_operand(trace, trace.in2[store1 as usize], load1);
    let other2 = other_operand(trace, trace.in2[store2 as usize], load2);
    let rhs = match (other1, other2) {
        (Some(a), Some(b)) => {
            let packed = match trace.push(
                OP_VPACK,
                TY_VEC,
                a,
                b,
                NO_OPERAND,
                0,
                0,
                FLAG_VECTORIZED,
            ) {
                Some(node) => node,
                None => return,
            };
            add_use(trace, a);
            add_use(trace, b);
            packed
        }
        _ => return,
    };
    let vec_op = match trace.op[trace.in2[store1 as usize] as usize] {
        OP_ADD_F => OP_VADD_F,
        OP_SUB_F => OP_VSUB_F,
        _ => OP_VMUL_F,
    };
    let vadd = match trace.push(vec_op, TY_VEC, vload, rhs, NO_OPERAND, 0, 0, FLAG_VECTORIZED) {
        Some(node) => node,
        None => return,
    };
    add_use(trace, vload);
    add_use(trace, rhs);
    let store_table = trace.in0[store1 as usize];
    let vstore = match trace.push(
        OP_VSTORE_F,
        TY_ANY,
        store_table,
        idx_node,
        vadd,
        0,
        0,
        FLAG_MEMORY | FLAG_SIDE_EFFECT | FLAG_VECTORIZED,
    ) {
        Some(node) => node,
        None => return,
    };
    add_use(trace, store_table);
    add_use(trace, idx_node);
    add_use(trace, vadd);
    for node in [load1, load2, store1, store2] {
        drop_use(trace, trace.in0[node as usize]);
        drop_use(trace, trace.in1[node as usize]);
        drop_use(trace, trace.in2[node as usize]);
        trace.in0[node as usize] = NO_OPERAND;
        trace.in1[node as usize] = NO_OPERAND;
        trace.in2[node as usize] = NO_OPERAND;
        trace.op[node as usize] = OP_NOP;
    }
    rebuild_mem_chain(trace);
}
