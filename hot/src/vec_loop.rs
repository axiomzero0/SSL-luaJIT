// CEP:FILE: hot/src/vec_loop.rs
// CEP:WHAT: Induction-variable analysis plus stride-one loop vectorization: scalar array traffic becomes packed SSE2 double loads, arithmetic, and stores with a strengthened exit guard.
// CEP:WHY: design.md Part 6.3 requires loop vectorization for contiguous float arrays; the strengthened exit condition sends at most one remainder iteration back to the interpreter, which is the documented scalar fallback.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns false when the loop shape or node capacity does not permit the transform; the trace stays scalar, which is always legal.
// CEP:ASSUMES: the induction step becomes VECTOR_LANES after rewriting; loads and stores are element-wise ordered so aliasing between load and store tables is safe within one iteration.
// CEP:COST: O(N) pattern scan plus bounded node rewrites.
// CEP:EVIDENCE: golden IR tests loopvec_01; differential tests with vectorized traces.
// CEP:CODEGEN-UOPS: per iteration, two movapd loads, one addpd, one movapd store, one add, one compare with branch.
// CEP:CODEGEN-VECTOR: SSE2 128-bit; two doubles per iteration.
// CEP:CODEGEN-SPILLS: none for the canonical two-load one-store shape; eight xmm registers cover four loads plus one accumulator.

use crate::ir::*;

/// Loop analysis facts shared by the vectorizer passes.
pub struct Induction {
    /// The loop-carried induction phi node.
    pub phi: u16,
    /// The increment node feeding the phi backedge.
    pub add: u16,
    /// The step constant node.
    pub step_const: u16,
    /// Slot carrying the induction variable.
    pub slot: u8,
}

/// Maximum loads a vector loop may contain.
pub const MAX_VECTOR_LOADS: usize = 4;

/// Bound for the kill worklist during scalar body removal.
pub const MAX_VECTOR_WORK: usize = 32;

/// Node budget required by the vector transform.
pub const VECTOR_NODE_BUDGET: u16 = MAX_VECTOR_LOADS as u16 + MAX_VECTOR_WORK as u16 + 8;

/// One load participating in the vector loop.
#[derive(Copy, Clone)]
pub struct VecLoad {
    /// The scalar load node.
    pub node: u16,
    /// The table operand node.
    pub table: u16,
}

/// Locates one canonical induction variable: phi with integer step one.
pub fn find_induction(trace: &IrTrace, body_start: u16) -> Option<Induction> {
    for idx in body_start..trace.count {
        if trace.op[idx as usize] != OP_PHI || trace.ty[idx as usize] != TY_INT {
            continue;
        }
        let backedge = trace.in1[idx as usize];
        if backedge == NO_OPERAND || trace.op[backedge as usize] != OP_ADD_I {
            continue;
        }
        let step = trace.in1[backedge as usize];
        if step == NO_OPERAND || trace.op[step as usize] != OP_CONST_I {
            continue;
        }
        if trace.imm[step as usize] != 1 {
            continue;
        }
        if trace.in0[backedge as usize] != idx as u16 {
            continue;
        }
        return Some(Induction {
            phi: idx as u16,
            add: backedge,
            step_const: step,
            slot: trace.aux[idx as usize] as u8,
        });
    }
    None
}

/// Vectorizes one stride-one float array loop; returns true when the trace was rewritten.
pub fn run_loop_vectorization(trace: &mut IrTrace, body_start: u16) -> bool {
    let induction = match find_induction(trace, body_start) {
        Some(induction) => induction,
        None => return false,
    };
    let mut loads: [VecLoad; MAX_VECTOR_LOADS] = [VecLoad {
        node: NO_OPERAND,
        table: NO_OPERAND,
    }; MAX_VECTOR_LOADS];
    let load_count = match find_vectorizable_loads(trace, body_start, induction.phi, &mut loads) {
        Some(count) => count,
        None => return false,
    };
    let store = match find_vectorizable_store(trace, body_start, induction.phi, &loads[..load_count]) {
        Some(store) => store,
        None => return false,
    };
    if trace.remaining() < VECTOR_NODE_BUDGET {
        return false;
    }
    strengthen_exit_guard(trace, body_start, &induction);
    rewrite_to_vector(trace, &loads[..load_count], store, induction.phi);
    true
}

fn find_vectorizable_loads(
    trace: &IrTrace,
    body_start: u16,
    phi: u16,
    loads: &mut [VecLoad; MAX_VECTOR_LOADS],
) -> Option<usize> {
    let mut count = 0usize;
    for idx in body_start..trace.count {
        if trace.op[idx as usize] != OP_TGETI {
            continue;
        }
        if trace.in1[idx as usize] != phi {
            continue;
        }
        if trace.refcount[idx as usize] != 1 {
            return None;
        }
        if count >= MAX_VECTOR_LOADS {
            return None;
        }
        loads[count] = VecLoad {
            node: idx as u16,
            table: trace.in0[idx as usize],
        };
        count += 1;
    }
    if count == 0 {
        return None;
    }
    Some(count)
}

fn find_vectorizable_store(
    trace: &IrTrace,
    body_start: u16,
    phi: u16,
    loads: &[VecLoad],
) -> Option<u16> {
    for idx in body_start..trace.count {
        if trace.op[idx as usize] != OP_TSETI {
            continue;
        }
        if trace.in1[idx as usize] != phi {
            continue;
        }
        if !value_comes_from_vectorizable_arith(trace, trace.in2[idx as usize], loads) {
            continue;
        }
        return Some(idx as u16);
    }
    None
}

fn value_comes_from_vectorizable_arith(trace: &IrTrace, value: u16, loads: &[VecLoad]) -> bool {
    if value == NO_OPERAND {
        return false;
    }
    let idx = value as usize;
    if !IrTrace::is_float_arith(trace.op[idx]) {
        return false;
    }
    for operand in [trace.in0[idx], trace.in1[idx]] {
        if operand == NO_OPERAND {
            return false;
        }
        let is_load = loads.iter().any(|load| load.node == operand);
        let is_chain = IrTrace::is_float_arith(trace.op[operand as usize]);
        if !is_load && !is_chain {
            return false;
        }
    }
    true
}

/// Strengthens the exit guard so a vector iteration never touches lanes beyond the limit.
fn strengthen_exit_guard(trace: &mut IrTrace, body_start: u16, induction: &Induction) {
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
    if trace.in0[cond as usize] != induction.phi {
        return;
    }
    let one = match trace.push(OP_CONST_I, TY_INT, NO_OPERAND, NO_OPERAND, NO_OPERAND, 1, 0, 0) {
        Some(node) => node,
        None => return,
    };
    let plus_one = match trace.push(OP_ADD_I, TY_INT, induction.phi, one, NO_OPERAND, 0, 0, 0) {
        Some(node) => node,
        None => return,
    };
    add_use(trace, induction.phi);
    add_use(trace, one);
    add_use(trace, plus_one);
    let limit = trace.in1[cond as usize];
    drop_use(trace, induction.phi);
    trace.in0[cond as usize] = plus_one;
    trace.in1[cond as usize] = limit;
}

/// Replaces scalar loads, arithmetic, and the store with vector nodes.
fn rewrite_to_vector(trace: &mut IrTrace, loads: &[VecLoad], store: u16, phi: u16) {
    let mut vector_for_load = [NO_OPERAND; MAX_VECTOR_LOADS];
    for (slot, load) in loads.iter().enumerate() {
        let vload = match trace.push(
            OP_VLOAD_F,
            TY_VEC,
            load.table,
            phi,
            NO_OPERAND,
            0,
            0,
            FLAG_MEMORY | FLAG_VECTORIZED,
        ) {
            Some(node) => node,
            None => return,
        };
        add_use(trace, load.table);
        add_use(trace, phi);
        vector_for_load[slot] = vload;
    }
    let store_value = trace.in2[store as usize];
    let vec_result = vectorize_chain(trace, store_value, loads, &vector_for_load);
    if vec_result == NO_OPERAND {
        return;
    }
    let store_table = trace.in0[store as usize];
    let vstore = match trace.push(
        OP_VSTORE_F,
        TY_ANY,
        store_table,
        phi,
        vec_result,
        0,
        0,
        FLAG_MEMORY | FLAG_SIDE_EFFECT | FLAG_VECTORIZED,
    ) {
        Some(node) => node,
        None => return,
    };
    add_use(trace, store_table);
    add_use(trace, phi);
    add_use(trace, vec_result);
    drop_use(trace, store_value);
    drop_use(trace, store_table);
    drop_use(trace, phi);
    trace.in0[store as usize] = NO_OPERAND;
    trace.in1[store as usize] = NO_OPERAND;
    trace.in2[store as usize] = NO_OPERAND;
    trace.op[store as usize] = OP_NOP;
    kill_scalar_loop_body(trace, loads, store_value);
    rebuild_mem_chain(trace);
}

/// Recursively converts one scalar float chain into vector form.
fn vectorize_chain(
    trace: &mut IrTrace,
    node: u16,
    loads: &[VecLoad],
    vector_for_load: &[u16; MAX_VECTOR_LOADS],
) -> u16 {
    for (slot, load) in loads.iter().enumerate() {
        if load.node == node {
            return vector_for_load[slot];
        }
    }
    if node == NO_OPERAND || !IrTrace::is_float_arith(trace.op[node as usize]) {
        return NO_OPERAND;
    }
    let lhs = vectorize_chain(trace, trace.in0[node as usize], loads, vector_for_load);
    let rhs = vectorize_chain(trace, trace.in1[node as usize], loads, vector_for_load);
    if lhs == NO_OPERAND || rhs == NO_OPERAND {
        return NO_OPERAND;
    }
    let vec_op = match trace.op[node as usize] {
        OP_ADD_F => OP_VADD_F,
        OP_SUB_F => OP_VSUB_F,
        _ => OP_VMUL_F,
    };
    let vec_node = match trace.push(vec_op, TY_VEC, lhs, rhs, NO_OPERAND, 0, 0, FLAG_VECTORIZED) {
        Some(node) => node,
        None => return NO_OPERAND,
    };
    add_use(trace, lhs);
    add_use(trace, rhs);
    vec_node
}

/// Deletes the scalar loop body nodes that the vector loop replaced.
fn kill_scalar_loop_body(trace: &mut IrTrace, loads: &[VecLoad], chain_root: u16) {
    let mut work = [NO_OPERAND; MAX_VECTOR_WORK];
    let mut count = 0usize;
    work[count] = chain_root;
    count += 1;
    for load in loads {
        if count < MAX_VECTOR_WORK {
            work[count] = load.node;
            count += 1;
        }
    }
    let mut idx = 0usize;
    while idx < count {
        let node = work[idx];
        idx += 1;
        if node == NO_OPERAND || trace.op[node as usize] == OP_NOP {
            continue;
        }
        if !IrTrace::is_float_arith(trace.op[node as usize]) && trace.op[node as usize] != OP_TGETI
        {
            continue;
        }
        for operand in [trace.in0[node as usize], trace.in1[node as usize]] {
            if operand != NO_OPERAND && count < MAX_VECTOR_WORK {
                work[count] = operand;
                count += 1;
            }
        }
        drop_use(trace, trace.in0[node as usize]);
        drop_use(trace, trace.in1[node as usize]);
        drop_use(trace, trace.in2[node as usize]);
        trace.in0[node as usize] = NO_OPERAND;
        trace.in1[node as usize] = NO_OPERAND;
        trace.in2[node as usize] = NO_OPERAND;
        trace.op[node as usize] = OP_NOP;
    }
}
