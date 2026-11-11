// CEP:FILE: hot/src/mir_build.rs
// CEP:WHAT: MIR construction: schedules the optimized IR into linear machine-independent records, materializes guarded vregs, records phi copies, and writes deoptimization snapshots.
// CEP:WHY: design.md Part 4 requires linearization after optimization and Part 9 requires a snapshot per guard; hoisted nodes schedule first so LICM results land in the pre-header.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns MirError on capacity exhaustion; callers abort compilation deterministically.
// CEP:ASSUMES: untyped slot flows stay boxed in the slot array; typed vregs exist only after a guard pins the kind; slot_nodes maps each frame slot to its final value node.
// CEP:COST: O(N) schedule plus O(N) lowering with bounded snapshot writes.
// CEP:EVIDENCE: golden MIR tests; differential tests with snapshot reconstruction.

use crate::ir::*;
use crate::mir::*;
use ssl_config::limits as L;

/// MIR build failure enumeration.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum MirError {
    /// Instruction capacity exhausted.
    InsnCapacity,
    /// Virtual register capacity exhausted.
    VregCapacity,
    /// Snapshot pool exhausted.
    SnapshotCapacity,
}

/// Slot kind codes used for re-boxing and guards.
pub const KIND_NIL: u8 = 0;
pub const KIND_INT: u8 = 1;
pub const KIND_NUM: u8 = 2;
pub const KIND_BOOL: u8 = 3;
pub const KIND_STR: u8 = 4;
pub const KIND_TBL: u8 = 5;

/// Exit mapping produced by reduction vectorization.
#[derive(Copy, Clone)]
pub struct ReductionExit {
    /// Slot whose exit value is the reduced scalar.
    pub slot: u8,
    /// The horizontal-add node.
    pub hadd: u16,
}

/// Builds one MIR body from an optimized trace.
pub fn build_mir(
    trace: &IrTrace,
    slot_nodes: &[u16; L::MAX_SLOTS as usize],
    reductions: &[ReductionExit],
) -> Result<MirBody, MirError> {
    let mut body = MirBody::new();
    let mut state = LoweringState::new(trace, slot_nodes, reductions);
    emit_prologue_alloc_check(trace, &mut body)?;
    for pass in 0..2u8 {
        for idx in 0..trace.count as usize {
            let hoisted = (trace.flags[idx] & FLAG_HOISTED) != 0;
            let in_pass = (pass == 0) == hoisted;
            if !in_pass || trace.op[idx] == OP_NOP {
                continue;
            }
            lower_node(trace, idx, &mut body, &mut state)?;
        }
    }
    for copy in state.phi_copies.iter() {
        if copy.phi != 0 && copy.src != 0 {
            let insn = MirInsn {
                op: if copy.vector { M_MOV_F } else { M_MOV_I },
                dst: copy.phi,
                src0: copy.src,
                src1: 0,
                imm: 0,
                aux: 0,
            };
            body.push(insn).ok_or(MirError::InsnCapacity)?;
        }
    }
    for store in state.phi_stores.iter() {
        if store.slot < L::MAX_SLOTS as usize && store.vreg != 0 {
            let tag = kind_tag_of(store.kind);
            body.push(MirInsn {
                op: M_STORE_SLOT,
                dst: 0,
                src0: store.vreg,
                src1: 0,
                imm: store.slot as i32,
                aux: store.kind as u16,
            })
            .ok_or(MirError::InsnCapacity)?;
            let _ = tag;
        }
    }
    let back = MirInsn {
        op: M_LOOP_BACK,
        dst: 0,
        src0: 0,
        src1: 0,
        imm: 0,
        aux: 0,
    };
    body.push(back).ok_or(MirError::InsnCapacity)?;
    Ok(body)
}

/// Mutable lowering state shared across node lowering.
struct LoweringState<'a> {
    vregs: [u16; L::MAX_IR_NODES as usize],
    node_vreg: [bool; L::MAX_IR_NODES as usize],
    node_slot: [u16; L::MAX_IR_NODES as usize],
    slot_vreg: [u16; L::MAX_SLOTS as usize],
    slot_kind: [u8; L::MAX_SLOTS as usize],
    slot_valid: [bool; L::MAX_SLOTS as usize],
    phi_copies: [PhiCopy; L::MAX_SLOTS as usize],
    phi_copy_count: usize,
    phi_stores: [PhiStore; L::MAX_SLOTS as usize],
    phi_store_count: usize,
    reductions: &'a [ReductionExit],
}

/// One slot write-back at the backedge carrying the phi value.
#[derive(Copy, Clone)]
struct PhiStore {
    slot: usize,
    vreg: u16,
    kind: u8,
}

/// One phi merge copy emitted at the backedge.
#[derive(Copy, Clone)]
struct PhiCopy {
    phi: u16,
    src: u16,
    vector: bool,
}

impl<'a> LoweringState<'a> {
    fn new(
        trace: &IrTrace,
        slot_nodes: &[u16; L::MAX_SLOTS as usize],
        reductions: &'a [ReductionExit],
    ) -> LoweringState<'a> {
        let mut state = LoweringState {
            vregs: [0; L::MAX_IR_NODES as usize],
            node_vreg: [false; L::MAX_IR_NODES as usize],
            node_slot: [NO_OPERAND; L::MAX_IR_NODES as usize],
            slot_vreg: [0; L::MAX_SLOTS as usize],
            slot_kind: [KIND_NIL; L::MAX_SLOTS as usize],
            slot_valid: [false; L::MAX_SLOTS as usize],
            phi_copies: [PhiCopy {
                phi: 0,
                src: 0,
                vector: false,
            }; L::MAX_SLOTS as usize],
            phi_copy_count: 0,
            phi_stores: [PhiStore {
                slot: 0,
                vreg: 0,
                kind: 0,
            }; L::MAX_SLOTS as usize],
            phi_store_count: 0,
            reductions,
        };
        for slot in 0..L::MAX_SLOTS as usize {
            let node = slot_nodes[slot];
            if node != NO_OPERAND && (node as usize) < L::MAX_IR_NODES as usize {
                state.node_slot[node as usize] = slot as u16;
            }
        }
        let _ = trace;
        state.reductions = reductions;
        state
    }

    fn slot_of(&self, idx: usize) -> Option<usize> {
        let slot = self.node_slot[idx];
        if slot == NO_OPERAND {
            None
        } else {
            Some(slot as usize)
        }
    }
}

/// Emits the inline allocation preflight for traces containing TNEW nodes.
fn emit_prologue_alloc_check(trace: &IrTrace, body: &mut MirBody) -> Result<(), MirError> {
    let mut total = 0i32;
    for idx in 0..trace.count as usize {
        if trace.op[idx] == OP_TNEW {
            total += trace.imm[idx] * (ssl_config::target_model::heap_layout::CELL_BYTES as i32)
                + (ssl_config::target_model::heap_layout::HEADER_BYTES as i32);
        }
    }
    if total == 0 {
        return Ok(());
    }
    let insn = MirInsn {
        op: M_ALLOC_CHECK,
        dst: 0,
        src0: 0,
        src1: 0,
        imm: total,
        aux: ssl_config::limits::EXIT_ALLOC as u16,
    };
    let _ = body.push(insn).ok_or(MirError::InsnCapacity)?;
    Ok(())
}

/// Lowers one IR node into MIR records.
fn lower_node(
    trace: &IrTrace,
    idx: usize,
    body: &mut MirBody,
    state: &mut LoweringState,
) -> Result<(), MirError> {
    let op = trace.op[idx];
    match op {
        OP_PARAM => Ok(()),
        OP_CONST_I | OP_CONST_F => lower_const(trace, idx, body, state),
        OP_GUARD_INT | OP_GUARD_NUM => lower_type_guard(trace, idx, body, state),
        OP_GUARD_SHAPE => lower_shape_guard(trace, idx, body, state),
        OP_GUARD_BOOL => lower_bool_guard(trace, idx, body, state),
        OP_ADD_I | OP_SUB_I | OP_MUL_I => lower_int_arith(trace, idx, body, state),
        OP_ADD_F | OP_SUB_F | OP_MUL_F | OP_DIV_F => lower_float_arith(trace, idx, body, state),
        OP_LT_I | OP_LE_I | OP_EQ_I | OP_NE_I | OP_LT_F | OP_LE_F | OP_EQ_F | OP_NE_F => {
            lower_compare_value(trace, idx, body, state)
        }
        OP_INT2F => {
            let src = operand_vreg(trace, trace.in0[idx], state);
            let dst = body.new_vreg(VR_XMM, KIND_NUM).ok_or(MirError::VregCapacity)?;
            body.push(MirInsn {
                op: M_INT2F,
                dst,
                src0: src,
                src1: 0,
                imm: 0,
                aux: 0,
            })
            .ok_or(MirError::InsnCapacity)?;
            state.vregs[idx] = dst;
            state.node_vreg[idx] = true;
            Ok(())
        }
        OP_CALLM => {
            let src = operand_vreg(trace, trace.in0[idx], state);
            let dst = body.new_vreg(VR_XMM, KIND_NUM).ok_or(MirError::VregCapacity)?;
            body.push(MirInsn {
                op: M_CALLM,
                dst,
                src0: src,
                src1: 0,
                imm: trace.imm[idx],
                aux: 0,
            })
            .ok_or(MirError::InsnCapacity)?;
            state.vregs[idx] = dst;
            state.node_vreg[idx] = true;
            Ok(())
        }
        OP_TNEW => {
            let handle = body.new_vreg(VR_GPR, KIND_TBL).ok_or(MirError::VregCapacity)?;
            body.push(MirInsn {
                op: M_NEW_TABLE,
                dst: handle,
                src0: 0,
                src1: 0,
                imm: trace.imm[idx],
                aux: trace.aux[idx],
            })
            .ok_or(MirError::InsnCapacity)?;
            state.vregs[idx] = handle;
            state.node_vreg[idx] = true;
            Ok(())
        }
        OP_TGETI => {
            let table = table_vreg(trace, trace.in0[idx], state);
            let index = index_vreg(trace, trace.in1[idx], state);
            body.push(MirInsn {
                op: M_LOAD_ARR_SLOT,
                dst: 0,
                src0: table,
                src1: index,
                imm: trace.aux[idx] as i32,
                aux: idx as u16,
            })
            .ok_or(MirError::InsnCapacity)?;
            if let Some(slot) = state.slot_of(idx) {
                state.slot_valid[slot] = false;
            }
            Ok(())
        }
        OP_TSETI => {
            let table = table_vreg(trace, trace.in0[idx], state);
            let index = index_vreg(trace, trace.in1[idx], state);
            let (source_slot, source_vreg) = value_source(trace, trace.in2[idx], state);
            body.push(MirInsn {
                op: M_STORE_ARR_SLOT,
                dst: 0,
                src0: table,
                src1: index,
                imm: source_slot as i32,
                aux: source_vreg,
            })
            .ok_or(MirError::InsnCapacity)?;
            Ok(())
        }
        OP_GLOAD => {
            body.push(MirInsn {
                op: M_LOAD_G_SLOT,
                dst: 0,
                src0: 0,
                src1: 0,
                imm: trace.imm[idx],
                aux: trace.aux[idx],
            })
            .ok_or(MirError::InsnCapacity)?;
            if let Some(slot) = state.slot_of(idx) {
                state.slot_valid[slot] = false;
            }
            Ok(())
        }
        OP_GSTORE => {
            let (source_slot, _) = value_source(trace, trace.in0[idx], state);
            body.push(MirInsn {
                op: M_STORE_G_SLOT,
                dst: 0,
                src0: 0,
                src1: 0,
                imm: source_slot as i32,
                aux: trace.aux[idx],
            })
            .ok_or(MirError::InsnCapacity)?;
            Ok(())
        }
        OP_VLOAD_F => lower_vec_load(trace, idx, body, state),
        OP_VSTORE_F => lower_vec_store(trace, idx, body, state),
        OP_VADD_F | OP_VSUB_F | OP_VMUL_F => lower_vec_arith(trace, idx, body, state),
        OP_VPACK => lower_vec_pack(trace, idx, body, state),
        OP_HADD_F => lower_hadd(trace, idx, body, state),
        OP_PHI => lower_phi(trace, idx, body, state),
        _ => Ok(()),
    }
}

fn lower_const(
    trace: &IrTrace,
    idx: usize,
    body: &mut MirBody,
    state: &mut LoweringState,
) -> Result<(), MirError> {
    let is_float = trace.op[idx] == OP_CONST_F;
    let class = if is_float { VR_XMM } else { VR_GPR };
    let kind = if is_float { KIND_NUM } else { KIND_INT };
    let vreg = body.new_vreg(class, kind).ok_or(MirError::VregCapacity)?;
    let insn = MirInsn {
        op: if is_float { M_CONST_F } else { M_CONST_I },
        dst: vreg,
        src0: 0,
        src1: 0,
        imm: trace.imm[idx],
        aux: trace.aux[idx],
    };
    body.push(insn).ok_or(MirError::InsnCapacity)?;
    state.vregs[idx] = vreg;
    state.node_vreg[idx] = true;
    Ok(())
}

fn lower_type_guard(
    trace: &IrTrace,
    idx: usize,
    body: &mut MirBody,
    state: &mut LoweringState,
) -> Result<(), MirError> {
    let slot = trace.aux[idx] as usize;
    let kind = if trace.op[idx] == OP_GUARD_INT {
        KIND_INT
    } else {
        KIND_NUM
    };
    if state.slot_valid[slot] && state.slot_kind[slot] == kind {
        state.vregs[idx] = state.slot_vreg[slot];
        state.node_vreg[idx] = true;
        return Ok(());
    }
    let guard = MirInsn {
        op: M_GUARD,
        dst: 0,
        src0: 0,
        src1: 0,
        imm: if trace.op[idx] == OP_GUARD_INT {
            GUARD_KIND_INT
        } else {
            GUARD_KIND_NUM
        },
        aux: idx as u16,
    };
    body.push(guard).ok_or(MirError::InsnCapacity)?;
    record_snapshot(body, idx as u16, trace.pc[idx], state)?;
    let value_node = trace.in0[idx];
    let vreg = body.new_vreg(VR_GPR, kind).ok_or(MirError::VregCapacity)?;
    body.push(MirInsn {
        op: M_LOAD_SLOT,
        dst: vreg,
        src0: 0,
        src1: 0,
        imm: slot as i32,
        aux: kind as u16,
    })
    .ok_or(MirError::InsnCapacity)?;
    if value_node != NO_OPERAND {
        state.vregs[value_node as usize] = vreg;
        state.node_vreg[value_node as usize] = true;
    }
    state.vregs[idx] = vreg;
    state.node_vreg[idx] = true;
    state.slot_vreg[slot] = vreg;
    state.slot_kind[slot] = kind;
    state.slot_valid[slot] = true;
    Ok(())
}

fn lower_shape_guard(
    trace: &IrTrace,
    idx: usize,
    body: &mut MirBody,
    state: &mut LoweringState,
) -> Result<(), MirError> {
    let slot = trace.aux[idx] as usize;
    if state.slot_valid[slot] && state.slot_kind[slot] == KIND_TBL {
        state.vregs[idx] = state.slot_vreg[slot];
        state.node_vreg[idx] = true;
        return Ok(());
    }
    let guard = MirInsn {
        op: M_GUARD_SHAPE,
        dst: 0,
        src0: 0,
        src1: 0,
        imm: 0,
        aux: idx as u16,
    };
    body.push(guard).ok_or(MirError::InsnCapacity)?;
    record_snapshot(body, idx as u16, trace.pc[idx], state)?;
    let value_node = trace.in0[idx];
    let vreg = body.new_vreg(VR_GPR, KIND_TBL).ok_or(MirError::VregCapacity)?;
    body.push(MirInsn {
        op: M_LOAD_SLOT,
        dst: vreg,
        src0: 0,
        src1: 0,
        imm: slot as i32,
        aux: KIND_TBL as u16,
    })
    .ok_or(MirError::InsnCapacity)?;
    if value_node != NO_OPERAND {
        state.vregs[value_node as usize] = vreg;
        state.node_vreg[value_node as usize] = true;
    }
    state.vregs[idx] = vreg;
    state.node_vreg[idx] = true;
    state.slot_vreg[slot] = vreg;
    state.slot_kind[slot] = KIND_TBL;
    state.slot_valid[slot] = true;
    Ok(())
}

fn lower_bool_guard(
    trace: &IrTrace,
    idx: usize,
    body: &mut MirBody,
    state: &mut LoweringState,
) -> Result<(), MirError> {
    let cond = trace.in0[idx];
    if cond == NO_OPERAND {
        return Ok(());
    }
    let cond_idx = cond as usize;
    let float = matches!(
        trace.op[cond_idx],
        OP_LT_F | OP_LE_F | OP_EQ_F | OP_NE_F
    );
    let lhs = operand_vreg(trace, trace.in0[cond_idx], state);
    let rhs = operand_vreg(trace, trace.in1[cond_idx], state);
    let code = compare_code(trace.op[cond_idx]);
    body.push(MirInsn {
        op: if float { M_CMP_F } else { M_CMP_I },
        dst: 0,
        src0: lhs,
        src1: rhs,
        imm: code,
        aux: 0,
    })
    .ok_or(MirError::InsnCapacity)?;
    let expected = trace.imm[idx] != 0;
    body.push(MirInsn {
        op: M_GUARD_FLAG,
        dst: 0,
        src0: code as u16,
        src1: float as u16,
        imm: expected as i32,
        aux: idx as u16,
    })
    .ok_or(MirError::InsnCapacity)?;
    record_snapshot(body, idx as u16, trace.pc[idx], state)
}

fn lower_int_arith(
    trace: &IrTrace,
    idx: usize,
    body: &mut MirBody,
    state: &mut LoweringState,
) -> Result<(), MirError> {
    let dst = body.new_vreg(VR_GPR, KIND_INT).ok_or(MirError::VregCapacity)?;
    body.push(MirInsn {
        op: match trace.op[idx] {
            OP_ADD_I => M_ADD_I,
            OP_SUB_I => M_SUB_I,
            _ => M_MUL_I,
        },
        dst,
        src0: operand_vreg(trace, trace.in0[idx], state),
        src1: operand_vreg(trace, trace.in1[idx], state),
        imm: 0,
        aux: 0,
    })
    .ok_or(MirError::InsnCapacity)?;
    state.vregs[idx] = dst;
    state.node_vreg[idx] = true;
    Ok(())
}

fn lower_float_arith(
    trace: &IrTrace,
    idx: usize,
    body: &mut MirBody,
    state: &mut LoweringState,
) -> Result<(), MirError> {
    let dst = body.new_vreg(VR_XMM, KIND_NUM).ok_or(MirError::VregCapacity)?;
    body.push(MirInsn {
        op: match trace.op[idx] {
            OP_ADD_F => M_ADD_F,
            OP_SUB_F => M_SUB_F,
            OP_MUL_F => M_MUL_F,
            _ => M_DIV_F,
        },
        dst,
        src0: operand_vreg(trace, trace.in0[idx], state),
        src1: operand_vreg(trace, trace.in1[idx], state),
        imm: 0,
        aux: 0,
    })
    .ok_or(MirError::InsnCapacity)?;
    state.vregs[idx] = dst;
    state.node_vreg[idx] = true;
    Ok(())
}

fn lower_compare_value(
    trace: &IrTrace,
    idx: usize,
    body: &mut MirBody,
    state: &mut LoweringState,
) -> Result<(), MirError> {
    let float = matches!(
        trace.op[idx],
        OP_LT_F | OP_LE_F | OP_EQ_F | OP_NE_F
    );
    let lhs = operand_vreg(trace, trace.in0[idx], state);
    let rhs = operand_vreg(trace, trace.in1[idx], state);
    let code = compare_code(trace.op[idx]);
    body.push(MirInsn {
        op: if float { M_CMP_F } else { M_CMP_I },
        dst: 0,
        src0: lhs,
        src1: rhs,
        imm: code,
        aux: 0,
    })
    .ok_or(MirError::InsnCapacity)?;
    let dst = body.new_vreg(VR_GPR, KIND_BOOL).ok_or(MirError::VregCapacity)?;
    let float = matches!(
        trace.op[idx],
        OP_LT_F | OP_LE_F | OP_EQ_F | OP_NE_F
    );
    body.push(MirInsn {
        op: M_SET_BOOL,
        dst,
        src0: 0,
        src1: 0,
        imm: code as i32 | ((float as i32) << 8),
        aux: 0,
    })
    .ok_or(MirError::InsnCapacity)?;
    state.vregs[idx] = dst;
    state.node_vreg[idx] = true;
    if let Some(slot) = state.slot_of(idx) {
        state.slot_vreg[slot] = dst;
        state.slot_kind[slot] = KIND_BOOL;
        state.slot_valid[slot] = true;
    }
    Ok(())
}

fn lower_vec_load(
    trace: &IrTrace,
    idx: usize,
    body: &mut MirBody,
    state: &mut LoweringState,
) -> Result<(), MirError> {
    let table = table_vreg(trace, trace.in0[idx], state);
    let index = index_vreg(trace, trace.in1[idx], state);
    let dst = body.new_vreg(VR_XMM, KIND_NUM).ok_or(MirError::VregCapacity)?;
    body.push(MirInsn {
        op: M_VEC_LOAD,
        dst,
        src0: table,
        src1: index,
        imm: 0,
        aux: idx as u16,
    })
    .ok_or(MirError::InsnCapacity)?;
    state.vregs[idx] = dst;
    state.node_vreg[idx] = true;
    Ok(())
}

fn lower_vec_store(
    trace: &IrTrace,
    idx: usize,
    body: &mut MirBody,
    state: &mut LoweringState,
) -> Result<(), MirError> {
    let table = table_vreg(trace, trace.in0[idx], state);
    let index = index_vreg(trace, trace.in1[idx], state);
    let value = operand_vreg(trace, trace.in2[idx], state);
    let written = body.push(MirInsn {
        op: M_VEC_STORE,
        dst: 0,
        src0: table,
        src1: index,
        imm: value as i32,
        aux: idx as u16,
    });
    if written.is_none() {
        return Err(MirError::InsnCapacity);
    }
    Ok(())
}

fn lower_vec_arith(
    trace: &IrTrace,
    idx: usize,
    body: &mut MirBody,
    state: &mut LoweringState,
) -> Result<(), MirError> {
    let lhs = operand_vreg(trace, trace.in0[idx], state);
    let rhs = operand_vreg(trace, trace.in1[idx], state);
    let dst = body.new_vreg(VR_XMM, KIND_NUM).ok_or(MirError::VregCapacity)?;
    body.push(MirInsn {
        op: match trace.op[idx] {
            OP_VADD_F => M_VEC_ADD,
            OP_VSUB_F => M_VEC_SUB,
            _ => M_VEC_MUL,
        },
        dst,
        src0: lhs,
        src1: rhs,
        imm: 0,
        aux: 0,
    })
    .ok_or(MirError::InsnCapacity)?;
    state.vregs[idx] = dst;
    state.node_vreg[idx] = true;
    Ok(())
}

fn lower_vec_pack(
    trace: &IrTrace,
    idx: usize,
    body: &mut MirBody,
    state: &mut LoweringState,
) -> Result<(), MirError> {
    let lo = operand_vreg(trace, trace.in0[idx], state);
    let hi = operand_vreg(trace, trace.in1[idx], state);
    let dst = body.new_vreg(VR_XMM, KIND_NUM).ok_or(MirError::VregCapacity)?;
    body.push(MirInsn {
        op: M_VEC_PACK,
        dst,
        src0: lo,
        src1: hi,
        imm: 0,
        aux: 0,
    })
    .ok_or(MirError::InsnCapacity)?;
    state.vregs[idx] = dst;
    state.node_vreg[idx] = true;
    Ok(())
}

fn lower_hadd(
    trace: &IrTrace,
    idx: usize,
    body: &mut MirBody,
    state: &mut LoweringState,
) -> Result<(), MirError> {
    let src = operand_vreg(trace, trace.in0[idx], state);
    let dst = body.new_vreg(VR_XMM, KIND_NUM).ok_or(MirError::VregCapacity)?;
    body.push(MirInsn {
        op: M_VEC_HADD,
        dst,
        src0: src,
        src1: 0,
        imm: 0,
        aux: trace.aux[idx],
    })
    .ok_or(MirError::InsnCapacity)?;
    state.vregs[idx] = dst;
    state.node_vreg[idx] = true;
    for reduction in state.reductions {
        if reduction.hadd == idx as u16 {
            state.slot_vreg[reduction.slot as usize] = dst;
            state.slot_kind[reduction.slot as usize] = KIND_NUM;
            state.slot_valid[reduction.slot as usize] = true;
        }
    }
    Ok(())
}

fn lower_phi(
    trace: &IrTrace,
    idx: usize,
    body: &mut MirBody,
    state: &mut LoweringState,
) -> Result<(), MirError> {
    let vector = trace.ty[idx] == TY_VEC;
    let class = if vector { VR_XMM } else { VR_GPR };
    let dst = body.new_vreg(class, KIND_NUM).ok_or(MirError::VregCapacity)?;
    let preheader = trace.in0[idx];
    let src = operand_vreg(trace, preheader, state);
    if src != 0 {
        body.push(MirInsn {
            op: if vector { M_MOV_F } else { M_MOV_I },
            dst,
            src0: src,
            src1: 0,
            imm: 0,
            aux: 0,
        })
        .ok_or(MirError::InsnCapacity)?;
    }
    let backedge = trace.in1[idx];
    if backedge != NO_OPERAND {
        let back_src = operand_vreg(trace, backedge, state);
        if state.phi_copy_count < state.phi_copies.len() {
            state.phi_copies[state.phi_copy_count] = PhiCopy {
                phi: dst,
                src: back_src,
                vector,
            };
            state.phi_copy_count += 1;
        }
    }
    state.vregs[idx] = dst;
    state.node_vreg[idx] = true;
    if let Some(slot) = state.slot_of(idx) {
        if state.phi_store_count < state.phi_stores.len() {
            state.phi_stores[state.phi_store_count] = PhiStore {
                slot,
                vreg: dst,
                kind: KIND_INT,
            };
            state.phi_store_count += 1;
        }
    }
    Ok(())
}

fn operand_vreg(trace: &IrTrace, node: u16, state: &LoweringState) -> u16 {
    if node == NO_OPERAND || !state.node_vreg[node as usize] {
        return 0;
    }
    state.vregs[node as usize]
}

fn table_vreg(trace: &IrTrace, node: u16, state: &LoweringState) -> u16 {
    operand_vreg(trace, node, state)
}

fn index_vreg(trace: &IrTrace, node: u16, state: &LoweringState) -> u16 {
    operand_vreg(trace, node, state)
}

/// Resolves one value source as a boxed slot index or a typed vreg.
fn value_source(trace: &IrTrace, node: u16, state: &LoweringState) -> (u16, u16) {
    if node != NO_OPERAND && state.node_vreg[node as usize] {
        return (0, state.vregs[node as usize]);
    }
    if node != NO_OPERAND {
        let slot = trace.aux[node as usize];
        if (slot as usize) < L::MAX_SLOTS as usize {
            return (slot, 0);
        }
    }
    (0, 0)
}

fn compare_code(op: u16) -> i32 {
    match op {
        OP_LT_I | OP_LT_F => 0,
        OP_LE_I | OP_LE_F => 1,
        OP_EQ_I | OP_EQ_F => 2,
        _ => 3,
    }
}

/// Maps a kind to its heap tag value for slot stores.
fn kind_tag_of(kind: u8) -> u64 {
    match kind {
        KIND_INT => crate::vm_value::TAG_INT,
        KIND_NUM => crate::vm_value::TAG_NUM,
        KIND_BOOL => crate::vm_value::TAG_BOOL,
        KIND_STR => crate::vm_value::TAG_STR,
        _ => crate::vm_value::TAG_TBL,
    }
}

/// Records one snapshot from the current slot-to-vreg state.
fn record_snapshot(
    body: &mut MirBody,
    guard_id: u16,
    resume_pc: u32,
    state: &LoweringState,
) -> Result<(), MirError> {
    let mut entries: [SnapEntry; L::MAX_SLOTS as usize] = [SnapEntry {
        slot: 0,
        vreg: 0,
        kind: 0,
    }; L::MAX_SLOTS as usize];
    let mut count = 0usize;
    for slot in 0..L::MAX_SLOTS as usize {
        if state.slot_valid[slot] && state.slot_vreg[slot] != 0 {
            entries[count] = SnapEntry {
                slot: slot as u8,
                vreg: state.slot_vreg[slot],
                kind: state.slot_kind[slot],
            };
            count += 1;
        }
    }
    if body.add_snapshot(guard_id, resume_pc, &entries[..count]) {
        Ok(())
    } else {
        Err(MirError::SnapshotCapacity)
    }
}
