// CEP:FILE: hot/src/ir_build.rs
// CEP:WHAT: Graphification and incremental GVN: converts the linear trace buffer into the SoA Sea of Nodes while deduplicating pure nodes and guards through a flat hash table.
// CEP:WHY: design.md Part 5.1 mandates single-pass graphification with O(1) incremental value numbering; lazy parameter nodes and backedge phis give correct loop-carried data flow without control-flow-graph construction.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns BuildError when node or GVN capacity is exhausted or the buffer contains an unsupported opcode; never panics.
// CEP:ASSUMES: the trace buffer is one closed loop iteration ending at a backedge; slots not read in the body need no phi.
// CEP:COST: O(N) over recorded ops with O(1) hashed dedup per node; no allocation.
// CEP:EVIDENCE: golden IR tests; verifier runs after every build in tests.

use crate::bytecode as bc;
use crate::ir::*;
use crate::record::{TraceBuffer, TraceOp, OBS_INT, OBS_NUM, OBS_TBL};
use ssl_config::limits as L;

/// Graphification failure enumeration.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum BuildError {
    /// IR node capacity exhausted.
    NodeCapacity,
    /// GVN table capacity exhausted.
    GvnCapacity,
    /// Recorded opcode has no IR lowering.
    UnsupportedOpcode(u8),
}

/// GVN empty-slot sentinel for the open-addressing table.
const GVN_EMPTY: u16 = 0xFFFF;

/// Result of graphifying one trace.
pub struct BuildOutput {
    /// Built IR arrays.
    pub trace: IrTrace,
    /// Final per-slot node indices after the backedge (phi nodes included).
    pub slot_nodes: [u16; L::MAX_SLOTS as usize],
    /// First node index inside the loop body (pre-header end).
    pub body_start: u16,
}

struct GvnTable {
    slots: [u16; L::MAX_GVN_SLOTS as usize],
}

impl GvnTable {
    fn new() -> GvnTable {
        GvnTable {
            slots: [GVN_EMPTY; L::MAX_GVN_SLOTS as usize],
        }
    }

    fn lookup(&self, trace: &IrTrace, candidate: u16) -> Option<u16> {
        let mut slot = (signature(trace, candidate) % L::MAX_GVN_SLOTS as u64) as usize;
        for _ in 0..L::MAX_GVN_SLOTS {
            let entry = self.slots[slot];
            if entry == GVN_EMPTY {
                return None;
            }
            if same_signature(trace, entry, candidate) {
                return Some(entry);
            }
            slot = (slot + 1) % L::MAX_GVN_SLOTS as usize;
        }
        None
    }

    fn insert(&mut self, trace: &IrTrace, idx: u16) -> Result<(), BuildError> {
        let mut slot = (signature(trace, idx) % L::MAX_GVN_SLOTS as u64) as usize;
        for _ in 0..L::MAX_GVN_SLOTS {
            let entry = self.slots[slot];
            if entry == GVN_EMPTY {
                self.slots[slot] = idx;
                return Ok(());
            }
            if same_signature(trace, entry, idx) {
                return Ok(());
            }
            slot = (slot + 1) % L::MAX_GVN_SLOTS as usize;
        }
        Err(BuildError::GvnCapacity)
    }
}

/// Builder state: environment plus dedup table.
pub struct Builder {
    trace: IrTrace,
    env: [u16; L::MAX_SLOTS as usize],
    params: [u16; L::MAX_SLOTS as usize],
    gvn: GvnTable,
    mem_last: u16,
}

impl Builder {
    pub fn new() -> Builder {
        Builder {
            trace: IrTrace::new(),
            env: [NO_OPERAND; L::MAX_SLOTS as usize],
            params: [NO_OPERAND; L::MAX_SLOTS as usize],
            gvn: GvnTable::new(),
            mem_last: NO_OPERAND,
        }
    }

    /// Returns the node for one slot, creating its pre-header parameter on first read.
    fn param(&mut self, slot: u8) -> Result<u16, BuildError> {
        let idx = slot as usize;
        if self.env[idx] != NO_OPERAND {
            return Ok(self.env[idx]);
        }
        let node = self
            .trace
            .push(OP_PARAM, TY_ANY, NO_OPERAND, NO_OPERAND, NO_OPERAND, slot as i32, slot as u16, 0)
            .ok_or(BuildError::NodeCapacity)?;
        self.trace.pc[node as usize] = 0;
        self.params[idx] = node;
        self.env[idx] = node;
        Ok(node)
    }

    /// Pushes one node through the GVN table, returning the deduplicated index.
    fn push_pure(&mut self, node: u16) -> Result<u16, BuildError> {
        if let Some(existing) = self.gvn.lookup(&self.trace, node) {
            drop_node(&mut self.trace, node);
            add_use(&mut self.trace, existing);
            return Ok(existing);
        }
        self.gvn.insert(&self.trace, node)?;
        Ok(node)
    }

    /// Pushes one node that references operands with use counting.
    fn push_node(
        &mut self,
        op: u16,
        ty: u8,
        in0: u16,
        in1: u16,
        in2: u16,
        imm: i32,
        aux: u16,
        flags: u16,
        pc: u32,
    ) -> Result<u16, BuildError> {
        let node = self
            .trace
            .push(op, ty, in0, in1, in2, imm, aux, flags)
            .ok_or(BuildError::NodeCapacity)?;
        self.trace.pc[node as usize] = pc;
        add_use(&mut self.trace, in0);
        add_use(&mut self.trace, in1);
        add_use(&mut self.trace, in2);
        Ok(node)
    }

    /// Emits a type guard for one value node with the observed type.
    fn guard_value(&mut self, value: u16, obs: u8, slot: u8) -> Result<u16, BuildError> {
        let (op, ty) = match obs {
            OBS_INT => (OP_GUARD_INT, TY_INT),
            OBS_NUM => (OP_GUARD_NUM, TY_NUM),
            _ => return Ok(value),
        };
        let guard = self.push_node(op, ty, value, NO_OPERAND, NO_OPERAND, 0, slot as u16, FLAG_SIDE_EFFECT, 0)?;
        self.push_pure(guard)
    }

    /// Emits the array-shape guard for one table node.
    fn guard_shape(&mut self, table: u16, slot: u8) -> Result<u16, BuildError> {
        let guard = self.push_node(
            OP_GUARD_SHAPE,
            TY_TBL,
            table,
            NO_OPERAND,
            NO_OPERAND,
            0,
            slot as u16,
            FLAG_SIDE_EFFECT,
            0,
        )?;
        self.push_pure(guard)
    }

    /// Chains a memory-producing node into the abstract memory order.
    fn memory_node(&mut self, node: u16) {
        self.trace.mem_in[node as usize] = self.mem_last;
        self.mem_last = node;
    }
}

/// Converts one recorded iteration into the SoA IR with incremental GVN.
pub fn build_trace(buffer: &TraceBuffer) -> Result<BuildOutput, BuildError> {
    let mut builder = Builder::new();
    for idx in 0..buffer.count as usize {
        let op = &buffer.ops[idx];
        lower_op(&mut builder, op)?;
    }
    close_backedge(&mut builder, buffer)?;
    Ok(BuildOutput {
        trace: builder.trace,
        slot_nodes: builder.env,
        body_start: 0,
    })
}

/// Lowers one recorded bytecode operation into IR nodes.
fn lower_op(builder: &mut Builder, op: &TraceOp) -> Result<(), BuildError> {
    match op.bc_op {
        bc::OP_LOADK => lower_loadk(builder, op),
        bc::OP_MOVE => {
            let value = builder.param(op.b)?;
            builder.env[op.a as usize] = value;
            Ok(())
        }
        bc::OP_ADDI => {
            let lhs = builder.param(op.b)?;
            let guarded = builder.guard_value(lhs, op.lhs_ty, op.b)?;
            let k = builder.push_node(OP_CONST_I, TY_INT, NO_OPERAND, NO_OPERAND, NO_OPERAND, op.imm, 0, 0, op.pc)?;
            let k = builder.push_pure(k)?;
            let sum = builder.push_node(OP_ADD_I, TY_INT, guarded, k, NO_OPERAND, 0, op.a as u16, 0, op.pc)?;
            builder.env[op.a as usize] = builder.push_pure(sum)?;
            Ok(())
        }
        bc::OP_ADD | bc::OP_SUB | bc::OP_MUL | bc::OP_DIV => lower_arith(builder, op),
        bc::OP_LT | bc::OP_LE | bc::OP_EQ | bc::OP_GT | bc::OP_GE | bc::OP_NE => {
            lower_compare(builder, op)
        }
        bc::OP_JMP => Ok(()),
        bc::OP_JMPIF | bc::OP_JMPNOT => {
            let cond = builder.param(op.a)?;
            let expected = if op.bc_op == bc::OP_JMPIF {
                op.taken
            } else {
                !op.taken
            };
            let _ = builder.push_node(
                OP_GUARD_BOOL,
                TY_BOOL,
                cond,
                NO_OPERAND,
                NO_OPERAND,
                expected as i32,
                op.a as u16,
                FLAG_SIDE_EFFECT,
                op.pc,
            )?;
            Ok(())
        }
        bc::OP_TNEW => {
            let node = builder.push_node(OP_TNEW, TY_TBL, NO_OPERAND, NO_OPERAND, NO_OPERAND, op.imm, op.a as u16, FLAG_MEMORY | FLAG_SIDE_EFFECT, op.pc)?;
            builder.memory_node(node);
            builder.env[op.a as usize] = node;
            Ok(())
        }
        bc::OP_TGETI => {
            let table = builder.param(op.b)?;
            let table = builder.guard_shape(table, op.b)?;
            let idx_val = builder.param(op.c)?;
            let idx_val = builder.guard_value(idx_val, op.rhs_ty, op.c)?;
            let load = builder.push_node(OP_TGETI, TY_ANY, table, idx_val, NO_OPERAND, 0, op.a as u16, FLAG_MEMORY, op.pc)?;
            builder.memory_node(load);
            builder.env[op.a as usize] = load;
            Ok(())
        }
        bc::OP_TSETI => {
            let table = builder.param(op.b)?;
            let table = builder.guard_shape(table, op.b)?;
            let idx_val = builder.param(op.c)?;
            let idx_val = builder.guard_value(idx_val, op.rhs_ty, op.c)?;
            let val = builder.param(op.a)?;
            let store = builder.push_node(OP_TSETI, TY_ANY, table, idx_val, val, 0, 0, FLAG_MEMORY | FLAG_SIDE_EFFECT, op.pc)?;
            builder.memory_node(store);
            builder.env[op.a as usize] = val;
            Ok(())
        }
        bc::OP_GGET => {
            let load = builder.push_node(OP_GLOAD, TY_ANY, NO_OPERAND, NO_OPERAND, NO_OPERAND, op.c as i32, op.c as u16, FLAG_MEMORY, op.pc)?;
            builder.memory_node(load);
            builder.env[op.a as usize] = load;
            Ok(())
        }
        bc::OP_GSET => {
            let val = builder.param(op.a)?;
            let store = builder.push_node(OP_GSTORE, TY_ANY, val, NO_OPERAND, NO_OPERAND, op.c as i32, op.c as u16, FLAG_MEMORY | FLAG_SIDE_EFFECT, op.pc)?;
            builder.memory_node(store);
            builder.env[op.a as usize] = val;
            Ok(())
        }
        bc::OP_CALLM => {
            let arg = builder.param(op.c)?;
            let arg = builder.guard_value(arg, op.lhs_ty, op.c)?;
            let call = builder.push_node(OP_CALLM, result_ty(op), arg, NO_OPERAND, NO_OPERAND, op.imm as i32, op.a as u16, 0, op.pc)?;
            builder.env[op.a as usize] = builder.push_pure(call)?;
            Ok(())
        }
        bc::OP_RET | bc::OP_PRINT => Err(BuildError::UnsupportedOpcode(op.bc_op)),
        _ => Err(BuildError::UnsupportedOpcode(op.bc_op)),
    }
}

fn result_ty(op: &TraceOp) -> u8 {
    if op.res_ty == OBS_INT {
        TY_INT
    } else {
        TY_NUM
    }
}

fn lower_loadk(builder: &mut Builder, op: &TraceOp) -> Result<(), BuildError> {
    let const_index = op.b as u32 | (op.c as u32) << 8;
    let node = builder.push_node(
        OP_CONST_I,
        TY_ANY,
        NO_OPERAND,
        NO_OPERAND,
        NO_OPERAND,
        const_index as i32,
        op.a as u16,
        0,
        op.pc,
    )?;
    builder.env[op.a as usize] = builder.push_pure(node)?;
    Ok(())
}

fn as_float(builder: &mut Builder, node: u16, obs: u8) -> Result<u16, BuildError> {
    if obs == OBS_INT {
        let conv = builder.push_node(OP_INT2F, TY_NUM, node, NO_OPERAND, NO_OPERAND, 0, 0, 0, 0)?;
        return builder.push_pure(conv);
    }
    Ok(node)
}

fn lower_arith(builder: &mut Builder, op: &TraceOp) -> Result<(), BuildError> {
    let lhs = builder.param(op.b)?;
    let rhs = builder.param(op.c)?;
    let lhs_g = builder.guard_value(lhs, op.lhs_ty, op.b)?;
    let rhs_g = builder.guard_value(rhs, op.rhs_ty, op.c)?;
    let float_op = op.bc_op == bc::OP_DIV || op.lhs_ty == OBS_NUM || op.rhs_ty == OBS_NUM;
    if float_op {
        let l = as_float(builder, lhs_g, op.lhs_ty)?;
        let r = as_float(builder, rhs_g, op.rhs_ty)?;
        let arith_op = match op.bc_op {
            bc::OP_ADD => OP_ADD_F,
            bc::OP_SUB => OP_SUB_F,
            bc::OP_MUL => OP_MUL_F,
            _ => OP_DIV_F,
        };
        let sum = builder.push_node(arith_op, TY_NUM, l, r, NO_OPERAND, 0, op.a as u16, 0, op.pc)?;
        builder.env[op.a as usize] = builder.push_pure(sum)?;
    } else {
        let arith_op = match op.bc_op {
            bc::OP_ADD => OP_ADD_I,
            bc::OP_SUB => OP_SUB_I,
            _ => OP_MUL_I,
        };
        let sum = builder.push_node(arith_op, TY_INT, lhs_g, rhs_g, NO_OPERAND, 0, op.a as u16, 0, op.pc)?;
        builder.env[op.a as usize] = builder.push_pure(sum)?;
    }
    Ok(())
}

fn lower_compare(builder: &mut Builder, op: &TraceOp) -> Result<(), BuildError> {
    let lhs = builder.param(op.b)?;
    let rhs = builder.param(op.c)?;
    let lhs_g = builder.guard_value(lhs, op.lhs_ty, op.b)?;
    let rhs_g = builder.guard_value(rhs, op.rhs_ty, op.c)?;
    let float = op.lhs_ty == OBS_NUM || op.rhs_ty == OBS_NUM;
    let (l, r) = if float {
        (
            as_float(builder, lhs_g, op.lhs_ty)?,
            as_float(builder, rhs_g, op.rhs_ty)?,
        )
    } else {
        (lhs_g, rhs_g)
    };
    let (cmp_op, a, b) = match (op.bc_op, float) {
        (bc::OP_LT, false) => (OP_LT_I, l, r),
        (bc::OP_LE, false) => (OP_LE_I, l, r),
        (bc::OP_EQ, false) => (OP_EQ_I, l, r),
        (bc::OP_NE, false) => (OP_NE_I, l, r),
        (bc::OP_GT, false) => (OP_LT_I, r, l),
        (bc::OP_GE, false) => (OP_LE_I, r, l),
        (bc::OP_LT, true) => (OP_LT_F, l, r),
        (bc::OP_LE, true) => (OP_LE_F, l, r),
        (bc::OP_EQ, true) => (OP_EQ_F, l, r),
        (bc::OP_NE, true) => (OP_NE_F, l, r),
        (bc::OP_GT, true) => (OP_LT_F, r, l),
        _ => (OP_LE_F, r, l),
    };
    let cmp = builder.push_node(cmp_op, TY_BOOL, a, b, NO_OPERAND, 0, op.a as u16, 0, op.pc)?;
    builder.env[op.a as usize] = builder.push_pure(cmp)?;
    Ok(())
}

/// Creates phi nodes for loop-carried slots and finalizes the builder.
fn close_backedge(builder: &mut Builder, buffer: &TraceBuffer) -> Result<(), BuildError> {
    let _ = buffer;
    for slot in 0..L::MAX_SLOTS as usize {
        let current = builder.env[slot];
        let param = builder.params[slot];
        if param != NO_OPERAND && current != param && current != NO_OPERAND {
            let phi = builder.push_node(
                OP_PHI,
                TY_ANY,
                param,
                current,
                NO_OPERAND,
                0,
                slot as u16,
                FLAG_SIDE_EFFECT,
                buffer.header_pc,
            )?;
            builder.env[slot] = phi;
        }
    }
    Ok(())
}

/// Releases a just-created node that GVN deduplicated away, returning operand references.
fn drop_node(trace: &mut IrTrace, node: u16) {
    drop_use(trace, trace.in0[node as usize]);
    drop_use(trace, trace.in1[node as usize]);
    drop_use(trace, trace.in2[node as usize]);
    trace.op[node as usize] = OP_NOP;
    trace.count -= 1;
}
