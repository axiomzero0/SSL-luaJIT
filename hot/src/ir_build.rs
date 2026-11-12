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
use crate::mir_build::{KIND_BOOL, KIND_INT, KIND_NIL, KIND_NUM, KIND_TBL};
use crate::record::{TraceBuffer, TraceOp, OBS_BOOL, OBS_INT, OBS_NONE, OBS_NUM, OBS_TBL};
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
    phis: [u16; L::MAX_SLOTS as usize],
    gvn: GvnTable,
    mem_last: u16,
}

impl Builder {
    pub fn new() -> Builder {
        Builder {
            trace: IrTrace::new(),
            env: [NO_OPERAND; L::MAX_SLOTS as usize],
            params: [NO_OPERAND; L::MAX_SLOTS as usize],
            phis: [NO_OPERAND; L::MAX_SLOTS as usize],
            gvn: GvnTable::new(),
            mem_last: NO_OPERAND,
        }
    }

    /// Pre-creates the loop-carried phi for one slot written inside the trace.
    /// Body reads must observe the previous iteration's final value, which is the
    /// phi, not the trace-entry parameter; the backedge input is patched at close.
    fn prepare_loop_carried(&mut self, slot: u8, header_pc: u32) -> Result<(), BuildError> {
        let idx = slot as usize;
        let param = self.param(slot)?;
        let phi = self.push_node(
            OP_PHI,
            TY_ANY,
            param,
            param,
            NO_OPERAND,
            0,
            slot as u16,
            FLAG_SIDE_EFFECT,
            header_pc,
        )?;
        self.phis[idx] = phi;
        self.env[idx] = phi;
        Ok(())
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

    /// Emits a type guard for one value node with the observed type. The
    /// guard's recorded pc is the CONSUMING operation's pc: a guard exit must
    /// resume there, not at bytecode zero (which would re-run the whole
    /// program prologue on every deopt).
    fn guard_value(&mut self, value: u16, obs: u8, slot: u8, pc: u32) -> Result<u16, BuildError> {
        let (op, ty) = match obs {
            OBS_INT => (OP_GUARD_INT, TY_INT),
            OBS_NUM => (OP_GUARD_NUM, TY_NUM),
            _ => return Ok(value),
        };
        let guard = self.push_node(op, ty, value, NO_OPERAND, NO_OPERAND, 0, slot as u16, FLAG_SIDE_EFFECT, pc)?;
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

/// Reports whether one recorded opcode writes its `a` field as a frame slot.
fn op_writes_slot(op: u8) -> bool {
    matches!(
        op,
        bc::OP_LOADK
            | bc::OP_MOVE
            | bc::OP_ADDI
            | bc::OP_ADD
            | bc::OP_SUB
            | bc::OP_MUL
            | bc::OP_DIV
            | bc::OP_LT
            | bc::OP_LE
            | bc::OP_EQ
            | bc::OP_GT
            | bc::OP_GE
            | bc::OP_NE
            | bc::OP_TNEW
            | bc::OP_TGETI
            | bc::OP_TGETK
            | bc::OP_GGET
            | bc::OP_CALLM
    )
}

/// Converts one recorded iteration into the SoA IR with incremental GVN.
/// The program's constant pool resolves LOADK values so const nodes carry raw
/// values (never pool indices) downstream; ADDI immediates join the same rule.
pub fn build_trace(buffer: &TraceBuffer, consts: &[bc::Const]) -> Result<BuildOutput, BuildError> {
    let mut builder = Builder::new();
    // Pre-pass: every slot written inside the loop is loop-carried; its body reads
    // must bind to a header phi, not to the trace-entry parameter.
    let mut written = [false; L::MAX_SLOTS as usize];
    for idx in 0..buffer.count as usize {
        let op = &buffer.ops[idx];
        if op_writes_slot(op.bc_op) {
            written[op.a as usize] = true;
        }
    }
    for slot in 0..L::MAX_SLOTS as usize {
        if written[slot] {
            builder.prepare_loop_carried(slot as u8, buffer.header_pc)?;
        }
    }
    for idx in 0..buffer.count as usize {
        let op = &buffer.ops[idx];
        lower_op(&mut builder, op, idx, buffer, consts)?;
    }
    close_backedge(&mut builder, buffer)?;
    Ok(BuildOutput {
        trace: builder.trace,
        slot_nodes: builder.env,
        body_start: 0,
    })
}

/// Lowers one recorded bytecode operation into IR nodes.
fn lower_op(
    builder: &mut Builder,
    op: &TraceOp,
    op_idx: usize,
    buffer: &TraceBuffer,
    consts: &[bc::Const],
) -> Result<(), BuildError> {
    let _ = buffer;
    match op.bc_op {
        bc::OP_LOADK => lower_loadk(builder, op, consts),
        bc::OP_MOVE => {
            let value = builder.param(op.b)?;
            // Materialize the copy as a side-effecting slot store so the machine
            // keeps the destination slot's memory in sync with the interpreter;
            // later slot loads (guards) and deopt reads depend on that memory.
            // The recorded result type gives the store its static tag.
            let kind = match op.res_ty {
                OBS_INT => KIND_INT,
                OBS_NUM => KIND_NUM,
                OBS_BOOL => KIND_BOOL,
                OBS_TBL => KIND_TBL,
                _ => KIND_NIL,
            };
            let node = builder.push_node(
                OP_COPY_S,
                TY_ANY,
                value,
                NO_OPERAND,
                NO_OPERAND,
                kind as i32,
                op.a as u16,
                FLAG_SIDE_EFFECT,
                op.pc,
            )?;
            builder.env[op.a as usize] = node;
            Ok(())
        }
        bc::OP_ADDI => {
            let lhs = builder.param(op.b)?;
            let guarded = builder.guard_value(lhs, op.lhs_ty, op.b, op.pc)?;
            let k = builder.push_node(OP_CONST_I, TY_INT, NO_OPERAND, NO_OPERAND, NO_OPERAND, op.imm, 0, 0, op.pc)?;
            builder.trace.const_values[k as usize] = op.imm as i64 as u64;
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
            // A guard exit must resume at the operation that PRODUCED the
            // condition slot, not at the branch itself: the machine exits
            // before recomputing the bool, so resuming at the branch would
            // read a stale value and ping-pong on the same guard forever.
            // Loop-carried condition slots (no in-trace producer) are already
            // machine-fresh at the branch, so the branch pc stays correct.
            let mut resume_pc = op.pc;
            let mut scan = op_idx;
            while scan > 0 {
                scan -= 1;
                let earlier = &buffer.ops[scan];
                if op_writes_slot(earlier.bc_op) && earlier.a == op.a {
                    resume_pc = earlier.pc;
                    break;
                }
            }
            let _ = builder.push_node(
                OP_GUARD_BOOL,
                TY_BOOL,
                cond,
                NO_OPERAND,
                NO_OPERAND,
                expected as i32,
                op.a as u16,
                FLAG_SIDE_EFFECT,
                resume_pc,
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
            let idx_val = builder.guard_value(idx_val, op.rhs_ty, op.c, op.pc)?;
            // Carry the observed element type so the MIR layer reloads the
            // value with the right register class.
            let load_ty = match op.res_ty {
                crate::record::OBS_NUM => TY_NUM,
                crate::record::OBS_INT => TY_INT,
                _ => TY_ANY,
            };
            let load = builder.push_node(OP_TGETI, load_ty, table, idx_val, NO_OPERAND, 0, op.a as u16, FLAG_MEMORY, op.pc)?;
            builder.memory_node(load);
            builder.env[op.a as usize] = load;
            Ok(())
        }
        bc::OP_TSETI => {
            let table = builder.param(op.b)?;
            let table = builder.guard_shape(table, op.b)?;
            let idx_val = builder.param(op.c)?;
            let idx_val = builder.guard_value(idx_val, op.rhs_ty, op.c, op.pc)?;
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
            let arg = builder.guard_value(arg, op.lhs_ty, op.c, op.pc)?;
            // The CALLM function id rides field b (CALLM has no immediate word,
            // so TraceOp.imm is always zero here).
            let call = builder.push_node(OP_CALLM, result_ty(op), arg, NO_OPERAND, NO_OPERAND, op.b as i32, op.a as u16, 0, op.pc)?;
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

fn lower_loadk(builder: &mut Builder, op: &TraceOp, consts: &[bc::Const]) -> Result<(), BuildError> {
    let const_index = op.b as u32 | (op.c as u32) << 8;
    let (op_code, ty, value) = match consts.get(const_index as usize) {
        Some(bc::Const::Int(v)) => (OP_CONST_I, TY_INT, *v as i64 as u64),
        // Full 64-bit float bit pattern; imm alone cannot hold it.
        Some(bc::Const::Num(v)) => (OP_CONST_F, TY_NUM, v.to_bits()),
        // Strings are not numeric values; the trace keeps a placeholder int
        // (string consts only matter as TGETK/TSETK keys, lowered elsewhere).
        _ => (OP_CONST_I, TY_INT, 0),
    };
    let node = builder.push_node(
        op_code,
        ty,
        NO_OPERAND,
        NO_OPERAND,
        NO_OPERAND,
        0,
        op.a as u16,
        0,
        op.pc,
    )?;
    builder.trace.const_values[node as usize] = value;
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
    let lhs_g = builder.guard_value(lhs, op.lhs_ty, op.b, op.pc)?;
    let rhs_g = builder.guard_value(rhs, op.rhs_ty, op.c, op.pc)?;
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
    let lhs_g = builder.guard_value(lhs, op.lhs_ty, op.b, op.pc)?;
    let rhs_g = builder.guard_value(rhs, op.rhs_ty, op.c, op.pc)?;
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

/// Resolves one end-of-iteration value through phi chains to a non-phi node.
/// At the loop bottom every header phi evaluates to its backedge input, so a
/// backedge edge targeting a phi can legally target that phi's backedge input.
/// Walking the chain also removes phi-to-phi dependences from the machine-level
/// sequential phi-copy sequence, which would otherwise corrupt register values.
fn resolve_backedge_value(builder: &Builder, start: u16, start_slot: usize) -> u16 {
    let mut node = start;
    let mut hops = 0usize;
    while node != NO_OPERAND
        && builder.trace.op[node as usize] == OP_PHI
        && node != builder.phis[start_slot]
        && hops < L::MAX_SLOTS as usize
    {
        node = builder.trace.in1[node as usize];
        hops += 1;
    }
    if node != NO_OPERAND && builder.trace.op[node as usize] == OP_PHI {
        // The chain looped back to the start phi: the slot carries its own
        // entry value around the loop.
        return builder.params[start_slot];
    }
    if node == NO_OPERAND {
        return builder.params[start_slot];
    }
    node
}

/// Patches the pre-created loop-carried phis with the end-of-iteration values.
fn close_backedge(builder: &mut Builder, buffer: &TraceBuffer) -> Result<(), BuildError> {
    let _ = buffer;
    for slot in 0..L::MAX_SLOTS as usize {
        let phi = builder.phis[slot];
        if phi == NO_OPERAND {
            continue;
        }
        let mut current = builder.env[slot];
        if current == phi || current == NO_OPERAND {
            // No write updated the slot after the phi was created (or the write
            // deduplicated to the phi itself); the backedge carries the parameter.
            current = builder.params[slot];
        }
        let current = resolve_backedge_value(builder, current, slot);
        let placeholder = builder.trace.in1[phi as usize];
        drop_use(&mut builder.trace, placeholder);
        builder.trace.in1[phi as usize] = current;
        add_use(&mut builder.trace, current);
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
