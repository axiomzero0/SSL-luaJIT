// CEP:FILE: hot/src/ir.rs
// CEP:WHAT: The Structure-of-Arrays Sea of Nodes IR: opcode, type, operand, immediate, refcount, cost, and flag arrays with GVN signatures.
// CEP:WHY: design.md Part 3 mandates parallel contiguous arrays instead of pointer nodes so every pass is a linear sweep at memory-bandwidth speed; stable u16 indices give deterministic printing, hashing, and verification.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Constructors return None when node capacity is exhausted; passes never panic.
// CEP:ASSUMES: node indices are strictly less than MAX_IR_NODES and 0xFFFF marks an absent operand; enforced by the builder and verifier.
// CEP:COST: node append is amortized constant; traversal is sequential array scanning.
// CEP:EVIDENCE: unit tests ssl-tests::unit_ir; golden IR tests.

use ssl_config::limits as L;

/// Absent operand sentinel.
pub const NO_OPERAND: u16 = 0xFFFF;

// Node opcodes.
/// Placeholder left by dead-code elimination and scalar replacement.
pub const OP_NOP: u16 = 0;
/// Integer constant.
pub const OP_CONST_I: u16 = 1;
/// Double constant.
pub const OP_CONST_F: u16 = 2;
/// Pre-header entry value of one slot.
pub const OP_PARAM: u16 = 3;
/// Loop-header merge of pre-header and backedge values.
pub const OP_PHI: u16 = 4;
pub const OP_ADD_I: u16 = 5;
pub const OP_SUB_I: u16 = 6;
pub const OP_MUL_I: u16 = 7;
pub const OP_ADD_F: u16 = 8;
pub const OP_SUB_F: u16 = 9;
pub const OP_MUL_F: u16 = 10;
pub const OP_DIV_F: u16 = 11;
pub const OP_LT_I: u16 = 12;
pub const OP_LE_I: u16 = 13;
pub const OP_EQ_I: u16 = 14;
pub const OP_LT_F: u16 = 15;
pub const OP_LE_F: u16 = 16;
pub const OP_EQ_F: u16 = 17;
/// Runtime type guard pinning a slot to integer.
pub const OP_GUARD_INT: u16 = 18;
/// Runtime type guard pinning a slot to double.
pub const OP_GUARD_NUM: u16 = 19;
/// Runtime shape guard pinning a table to array shape.
pub const OP_GUARD_SHAPE: u16 = 20;
/// Branch guard recording the taken direction of a conditional jump.
pub const OP_GUARD_BOOL: u16 = 21;
/// Array table allocation with immediate length; memory effect.
pub const OP_TNEW: u16 = 22;
/// Array table load; memory effect.
pub const OP_TGETI: u16 = 23;
/// Array table store; memory effect.
pub const OP_TSETI: u16 = 24;
/// Global load; memory effect.
pub const OP_GLOAD: u16 = 25;
/// Global store; memory effect.
pub const OP_GSTORE: u16 = 26;
/// Math builtin call.
pub const OP_CALLM: u16 = 27;
/// Integer to double conversion.
pub const OP_INT2F: u16 = 28;
/// Packed double load from an array at a node index; memory effect.
pub const OP_VLOAD_F: u16 = 29;
/// Packed double store to an array at a node index; memory effect.
pub const OP_VSTORE_F: u16 = 30;
pub const OP_VADD_F: u16 = 31;
pub const OP_VSUB_F: u16 = 32;
pub const OP_VMUL_F: u16 = 33;
/// Packs two scalars into one vector.
pub const OP_VPACK: u16 = 34;
/// Horizontal add of a two-lane vector.
pub const OP_HADD_F: u16 = 35;
/// Broadcasts a scalar into both lanes.
pub const OP_VSPLAT_F: u16 = 36;
/// Integer not-equal compare.
pub const OP_NE_I: u16 = 37;
/// Double not-equal compare.
pub const OP_NE_F: u16 = 38;

// Type tags.
/// Any dynamic value.
pub const TY_ANY: u8 = 0;
pub const TY_INT: u8 = 1;
pub const TY_NUM: u8 = 2;
pub const TY_BOOL: u8 = 3;
pub const TY_TBL: u8 = 4;
/// Two-lane double vector.
pub const TY_VEC: u8 = 5;

// Flag bits.
/// Node was hoisted out of the loop by LICM.
pub const FLAG_HOISTED: u16 = 1;
/// Node reads or writes abstract memory.
pub const FLAG_MEMORY: u16 = 2;
/// Node has side effects or guards and cannot be dead-code eliminated.
pub const FLAG_SIDE_EFFECT: u16 = 4;
/// Node participates in the vectorizer output.
pub const FLAG_VECTORIZED: u16 = 8;

/// SoA node arrays for one trace.
pub struct IrTrace {
    /// Opcode per node.
    pub op: [u16; L::MAX_IR_NODES as usize],
    /// Result type per node.
    pub ty: [u8; L::MAX_IR_NODES as usize],
    /// First operand per node.
    pub in0: [u16; L::MAX_IR_NODES as usize],
    /// Second operand per node.
    pub in1: [u16; L::MAX_IR_NODES as usize],
    /// Third operand per node.
    pub in2: [u16; L::MAX_IR_NODES as usize],
    /// Immediate per node (constant values, lengths, function ids).
    pub imm: [i32; L::MAX_IR_NODES as usize],
    /// Auxiliary per node (slot indices for guards, global ids for memory ops).
    pub aux: [u16; L::MAX_IR_NODES as usize],
    /// Memory state input edge per node (abstract memory ordering).
    pub mem_in: [u16; L::MAX_IR_NODES as usize],
    /// Reference count per node.
    pub refcount: [u16; L::MAX_IR_NODES as usize],
    /// Selector cost per node filled by instruction selection.
    pub cost: [u16; L::MAX_IR_NODES as usize],
    /// Flag bits per node.
    pub flags: [u16; L::MAX_IR_NODES as usize],
    /// Source bytecode word index per node (for snapshots and remarks).
    pub pc: [u32; L::MAX_IR_NODES as usize],
    /// Live node count.
    pub count: u16,
}

impl IrTrace {
    pub fn new() -> IrTrace {
        IrTrace {
            op: [OP_NOP; L::MAX_IR_NODES as usize],
            ty: [TY_ANY; L::MAX_IR_NODES as usize],
            in0: [NO_OPERAND; L::MAX_IR_NODES as usize],
            in1: [NO_OPERAND; L::MAX_IR_NODES as usize],
            in2: [NO_OPERAND; L::MAX_IR_NODES as usize],
            imm: [0; L::MAX_IR_NODES as usize],
            aux: [0; L::MAX_IR_NODES as usize],
            mem_in: [NO_OPERAND; L::MAX_IR_NODES as usize],
            refcount: [0; L::MAX_IR_NODES as usize],
            cost: [0; L::MAX_IR_NODES as usize],
            flags: [0; L::MAX_IR_NODES as usize],
            pc: [0; L::MAX_IR_NODES as usize],
            count: 0,
        }
    }

    /// Appends one node and returns its index.
    pub fn push(
        &mut self,
        op: u16,
        ty: u8,
        in0: u16,
        in1: u16,
        in2: u16,
        imm: i32,
        aux: u16,
        flags: u16,
    ) -> Option<u16> {
        if self.count as u32 >= L::MAX_IR_NODES {
            return None;
        }
        let idx = self.count;
        self.op[idx as usize] = op;
        self.ty[idx as usize] = ty;
        self.in0[idx as usize] = in0;
        self.in1[idx as usize] = in1;
        self.in2[idx as usize] = in2;
        self.imm[idx as usize] = imm;
        self.aux[idx as usize] = aux;
        self.flags[idx as usize] = flags;
        self.refcount[idx as usize] = 0;
        self.count += 1;
        Some(idx)
    }

    /// Free node capacity left in the arrays.
    pub fn remaining(&self) -> u16 {
        (L::MAX_IR_NODES as u16).saturating_sub(self.count)
    }

    /// True when the node index holds a live node.
    pub fn is_live(&self, idx: u16) -> bool {
        (idx as usize) < self.count as usize && self.op[idx as usize] != OP_NOP
    }

    /// True when the node reads or writes abstract memory.
    pub fn is_memory(&self, idx: u16) -> bool {
        let at = idx as usize;
        at < self.count as usize && (self.flags[at] & FLAG_MEMORY) != 0
    }

    /// True when the opcode is guarded or otherwise side-effecting.
    pub fn is_side_effect(&self, idx: u16) -> bool {
        let at = idx as usize;
        at < self.count as usize && (self.flags[at] & FLAG_SIDE_EFFECT) != 0
    }

    /// True when the opcode is one of the float arithmetic forms.
    pub fn is_float_arith(op: u16) -> bool {
        matches!(op, OP_ADD_F | OP_SUB_F | OP_MUL_F | OP_DIV_F)
    }

    /// True when the opcode is one of the integer arithmetic forms.
    pub fn is_int_arith(op: u16) -> bool {
        matches!(op, OP_ADD_I | OP_SUB_I | OP_MUL_I)
    }

    /// True when the opcode is a vector binary operation.
    pub fn is_vector_arith(op: u16) -> bool {
        matches!(op, OP_VADD_F | OP_VSUB_F | OP_VMUL_F)
    }

    /// True when the opcode is a comparison.
    pub fn is_compare(op: u16) -> bool {
        matches!(
            op,
            OP_LT_I | OP_LE_I | OP_EQ_I | OP_NE_I | OP_LT_F | OP_LE_F | OP_EQ_F | OP_NE_F
        )
    }
}

impl Default for IrTrace {
    fn default() -> IrTrace {
        IrTrace::new()
    }
}

/// Computes the deterministic GVN signature hash of one node.
pub fn signature(trace: &IrTrace, idx: u16) -> u64 {
    let base = idx as usize;
    let mut hash: u64 = 0x9E37_79B9_7F4A_7C15;
    hash ^= (trace.op[base] as u64).rotate_left(8);
    hash ^= (trace.in0[base] as u64).rotate_left(16);
    hash ^= (trace.in1[base] as u64).rotate_left(24);
    hash ^= (trace.in2[base] as u64).rotate_left(32);
    hash ^= (trace.imm[base] as u64).rotate_left(40);
    hash ^= (trace.aux[base] as u64).rotate_left(48);
    hash
}

/// Reports whether two nodes are GVN-identical for deduplication.
pub fn same_signature(trace: &IrTrace, a: u16, b: u16) -> bool {
    let (ia, ib) = (a as usize, b as usize);
    if ia >= trace.count as usize || ib >= trace.count as usize {
        return false;
    }
    trace.op[ia] == trace.op[ib]
        && trace.in0[ia] == trace.in0[ib]
        && trace.in1[ia] == trace.in1[ib]
        && trace.in2[ia] == trace.in2[ib]
        && trace.imm[ia] == trace.imm[ib]
        && trace.aux[ia] == trace.aux[ib]
}

/// Marks one operand reference, bumping the producer refcount.
pub fn add_use(trace: &mut IrTrace, producer: u16) {
    if producer != NO_OPERAND && (producer as usize) < trace.count as usize {
        trace.refcount[producer as usize] = trace.refcount[producer as usize].saturating_add(1);
    }
}

/// Rewires the abstract memory chain after nodes were deleted or reordered.
pub fn rebuild_mem_chain(trace: &mut IrTrace) {
    let mut previous: u16 = NO_OPERAND;
    for idx in 0..trace.count as usize {
        if trace.op[idx] == OP_NOP {
            continue;
        }
        if trace.is_memory(idx as u16) {
            trace.mem_in[idx] = previous;
            previous = idx as u16;
        } else {
            trace.mem_in[idx] = NO_OPERAND;
        }
    }
}

/// Drops one operand reference, decrementing the producer refcount.
pub fn drop_use(trace: &mut IrTrace, producer: u16) {
    if producer != NO_OPERAND && (producer as usize) < trace.count as usize {
        trace.refcount[producer as usize] = trace.refcount[producer as usize].saturating_sub(1);
    }
}
