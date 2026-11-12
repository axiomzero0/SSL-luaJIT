// CEP:FILE: hot/src/mir.rs
// CEP:WHAT: The linear Machine IR: fixed-width instruction records, virtual register classes, and guard snapshots.
// CEP:WHY: design.md Part 4 mandates a strictly linear register-oriented IR after optimization; snapshots per guard enable perfect deoptimization state per design.md Part 9.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Builders return None on capacity exhaustion; consumers treat a failed build as a compile abort.
// CEP:ASSUMES: virtual registers are untyped but carry a register class; snapshots map frame slots to vregs or constants.
// CEP:COST: instruction append is amortized constant; scheduling is one pass.
// CEP:EVIDENCE: unit tests ssl-tests::unit_mir; golden MIR tests.

use ssl_config::limits as L;

/// Virtual register class: general purpose.
pub const VR_GPR: u8 = 0;
/// Virtual register class: vector double.
pub const VR_XMM: u8 = 1;

// Generic MIR opcodes lowered by the target.
/// Load constant integer into a GPR vreg.
pub const M_CONST_I: u16 = 1;
/// Load constant double into an XMM vreg (imm = constant pool index).
pub const M_CONST_F: u16 = 2;
/// Copy GPR vreg.
pub const M_MOV_I: u16 = 3;
/// Copy XMM vreg.
pub const M_MOV_F: u16 = 4;
pub const M_ADD_I: u16 = 5;
pub const M_SUB_I: u16 = 6;
pub const M_MUL_I: u16 = 7;
pub const M_ADD_F: u16 = 8;
pub const M_SUB_F: u16 = 9;
pub const M_MUL_F: u16 = 10;
pub const M_DIV_F: u16 = 11;
pub const M_INT2F: u16 = 12;
pub const M_CMP_I: u16 = 13;
pub const M_CMP_F: u16 = 14;
/// Materialize a boolean from flags (imm selects the setcc condition).
pub const M_SET_BOOL: u16 = 15;
/// Guard one slot against a type (imm = guard kind).
pub const M_GUARD: u16 = 16;
/// Guard boolean polarity (imm = expected).
pub const M_GUARD_BOOL: u16 = 17;
/// Load a global into a GPR or XMM vreg (imm = global slot).
pub const M_LOAD_G: u16 = 18;
/// Store a vreg into a global (imm = global slot).
pub const M_STORE_G: u16 = 19;
/// Load one array cell payload into a vreg (src0 = table handle vreg, src1 = index vreg).
pub const M_LOAD_ARR: u16 = 20;
/// Store a vreg payload into one array cell.
pub const M_STORE_ARR: u16 = 21;
/// Math builtin call (imm = fnid).
/// Math builtin call, fully slot-mediated: imm = helper fnid, src0 = argument
/// slot, aux = result slot. The machine reads [state + arg payload], calls the
/// helper, and writes [state + result payload]; no vreg crosses the call, so
/// caller-clobbered registers cannot corrupt live values.
pub const M_CALLM: u16 = 22;
/// Bump-allocate one table into a GPR vreg (imm = length; prologue checked).
pub const M_NEW_TABLE: u16 = 23;
/// Store one vreg back into its frame slot with re-boxing (imm = slot, aux = type).
pub const M_STORE_SLOT: u16 = 24;
/// Terminate the trace by jumping to an exit stub (imm = exit id).
pub const M_EXIT: u16 = 25;
pub const M_VEC_LOAD: u16 = 26;
pub const M_VEC_STORE: u16 = 27;
pub const M_VEC_ADD: u16 = 28;
pub const M_VEC_SUB: u16 = 29;
pub const M_VEC_MUL: u16 = 30;
pub const M_VEC_PACK: u16 = 31;
pub const M_VEC_HADD: u16 = 32;
/// Guard shape for a table slot.
pub const M_GUARD_SHAPE: u16 = 33;
/// Unbox one frame slot payload into a vreg (imm = slot, aux = kind).
pub const M_LOAD_SLOT: u16 = 34;
/// Copy one boxed cell from an array into a frame slot (src0 = table, src1 = index, imm = slot).
pub const M_LOAD_ARR_SLOT: u16 = 35;
/// Store one boxed slot or vreg payload into an array cell (imm = source slot, aux = value vreg).
pub const M_STORE_ARR_SLOT: u16 = 36;
/// Copy one boxed global into a frame slot (imm = global, aux = slot).
pub const M_LOAD_G_SLOT: u16 = 37;
/// Copy one boxed frame slot into a global (imm = source slot, aux = global).
pub const M_STORE_G_SLOT: u16 = 38;
/// Guard the last comparison flags against the expected polarity.
pub const M_GUARD_FLAG: u16 = 39;
/// Jump back to the trace header.
pub const M_LOOP_BACK: u16 = 40;
/// Inline allocation preflight before the loop body (imm = total bytes).
pub const M_ALLOC_CHECK: u16 = 41;
/// Loads a double from a frame slot's payload into an xmm vreg (imm = slot).
pub const M_LOAD_SLOT_F: u16 = 42;
/// Stores an xmm vreg into a frame slot's payload (imm = slot).
pub const M_STORE_SLOT_F: u16 = 43;

/// Guard kinds for M_GUARD imm.
/// Guard kind: integer add/sub/mul overflowed and must deoptimize.
pub const GUARD_KIND_OFLOW: i32 = 3;

pub const GUARD_KIND_INT: i32 = 1;
/// Guard kind: double.
pub const GUARD_KIND_NUM: i32 = 2;

/// One fixed-width machine-independent MIR record.
#[derive(Copy, Clone)]
pub struct MirInsn {
    /// Generic opcode.
    pub op: u16,
    /// Destination vreg.
    pub dst: u16,
    /// First source vreg.
    pub src0: u16,
    /// Second source vreg.
    pub src1: u16,
    /// Immediate.
    pub imm: i32,
    /// Auxiliary (slot, guard id, or flag).
    pub aux: u16,
}

impl MirInsn {
    pub const fn empty() -> MirInsn {
        MirInsn {
            op: 0,
            dst: 0,
            src0: 0,
            src1: 0,
            imm: 0,
            aux: 0,
        }
    }
}

/// One snapshot entry mapping a frame slot to a vreg and value kind.
#[derive(Copy, Clone)]
pub struct SnapEntry {
    /// Frame slot index.
    pub slot: u8,
    /// Virtual register holding the unboxed payload.
    pub vreg: u16,
    /// Value kind: 1 int, 2 num, 3 bool, 0 nil.
    pub kind: u8,
}

/// Snapshot recorded at one guard.
#[derive(Copy, Clone)]
pub struct Snapshot {
    /// Guard id this snapshot belongs to.
    pub guard: u16,
    /// Bytecode resume point (word index of the guarded op).
    pub resume_pc: u32,
    /// Entry range inside the snapshot entry pool.
    pub start: u16,
    /// Entry count.
    pub len: u16,
}

/// MIR function body with vreg classes and snapshot pool.
pub struct MirBody {
    /// Instruction records.
    pub insns: [MirInsn; L::MAX_MIR_INSNS as usize],
    /// Instruction count.
    pub count: u32,
    /// Register class per vreg.
    pub vreg_class: [u8; L::MAX_VREGS as usize],
    /// Value kind per vreg for re-boxing at exits.
    pub vreg_kind: [u8; L::MAX_VREGS as usize],
    /// Live vreg count.
    pub vreg_count: u16,
    /// Snapshot entry pool.
    pub snap_entries: [SnapEntry; L::MAX_SNAPSHOT_SLOTS as usize * L::MAX_GUARDS as usize],
    /// Used snapshot entries.
    pub snap_used: u32,
    /// Snapshot records.
    pub snapshots: [Snapshot; L::MAX_GUARDS as usize],
    /// Snapshot count.
    pub snapshot_count: u16,
}

impl MirBody {
    pub fn new() -> MirBody {
        MirBody {
            insns: [MirInsn::empty(); L::MAX_MIR_INSNS as usize],
            count: 0,
            vreg_class: [VR_GPR; L::MAX_VREGS as usize],
            vreg_kind: [0; L::MAX_VREGS as usize],
            vreg_count: 0,
            snap_entries: [SnapEntry {
                slot: 0,
                vreg: 0,
                kind: 0,
            }; L::MAX_SNAPSHOT_SLOTS as usize * L::MAX_GUARDS as usize],
            snapshots: [Snapshot {
                guard: 0,
                resume_pc: 0,
                start: 0,
                len: 0,
            }; L::MAX_GUARDS as usize],
            snap_used: 0,
            snapshot_count: 0,
        }
    }

    /// Allocates one virtual register of the given class.
    pub fn new_vreg(&mut self, class: u8, kind: u8) -> Option<u16> {
        if self.vreg_count as u32 >= L::MAX_VREGS {
            return None;
        }
        let vreg = self.vreg_count;
        self.vreg_class[vreg as usize] = class;
        self.vreg_kind[vreg as usize] = kind;
        self.vreg_count += 1;
        Some(vreg)
    }

    /// Appends one instruction.
    pub fn push(&mut self, insn: MirInsn) -> Option<u32> {
        if self.count as u32 >= L::MAX_MIR_INSNS {
            return None;
        }
        self.insns[self.count as usize] = insn;
        self.count += 1;
        Some(self.count - 1)
    }

    /// Records one snapshot for a guard with the given slot mapping.
    pub fn add_snapshot(&mut self, guard: u16, resume_pc: u32, entries: &[SnapEntry]) -> bool {
        if self.snapshot_count as u32 >= L::MAX_GUARDS {
            return false;
        }
        if self.snap_used as usize + entries.len() > self.snap_entries.len() {
            return false;
        }
        let start = self.snap_used as u16;
        for entry in entries {
            self.snap_entries[self.snap_used as usize] = *entry;
            self.snap_used += 1;
        }
        self.snapshots[self.snapshot_count as usize] = Snapshot {
            guard,
            resume_pc,
            start,
            len: entries.len() as u16,
        };
        self.snapshot_count += 1;
        true
    }
}

impl Default for MirBody {
    fn default() -> MirBody {
        MirBody::new()
    }
}
