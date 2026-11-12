// CEP:FILE: target/x86_64/src/machine.rs
// CEP:WHAT: Machine function container: instruction buffer, label allocation, register class map, and the lowering context shared by the isel modules.
// CEP:WHY: Chapter 62.3.3 partitions instruction selection by class; a shared context keeps each isel file to one instruction class with one consistent label and register vocabulary.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns None on label exhaustion; capacity bounds make failure deterministic and visible.
// CEP:ASSUMES: vreg classes come from the MIR body; scratch registers r10 and r11 are reserved for address computation and excluded from allocation.
// CEP:COST: append is amortized constant.
// CEP:EVIDENCE: golden machine tests; differential codegen.

use crate::isa_def::*;
use ssl_config::limits as L;
use ssl_hot::mir::{MirBody, VR_XMM};

/// Machine instruction buffer with labels.
pub struct MachineFunction {
    /// Machine instructions in order.
    pub insns: [MachineInsn; L::MAX_MIR_INSNS as usize],
    /// Instruction count.
    pub count: u32,
    /// Register class per vreg.
    pub vreg_class: [u8; L::MAX_VREGS as usize],
    /// Value kind per vreg for exit re-boxing.
    pub vreg_kind: [u8; L::MAX_VREGS as usize],
    /// Live vreg count.
    pub vreg_count: u16,
    /// Next local label id.
    pub next_label: u16,
    /// Immediate value per vreg when the vreg is a materialized integer constant.
    pub const_imm: [i32; L::MAX_VREGS as usize],
    /// Const flag per vreg for folded immediate tile selection.
    pub is_const: [bool; L::MAX_VREGS as usize],
}

/// Label id of the trace entry.
pub const LABEL_HEADER: u16 = 0;
/// First guard stub label id.
pub const LABEL_STUB_BASE: u16 = 1;
/// First helper label id.
pub const LABEL_HELPER_BASE: u16 = 128;
/// First local label id.
pub const LABEL_LOCAL_BASE: u16 = 256;
/// Label of the allocation slow-path stub.
pub const LABEL_ALLOC_STUB: u16 = 255;
/// Scratch vreg id A below the physical base.
pub const SCRATCH_VREG_A: u16 = 0x7FFE;
/// Scratch vreg id B below the physical base.
pub const SCRATCH_VREG_B: u16 = 0x7FFF;

impl MachineFunction {
    pub fn new(mir: &MirBody) -> MachineFunction {
        let mut function = MachineFunction {
            insns: [MachineInsn::new(X_NOP); L::MAX_MIR_INSNS as usize],
            count: 0,
            vreg_class: [CLASS_GPR; L::MAX_VREGS as usize],
            vreg_kind: [0; L::MAX_VREGS as usize],
            vreg_count: mir.vreg_count,
            next_label: LABEL_LOCAL_BASE,
            const_imm: [0; L::MAX_VREGS as usize],
            is_const: [false; L::MAX_VREGS as usize],
        };
        for vreg in 0..mir.vreg_count as usize {
            function.vreg_class[vreg] = if mir.vreg_class[vreg] == VR_XMM {
                CLASS_XMM
            } else {
                CLASS_GPR
            };
            function.vreg_kind[vreg] = mir.vreg_kind[vreg];
        }
        function
    }

    pub fn push(&mut self, insn: MachineInsn) -> bool {
        if self.count as usize >= self.insns.len() {
            return false;
        }
        self.insns[self.count as usize] = insn;
        self.count += 1;
        true
    }

    pub fn alloc_label(&mut self) -> Option<u16> {
        if self.next_label == NO_LABEL {
            return None;
        }
        let label = self.next_label;
        self.next_label += 1;
        Some(label)
    }


    pub fn scratch_gpr(&self) -> u16 {
        SCRATCH_VREG_A
    }

    pub fn scratch_gpr2(&self) -> u16 {
        SCRATCH_VREG_B
    }

    pub fn note_const(&mut self, vreg: u16, imm: i32) {
        if (vreg as usize) < self.is_const.len() {
            self.is_const[vreg as usize] = true;
            self.const_imm[vreg as usize] = imm;
        }
    }

    pub fn vreg_is_const_source(&self, vreg: u16) -> bool {
        (vreg as usize) < self.is_const.len() && self.is_const[vreg as usize]
    }

    pub fn vreg_const_imm(&self, vreg: u16) -> i32 {
        if (vreg as usize) < self.const_imm.len() {
            self.const_imm[vreg as usize]
        } else {
            0
        }
    }

    pub fn vreg_kind(&self, vreg: u16) -> u8 {
        if (vreg as usize) < self.vreg_kind.len() {
            self.vreg_kind[vreg as usize]
        } else {
            0
        }
    }

    pub fn vreg_const_addend(&self, vreg: u16, mir_op: u16) -> i32 {
        let imm = self.vreg_const_imm(vreg);
        if mir_op == ssl_hot::mir::M_SUB_I {
            -imm
        } else {
            imm
        }
    }
}

/// Guard stub label for one guard id.
pub const fn stub_label(guard_id: u16) -> u16 {
    LABEL_STUB_BASE + guard_id
}

/// Helper label for one math function id.
pub const fn helper_label(fnid: u16) -> u16 {
    LABEL_HELPER_BASE + fnid
}
