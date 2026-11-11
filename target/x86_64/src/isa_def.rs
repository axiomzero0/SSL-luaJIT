// CEP:FILE: target/x86_64/src/isa_def.rs
// CEP:WHAT: Machine instruction definitions, condition codes, register encodings, labels, and the machine instruction record for the x86-64 backend.
// CEP:WHY: The backend needs one total instruction vocabulary with encodable fields; stable opcode numbers give deterministic layouts, golden disassembly, and versioned codegen.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: none; declarations only.
// CEP:ASSUMES: the SysV AMD64 ABI with callee-saved rbx and r12 through r14; ISA level x86-64-v1 plus SSE2 per the target model.
// CEP:COST: declarations only.
// CEP:EVIDENCE: encoder round-trip tests; golden disassembly tests.

/// Machine opcode: mov r64, imm32 (sign extended).
pub const X_MOV_IR: u16 = 1;
/// Machine opcode: mov r64, r64.
pub const X_MOV_RR: u16 = 2;
/// Machine opcode: mov r64, [state + slot payload].
pub const X_MOV_SLOT_R: u16 = 3;
/// Machine opcode: mov [state + slot payload], r64.
pub const X_MOV_R_SLOT: u16 = 4;
/// Machine opcode: mov [state + slot tag], imm32.
pub const X_MOV_SLOT_TAG: u16 = 5;
pub const X_ADD_RR: u16 = 6;
pub const X_SUB_RR: u16 = 7;
pub const X_IMUL_RR: u16 = 8;
pub const X_ADD_IR: u16 = 9;
pub const X_XOR_RR: u16 = 10;
pub const X_CMP_RR: u16 = 11;
pub const X_SETC: u16 = 12;
pub const X_MOVD_X2G: u16 = 13;
pub const X_MOVD_G2X: u16 = 14;
pub const X_CVT_SI2SD: u16 = 15;
pub const X_CVTTSD2SI: u16 = 16;
pub const X_MOVSD_X2X: u16 = 17;
pub const X_MOVSD_M2X: u16 = 18;
pub const X_MOVSD_X2M: u16 = 19;
pub const X_ADDSD: u16 = 20;
pub const X_SUBSD: u16 = 21;
pub const X_MULSD: u16 = 22;
pub const X_DIVSD: u16 = 23;
pub const X_SQRTSD: u16 = 24;
pub const X_UCOMISD: u16 = 25;
pub const X_PXOR: u16 = 26;
pub const X_MOVAPD_M2X: u16 = 27;
pub const X_MOVAPD_X2M: u16 = 28;
pub const X_UNPCKLPD: u16 = 29;
pub const X_UNPCKHPD: u16 = 30;
pub const X_JCC_REL: u16 = 31;
pub const X_JMP_REL: u16 = 32;
pub const X_CALL_REL: u16 = 33;
pub const X_RET: u16 = 34;
pub const X_LEA_TABLE: u16 = 35;
pub const X_SPILL: u16 = 36;
pub const X_RELOAD: u16 = 37;
pub const X_BARRIER_MAYBE: u16 = 38;
pub const X_NOP: u16 = 39;
pub const X_SHL_IR: u16 = 40;
pub const X_MOV_IR64: u16 = 41;
pub const X_LOAD_IDX: u16 = 42;
pub const X_STORE_IDX: u16 = 43;
pub const X_CMOVL: u16 = 44;
pub const X_FABS_X: u16 = 45;
pub const X_SHR_IR: u16 = 46;
pub const X_STORE_ZERO_IDX: u16 = 47;
pub const X_BIND_LABEL: u16 = 48;
pub const X_CMP_IR: u16 = 49;
pub const X_ADDPD: u16 = 50;
pub const X_SUBPD: u16 = 51;
pub const X_MULPD: u16 = 52;

/// Condition code low nibble: jump less (signed).
pub const CC_LT_I: u8 = 0xC;
/// Condition code low nibble: jump less or equal (signed).
pub const CC_LE_I: u8 = 0xE;
/// Condition code low nibble: jump greater or equal (signed).
pub const CC_GE_I: u8 = 0xD;
/// Condition code low nibble: jump greater (signed).
pub const CC_GT_I: u8 = 0xF;
/// Condition code low nibble: jump equal.
pub const CC_EQ: u8 = 0x4;
/// Condition code low nibble: jump not equal.
pub const CC_NE: u8 = 0x5;
/// Condition code low nibble: jump below (ucomisd CF1 ZF0).
pub const CC_LT_F: u8 = 0x2;
/// Condition code low nibble: jump below or equal (ucomisd CF1 or ZF1).
pub const CC_LE_F: u8 = 0x6;
/// Condition code low nibble: jump above (ucomisd CF0 ZF0).
pub const CC_A: u8 = 0x7;
/// Condition code low nibble: jump not below (ucomisd CF0).
pub const CC_AE: u8 = 0x3;

/// One machine instruction with virtual registers, immediates, and label references.
#[derive(Copy, Clone)]
pub struct MachineInsn {
    /// Machine opcode.
    pub op: u16,
    /// Destination register id (vreg before allocation, physical after).
    pub dst: u16,
    /// First source register id.
    pub src0: u16,
    /// Second source register id.
    pub src1: u16,
    /// Immediate or slot/global offset.
    pub imm: i32,
    /// Condition code, label id, or auxiliary marker.
    pub aux: u16,
    /// Second immediate (slot tag constants).
    pub imm2: i32,
}

impl MachineInsn {
    pub const fn new(op: u16) -> MachineInsn {
        MachineInsn {
            op,
            dst: 0,
            src0: 0,
            src1: 0,
            imm: 0,
            aux: 0,
            imm2: 0,
        }
    }
}

/// Label reference for branch resolution during layout.
pub const NO_LABEL: u16 = 0xFFFF;

/// Physical register id sentinel meaning spilled.
pub const REG_SPILLED: u16 = 0xFF00;

/// Vreg id base marking physical registers that bypass allocation.
pub const PHYS_BASE: u16 = 0x8000;

/// Register class of one vreg: general purpose.
pub const CLASS_GPR: u8 = 0;
/// Register class of one vreg: SSE double.
pub const CLASS_XMM: u8 = 1;

/// Deterministically computes the interval id of one vreg for the allocator.
pub const fn vreg_interval(vreg: u16) -> usize {
    vreg as usize
}
