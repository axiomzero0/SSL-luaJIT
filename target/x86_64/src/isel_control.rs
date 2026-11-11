// CEP:FILE: target/x86_64/src/isel_control.rs
// CEP:WHAT: Instruction selection for control flow: comparisons, type and shape guards, boolean guards, math calls, and trace exits.
// CEP:WHY: design.md Part 9 makes guards the control-flow splits to side traces; every guard emits a compare, a conditional branch to its stub, and a snapshot-backed exit.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns false on machine buffer rejection; callers abort compilation deterministically.
// CEP:ASSUMES: stub labels are stub_label(guard_id) and helpers helper_label(fnid); integer compares use signed jcc and float compares use ucomisd jb or jbe forms.
// CEP:COST: one compare plus one branch per guard; math calls are direct rel32 calls into registered helpers.
// CEP:EVIDENCE: differential tests with guard exits and deoptimization; golden disassembly.
// CEP:TARGET: x86-64

use crate::isa_def::*;
use crate::isel_memory::{slot_payload_disp, slot_tag_disp};
use crate::machine::{helper_label, stub_label, MachineFunction};
use ssl_config::target_model::jit_state_layout as layout;
use ssl_hot::mir::MirInsn;
use ssl_hot::vm_value::{TAG_INT, TAG_NUM, TAG_TBL};

/// Lowers one control-class MIR instruction into machine tiles.
pub fn lower_control(mir: &MirInsn, machine: &mut MachineFunction) -> bool {
    match mir.op {
        ssl_hot::mir::M_CMP_I | ssl_hot::mir::M_CMP_F => lower_compare(mir, machine),
        ssl_hot::mir::M_GUARD => lower_type_guard(mir, machine),
        ssl_hot::mir::M_GUARD_SHAPE => lower_shape_guard(mir, machine),
        ssl_hot::mir::M_GUARD_FLAG => lower_flag_guard(mir, machine),
        ssl_hot::mir::M_CALLM => lower_callm(mir, machine),
        ssl_hot::mir::M_EXIT => lower_exit(mir, machine),
        ssl_hot::mir::M_LOOP_BACK => {
            let mut insn = MachineInsn::new(X_JMP_REL);
            insn.aux = crate::machine::LABEL_HEADER;
            machine.push(insn)
        }
        _ => false,
    }
}

fn lower_compare(mir: &MirInsn, machine: &mut MachineFunction) -> bool {
    let mut insn = MachineInsn::new(if mir.op == ssl_hot::mir::M_CMP_F {
        X_UCOMISD
    } else {
        X_CMP_RR
    });
    insn.src0 = mir.src0;
    insn.src1 = mir.src1;
    machine.push(insn)
}

fn lower_type_guard(mir: &MirInsn, machine: &mut MachineFunction) -> bool {
    let scratch = machine.scratch_gpr();
    let mut load = MachineInsn::new(X_MOV_SLOT_R);
    load.dst = scratch;
    load.imm = slot_tag_disp(mir.imm);
    if !machine.push(load) {
        return false;
    }
    let expected = if mir.imm == ssl_hot::mir::GUARD_KIND_INT {
        TAG_INT
    } else {
        TAG_NUM
    };
    let mut imm = MachineInsn::new(X_MOV_IR);
    imm.dst = machine.scratch_gpr2();
    imm.imm = expected as i32;
    if !machine.push(imm) {
        return false;
    }
    let mut cmp = MachineInsn::new(X_CMP_RR);
    cmp.src0 = scratch;
    cmp.src1 = machine.scratch_gpr2();
    if !machine.push(cmp) {
        return false;
    }
    let mut branch = MachineInsn::new(X_JCC_REL);
    branch.imm = CC_NE as i32;
    branch.aux = stub_label(mir.aux);
    machine.push(branch)
}

fn lower_shape_guard(mir: &MirInsn, machine: &mut MachineFunction) -> bool {
    let scratch = machine.scratch_gpr();
    let mut load = MachineInsn::new(X_MOV_SLOT_R);
    load.dst = scratch;
    load.imm = slot_payload_disp(mir.imm);
    if !machine.push(load) {
        return false;
    }
    let mut shift = MachineInsn::new(X_SHL_IR);
    shift.dst = scratch;
    shift.imm = 4;
    if !machine.push(shift) {
        return false;
    }
    let mut shape = MachineInsn::new(X_LOAD_IDX);
    shape.dst = scratch;
    shape.imm = 1;
    if !machine.push(shape) {
        return false;
    }
    let mut cmp = MachineInsn::new(X_CMP_IR);
    cmp.src0 = scratch;
    cmp.imm = 0;
    if !machine.push(cmp) {
        return false;
    }
    let mut branch = MachineInsn::new(X_JCC_REL);
    branch.imm = CC_NE as i32;
    branch.aux = stub_label(mir.aux);
    machine.push(branch)
}

fn lower_flag_guard(mir: &MirInsn, machine: &mut MachineFunction) -> bool {
    let expected = mir.imm != 0;
    let code = mir.src0 as i32;
    let float = mir.src1 != 0;
    let cc = cc_for(code, float);
    let branch_cc = if expected { invert(cc) } else { cc };
    let mut branch = MachineInsn::new(X_JCC_REL);
    branch.imm = branch_cc as i32;
    branch.aux = stub_label(mir.aux);
    machine.push(branch)
}

/// Maps a compare code to the x86 condition-code low nibble.
pub const fn cc_for(code: i32, float: bool) -> u8 {
    match (code, float) {
        (0, false) => CC_LT_I,
        (1, false) => CC_LE_I,
        (2, false) => CC_EQ,
        (3, false) => CC_NE,
        (0, true) => CC_LT_F,
        (1, true) => CC_LE_F,
        (2, true) => CC_EQ,
        _ => CC_NE,
    }
}

/// Inverts one condition code for negative guards.
pub const fn invert(cc: u8) -> u8 {
    match cc {
        CC_LT_I => CC_GE_I,
        CC_LE_I => CC_GT_I,
        CC_EQ => CC_NE,
        CC_NE => CC_EQ,
        CC_LT_F => CC_AE,
        CC_LE_F => CC_A,
        CC_AE => CC_LT_F,
        CC_A => CC_LE_F,
        CC_GE_I => CC_LT_I,
        _ => CC_GT_I,
    }
}

fn lower_callm(mir: &MirInsn, machine: &mut MachineFunction) -> bool {
    if mir.src0 != mir.dst && mir.src0 != 0 {
        let mut move_arg = MachineInsn::new(X_MOVSD_X2X);
        move_arg.dst = mir.dst;
        move_arg.src0 = mir.src0;
        if !machine.push(move_arg) {
            return false;
        }
    }
    let mut call = MachineInsn::new(X_CALL_REL);
    call.aux = helper_label(mir.imm as u16);
    if !machine.push(call) {
        return false;
    }
    let mut result = MachineInsn::new(X_MOVSD_X2X);
    result.dst = mir.dst;
    result.src0 = PHYS_BASE;
    machine.push(result)
}

fn lower_exit(mir: &MirInsn, machine: &mut MachineFunction) -> bool {
    let mut insn = MachineInsn::new(X_JMP_REL);
    insn.aux = crate::machine::LABEL_ALLOC_STUB;
    insn.imm = mir.imm;
    let _ = layout::EXIT_ID;
    machine.push(insn)
}
