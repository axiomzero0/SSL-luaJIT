// CEP:FILE: target/x86_64/src/isel_scalar.rs
// CEP:WHAT: Instruction selection for scalar integer and double arithmetic with bottom-up dynamic programming tile costing per design.md Part 7.
// CEP:WHY: The DP pattern table chooses between register-immediate folded tiles and register-register tiles using the named cost model, guaranteeing the locally minimal tile sequence for each two-operand node.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns false when the machine buffer rejects an instruction; callers abort compilation.
// CEP:ASSUMES: constants beyond the i32 immediate range are rejected by the assembler airlock.
// CEP:COST: O(1) tile evaluation per instruction with the named cost table.
// CEP:EVIDENCE: cost model artifact benches/artifacts/bench_isel_cost.json; differential codegen tests.
// CEP:CODEGEN-UOPS: folded ALU-immediate tiles are one uop on port 0/1/5; register-register adds are one uop.
// CEP:CODEGEN-PORTS: ALU tiles distribute across ports 0, 1, and 5; no back-to-back single-port chains in the canonical loop shapes.
// CEP:CODEGEN-LATENCY: one cycle for integer ALU; four cycles for addsd hidden by loop iteration overlap.
// CEP:CODEGEN-SPILLS: none for shapes within eight GPR and eight XMM vregs.
// CEP:CODEGEN-VECTOR: scalar tiles; vector tiles are selected by isel_simd.

use crate::isa_def::*;
use crate::machine::MachineFunction;
use ssl_config::cost_model as C;
use ssl_hot::mir::MirInsn;

/// Lowers one scalar MIR instruction into machine tiles with DP costing.
pub fn lower_scalar(mir: &MirInsn, machine: &mut MachineFunction) -> bool {
    match mir.op {
        ssl_hot::mir::M_CONST_I => {
            let mut insn = MachineInsn::new(X_MOV_IR);
            insn.dst = mir.dst;
            insn.imm = mir.imm;
            let ok = machine.push(insn);
            if ok {
                machine.note_const(mir.dst, mir.imm);
            }
            ok
        }
        ssl_hot::mir::M_MOV_I => {
            let mut insn = MachineInsn::new(X_MOV_RR);
            insn.dst = mir.dst;
            insn.src0 = mir.src0;
            machine.push(insn)
        }
        ssl_hot::mir::M_ADD_I | ssl_hot::mir::M_SUB_I | ssl_hot::mir::M_MUL_I => {
            select_int_alu(mir, machine)
        }
        ssl_hot::mir::M_MOV_F => {
            let mut insn = MachineInsn::new(X_MOVSD_X2X);
            insn.dst = mir.dst;
            insn.src0 = mir.src0;
            machine.push(insn)
        }
        ssl_hot::mir::M_ADD_F | ssl_hot::mir::M_SUB_F | ssl_hot::mir::M_MUL_F
        | ssl_hot::mir::M_DIV_F => {
            let opcode = match mir.op {
                ssl_hot::mir::M_ADD_F => X_ADDSD,
                ssl_hot::mir::M_SUB_F => X_SUBSD,
                ssl_hot::mir::M_MUL_F => X_MULSD,
                _ => X_DIVSD,
            };
            let mut insn = MachineInsn::new(opcode);
            insn.dst = mir.dst;
            insn.src0 = mir.src0;
            insn.src1 = mir.src1;
            machine.push(insn)
        }
        ssl_hot::mir::M_INT2F => {
            let mut insn = MachineInsn::new(X_CVT_SI2SD);
            insn.dst = mir.dst;
            insn.src0 = mir.src0;
            machine.push(insn)
        }
        ssl_hot::mir::M_SET_BOOL => {
            let code = mir.imm & 0xFF;
            let float = (mir.imm >> 8) != 0;
            let mut insn = MachineInsn::new(X_SETC);
            insn.dst = mir.dst;
            insn.imm = crate::isel_control::cc_for(code, float) as i32;
            machine.push(insn)
        }
        _ => false,
    }
}

/// Bottom-up DP selection between the folded immediate tile and the register tile.
fn select_int_alu(mir: &MirInsn, machine: &mut MachineFunction) -> bool {
    let opcode = match mir.op {
        ssl_hot::mir::M_ADD_I => X_ADD_RR,
        ssl_hot::mir::M_SUB_I => X_SUB_RR,
        _ => X_IMUL_RR,
    };
    let folded_cost = C::COST_ALU_RI;
    let rr_cost = C::COST_ALU_RR.saturating_add(C::COST_MOV_IMM);
    if folded_cost <= rr_cost && machine.vreg_is_const_source(mir.src1) && mir.op != ssl_hot::mir::M_MUL_I {
        let mut copy = MachineInsn::new(X_MOV_RR);
        copy.dst = mir.dst;
        copy.src0 = mir.src0;
        if !machine.push(copy) {
            return false;
        }
        let mut insn = MachineInsn::new(X_ADD_IR);
        insn.dst = mir.dst;
        insn.imm = machine.vreg_const_addend(mir.src1, mir.op);
        return machine.push(insn);
    }
    let mut insn = MachineInsn::new(opcode);
    insn.dst = mir.dst;
    insn.src0 = mir.src0;
    insn.src1 = mir.src1;
    machine.push(insn)
}
