// CEP:FILE: target/x86_64/src/isel_simd.rs
// CEP:WHAT: Instruction selection for packed SSE2 double operations: vector loads and stores, packed arithmetic, lane packing, and horizontal reduction.
// CEP:WHY: design.md Part 6 emits SIMD tiles when the vectorizer proves legality; SSE2 is the deterministic ISA floor (x86-64-v1 plus SSE2) so emission stays reproducible.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns false on machine buffer rejection; callers abort compilation deterministically.
// CEP:ASSUMES: vector nodes are two-lane doubles; the horizontal combine uses unpckhpd plus addsd because SSE3 haddpd is above the ISA floor.
// CEP:COST: one movapd per vector load or store; one addpd per packed arithmetic; two instructions for the horizontal combine.
// CEP:EVIDENCE: golden disassembly of vector traces; differential tests.
// CEP:CODEGEN-UOPS: movapd one uop port 2 or 3; addpd one uop port 0 or 1; unpckhpd one uop port 5.
// CEP:CODEGEN-VECTOR: SSE2 128-bit, two doubles per tile.
// CEP:TARGET: x86-64 (SSE2)

use crate::isa_def::*;
use crate::machine::MachineFunction;
use ssl_config::target_model::heap_layout as hlayout;
use ssl_hot::mir::MirInsn;

/// Lowers one SIMD-class MIR instruction into machine tiles.
pub fn lower_simd(mir: &MirInsn, machine: &mut MachineFunction) -> bool {
    match mir.op {
        ssl_hot::mir::M_VEC_LOAD => {
            let mut insn = MachineInsn::new(X_MOVAPD_M2X);
            insn.dst = mir.dst;
            insn.src0 = mir.src0;
            insn.src1 = mir.src1;
            insn.imm = hlayout::HEADER_BYTES as i32 + 8;
            machine.push(insn)
        }
        ssl_hot::mir::M_VEC_STORE => {
            let mut insn = MachineInsn::new(X_MOVAPD_X2M);
            insn.src0 = mir.src0;
            insn.src1 = mir.src1;
            insn.imm = hlayout::HEADER_BYTES as i32 + 8;
            insn.aux = mir.imm as u16;
            machine.push(insn)
        }
        ssl_hot::mir::M_VEC_ADD | ssl_hot::mir::M_VEC_SUB | ssl_hot::mir::M_VEC_MUL => {
            let opcode = match mir.op {
                ssl_hot::mir::M_VEC_ADD => X_ADDPD,
                ssl_hot::mir::M_VEC_SUB => X_SUBPD,
                _ => X_MULPD,
            };
            let mut insn = MachineInsn::new(opcode);
            insn.dst = mir.dst;
            insn.src0 = mir.src0;
            insn.src1 = mir.src1;
            machine.push(insn)
        }
        ssl_hot::mir::M_VEC_PACK => {
            let mut insn = MachineInsn::new(X_UNPCKLPD);
            insn.dst = mir.dst;
            insn.src0 = mir.src0;
            insn.src1 = mir.src1;
            machine.push(insn)
        }
        ssl_hot::mir::M_VEC_HADD => {
            let mut high = MachineInsn::new(X_UNPCKHPD);
            high.dst = mir.dst;
            high.src0 = mir.src0;
            if !machine.push(high) {
                return false;
            }
            let mut add = MachineInsn::new(X_ADDSD);
            add.dst = mir.dst;
            add.src0 = mir.src0;
            machine.push(add)
        }
        ssl_hot::mir::M_CONST_F => {
            let scratch = machine.scratch_gpr();
            let mut bits = MachineInsn::new(X_MOV_IR64);
            bits.dst = scratch;
            bits.imm = mir.imm;
            if !machine.push(bits) {
                return false;
            }
            let mut move_bits = MachineInsn::new(X_MOVD_G2X);
            move_bits.dst = mir.dst;
            move_bits.src0 = scratch;
            machine.push(move_bits)
        }
        _ => false,
    }
}
