// CEP:FILE: target/x86_64/src/isel.rs
// CEP:WHAT: Instruction selection dispatcher: lowers every MIR record through the class-partitioned isel modules into the machine buffer.
// CEP:WHY: Chapter 62.3.3 requires isel partitioning by instruction class; the dispatcher is the single pipeline step that routes records to scalar, memory, control, or SIMD selection.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns an error naming the unhandled MIR opcode; unknown records abort compilation deterministically.
// CEP:ASSUMES: the MIR body was produced by mir_build and only contains opcodes in the SSL-LuaJIT set.
// CEP:COST: O(N) dispatch with O(1) routing per record.
// CEP:EVIDENCE: golden machine tests; differential codegen.

use crate::isa_def::*;
use crate::isel_control;
use crate::isel_memory;
use crate::isel_scalar;
use crate::isel_simd;
use crate::machine::MachineFunction;
use ssl_hot::mir::MirBody;

/// Instruction selection failure enumeration.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum IselError {
    /// A MIR opcode has no lowering.
    Unhandled(u16),
    /// The machine buffer rejected an instruction.
    MachineFull,
}

/// Lowers a complete MIR body into the machine buffer.
pub fn select_instructions(mir: &MirBody, machine: &mut MachineFunction) -> Result<(), IselError> {
    for idx in 0..mir.count as usize {
        let mir_insn = mir.insns[idx];
        let lowered = match mir_insn.op {
            ssl_hot::mir::M_CONST_I
            | ssl_hot::mir::M_MOV_I
            | ssl_hot::mir::M_ADD_I
            | ssl_hot::mir::M_SUB_I
            | ssl_hot::mir::M_MUL_I
            | ssl_hot::mir::M_MOV_F
            | ssl_hot::mir::M_ADD_F
            | ssl_hot::mir::M_SUB_F
            | ssl_hot::mir::M_MUL_F
            | ssl_hot::mir::M_DIV_F
            | ssl_hot::mir::M_INT2F
            | ssl_hot::mir::M_SET_BOOL => isel_scalar::lower_scalar(&mir_insn, machine),
            ssl_hot::mir::M_LOAD_SLOT
            | ssl_hot::mir::M_STORE_SLOT
            | ssl_hot::mir::M_LOAD_ARR_SLOT
            | ssl_hot::mir::M_STORE_ARR_SLOT
            | ssl_hot::mir::M_LOAD_G_SLOT
            | ssl_hot::mir::M_STORE_G_SLOT
            | ssl_hot::mir::M_NEW_TABLE
            | ssl_hot::mir::M_ALLOC_CHECK => isel_memory::lower_memory(&mir_insn, machine),
            ssl_hot::mir::M_CMP_I
            | ssl_hot::mir::M_CMP_F
            | ssl_hot::mir::M_GUARD
            | ssl_hot::mir::M_GUARD_SHAPE
            | ssl_hot::mir::M_GUARD_FLAG
            | ssl_hot::mir::M_CALLM
            | ssl_hot::mir::M_EXIT
            | ssl_hot::mir::M_LOOP_BACK => isel_control::lower_control(&mir_insn, machine),
            ssl_hot::mir::M_VEC_LOAD
            | ssl_hot::mir::M_VEC_STORE
            | ssl_hot::mir::M_VEC_ADD
            | ssl_hot::mir::M_VEC_SUB
            | ssl_hot::mir::M_VEC_MUL
            | ssl_hot::mir::M_VEC_PACK
            | ssl_hot::mir::M_VEC_HADD
            | ssl_hot::mir::M_CONST_F => isel_simd::lower_simd(&mir_insn, machine),
            _ => return Err(IselError::Unhandled(mir_insn.op)),
        };
        if !lowered {
            return Err(IselError::MachineFull);
        }
    }
    Ok(())
}
