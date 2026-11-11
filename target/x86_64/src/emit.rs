// CEP:FILE: target/x86_64/src/emit.rs
// CEP:WHAT: The machine code emitter: layout with label resolution, peephole rewrites, exit stubs, helper thunks, and W^X publication through the ffi manager.
// CEP:WHY: design.md Part 7 requires peephole micro-optimization during emission and Part 9 requires patchable guard exits; the emitter is the only writer of executable memory and publishes only after sealing.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns EmitError on overflow, unknown labels, or unresolvable helpers; the caller discards the trace deterministically.
// CEP:ASSUMES: machine buffers contain only encoder-supported opcodes; rbx carries the state pointer and r15 the heap base inside traces; r10 and r11 are encoder scratch.
// CEP:COST: one encode pass plus one patch pass; bounded by the code cache size.
// CEP:EVIDENCE: golden disassembly artifacts; differential JIT execution.
// CEP:SECURITY: the region is sealed read-execute before any entry pointer escapes this module.
// CEP:UNSAFE: encodes into the writable stage of the ffi-owned region only; execution goes through the validated ffi entry wrapper.

use crate::isa_def::*;
use crate::isa_enc::{EncodeError, Encoder};
use crate::machine::{LABEL_ALLOC_STUB, LABEL_HEADER};
use crate::regalloc::Allocation;
use ssl_ffi::ffi_mmap::CodeMemory;
use ssl_config::bytecode_consts::Const;
use ssl_config::target_model::jit_state_layout as layout;
use ssl_config::target_model::abi_reservation as abi;
use ssl_hot::mir::{MirBody, SnapEntry};
use ssl_hot::vm_value::{TAG_BOOL, TAG_INT, TAG_NUM, TAG_STR, TAG_TBL};

/// Emitter failure enumeration.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum EmitError {
    /// The output buffer rejected an instruction.
    Overflow,
    /// A branch referenced an unknown label.
    BadLabel,
    /// A helper address was unavailable.
    BadHelper,
    /// The ffi stage rejected a write or seal.
    Memory,
}

/// Label table with deterministic ordering.
pub struct LabelTable {
    entries: [(u16, usize); LABEL_TABLE_CAP],
    count: usize,
}

/// Maximum labels per trace emission.
pub const LABEL_TABLE_CAP: usize = 128;

impl LabelTable {
    fn new() -> LabelTable {
        LabelTable {
            entries: [(0, 0); LABEL_TABLE_CAP],
            count: 0,
        }
    }

    fn insert(&mut self, label: u16, offset: usize) -> bool {
        for idx in 0..self.count {
            if self.entries[idx].0 == label {
                self.entries[idx].1 = offset;
                return true;
            }
        }
        if self.count >= LABEL_TABLE_CAP {
            return false;
        }
        self.entries[self.count] = (label, offset);
        self.count += 1;
        true
    }

    fn get(&self, label: u16) -> Option<usize> {
        for idx in 0..self.count {
            if self.entries[idx].0 == label {
                return Some(self.entries[idx].1);
            }
        }
        None
    }

    /// Debug accessor listing all label offsets in insertion order.
    pub fn debug_entries(&self) -> [(u16, usize); LABEL_TABLE_CAP] {
        let mut out = [(0u16, 0usize); LABEL_TABLE_CAP];
        for idx in 0..self.count {
            out[idx] = self.entries[idx];
        }
        out
    }

    /// Number of bound labels.
    pub fn debug_count(&self) -> usize {
        self.count
    }
}

/// Branch fixup record.
#[derive(Copy, Clone)]
struct Fixup {
    at: usize,
    label: u16,
}

/// Emission result: sealed code, label offsets, and the trace entry offset (always the prologue).
pub struct Emitted {
    /// Sealed code region.
    pub code: CodeMemory,
    /// Resolved label offsets.
    pub labels: LabelTable,
    /// Byte offset of the trace entry.
    pub entry: usize,
    /// Byte offset of each guard stub ret for later side-trace patching.
    pub stub_rets: [u16; ssl_config::limits::EXIT_GUARD_LIMIT as usize],
}

/// Encodes one machine function into a fresh code region and seals it.
pub fn emit_trace(
    machine: &crate::machine::MachineFunction,
    allocation: &Allocation,
    mir: &MirBody,
    consts: &[Const],
) -> Result<Emitted, EmitError> {
    let mut code = CodeMemory::new(CODE_REQUEST_BYTES).map_err(|_| EmitError::Memory)?;
    let outcome = {
        let stage: &mut [u8] = code.stage();
        let mut encoder = Encoder::new(stage);
        encode_all(machine, allocation, mir, consts, &mut encoder)?
    };
    code.mark_used(outcome.len);
    code.seal().map_err(|_| EmitError::Memory)?;
    Ok(Emitted {
        stub_rets: outcome.stub_rets,
        code,
        labels: outcome.labels,
        entry: 0,
    })
}

/// Requested code region size per trace.
const CODE_REQUEST_BYTES: usize = 1 << 16;

/// Encode outcome carried out of the stage borrow.
pub struct EncodeOutcome {
    /// Encoded length.
    pub len: usize,
    /// Label table.
    pub labels: LabelTable,
    /// Trace entry offset.
    pub header: usize,
    /// Guard stub ret offsets.
    pub stub_rets: [u16; ssl_config::limits::EXIT_GUARD_LIMIT as usize],
}

type EncodeResult = EncodeOutcome;

/// Fixup vector without heap allocation.
pub struct Vec_Fixup {
    pub items: [Fixup; FIXUP_CAP],
    pub len: usize,
}

/// Maximum branch fixups per trace.
pub const FIXUP_CAP: usize = 160;

impl Vec_Fixup {
    fn new() -> Vec_Fixup {
        Vec_Fixup {
            items: [Fixup { at: 0, label: 0 }; FIXUP_CAP],
            len: 0,
        }
    }

    fn push(&mut self, fixup: Fixup) -> bool {
        if self.len >= FIXUP_CAP {
            return false;
        }
        self.items[self.len] = fixup;
        self.len += 1;
        true
    }
}

/// Encodes prologue, body, stubs, and helpers; patches branches; returns offsets.
fn encode_all(
    machine: &crate::machine::MachineFunction,
    allocation: &Allocation,
    mir: &MirBody,
    consts: &[Const],
    encoder: &mut Encoder,
) -> Result<EncodeOutcome, EmitError> {
    emit_prologue(machine, allocation, encoder)?;
    let header = encoder.len;
    let mut labels = LabelTable::new();
    if !labels.insert(LABEL_HEADER, header) {
        return Err(EmitError::Overflow);
    }
    if !emit_header_reset(encoder) {
        return Err(EmitError::Overflow);
    }
    let mut fixups = Vec_Fixup::new();
    for idx in 0..machine.count as usize {
        emit_insn(
            &machine.insns[idx],
            allocation,
            consts,
            encoder,
            &mut labels,
            &mut fixups,
        )?;
    }
    let stub_rets = emit_stubs(machine, allocation, mir, encoder, &mut labels, &mut fixups)?;
    for idx in 0..fixups.len {
        let fix = fixups.items[idx];
        let target = labels.get(fix.label).ok_or(EmitError::BadLabel)?;
        if cfg!(feature = "trace-debug") {
            eprintln!("DBG patch at={} label={} target={}", fix.at, fix.label, target);
        }
        encoder.patch_rel32(fix.at, target).map_err(|_| EmitError::Overflow)?;
    }
    Ok(EncodeOutcome {
        len: encoder.len,
        labels,
        header,
        stub_rets,
    })
}

/// Emits the prologue: saved registers, state pointer, heap base, allocation reservation, and alignment pad.
fn emit_prologue(
    machine: &crate::machine::MachineFunction,
    allocation: &Allocation,
    encoder: &mut Encoder,
) -> Result<(), EmitError> {
    push_raw(encoder, 0x53)?;
    push_raw2(encoder, 0x41, 0x55)?;
    push_raw2(encoder, 0x41, 0x56)?;
    let mut pushes = 3u8;
    if allocation.uses_r12() {
        push_raw2(encoder, 0x41, 0x54)?;
        pushes += 1;
    }
    let _ = machine;
    if pushes % 2 == 0 {
        push_raw2(encoder, 0x48, 0x83)?;
        push_raw(encoder, 0xEC)?;
        push_raw(encoder, 0x08)?;
    }
    mov_rr_raw(encoder, abi::STATE_PTR_GPR, abi::STATE_PTR_ARG_GPR)?;
    mov_slot_r_raw(encoder, abi::HEAP_BASE_GPR, layout::HEAP_BASE as i32)?;
    mov_slot_r_raw(encoder, abi::ALLOC_START_GPR, layout::BUMP_PTR as i32)?;
    Ok(())
}

/// Emits the per-iteration allocation cursor reset at the loop header.
pub fn emit_header_reset(encoder: &mut Encoder) -> bool {
    mov_rr_raw(encoder, abi::ALLOC_CURSOR_GPR, abi::ALLOC_START_GPR).is_ok()
}

fn push_raw(encoder: &mut Encoder, byte: u8) -> Result<(), EmitError> {
    encoder.push(byte).map_err(|_| EmitError::Overflow)
}

fn push_raw2(encoder: &mut Encoder, a: u8, b: u8) -> Result<(), EmitError> {
    encoder.push(a).map_err(|_| EmitError::Overflow)?;
    encoder.push(b).map_err(|_| EmitError::Overflow)
}

fn mov_rr_raw(encoder: &mut Encoder, dst: u8, src: u8) -> Result<(), EmitError> {
    let rex = 0x48 | ((src >= 8) as u8) << 2 | ((dst >= 8) as u8);
    encoder.push(rex).map_err(|_| EmitError::Overflow)?;
    encoder.push(0x89).map_err(|_| EmitError::Overflow)?;
    encoder
        .push(0xC0 | ((src & 7) << 3) | (dst & 7))
        .map_err(|_| EmitError::Overflow)
}

fn mov_slot_r_raw(encoder: &mut Encoder, dst: u8, disp: i32) -> Result<(), EmitError> {
    let rex = 0x48 | ((dst >= 8) as u8) << 2;
    encoder.push(rex).map_err(|_| EmitError::Overflow)?;
    encoder.push(0x8B).map_err(|_| EmitError::Overflow)?;
    encoder
        .push(0x80 | ((dst & 7) << 3) | 3)
        .map_err(|_| EmitError::Overflow)?;
    encoder.push_le32(disp as u32).map_err(|_| EmitError::Overflow)
}

/// Physical register id for a vreg; PHYS_BASE ids pass through; the emit scratch maps to r11.
fn phys(allocation: &Allocation, vreg: u16) -> u8 {
    if vreg >= PHYS_BASE {
        return (vreg - PHYS_BASE) as u8;
    }
    if vreg == CRATE_SCRATCH_A {
        return SCRATCH_EMIT_A;
    }
    if vreg == CRATE_SCRATCH_B {
        return SCRATCH_EMIT_B;
    }
    let mapped = allocation.map[vreg as usize];
    (mapped - PHYS_BASE) as u8
}

/// Machine scratch vreg ids agreed with the isel layer.
pub const CRATE_SCRATCH_A: u16 = crate::machine::SCRATCH_VREG_A;
pub const CRATE_SCRATCH_B: u16 = crate::machine::SCRATCH_VREG_B;

/// Physical scratch registers behind the scratch vregs.
const SCRATCH_EMIT_A: u8 = 10;
const SCRATCH_EMIT_B: u8 = 11;

/// Reserved encoder scratch for tag stores.
const SCRATCH_EMIT: u8 = SCRATCH_EMIT_B;

/// Emits one machine instruction with peephole rewrites.
fn emit_insn(
    insn: &MachineInsn,
    allocation: &Allocation,
    consts: &[Const],
    encoder: &mut Encoder,
    labels: &mut LabelTable,
    fixups: &mut Vec_Fixup,
) -> Result<(), EmitError> {
    match insn.op {
        X_MOV_IR => {
            if insn.imm == 0 {
                let dst = phys(allocation, insn.dst);
                encoder.alu_rr(0x31, dst, dst).map_err(|_| EmitError::Overflow)?;
                return Ok(());
            }
            encoder
                .mov_ir(phys(allocation, insn.dst), insn.imm)
                .map_err(|_| EmitError::Overflow)
        }
        X_MOV_IR64 => {
            let dst = phys(allocation, insn.dst);
            let bits = const_bits(consts, insn.imm).ok_or(EmitError::BadHelper)?;
            emit_mov_ir64(encoder, dst, bits)
        }
        X_MOV_RR => {
            let dst = phys(allocation, insn.dst);
            let src = phys(allocation, insn.src0);
            if dst == src {
                return Ok(());
            }
            encoder.mov_rr(dst, src).map_err(|_| EmitError::Overflow)
        }
        X_MOV_SLOT_R => encoder
            .mov_slot_r(phys(allocation, insn.dst), insn.imm)
            .map_err(|_| EmitError::Overflow),
        X_MOV_R_SLOT => encoder
            .mov_r_slot(phys(allocation, insn.src0), insn.imm)
            .map_err(|_| EmitError::Overflow),
        X_MOV_SLOT_TAG => encoder
            .store_slot_imm32(insn.imm, insn.imm2)
            .map_err(|_| EmitError::Overflow),
        X_ADD_RR => {
            let dst = phys(allocation, insn.dst);
            let base = phys(allocation, insn.src0);
            if dst != base {
                encoder.mov_rr(dst, base).map_err(|_| EmitError::Overflow)?;
            }
            let src = phys(allocation, insn.src1);
            encoder.alu_rr(0x01, dst, src).map_err(|_| EmitError::Overflow)
        }
        X_SUB_RR => {
            let dst = phys(allocation, insn.dst);
            let base = phys(allocation, insn.src0);
            if dst != base {
                encoder.mov_rr(dst, base).map_err(|_| EmitError::Overflow)?;
            }
            let src = phys(allocation, insn.src1);
            encoder.alu_rr(0x29, dst, src).map_err(|_| EmitError::Overflow)
        }
        X_XOR_RR => {
            let dst = phys(allocation, insn.dst);
            encoder.alu_rr(0x31, dst, dst).map_err(|_| EmitError::Overflow)
        }
        X_CMP_RR => {
            let a = phys(allocation, insn.src0);
            let b = phys(allocation, insn.src1);
            encoder.alu_rr(0x39, a, b).map_err(|_| EmitError::Overflow)
        }
        X_IMUL_RR => {
            let dst = phys(allocation, insn.dst);
            let base = phys(allocation, insn.src0);
            if dst != base {
                encoder.mov_rr(dst, base).map_err(|_| EmitError::Overflow)?;
            }
            let src = phys(allocation, insn.src1);
            encoder.imul_rr(dst, src).map_err(|_| EmitError::Overflow)
        }
        X_ADD_IR => {
            if insn.imm == 0 {
                return Ok(());
            }
            encoder
                .alu_ir(0, phys(allocation, insn.dst), insn.imm)
                .map_err(|_| EmitError::Overflow)
        }
        X_SHL_IR => encoder
            .shift_ir(0x4, phys(allocation, insn.dst), insn.imm)
            .map_err(|_| EmitError::Overflow),
        X_SHR_IR => encoder
            .shift_ir(0x5, phys(allocation, insn.dst), insn.imm)
            .map_err(|_| EmitError::Overflow),
        X_CMP_IR => encoder
            .alu_ir(0x7, phys(allocation, insn.src0), insn.imm)
            .map_err(|_| EmitError::Overflow),
        X_SETC => encoder
            .setcc(insn.imm as u8, phys(allocation, insn.dst))
            .map_err(|_| EmitError::Overflow),
        X_MOVD_G2X | X_MOVD_X2G => {
            let to_xmm = insn.op == X_MOVD_G2X;
            let a = phys(allocation, insn.dst);
            let b = phys(allocation, insn.src0);
            encoder.movq(to_xmm, a, b).map_err(|_| EmitError::Overflow)
        }
        X_CVT_SI2SD => encoder
            .cvt_si2sd(phys(allocation, insn.dst), phys(allocation, insn.src0))
            .map_err(|_| EmitError::Overflow),
        X_CVTTSD2SI => encoder
            .cvttsd2si(phys(allocation, insn.dst), phys(allocation, insn.src0))
            .map_err(|_| EmitError::Overflow),
        X_MOVSD_X2X => {
            let dst = phys(allocation, insn.dst);
            let src = phys(allocation, insn.src0);
            if dst == src {
                return Ok(());
            }
            encoder.sse_rr(0xF2, 0x10, dst, src).map_err(|_| EmitError::Overflow)
        }
        X_ADDSD | X_SUBSD | X_MULSD | X_DIVSD => {
            let opcode = match insn.op {
                X_ADDSD => 0x58,
                X_SUBSD => 0x5C,
                X_MULSD => 0x59,
                _ => 0x5E,
            };
            let dst = phys(allocation, insn.dst);
            let base = phys(allocation, insn.src0);
            if dst != base {
                encoder.sse_rr(0xF2, 0x10, dst, base).map_err(|_| EmitError::Overflow)?;
            }
            let src = phys(allocation, insn.src1);
            encoder.sse_rr(0xF2, opcode, dst, src).map_err(|_| EmitError::Overflow)
        }
        X_SQRTSD => encoder
            .sse_rr(0xF2, 0x51, phys(allocation, insn.dst), phys(allocation, insn.src0))
            .map_err(|_| EmitError::Overflow),
        X_UCOMISD => encoder
            .sse_rr(0x66, 0x2E, phys(allocation, insn.src0), phys(allocation, insn.src1))
            .map_err(|_| EmitError::Overflow),
        X_PXOR => {
            let dst = phys(allocation, insn.dst);
            encoder.sse_rr(0x66, 0xEF, dst, dst).map_err(|_| EmitError::Overflow)
        }
        X_ADDPD | X_SUBPD | X_MULPD => {
            let opcode = match insn.op {
                X_ADDPD => 0x58,
                X_SUBPD => 0x5C,
                _ => 0x59,
            };
            let dst = phys(allocation, insn.dst);
            let base = phys(allocation, insn.src0);
            if dst != base {
                encoder.sse_rr(0x66, 0x28, dst, base).map_err(|_| EmitError::Overflow)?;
            }
            let src = phys(allocation, insn.src1);
            encoder.sse_rr(0x66, opcode, dst, src).map_err(|_| EmitError::Overflow)
        }
        X_UNPCKLPD | X_UNPCKHPD => encoder
            .unpckpd(insn.op == X_UNPCKHPD, phys(allocation, insn.dst), phys(allocation, insn.src1))
            .map_err(|_| EmitError::Overflow),
        X_MOVAPD_M2X | X_MOVSD_M2X => {
            let dst = phys(allocation, insn.dst);
            let prefix = if insn.op == X_MOVAPD_M2X { 0x66 } else { 0xF2 };
            let opcode = if insn.op == X_MOVAPD_M2X { 0x28 } else { 0x10 };
            emit_heap_sse_access(
                encoder,
                opcode,
                prefix,
                phys(allocation, insn.src0),
                phys(allocation, insn.src1),
                disp_for(insn.imm),
                true,
            )
        }
        X_MOVAPD_X2M | X_MOVSD_X2M => {
            let src = phys(allocation, insn.aux);
            let prefix = if insn.op == X_MOVAPD_X2M { 0x66 } else { 0xF2 };
            let opcode = if insn.op == X_MOVAPD_X2M { 0x29 } else { 0x11 };
            emit_heap_sse_access(
                encoder,
                opcode,
                prefix,
                phys(allocation, insn.src0),
                phys(allocation, insn.src1),
                disp_for(insn.imm),
                false,
            )
        }
        X_LOAD_IDX => encoder
            .heap_idx_load(phys(allocation, insn.dst), phys(allocation, insn.src1), 0, insn.imm)
            .map_err(|_| EmitError::Overflow),
        X_STORE_IDX => encoder
            .heap_idx_store(phys(allocation, insn.src0), phys(allocation, insn.src1), scale_bits(insn.aux), insn.imm)
            .map_err(|_| EmitError::Overflow),
        X_STORE_ZERO_IDX => encoder
            .heap_zero_store(phys(allocation, insn.src0), insn.imm)
            .map_err(|_| EmitError::Overflow),
        X_JCC_REL | X_JMP_REL => {
            let at = if insn.op == X_JCC_REL {
                encoder.jcc_rel32(insn.imm as u8).map_err(|_| EmitError::Overflow)?
            } else {
                encoder.jmp_rel32().map_err(|_| EmitError::Overflow)?
            };
            if !fixups.push(Fixup { at, label: insn.aux }) {
                return Err(EmitError::Overflow);
            }
            Ok(())
        }
        X_CALL_REL => {
            let at = encoder.call_rel32().map_err(|_| EmitError::Overflow)?;
            if !fixups.push(Fixup { at, label: insn.aux }) {
                return Err(EmitError::Overflow);
            }
            Ok(())
        }
        X_BIND_LABEL => {
            if !labels.insert(insn.aux, encoder.len) {
                return Err(EmitError::Overflow);
            }
            Ok(())
        }
        X_RET => encoder.ret().map_err(|_| EmitError::Overflow),
        X_NOP => encoder.nop().map_err(|_| EmitError::Overflow),
        _ => Err(EmitError::Overflow),
    }
}

/// Scratch vreg ids emitted by the isel layer route to fixed physical registers.
fn scale_bits(aux: u16) -> u8 {
    match aux {
        1 => 1,
        2 => 2,
        3 => 3,
        _ => 0,
    }
}

/// Byte displacement inside one heap object for the vector field selector.
fn disp_for(selector: i32) -> i32 {
    if selector >= 0 {
        selector
    } else {
        8
    }
}

fn const_bits(consts: &[Const], index: i32) -> Option<u64> {
    match consts.get(index as usize) {
        Some(Const::Num(value)) => Some(value.to_bits()),
        Some(Const::Int(value)) => Some(*value as u64),
        _ => None,
    }
}

/// Emits an address computation then an SSE heap access through r15 with the isel scratch.
fn emit_heap_sse_access(
    encoder: &mut Encoder,
    opcode: u8,
    prefix: u8,
    table: u8,
    index: u8,
    disp: i32,
    load: bool,
) -> Result<(), EmitError> {
    mov_rr_raw(encoder, SCRATCH_EMIT_A, table)?;
    encoder.shift_ir(0x4, SCRATCH_EMIT_A, 4).map_err(|_| EmitError::Overflow)?;
    mov_rr_raw(encoder, SCRATCH_EMIT_B, index)?;
    encoder.shift_ir(0x4, SCRATCH_EMIT_B, 4).map_err(|_| EmitError::Overflow)?;
    encoder.alu_rr(0x01, SCRATCH_EMIT_A, SCRATCH_EMIT_B).map_err(|_| EmitError::Overflow)?;
    let _ = table;
    if load {
        encoder
            .heap_sse_load(opcode, prefix, SCRATCH_SSE, SCRATCH_EMIT_A, disp)
            .map_err(|_| EmitError::Overflow)
    } else {
        encoder
            .heap_sse_store(opcode, prefix, SCRATCH_SSE, SCRATCH_EMIT_A, disp)
            .map_err(|_| EmitError::Overflow)
    }
}

/// Fixed xmm scratch for staged vector accesses (xmm7).
const SCRATCH_SSE: u8 = 7;

/// Emits the guard exit stubs, allocation stub, and helper thunks after the body.
fn emit_stubs(
    machine: &crate::machine::MachineFunction,
    allocation: &Allocation,
    mir: &MirBody,
    encoder: &mut Encoder,
    labels: &mut LabelTable,
    fixups: &mut Vec_Fixup,
) -> Result<[u16; ssl_config::limits::EXIT_GUARD_LIMIT as usize], EmitError> {
    let _ = (machine, fixups);
    let mut emitted_stub_rets = [0u16; ssl_config::limits::EXIT_GUARD_LIMIT as usize];

    for idx in 0..mir.snapshot_count as usize {
        let snapshot = mir.snapshots[idx];
        if !labels.insert(crate::machine::stub_label(snapshot.guard), encoder.len) {
            return Err(EmitError::Overflow);
        }
        let start = snapshot.start as usize;
        let stop = (start + snapshot.len as usize).min(mir.snap_used as usize);
        for entry in &mir.snap_entries[start..stop] {
            emit_snapshot_entry(encoder, allocation, entry)?;
        }
        let exit_id = ssl_config::limits::EXIT_GUARD_BASE + snapshot.guard as u32;
        encoder
            .mov_ir(0, exit_id as i32)
            .map_err(|_| EmitError::Overflow)?;
        emit_epilogue(allocation, encoder)?;
        if (snapshot.guard as usize) < emitted_stub_rets.len() {
            emitted_stub_rets[snapshot.guard as usize] = (encoder.len - 1) as u16;
        }
        for _ in 0..PATCH_PAD_NOPS {
            encoder.nop().map_err(|_| EmitError::Overflow)?;
        }
    }
    if !labels.insert(LABEL_ALLOC_STUB, encoder.len) {
        return Err(EmitError::Overflow);
    }
    encoder
        .mov_ir(0, ssl_config::limits::EXIT_ALLOC as i32)
        .map_err(|_| EmitError::Overflow)?;
    emit_epilogue(allocation, encoder)?;
    for fnid in 0..ssl_config::limits::MATH_HELPER_COUNT {
        let address = ssl_ffi::ffi_math::helper_address(fnid as u8).ok_or(EmitError::BadHelper)?;
        if !labels.insert(crate::machine::helper_label(fnid as u16), encoder.len) {
            return Err(EmitError::Overflow);
        }
        emit_mov_ir64(encoder, SCRATCH_EMIT_A, address as u64)?;
        encoder.push(0xFF).map_err(|_| EmitError::Overflow)?;
        encoder.push(0xE2).map_err(|_| EmitError::Overflow)?;
    }
    Ok(emitted_stub_rets)
}

/// Padding nops after each stub ret reserved for side-trace patching.
const PATCH_PAD_NOPS: usize = 11;

/// Emits one snapshot entry: re-box the vreg payload into its frame slot.
fn emit_snapshot_entry(
    encoder: &mut Encoder,
    allocation: &Allocation,
    entry: &SnapEntry,
) -> Result<(), EmitError> {
    let tag = match entry.kind {
        1 => TAG_INT,
        2 => TAG_NUM,
        3 => TAG_BOOL,
        4 => TAG_STR,
        _ => TAG_TBL,
    };
    encoder
        .mov_ir(SCRATCH_EMIT, tag as i32)
        .map_err(|_| EmitError::Overflow)?;
    encoder
        .mov_r_slot(SCRATCH_EMIT, slot_tag_disp(entry.slot as i32))
        .map_err(|_| EmitError::Overflow)?;
    encoder
        .mov_r_slot(phys(allocation, entry.vreg), slot_payload_disp(entry.slot as i32))
        .map_err(|_| EmitError::Overflow)
}

/// Emits the register restore and return sequence mirroring the prologue.
fn emit_epilogue(allocation: &Allocation, encoder: &mut Encoder) -> Result<(), EmitError> {
    if allocation.uses_r12() {
        push_raw2(encoder, 0x48, 0x83)?;
        push_raw(encoder, 0xC4)?;
        push_raw(encoder, 0x08)?;
    }
    push_raw2(encoder, 0x41, 0x5E)?;
    push_raw2(encoder, 0x41, 0x5D)?;
    push_raw(encoder, 0x5B)?;
    encoder.ret().map_err(|_| EmitError::Overflow)
}

fn emit_mov_ir64(encoder: &mut Encoder, dst: u8, value: u64) -> Result<(), EmitError> {
    let rex = 0x48 | ((dst >= 8) as u8);
    encoder.push(rex).map_err(|_| EmitError::Overflow)?;
    encoder.push(0xB8 + (dst & 7)).map_err(|_| EmitError::Overflow)?;
    for shift in 0..8usize {
        encoder
            .push((value >> (shift * 8)) as u8)
            .map_err(|_| EmitError::Overflow)?;
    }
    Ok(())
}

/// disp of one slot tag inside VmState.
fn slot_tag_disp(slot: i32) -> i32 {
    layout::SLOTS as i32 + slot * 16
}

/// disp of one slot payload inside VmState.
fn slot_payload_disp(slot: i32) -> i32 {
    slot_tag_disp(slot) + 8
}

