// CEP:FILE: target/x86_64/src/isa_enc.rs
// CEP:WHAT: The x86-64 byte encoder: ModRM/SIB construction, immediate widths, branch relocation, and instruction byte emission into a caller buffer.
// CEP:WHY: design.md Part 7 requires writing native machine code; one deterministic encoder with byte-level tests is auditable and golden-testable.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns EncodeError::Overflow when the output buffer is too small; never panics and never writes past capacity.
// CEP:ASSUMES: registers are 64-bit encodings with REX.W; memory operands use base rbx (state), r15 (heap), or rsp-relative stack slots.
// CEP:COST: O(bytes) per instruction; emission is one linear pass.
// CEP:EVIDENCE: encoder round-trip tests against objdump in tests; golden disassembly.
// CEP:TARGET: x86-64

use crate::isa_def::*;

/// Encoder failure enumeration.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum EncodeError {
    /// Output buffer exhausted.
    Overflow,
    /// Register id outside the encodable range.
    BadRegister,
}

/// Output sink for encoded bytes with a hard capacity.
pub struct Encoder<'a> {
    pub buf: &'a mut [u8],
    pub len: usize,
}

impl<'a> Encoder<'a> {
    pub fn new(buf: &'a mut [u8]) -> Encoder<'a> {
        Encoder { buf, len: 0 }
    }

    pub fn push(&mut self, byte: u8) -> Result<(), EncodeError> {
        if self.len >= self.buf.len() {
            return Err(EncodeError::Overflow);
        }
        self.buf[self.len] = byte;
        self.len += 1;
        Ok(())
    }

    pub fn push_le32(&mut self, value: u32) -> Result<(), EncodeError> {
        self.push(value as u8)?;
        self.push((value >> 8) as u8)?;
        self.push((value >> 16) as u8)?;
        self.push((value >> 24) as u8)
    }

    /// Pushes a REX prefix with W set; arguments are the reg-field and rm-field high-bit flags.
    pub fn push_rex_w(&mut self, reg_high: bool, rm_high: bool) -> Result<(), EncodeError> {
        let mut rex = 0x48u8;
        if reg_high {
            rex |= 0x04;
        }
        if rm_high {
            rex |= 0x01;
        }
        self.push(rex)
    }

    /// Pushes a REX prefix without W for byte and SSE operations.
    pub fn push_rex(&mut self, reg_high: bool, index_high: bool, base_high: bool) -> Result<(), EncodeError> {
        let mut rex = 0x40u8;
        if reg_high {
            rex |= 0x04;
        }
        if index_high {
            rex |= 0x02;
        }
        if base_high {
            rex |= 0x01;
        }
        self.push(rex)
    }

    pub fn push_modrm(&mut self, mod_bits: u8, reg: u8, rm: u8) -> Result<(), EncodeError> {
        self.push((mod_bits << 6) | ((reg & 7) << 3) | (rm & 7))
    }

    /// Encodes mov r64, imm32 (sign extended).
    pub fn mov_ir(&mut self, reg: u8, imm: i32) -> Result<(), EncodeError> {
        self.push_rex_w(false, reg >= 8)?;
        self.push(0xC7)?;
        self.push_modrm(3, 0, reg)?;
        self.push_le32(imm as u32)
    }

    /// Encodes mov r64, r64.
    pub fn mov_rr(&mut self, dst: u8, src: u8) -> Result<(), EncodeError> {
        self.push_rex_w(src >= 8, dst >= 8)?;
        self.push(0x89)?;
        self.push_modrm(3, src, dst)
    }

    /// Encodes reg-to-reg ALU op: add (01), sub (29), xor (31), cmp (39).
    pub fn alu_rr(&mut self, opcode: u8, dst: u8, src: u8) -> Result<(), EncodeError> {
        self.push_rex_w(src >= 8, dst >= 8)?;
        self.push(opcode)?;
        self.push_modrm(3, src, dst)
    }

    /// Encodes imul r64, r64 (0F AF).
    pub fn imul_rr(&mut self, dst: u8, src: u8) -> Result<(), EncodeError> {
        self.push_rex_w(src >= 8, dst >= 8)?;
        self.push(0x0F)?;
        self.push(0xAF)?;
        self.push_modrm(3, dst, src)
    }

    /// Encodes add/sub/cmp r64, imm32 with the short 83 form when possible.
    pub fn alu_ir(&mut self, alu_op: u8, dst: u8, imm: i32) -> Result<(), EncodeError> {
        let short = imm >= -128 && imm <= 127;
        self.push_rex_w(false, dst >= 8)?;
        if short {
            self.push(0x83)?;
            self.push_modrm(3, alu_op, dst)?;
            self.push(imm as u8)?;
        } else {
            self.push(0x81)?;
            self.push_modrm(3, alu_op, dst)?;
            self.push_le32(imm as u32)?;
        }
        Ok(())
    }

    /// Encodes mov r64, [rbx + disp32] (state slot addressing).
    pub fn mov_slot_r(&mut self, dst: u8, disp: i32) -> Result<(), EncodeError> {
        self.push_rex_w(dst >= 8, false)?;
        self.push(0x8B)?;
        self.push_modrm(2, dst, 3)?;
        self.push_le32(disp as u32)
    }

    /// Encodes mov [rbx + disp32], r64.
    pub fn mov_r_slot(&mut self, src: u8, disp: i32) -> Result<(), EncodeError> {
        self.push_rex_w(src >= 8, false)?;
        self.push(0x89)?;
        self.push_modrm(2, src, 3)?;
        self.push_le32(disp as u32)
    }

    /// Encodes setcc r8 followed by movzx r64, r8.
    pub fn setcc(&mut self, cc: u8, dst: u8) -> Result<(), EncodeError> {
        self.push_rex(dst >= 8, false, false)?;
        self.push(0x0F)?;
        self.push(0x90 + cc)?;
        self.push_modrm(3, 0, dst)?;
        self.push_rex_w(dst >= 8, dst >= 8)?;
        self.push(0x0F)?;
        self.push(0xB6)?;
        self.push_modrm(3, dst, dst)
    }

    /// Encodes cvtsi2sd xmm, r64 (F2 0F 2A).
    pub fn cvt_si2sd(&mut self, xmm: u8, gpr: u8) -> Result<(), EncodeError> {
        self.push(0xF2)?;
        self.push_rex_w(xmm >= 8, gpr >= 8)?;
        self.push(0x0F)?;
        self.push(0x2A)?;
        self.push_modrm(3, xmm, gpr)
    }

    /// Encodes cvttsd2si r64, xmm (F2 0F 2C).
    pub fn cvttsd2si(&mut self, gpr: u8, xmm: u8) -> Result<(), EncodeError> {
        self.push(0xF2)?;
        self.push_rex_w(gpr >= 8, xmm >= 8)?;
        self.push(0x0F)?;
        self.push(0x2C)?;
        self.push_modrm(3, gpr, xmm)
    }

    /// Encodes movq xmm→gpr or gpr→xmm (66 0F 7E / 66 0F 6E).
    pub fn movq(&mut self, to_xmm: bool, a: u8, b: u8) -> Result<(), EncodeError> {
        self.push(0x66)?;
        self.push_rex(a >= 8, false, b >= 8)?;
        if to_xmm {
            self.push(0x0F)?;
            self.push(0x6E)?;
            self.push_modrm(3, a, b)?;
        } else {
            self.push(0x0F)?;
            self.push(0x7E)?;
            self.push_modrm(3, a, b)?;
        }
        Ok(())
    }

    /// Encodes a scalar SSE2 op with xmm register operands.
    pub fn sse_rr(&mut self, prefix: u8, opcode: u8, dst: u8, src: u8) -> Result<(), EncodeError> {
        self.push(prefix)?;
        self.push_rex(dst >= 8, false, src >= 8)?;
        self.push(0x0F)?;
        self.push(opcode)?;
        self.push_modrm(3, dst, src)
    }

    /// Encodes movsd/movapd from [base + disp32] into xmm.
    pub fn sse_load_mem(&mut self, opcode: u8, xmm: u8, base: u8, disp: i32, prefix: u8) -> Result<(), EncodeError> {
        self.push(prefix)?;
        self.push_rex(xmm >= 8, false, base >= 8)?;
        self.push(0x0F)?;
        self.push(opcode)?;
        self.push_modrm(2, xmm, base)?;
        self.push_le32(disp as u32)
    }

    /// Encodes movsd/movapd from xmm into [base + disp32].
    pub fn sse_store_mem(&mut self, opcode: u8, xmm: u8, base: u8, disp: i32, prefix: u8) -> Result<(), EncodeError> {
        self.push(prefix)?;
        self.push_rex(xmm >= 8, false, base >= 8)?;
        self.push(0x0F)?;
        self.push(opcode)?;
        self.push_modrm(2, xmm, base)?;
        self.push_le32(disp as u32)
    }

    /// Encodes unpcklpd or unpckhpd (66 0F 14 / 66 0F 15).
    pub fn unpckpd(&mut self, high: bool, dst: u8, src: u8) -> Result<(), EncodeError> {
        self.push(0x66)?;
        self.push_rex(dst >= 8, false, src >= 8)?;
        self.push(0x0F)?;
        self.push(if high { 0x15 } else { 0x14 })?;
        self.push_modrm(3, dst, src)
    }

    /// Encodes jcc rel32 with a placeholder patched later.
    pub fn jcc_rel32(&mut self, cc: u8) -> Result<usize, EncodeError> {
        self.push(0x0F)?;
        self.push(0x80 + cc)?;
        let at = self.len;
        self.push_le32(0)?;
        Ok(at)
    }

    /// Encodes jmp rel32 with a placeholder patched later.
    pub fn jmp_rel32(&mut self) -> Result<usize, EncodeError> {
        self.push(0xE9)?;
        let at = self.len;
        self.push_le32(0)?;
        Ok(at)
    }

    /// Encodes call rel32 with a placeholder patched later.
    pub fn call_rel32(&mut self) -> Result<usize, EncodeError> {
        self.push(0xE8)?;
        let at = self.len;
        self.push_le32(0)?;
        Ok(at)
    }

    /// Encodes ret.
    pub fn ret(&mut self) -> Result<(), EncodeError> {
        self.push(0xC3)
    }

    /// Encodes a nop.
    pub fn nop(&mut self) -> Result<(), EncodeError> {
        self.push(0x90)
    }

    /// Encodes lea r64, [r15 + index*scale + disp32] style table addressing via SIB.
    pub fn lea_table(&mut self, dst: u8, index: u8, scale: u8, disp: i32) -> Result<(), EncodeError> {
        self.push_rex_w(dst >= 8, false)?;
        self.push_rex_add_b();
        self.push(0x8D)?;
        self.push_modrm(2, dst, 4)?;
        self.push(((scale & 3) << 6) | ((index & 7) << 3) | 7)?;
        self.push_le32(disp as u32)
    }

    fn push_rex_add_b(&mut self) -> Result<(), EncodeError> {
        self.push(0x41)
    }

    /// Encodes mov [rbx + disp32], imm32.
    pub fn store_slot_imm32(&mut self, disp: i32, imm: i32) -> Result<(), EncodeError> {
        self.push(0x48)?;
        self.push(0xC7)?;
        self.push_modrm(2, 0, 3)?;
        self.push_le32(disp as u32)?;
        self.push_le32(imm as u32)
    }

    /// Encodes shift r64 by imm8: opext 4 = shl, 5 = shr.
    pub fn shift_ir(&mut self, opext: u8, dst: u8, imm: i32) -> Result<(), EncodeError> {
        self.push_rex_w(false, dst >= 8)?;
        self.push(0xC1)?;
        self.push_modrm(3, opext, dst)?;
        self.push(imm as u8)
    }

    /// Encodes mov r64, [r15 + index*scale + disp32] with SIB addressing.
    pub fn heap_idx_load(&mut self, dst: u8, index: u8, scale_bits: u8, disp: i32) -> Result<(), EncodeError> {
        let rex = 0x48 | ((dst >= 8) as u8) << 2 | ((index >= 8) as u8) << 1 | 1;
        self.push(rex)?;
        self.push(0x8B)?;
        self.push_modrm(2, dst, 4)?;
        self.push((scale_bits << 6) | ((index & 7) << 3) | 7)?;
        self.push_le32(disp as u32)
    }

    /// Encodes mov [r15 + index*scale + disp32], r64 with SIB addressing.
    pub fn heap_idx_store(&mut self, src: u8, index: u8, scale_bits: u8, disp: i32) -> Result<(), EncodeError> {
        let rex = 0x48 | ((src >= 8) as u8) << 2 | ((index >= 8) as u8) << 1 | 1;
        self.push(rex)?;
        self.push(0x89)?;
        self.push_modrm(2, src, 4)?;
        self.push((scale_bits << 6) | ((index & 7) << 3) | 7)?;
        self.push_le32(disp as u32)
    }

    /// Encodes movq [r15 + index*1 + disp32], imm0 (64-bit zero store via rax path).
    pub fn heap_zero_store(&mut self, index: u8, disp: i32) -> Result<(), EncodeError> {
        let rex = 0x49 | ((index >= 8) as u8) << 1;
        self.push(rex)?;
        self.push(0xC7)?;
        self.push(0x44)?;
        self.push((index & 7) << 3 | 7)?;
        self.push_le32(disp as u32)?;
        self.push_le32(0)
    }

    /// Encodes movapd/movsd xmm, [r15 + index*1 + disp32].
    pub fn heap_sse_load(&mut self, opcode: u8, prefix: u8, xmm: u8, index: u8, disp: i32) -> Result<(), EncodeError> {
        self.push(prefix)?;
        let rex = 0x40 | ((xmm >= 8) as u8) << 2 | ((index >= 8) as u8) << 1 | 1;
        self.push(rex)?;
        self.push(0x0F)?;
        self.push(opcode)?;
        self.push_modrm(2, xmm, 4)?;
        self.push((index & 7) << 3 | 7)?;
        self.push_le32(disp as u32)
    }

    /// Encodes movapd/movsd [r15 + index*1 + disp32], xmm.
    pub fn heap_sse_store(&mut self, opcode: u8, prefix: u8, xmm: u8, index: u8, disp: i32) -> Result<(), EncodeError> {
        self.push(prefix)?;
        let rex = 0x40 | ((xmm >= 8) as u8) << 2 | ((index >= 8) as u8) << 1 | 1;
        self.push(rex)?;
        self.push(0x0F)?;
        self.push(opcode)?;
        self.push_modrm(2, xmm, 4)?;
        self.push((index & 7) << 3 | 7)?;
        self.push_le32(disp as u32)
    }

    /// Patches a rel32 placeholder emitted earlier given the instruction end offset.
    pub fn patch_rel32(&mut self, at: usize, target_offset: usize) -> Result<(), EncodeError> {
        if at + 4 > self.len {
            return Err(EncodeError::Overflow);
        }
        let rel = (target_offset as i64) - (at as i64 + 4);
        if rel < i32::MIN as i64 || rel > i32::MAX as i64 {
            return Err(EncodeError::Overflow);
        }
        let bytes = (rel as i32).to_le_bytes();
        self.buf[at] = bytes[0];
        self.buf[at + 1] = bytes[1];
        self.buf[at + 2] = bytes[2];
        self.buf[at + 3] = bytes[3];
        Ok(())
    }
}
