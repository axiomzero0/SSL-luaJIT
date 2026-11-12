// CEP:FILE: target/x86_64/src/disasm.rs
// CEP:WHAT: Deterministic byte-level decoder for the emitted instruction subset; resolves instruction boundaries and delegates rendering to the text layer.
// CEP:WHY: Chapter 38.35 requires disassembly evidence; a strict parser over exactly the encodings the emitter produces turns any byte drift into a test failure, and correct per-instruction byte advancement makes instruction boundaries addressable.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns None at the first unknown byte sequence; goldens fail loudly on drift.
// CEP:ASSUMES: input was produced by this repository's encoder; foreign encodings are rejected rather than guessed; every decoded length equals the encoder's pushed length for the same form.
// CEP:COST: O(bytes) single pass.
// CEP:EVIDENCE: golden disassembly tests compare this output byte-for-byte; replay harness derives probe offsets from this decoder.
// CEP:TARGET: x86-64

use crate::disasm_text::{
    alu_ext_name, alu_name, cc_name, copy_str, finish, finish_text, render_reg2, render_reg_imm,
    render_reg_imm64, render_slot_imm, render_slot_load, render_slot_store, render_sse,
    render_sse_mem, sse_mem_name, sse_name, write_num,
};

/// One decoded instruction rendering.
pub struct Line {
    /// Byte offset of the instruction.
    pub offset: usize,
    /// Rendered mnemonic with operands.
    pub text: [u8; 96],
    /// Rendered length.
    pub len: usize,
}

// CEP:WHAT: Disassembles the buffer into a bounded list of rendered lines.
// CEP:WHY: Evidence tooling and the replay harness both need the full instruction sequence with byte offsets in one pass.
// CEP:STATUS: complete
// CEP:FAILURE: Stops at the first undecodable byte and returns the lines decoded so far; the caller detects truncation by count.
// CEP:ASSUMES: input was produced by this repository's encoder.
// CEP:COST: O(bytes) single pass with no allocation.
// CEP:EVIDENCE: golden disassembly tests compare this output byte-for-byte.
pub fn disassemble(bytes: &[u8], out: &mut [Line]) -> usize {
    let mut count = 0usize;
    let mut offset = 0usize;
    while offset < bytes.len() && count < out.len() {
        let next = decode_one(bytes, offset, &mut out[count]);
        match next {
            Some(end) => {
                count += 1;
                offset = end;
            }
            None => break,
        }
    }
    count
}

// CEP:WHAT: Decodes one instruction at the given offset: pattern-matches the encoder's exact forms, fills the line, and returns the end offset.
// CEP:WHY: Instruction boundaries drive golden evidence and replay probe placement; a decoder that matches the encoder byte-for-byte turns any emission drift into a loud failure.
// CEP:STATUS: complete
// CEP:FAILURE: Returns None at the first byte sequence the encoder cannot produce.
// CEP:ASSUMES: offset is within bytes; the stream was emitted by this repository's encoder.
// CEP:COST: O(instruction bytes) per call.
// CEP:EVIDENCE: golden disassembly tests; replay harness probe offsets.
fn decode_one(bytes: &[u8], offset: usize, line: &mut Line) -> Option<usize> {
    line.offset = offset;
    line.len = 0;
    let at = offset;
    let byte0 = *bytes.get(at)?;
    if byte0 == 0x90 {
        return finish(line, at + 1, "nop");
    }
    if byte0 == 0xC3 {
        return finish(line, at + 1, "ret");
    }
    if byte0 == 0x53 {
        return finish(line, at + 1, "push rbx");
    }
    if byte0 == 0x5B {
        return finish(line, at + 1, "pop rbx");
    }
    if byte0 == 0x5C {
        return finish(line, at + 1, "pop rsp");
    }
    if byte0 == 0x48 && bytes.get(at + 1) == Some(&0x83) && bytes.get(at + 2) == Some(&0xEC) {
        let imm = *bytes.get(at + 3)?;
        let mut text = [0u8; 96];
        let mut n = copy_str(&mut text, 0, "sub rsp, ");
        n = write_num(&mut text, n, imm as u64);
        return finish_text(line, at + 4, &text, n);
    }
    if byte0 == 0x48 && bytes.get(at + 1) == Some(&0x83) && bytes.get(at + 2) == Some(&0xC4) {
        let imm = *bytes.get(at + 3)?;
        let mut text = [0u8; 96];
        let mut n = copy_str(&mut text, 0, "add rsp, ");
        n = write_num(&mut text, n, imm as u64);
        return finish_text(line, at + 4, &text, n);
    }
    if byte0 == 0x41 {
        let byte1 = *bytes.get(at + 1)?;
        let name = match byte1 {
            0x55 => "push r13",
            0x56 => "push r14",
            0x57 => "push r15",
            0x54 => "push r12",
            0x5D => "pop r13",
            0x5E => "pop r14",
            0x5F => "pop r15",
            0x5C => "pop r12",
            _ => return None,
        };
        return finish(line, at + 2, name);
    }
    // REX-prefixed forms (0x40..0x4F).
    if byte0 & 0xF0 == 0x40 {
        let rex = byte0;
        let byte1 = *bytes.get(at + 1)?;
        if byte1 == 0x89 && *bytes.get(at + 2)? & 0xC0 == 0xC0 {
            let (rm, reg) = modrm_pair(bytes[at + 2], rex);
            let mut text = [0u8; 96];
            let n = render_reg2(&mut text, "mov", rm, reg);
            return finish_text(line, at + 3, &text, n);
        }
        // REX 8B/89 with mod=2 and SIB rm=100: heap access [r15 + idx*1 + disp32].
        if (byte1 == 0x8B || byte1 == 0x89) && bytes.get(at + 2)? & 0xC7 == 0x84 {
            let sib = *bytes.get(at + 3)?;
            let disp = read_le32(bytes, at + 4)?;
            if (sib & 0xC0) == 0x00 && (sib & 7) == 7 && ((sib >> 3) & 7) != 4 {
                let is_load = byte1 == 0x8B;
                let base = reg_from_reg_field(bytes[at + 2], rex);
                let index = sib_index(sib, rex);
                let mut text = [0u8; 96];
                let mut n = copy_str(&mut text, 0, if is_load { "mov r" } else { "mov [r15+" });
                if is_load {
                    n = write_num(&mut text, n, base as u64);
                    n = copy_str(&mut text, n, ", [r15+");
                }
                n = write_num(&mut text, n, index as u64);
                n = copy_str(&mut text, n, if is_load { "+" } else { "]+r" });
                // Store form keeps the value register in the reg field.
                let value = if is_load { 0 } else { reg_from_reg_field(bytes[at + 2], rex) };
                if !is_load {
                    n = write_num(&mut text, n, value as u64);
                }
                n = copy_str(&mut text, n, if is_load { "+" } else { "]" });
                let _ = n;
                let disp_v = disp as u64;
                let mut text2 = [0u8; 96];
                let mut m = copy_str(&mut text2, 0, "disp=");
                m = write_num(&mut text2, m, disp_v);
                let mut full = [0u8; 96];
                let mut k = copy_str(&mut full, 0, &std::str::from_utf8(&text[..n]).unwrap_or("?"));
                k = copy_str(&mut full, k, &std::str::from_utf8(&text2[..m]).unwrap_or("?"));
                return finish_text(line, at + 8, &full, k);
            }
            return None;
        }
        if byte1 == 0x8B && bytes.get(at + 2)? & 0xC7 == 0x83 {
            let dst = reg_from_reg_field(bytes[at + 2], rex);
            let disp = read_le32(bytes, at + 3)?;
            let mut text = [0u8; 96];
            let n = render_slot_load(&mut text, "mov", dst, disp);
            return finish_text(line, at + 7, &text, n);
        }
        if byte1 == 0x89 && bytes.get(at + 2)? & 0xC7 == 0x83 {
            let src = reg_from_reg_field(bytes[at + 2], rex);
            let disp = read_le32(bytes, at + 3)?;
            let mut text = [0u8; 96];
            let n = render_slot_store(&mut text, "mov", src, disp);
            return finish_text(line, at + 7, &text, n);
        }
        if byte1 == 0xC7 && *bytes.get(at + 2)? & 0xC7 == 0x83 {
            let disp = read_le32(bytes, at + 3)?;
            let imm = read_le32(bytes, at + 7)?;
            let mut text = [0u8; 96];
            let n = render_slot_imm(&mut text, disp, imm);
            return finish_text(line, at + 11, &text, n);
        }
        if byte1 == 0xC7 && *bytes.get(at + 2)? & 0xC0 == 0xC0 {
            let dst = reg_from_reg_field(bytes[at + 2], rex);
            let imm = read_le32(bytes, at + 3)?;
            let mut text = [0u8; 96];
            let n = render_reg_imm64(&mut text, "mov", dst, imm as i64 as u64);
            return finish_text(line, at + 7, &text, n);
        }
        if byte1 & 0xF8 == 0xB8 {
            let dst = reg_from_rm_bit(bytes[at + 1], rex);
            let mut value: u64 = 0;
            for shift in 0..8usize {
                value |= (*bytes.get(at + 2 + shift)? as u64) << (shift * 8);
            }
            let mut text = [0u8; 96];
            let n = render_reg_imm64(&mut text, "movabs", dst, value);
            return finish_text(line, at + 10, &text, n);
        }
        match byte1 {
            0x01 | 0x29 | 0x31 | 0x39 => {
                if *bytes.get(at + 2)? & 0xC0 == 0xC0 {
                    let (rm, reg) = modrm_pair(bytes[at + 2], rex);
                    let name = alu_name(byte1);
                    let mut text = [0u8; 96];
                    let n = render_reg2(&mut text, name, rm, reg);
                    return finish_text(line, at + 3, &text, n);
                }
                return None;
            }
            0x83 => {
                if *bytes.get(at + 2)? & 0xC0 == 0xC0 {
                    let dst = reg_from_rm_bit(bytes[at + 2], rex);
                    let ext = (bytes[at + 2] >> 3) & 7;
                    let imm = *bytes.get(at + 3)? as i8 as i64 as u64;
                    let mut text = [0u8; 96];
                    let n = render_reg_imm64(&mut text, alu_ext_name(ext), dst, imm);
                    return finish_text(line, at + 4, &text, n);
                }
                return None;
            }
            0x81 => {
                if *bytes.get(at + 2)? & 0xC0 == 0xC0 {
                    let dst = reg_from_rm_bit(bytes[at + 2], rex);
                    let ext = (bytes[at + 2] >> 3) & 7;
                    let imm = read_le32(bytes, at + 3)?;
                    let mut text = [0u8; 96];
                    let n = render_reg_imm64(&mut text, alu_ext_name(ext), dst, imm as i64 as u64);
                    return finish_text(line, at + 7, &text, n);
                }
                return None;
            }
            0xC1 => {
                if *bytes.get(at + 2)? & 0xC0 == 0xC0 {
                    let dst = reg_from_rm_bit(bytes[at + 2], rex);
                    let ext = (bytes[at + 2] >> 3) & 7;
                    let imm = *bytes.get(at + 3)?;
                    let name = match ext {
                        4 => "shl",
                        5 => "shr",
                        7 => "sar",
                        _ => return None,
                    };
                    let mut text = [0u8; 96];
                    let n = render_reg_imm(&mut text, name, dst, imm as u32);
                    return finish_text(line, at + 4, &text, n);
                }
                return None;
            }
            0x0F => {
                let opcode = *bytes.get(at + 2)?;
                let modrm = *bytes.get(at + 3)?;
                if opcode == 0xAF && modrm & 0xC0 == 0xC0 {
                    let dst = reg_from_reg_field(modrm, rex);
                    let src = reg_from_rm_bit(modrm, rex);
                    let mut text = [0u8; 96];
                    let n = render_reg2(&mut text, "imul", dst, src);
                    return finish_text(line, at + 4, &text, n);
                }
                if opcode & 0xF0 == 0x90 && modrm & 0xC0 == 0xC0 {
                    let dst = reg_from_rm_bit(modrm, rex);
                    let cc = opcode & 0x0F;
                    let mut text = [0u8; 96];
                    let mut n = copy_str(&mut text, 0, "set");
                    n = copy_str(&mut text, n, cc_name(cc));
                    n = copy_str(&mut text, n, " r");
                    n = write_num(&mut text, n, dst as u64);
                    return finish_text(line, at + 4, &text, n);
                }
                if opcode == 0xB6 && modrm & 0xC0 == 0xC0 {
                    let dst = reg_from_reg_field(modrm, rex);
                    let src = reg_from_rm_bit(modrm, rex);
                    let mut text = [0u8; 96];
                    let n = render_reg2(&mut text, "movzx", dst, src);
                    return finish_text(line, at + 4, &text, n);
                }
                return None;
            }
            _ => return None,
        }
    }
    // Prefixed SSE forms: prefix, REX, 0F, opcode, ModRM.
    if byte0 == 0x66 || byte0 == 0xF2 {
        let rex = *bytes.get(at + 1)?;
        if rex & 0xF0 != 0x40 {
            return None;
        }
        if *bytes.get(at + 2)? != 0x0F {
            return None;
        }
        return decode_prefixed_sse(bytes, at, byte0, rex, line);
    }
    if byte0 == 0x0F {
        return decode_0f_norex(bytes, at, line);
    }
    if byte0 == 0xE9 || byte0 == 0xE8 {
        let rel = read_le32(bytes, at + 1)?;
        let name = if byte0 == 0xE9 { "jmp" } else { "call" };
        let mut text = [0u8; 96];
        let mut n = copy_str(&mut text, 0, name);
        n = copy_str(&mut text, n, " rel=");
        n = write_num(&mut text, n, rel as u64);
        return finish_text(line, at + 5, &text, n);
    }
    None
}

// CEP:WHAT: Decodes one prefixed SSE form: prefix, REX, 0F, opcode, ModRM, with register-register or SIB memory operands.
// CEP:WHY: Heap SSE accesses always use r15-relative SIB addressing; the decoder resolves xmm, index, scale, and displacement for evidence.
// CEP:STATUS: complete
// CEP:FAILURE: Returns None for operand shapes the encoder cannot produce.
// CEP:ASSUMES: prefix is 66 or F2 and the following byte is a REX prefix.
// CEP:COST: O(instruction bytes) per call.
// CEP:EVIDENCE: golden disassembly tests.
fn decode_prefixed_sse(bytes: &[u8], at: usize, prefix: u8, rex: u8, line: &mut Line) -> Option<usize> {
    let opcode = *bytes.get(at + 3)?;
    let modrm = *bytes.get(at + 4)?;
    if modrm & 0xC0 == 0xC0 {
        let dst = reg_from_reg_field(modrm, rex);
        let src = reg_from_rm_bit(modrm, rex);
        let name = sse_name(prefix, opcode);
        let mut text = [0u8; 96];
        let n = render_sse(&mut text, name, dst, src);
        return finish_text(line, at + 5, &text, n);
    }
    if modrm & 0xC7 == 0x84 {
        let sib = *bytes.get(at + 5)?;
        let disp = read_le32(bytes, at + 6)?;
        let xmm = reg_from_reg_field(modrm, rex);
        let index = sib_index(sib, rex);
        let scale_bits = (sib >> 6) & 3;
        let name = sse_mem_name(prefix, opcode);
        let mut text = [0u8; 96];
        let n = render_sse_mem(&mut text, name, xmm, index, scale_bits, disp);
        return finish_text(line, at + 10, &text, n);
    }
    None
}

// CEP:WHAT: Decodes the REX-less 0F branch family (jcc rel32).
// CEP:WHY: Conditional branches leave the trace through guard stubs; their offsets are patched rel32 fields the decoder must render.
// CEP:STATUS: complete
// CEP:FAILURE: Returns None for non-branch 0F forms.
// CEP:ASSUMES: none
// CEP:COST: O(instruction bytes) per call.
// CEP:EVIDENCE: golden disassembly tests.
fn decode_0f_norex(bytes: &[u8], at: usize, line: &mut Line) -> Option<usize> {
    let byte1 = *bytes.get(at + 1)?;
    if byte1 & 0xF0 == 0x80 {
        let cc = byte1 & 0x0F;
        let rel = read_le32(bytes, at + 2)?;
        let mut text = [0u8; 96];
        let mut n = copy_str(&mut text, 0, "j");
        n = copy_str(&mut text, n, cc_name(cc));
        n = copy_str(&mut text, n, " rel=");
        n = write_num(&mut text, n, rel as u64);
        return finish_text(line, at + 6, &text, n);
    }
    None
}

/// Register in the ModRM rm position, extended by REX.B.
fn reg_from_rm_bit(modrm: u8, rex: u8) -> u8 {
    ((rex & 1) << 3) | (modrm & 7)
}

/// Register in the ModRM reg position, extended by REX.R.
fn reg_from_reg_field(modrm: u8, rex: u8) -> u8 {
    (((rex >> 2) & 1) << 3) | ((modrm >> 3) & 7)
}

/// reg/rm pair of a register-register ModRM byte: (rm with B, reg with R).
fn modrm_pair(modrm: u8, rex: u8) -> (u8, u8) {
    (reg_from_rm_bit(modrm, rex), reg_from_reg_field(modrm, rex))
}

/// SIB index register, extended by REX.X.
fn sib_index(sib: u8, rex: u8) -> u8 {
    (((rex >> 1) & 1) << 3) | ((sib >> 3) & 7)
}

// CEP:WHAT: Reads one little-endian i32 displacement or immediate at the given offset.
// CEP:WHY: Every disp32/im32 form needs the same bounded read; one helper keeps bounds checking uniform.
// CEP:STATUS: complete
// CEP:FAILURE: Returns None when fewer than four bytes remain.
// CEP:ASSUMES: none
// CEP:COST: O(1).
// CEP:EVIDENCE: golden disassembly tests.
fn read_le32(bytes: &[u8], at: usize) -> Option<i32> {
    if at + 4 > bytes.len() {
        return None;
    }
    Some(i32::from_le_bytes([
        bytes[at],
        bytes[at + 1],
        bytes[at + 2],
        bytes[at + 3],
    ]))
}
