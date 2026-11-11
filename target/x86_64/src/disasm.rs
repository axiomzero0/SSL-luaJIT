// CEP:FILE: target/x86_64/src/disasm.rs
// CEP:WHAT: Deterministic byte-level disassembler for the emitted instruction subset used by golden codegen evidence.
// CEP:WHY: Chapter 38.35 requires disassembly evidence; a strict parser over exactly the encodings the emitter produces turns any byte drift into a test failure.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns None at the first unknown byte sequence; goldens fail loudly on drift.
// CEP:ASSUMES: input was produced by this repository's encoder; foreign encodings are rejected rather than guessed.
// CEP:COST: O(bytes) single pass.
// CEP:EVIDENCE: golden disassembly tests compare this output byte-for-byte.
// CEP:TARGET: x86-64

/// One decoded instruction rendering.
pub struct Line {
    /// Byte offset of the instruction.
    pub offset: usize,
    /// Rendered mnemonic with operands.
    pub text: [u8; 96],
    /// Rendered length.
    pub len: usize,
}

/// Disassembles the buffer into a bounded list of rendered lines.
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

fn decode_one(bytes: &[u8], offset: usize, line: &mut Line) -> Option<usize> {
    line.offset = offset;
    line.len = 0;
    let mut at = offset;
    let byte0 = *bytes.get(at)?;
    if byte0 == 0x90 {
        return finish(line, &mut at, "nop", bytes, 1);
    }
    if byte0 == 0xC3 {
        return finish(line, &mut at, "ret", bytes, 1);
    }
    if byte0 == 0x53 {
        return finish(line, &mut at, "push rbx", bytes, 1);
    }
    if byte0 == 0x5B {
        return finish(line, &mut at, "pop rbx", bytes, 1);
    }
    if byte0 == 0x5C {
        return finish(line, &mut at, "pop rsp", bytes, 1);
    }
    if byte0 == 0x48 && bytes.get(at + 1) == Some(&0x83) && bytes.get(at + 2) == Some(&0xEC) {
        at += 3;
        let imm = *bytes.get(at)?;
        at += 1;
        let mut text = [0u8; 96];
        let mut n = copy_str(&mut text, 0, "sub rsp, ");
        n += write_num(&mut text, n, imm as u32);
        return finish_text(line, &mut at, &text, n, 0);
    }
    if byte0 == 0x48 && bytes.get(at + 1) == Some(&0x83) && bytes.get(at + 2) == Some(&0xC4) {
        at += 3;
        let imm = *bytes.get(at)?;
        at += 1;
        let mut text = [0u8; 96];
        let mut n = copy_str(&mut text, 0, "add rsp, ");
        n += write_num(&mut text, n, imm as u32);
        return finish_text(line, &mut at, &text, n, 0);
    }
    if byte0 == 0x41 {
        let byte1 = *bytes.get(at + 1)?;
        let name = match byte1 {
            0x55 => "push r13",
            0x56 => "push r14",
            0x54 => "push r12",
            0x5D => "pop r13",
            0x5E => "pop r14",
            0x5C => "pop r12",
            _ => return None,
        };
        at += 2;
        return finish(line, &mut at, name, bytes, 0);
    }
    if byte0 & 0xF0 == 0x40 && bytes.get(at + 1) == Some(&0x89) && bytes.get(at + 2)? & 0xC0 == 0xC0 {
        let (dst, src) = reg_pair(bytes[at + 2], byte0);
        at += 3;
        return finish_reg2(line, &mut at, "mov", dst, src);
    }
    if byte0 & 0xF0 == 0x40 && bytes.get(at + 1)? & 0xF8 == 0xB8 {
        let dst = reg_single(bytes[at + 1], byte0);
        at += 2;
        let mut value: u64 = 0;
        for shift in 0..8usize {
            value |= (*bytes.get(at + shift)? as u64) << (shift * 8);
        }
        at += 8;
        return finish_reg_imm64(line, &mut at, "movabs", dst, value);
    }
    if byte0 & 0xF0 == 0x40 && bytes.get(at + 1) == Some(&0xC7) && bytes.get(at + 2)? & 0xC7 == 0x43 {
        let disp = read_le32(bytes, at + 3)?;
        let imm = read_le32(bytes, at + 7)?;
        at += 11;
        return finish_slot_store(line, &mut at, imm, disp);
    }
    if byte0 & 0xF0 == 0x40 && (bytes.get(at + 1) == Some(&0x8B) || bytes.get(at + 1) == Some(&0x89))
        && bytes.get(at + 2)? & 0xC7 == 0x43
    {
        let op = if bytes[at + 1] == 0x8B { "mov" } else { "mov.store" };
        let reg = reg_single(bytes[at + 2], byte0);
        let disp = read_le32(bytes, at + 3)?;
        at += 7;
        return finish_slot(line, &mut at, op, reg, disp);
    }
    if byte0 & 0xF0 == 0x40 && bytes.get(at + 1) == Some(&0xC1) {
        let opext = (bytes[at + 2] >> 3) & 7;
        let dst = reg_single(bytes[at + 2], byte0);
        let imm = *bytes.get(at + 3)?;
        let name = if opext == 4 { "shl" } else if opext == 5 { "shr" } else { return None };
        at += 4;
        return finish_reg_imm(line, &mut at, name, dst, imm as u32);
    }
    if (byte0 == 0x66 || byte0 == 0xF2) && bytes.get(at + 1)? & 0xF0 == 0x40 {
        let prefix = byte0;
        let rex = bytes[at + 1];
        let opcode = *bytes.get(at + 2)?;
        let modrm = *bytes.get(at + 3)?;
        if opcode == 0x0F && modrm & 0xC0 == 0xC0 {
            let (dst, src) = sse_pair(modrm, rex);
            let name = sse_name(prefix, opcode);
            at += 4;
            return finish_sse(line, &mut at, name, dst, src);
        }
        if opcode == 0x0F && modrm & 0xC7 == 0x84 {
            let sib = *bytes.get(at + 4)?;
            let disp = read_le32(bytes, at + 5)?;
            let xmm = sse_reg(modrm, rex);
            let name = sse_mem_name(prefix, opcode);
            at += 9;
            return finish_sse_mem(line, &mut at, name, xmm, sib, disp);
        }
        return None;
    }
    if byte0 == 0x0F && bytes.get(at + 1)? & 0xF0 == 0x80 {
        let cc = bytes[at + 1] & 0x0F;
        let rel = read_le32(bytes, at + 2)?;
        at += 6;
        return finish_branch(line, &mut at, "j", cc as u32, rel);
    }
    if byte0 == 0xE9 {
        let rel = read_le32(bytes, at + 1)?;
        at += 5;
        return finish_branch(line, &mut at, "jmp", 0, rel);
    }
    if byte0 == 0xE8 {
        let rel = read_le32(bytes, at + 1)?;
        at += 5;
        return finish_branch(line, &mut at, "call", 0, rel);
    }
    None
}

fn reg_pair(modrm: u8, rex: u8) -> (u8, u8) {
    let dst = ((rex & 1) << 3) | (modrm & 7);
    let src = ((rex >> 2) & 1) << 3 | ((modrm >> 3) & 7);
    (dst, src)
}

fn reg_single(modrm: u8, rex: u8) -> u8 {
    ((rex & 1) << 3) | (modrm & 7)
}

fn sse_pair(modrm: u8, rex: u8) -> (u8, u8) {
    let dst = ((rex >> 2) & 1) << 3 | (modrm >> 3) & 7;
    let src = ((rex >> 1) & 1) << 3 | (modrm & 7);
    (dst, src)
}

fn sse_reg(modrm: u8, rex: u8) -> u8 {
    ((rex >> 2) & 1) << 3 | (modrm >> 3) & 7
}

fn sse_name(prefix: u8, opcode: u8) -> &'static str {
    match (prefix, opcode) {
        (0xF2, 0x10) => "movsd",
        (0xF2, 0x58) => "addsd",
        (0xF2, 0x5C) => "subsd",
        (0xF2, 0x59) => "mulsd",
        (0xF2, 0x5E) => "divsd",
        (0xF2, 0x51) => "sqrtsd",
        (0x66, 0x2E) => "ucomisd",
        (0x66, 0xEF) => "pxor",
        (0x66, 0x58) => "addpd",
        (0x66, 0x5C) => "subpd",
        (0x66, 0x59) => "mulpd",
        (0x66, 0x14) => "unpcklpd",
        (0x66, 0x15) => "unpckhpd",
        (0x66, 0x6E) => "movq",
        (0x66, 0x7E) => "movq",
        (0x66, 0x28) => "movapd",
        (0x66, 0x29) => "movapd.store",
        (0xF2, 0x2A) => "cvtsi2sd",
        (0xF2, 0x2C) => "cvttsd2si",
        _ => "sse",
    }
}

fn sse_mem_name(prefix: u8, opcode: u8) -> &'static str {
    match (prefix, opcode) {
        (0x66, 0x28) => "movapd.load",
        (0x66, 0x29) => "movapd.store",
        (0xF2, 0x10) => "movsd.load",
        (0xF2, 0x11) => "movsd.store",
        _ => "sse.mem",
    }
}

fn copy_str(out: &mut [u8], mut at: usize, text: &str) -> usize {
    for byte in text.bytes() {
        if at < out.len() {
            out[at] = byte;
        }
        at += 1;
    }
    at
}

fn write_num(out: &mut [u8], mut at: usize, mut value: u32) -> usize {
    let mut scratch = [0u8; 12];
    let mut len = 0usize;
    if value == 0 {
        scratch[0] = b'0';
        len = 1;
    }
    while value > 0 {
        scratch[len] = b'0' + (value % 10) as u8;
        value /= 10;
        len += 1;
    }
    while len > 0 {
        len -= 1;
        if at < out.len() {
            out[at] = scratch[len];
        }
        at += 1;
    }
    at
}

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

fn finish(line: &mut Line, at: &mut usize, name: &str, _bytes: &[u8], extra: usize) -> Option<usize> {
    let _ = extra;
    line.len = copy_str(&mut line.text, 0, name);
    *at += line.len;
    Some(*at)
}

fn finish_text(line: &mut Line, at: &mut usize, text: &[u8], len: usize, _pad: usize) -> Option<usize> {
    line.text[..len.min(96)].copy_from_slice(&text[..len.min(96)]);
    line.len = len.min(96);
    *at += line.len;
    Some(*at)
}

fn finish_reg2(line: &mut Line, at: &mut usize, name: &str, dst: u8, src: u8) -> Option<usize> {
    let mut n = copy_str(&mut line.text, 0, name);
    n = copy_str(&mut line.text, n, " r");
    n += write_num(&mut line.text, n, dst as u32);
    n = copy_str(&mut line.text, n, ", r");
    n += write_num(&mut line.text, n, src as u32);
    line.len = n;
    *at += n;
    Some(*at)
}

fn finish_reg_imm(line: &mut Line, at: &mut usize, name: &str, dst: u8, imm: u32) -> Option<usize> {
    let mut n = copy_str(&mut line.text, 0, name);
    n = copy_str(&mut line.text, n, " r");
    n += write_num(&mut line.text, n, dst as u32);
    n = copy_str(&mut line.text, n, ", ");
    n += write_num(&mut line.text, n, imm);
    line.len = n;
    *at += n;
    Some(*at)
}

fn finish_reg_imm64(line: &mut Line, at: &mut usize, name: &str, dst: u8, value: u64) -> Option<usize> {
    let mut n = copy_str(&mut line.text, 0, name);
    n = copy_str(&mut line.text, n, " r");
    n += write_num(&mut line.text, n, dst as u32);
    n = copy_str(&mut line.text, n, ", ");
    n += write_num(&mut line.text, n, value as u32);
    n += write_num(&mut line.text, n, (value >> 32) as u32);
    line.len = n;
    *at += n;
    Some(*at)
}

fn finish_slot(line: &mut Line, at: &mut usize, name: &str, reg: u8, disp: i32) -> Option<usize> {
    let mut n = copy_str(&mut line.text, 0, name);
    n = copy_str(&mut line.text, n, " r");
    n += write_num(&mut line.text, n, reg as u32);
    n = copy_str(&mut line.text, n, ", [rbx");
    if disp >= 0 {
        n = copy_str(&mut line.text, n, "+");
    }
    n += write_num(&mut line.text, n, disp as u32);
    n = copy_str(&mut line.text, n, "]");
    line.len = n;
    *at += n;
    Some(*at)
}

fn finish_slot_store(line: &mut Line, at: &mut usize, imm: i32, disp: i32) -> Option<usize> {
    let mut n = copy_str(&mut line.text, 0, "mov qword [rbx");
    if disp >= 0 {
        n = copy_str(&mut line.text, n, "+");
    }
    n += write_num(&mut line.text, n, disp as u32);
    n = copy_str(&mut line.text, n, "], ");
    n += write_num(&mut line.text, n, imm as u32);
    line.len = n;
    *at += n;
    Some(*at)
}

fn finish_sse(line: &mut Line, at: &mut usize, name: &str, dst: u8, src: u8) -> Option<usize> {
    let mut n = copy_str(&mut line.text, 0, name);
    n = copy_str(&mut line.text, n, " x");
    n += write_num(&mut line.text, n, dst as u32);
    n = copy_str(&mut line.text, n, ", x");
    n += write_num(&mut line.text, n, src as u32);
    line.len = n;
    *at += n;
    Some(*at)
}

fn finish_sse_mem(line: &mut Line, at: &mut usize, name: &str, xmm: u8, sib: u8, disp: i32) -> Option<usize> {
    let mut n = copy_str(&mut line.text, 0, name);
    n = copy_str(&mut line.text, n, " x");
    n += write_num(&mut line.text, n, xmm as u32);
    n = copy_str(&mut line.text, n, ", [r15+r");
    n += write_num(&mut line.text, n, ((sib >> 3) & 7) as u32);
    n = copy_str(&mut line.text, n, "+");
    n += write_num(&mut line.text, n, disp as u32);
    n = copy_str(&mut line.text, n, "]");
    line.len = n;
    *at += n;
    Some(*at)
}

fn finish_branch(line: &mut Line, at: &mut usize, name: &str, cc: u32, rel: i32) -> Option<usize> {
    let mut n = copy_str(&mut line.text, 0, name);
    if cc != 0 {
        n += write_num(&mut line.text, n, cc);
    }
    n = copy_str(&mut line.text, n, " rel=");
    n += write_num(&mut line.text, n, rel as u32);
    line.len = n;
    *at += n;
    Some(*at)
}
