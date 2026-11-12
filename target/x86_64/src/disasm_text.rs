// CEP:FILE: target/x86_64/src/disasm_text.rs
// CEP:WHAT: Text rendering layer of the disassembler: mnemonic tables and bounded renderers that turn decoded operands into fixed-buffer strings.
// CEP:WHY: Chapter 38.35 requires disassembly evidence; rendering is separated from decoding so byte-advance logic and text layout evolve independently under the 400-line atomic-file bound.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Renderers clip at the 96-byte line buffer; no error path exists because every operand form fits the buffer by construction.
// CEP:ASSUMES: every rendered operand string fits 96 bytes; numeric widths match the encoder's immediate ranges.
// CEP:COST: O(rendered bytes) per instruction; no allocation.
// CEP:EVIDENCE: golden disassembly tests compare this output byte-for-byte; replay harness derives probe offsets from the decoder that consumes this layer.
// CEP:TARGET: x86-64

// CEP:WHAT: Maps one ALU reg-reg opcode byte to its mnemonic.
// CEP:WHY: Decode arms need stable mnemonic text so goldens stay stable across refactorings.
// CEP:STATUS: complete
// CEP:FAILURE: Returns the generic name "alu" for out-of-table opcodes, which no emitter path produces.
// CEP:ASSUMES: opcode is one of 01, 29, 31, 39.
// CEP:COST: O(1) table lookup.
// CEP:EVIDENCE: golden disassembly tests.
pub(crate) fn alu_name(opcode: u8) -> &'static str {
    match opcode {
        0x01 => "add",
        0x29 => "sub",
        0x31 => "xor",
        0x39 => "cmp",
        _ => "alu",
    }
}

// CEP:WHAT: Maps one ALU reg-imm extension field to its mnemonic.
// CEP:WHY: The 83/81 immediate forms carry the operation in the ModRM reg field; one table keeps both forms consistent.
// CEP:STATUS: complete
// CEP:FAILURE: Returns the generic name "alu" for extensions no emitter path produces.
// CEP:ASSUMES: ext is 0..7.
// CEP:COST: O(1) table lookup.
// CEP:EVIDENCE: golden disassembly tests.
pub(crate) fn alu_ext_name(ext: u8) -> &'static str {
    match ext {
        0 => "add",
        1 => "or",
        2 => "adc",
        3 => "sbb",
        4 => "and",
        5 => "sub",
        6 => "xor",
        7 => "cmp",
        _ => "alu",
    }
}

// CEP:WHAT: Maps one condition code number to its mnemonic suffix.
// CEP:WHY: jcc and setcc share the same code space; one table keeps their renderings aligned.
// CEP:STATUS: complete
// CEP:FAILURE: Returns "?" for codes above 15, which cannot occur from a 4-bit field.
// CEP:ASSUMES: cc is 0..15.
// CEP:COST: O(1) table lookup.
// CEP:EVIDENCE: golden disassembly tests.
pub(crate) fn cc_name(cc: u8) -> &'static str {
    match cc {
        0 => "o",
        1 => "no",
        2 => "b",
        3 => "ae",
        4 => "e",
        5 => "ne",
        6 => "be",
        7 => "a",
        8 => "s",
        9 => "ns",
        10 => "p",
        11 => "np",
        12 => "l",
        13 => "ge",
        14 => "le",
        15 => "g",
        _ => "?",
    }
}

// CEP:WHAT: Maps one prefixed SSE register-register opcode to its mnemonic.
// CEP:WHY: Scalar and packed SSE2 forms share opcodes across prefixes; the table pins the (prefix, opcode) pairs the encoder produces.
// CEP:STATUS: complete
// CEP:FAILURE: Returns the generic name "sse" for pairs no emitter path produces.
// CEP:ASSUMES: prefix is 66 or F2.
// CEP:COST: O(1) table lookup.
// CEP:EVIDENCE: golden disassembly tests.
pub(crate) fn sse_name(prefix: u8, opcode: u8) -> &'static str {
    match (prefix, opcode) {
        (0xF2, 0x10) => "movsd",
        (0xF2, 0x58) => "addsd",
        (0xF2, 0x5C) => "subsd",
        (0xF2, 0x59) => "mulsd",
        (0xF2, 0x5E) => "divsd",
        (0xF2, 0x51) => "sqrtsd",
        (0xF2, 0x2A) => "cvtsi2sd",
        (0xF2, 0x2C) => "cvttsd2si",
        (0x66, 0x2E) => "ucomisd",
        (0x66, 0xEF) => "pxor",
        (0x66, 0x58) => "addpd",
        (0x66, 0x5C) => "subpd",
        (0x66, 0x59) => "mulpd",
        (0x66, 0x6E) => "movq",
        (0x66, 0x7E) => "movq",
        (0x66, 0x14) => "unpcklpd",
        (0x66, 0x15) => "unpckhpd",
        (0x66, 0x28) => "movapd",
        (0x66, 0x29) => "movapd.store",
        _ => "sse",
    }
}

// CEP:WHAT: Maps one prefixed SSE memory-access opcode to its mnemonic.
// CEP:WHY: Memory forms distinguish load and store variants that share one opcode byte.
// CEP:STATUS: complete
// CEP:FAILURE: Returns the generic name "sse.mem" for pairs no emitter path produces.
// CEP:ASSUMES: prefix is 66 or F2.
// CEP:COST: O(1) table lookup.
// CEP:EVIDENCE: golden disassembly tests.
pub(crate) fn sse_mem_name(prefix: u8, opcode: u8) -> &'static str {
    match (prefix, opcode) {
        (0xF2, 0x10) => "movsd.load",
        (0xF2, 0x11) => "movsd.store",
        (0x66, 0x28) => "movapd.load",
        (0x66, 0x29) => "movapd.store",
        _ => "sse.mem",
    }
}

// CEP:WHAT: Copies one string into the render buffer and returns the next free position.
// CEP:WHY: Every renderer composes its line from bounded string pieces; one helper keeps clipping behavior uniform.
// CEP:STATUS: complete
// CEP:FAILURE: Silently clips at the buffer end; no panic and no error path.
// CEP:ASSUMES: caller passes a position within the buffer.
// CEP:COST: O(string bytes).
// CEP:EVIDENCE: golden disassembly tests.
pub(crate) fn copy_str(out: &mut [u8], mut at: usize, text: &str) -> usize {
    for byte in text.bytes() {
        if at < out.len() {
            out[at] = byte;
        }
        at += 1;
    }
    at
}

// CEP:WHAT: Writes one unsigned decimal number into the render buffer and returns the next free position.
// CEP:WHY: Operand numbers are rendered without allocation; backward digit generation keeps the buffer write forward-only.
// CEP:STATUS: complete
// CEP:FAILURE: Silently clips at the buffer end; no panic and no error path.
// CEP:ASSUMES: buffer is at least 24 bytes larger than the written prefix so full u64 values fit.
// CEP:COST: O(digits).
// CEP:EVIDENCE: golden disassembly tests.
pub(crate) fn write_num(out: &mut [u8], mut at: usize, mut value: u64) -> usize {
    let mut scratch = [0u8; 24];
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

// CEP:WHAT: Writes one signed 64-bit immediate with a minus sign for negative values.
// CEP:WHY: Immediates and displacements are sign-extended 32-bit or 64-bit values; the unsigned helper cannot render the sign.
// CEP:STATUS: complete
// CEP:FAILURE: Silently clips at the buffer end; no panic and no error path.
// CEP:ASSUMES: value is interpreted as two's complement i64.
// CEP:COST: O(digits).
// CEP:EVIDENCE: golden disassembly tests cover negative immediates.
pub(crate) fn write_num_i64(out: &mut [u8], mut at: usize, value: u64) -> usize {
    if value >> 63 == 1 {
        let magnitude = (value as i64).unsigned_abs();
        if at < out.len() {
            out[at] = b'-';
        }
        return write_num(out, at + 1, magnitude);
    }
    write_num(out, at, value)
}

// CEP:WHAT: Installs one fixed mnemonic into a decoded line and returns the instruction end offset.
// CEP:WHY: Fixed-name forms (push, pop, ret, nop) need no composed buffer; the helper mirrors finish_text for them.
// CEP:STATUS: complete
// CEP:FAILURE: None; the mnemonic length is bounded by construction.
// CEP:ASSUMES: end equals the true instruction byte length.
// CEP:COST: O(mnemonic bytes).
// CEP:EVIDENCE: golden disassembly tests.
pub(crate) fn finish(line: &mut super::disasm::Line, end: usize, name: &str) -> Option<usize> {
    line.len = copy_str(&mut line.text, 0, name);
    Some(end)
}

// CEP:WHAT: Installs one composed render buffer into a decoded line and returns the instruction end offset.
// CEP:WHY: Decode arms compose into a local buffer and publish once; the helper clips to the 96-byte line width.
// CEP:STATUS: complete
// CEP:FAILURE: Silently clips at 96 bytes; no panic and no error path.
// CEP:ASSUMES: len equals the composed length reported by the renderer.
// CEP:COST: O(rendered bytes).
// CEP:EVIDENCE: golden disassembly tests.
pub(crate) fn finish_text(line: &mut super::disasm::Line, end: usize, text: &[u8], len: usize) -> Option<usize> {
    let clipped = len.min(96);
    line.text[..clipped].copy_from_slice(&text[..clipped]);
    line.len = clipped;
    Some(end)
}

// CEP:WHAT: Renders one register-register instruction with numeric operands.
// CEP:WHY: Register operands render as r0..r15 matching the encoder's physical numbering.
// CEP:STATUS: complete
// CEP:FAILURE: Silently clips at the buffer end; no panic and no error path.
// CEP:ASSUMES: none
// CEP:COST: O(rendered bytes).
// CEP:EVIDENCE: golden disassembly tests.
pub(crate) fn render_reg2(out: &mut [u8; 96], name: &str, dst: u8, src: u8) -> usize {
    let mut n = copy_str(out, 0, name);
    n = copy_str(out, n, " r");
    n = write_num(out, n, dst as u64);
    n = copy_str(out, n, ", r");
    n = write_num(out, n, src as u64);
    n
}

// CEP:WHAT: Renders one register-immediate instruction with an unsigned 32-bit operand.
// CEP:WHY: Shift forms carry imm8 operands rendered as unsigned values.
// CEP:STATUS: complete
// CEP:FAILURE: Silently clips at the buffer end; no panic and no error path.
// CEP:ASSUMES: none
// CEP:COST: O(rendered bytes).
// CEP:EVIDENCE: golden disassembly tests.
pub(crate) fn render_reg_imm(out: &mut [u8; 96], name: &str, dst: u8, imm: u32) -> usize {
    let mut n = copy_str(out, 0, name);
    n = copy_str(out, n, " r");
    n = write_num(out, n, dst as u64);
    n = copy_str(out, n, ", ");
    n = write_num(out, n, imm as u64);
    n
}

// CEP:WHAT: Renders one register-immediate instruction with a signed 64-bit operand.
// CEP:WHY: Immediate forms carry sign-extended operands; the signed renderer keeps negative values faithful.
// CEP:STATUS: complete
// CEP:FAILURE: Silently clips at the buffer end; no panic and no error path.
// CEP:ASSUMES: none
// CEP:COST: O(rendered bytes).
// CEP:EVIDENCE: golden disassembly tests cover negative immediates.
pub(crate) fn render_reg_imm64(out: &mut [u8; 96], name: &str, dst: u8, imm: u64) -> usize {
    let mut n = copy_str(out, 0, name);
    n = copy_str(out, n, " r");
    n = write_num(out, n, dst as u64);
    n = copy_str(out, n, ", ");
    n = write_num_i64(out, n, imm);
    n
}

// CEP:WHAT: Renders one state-slot load as `mov rN, [rbx+disp]`.
// CEP:WHY: Slot addressing is always rbx-relative disp32; one renderer keeps slot evidence readable and uniform.
// CEP:STATUS: complete
// CEP:FAILURE: Silently clips at the buffer end; no panic and no error path.
// CEP:ASSUMES: none
// CEP:COST: O(rendered bytes).
// CEP:EVIDENCE: golden disassembly tests.
pub(crate) fn render_slot_load(out: &mut [u8; 96], name: &str, reg: u8, disp: i32) -> usize {
    let mut n = copy_str(out, 0, name);
    n = copy_str(out, n, " r");
    n = write_num(out, n, reg as u64);
    n = copy_str(out, n, ", [rbx");
    n = render_disp(out, n, disp);
    n
}

// CEP:WHAT: Renders one state-slot store as `mov [rbx+disp], rN`.
// CEP:WHY: Slot stores mirror slot loads with operand order reversed; one renderer keeps both faithful.
// CEP:STATUS: complete
// CEP:FAILURE: Silently clips at the buffer end; no panic and no error path.
// CEP:ASSUMES: none
// CEP:COST: O(rendered bytes).
// CEP:EVIDENCE: golden disassembly tests.
pub(crate) fn render_slot_store(out: &mut [u8; 96], name: &str, reg: u8, disp: i32) -> usize {
    let mut n = copy_str(out, 0, name);
    n = copy_str(out, n, " [rbx");
    n = render_disp(out, n, disp);
    n = copy_str(out, n, "], r");
    n = write_num(out, n, reg as u64);
    n
}

// CEP:WHAT: Renders one immediate store as `mov qword [rbx+disp], imm`.
// CEP:WHY: Snapshot re-boxing stores carry a tag immediate; the renderer exposes the slot and tag for evidence.
// CEP:STATUS: complete
// CEP:FAILURE: Silently clips at the buffer end; no panic and no error path.
// CEP:ASSUMES: none
// CEP:COST: O(rendered bytes).
// CEP:EVIDENCE: golden disassembly tests.
pub(crate) fn render_slot_imm(out: &mut [u8; 96], disp: i32, imm: i32) -> usize {
    let mut n = copy_str(out, 0, "mov qword [rbx");
    n = render_disp(out, n, disp);
    n = copy_str(out, n, "], ");
    n = write_num_i64(out, n, imm as i64 as u64);
    n
}

// CEP:WHAT: Renders one displacement suffix including the sign and closing bracket.
// CEP:WHY: Slot and heap renderers share the sign-and-bracket convention; one helper keeps them identical.
// CEP:STATUS: complete
// CEP:FAILURE: Silently clips at the buffer end; no panic and no error path.
// CEP:ASSUMES: none
// CEP:COST: O(rendered bytes).
// CEP:EVIDENCE: golden disassembly tests.
pub(crate) fn render_disp(out: &mut [u8; 96], n: usize, disp: i32) -> usize {
    let mut n = n;
    if disp >= 0 {
        n = copy_str(out, n, "+");
    }
    n = write_num_i64(out, n, disp as i64 as u64);
    n = copy_str(out, n, "]");
    n
}

// CEP:WHAT: Renders one SSE register-register instruction.
// CEP:WHY: SSE operands render as x0..x7 matching the encoder's xmm numbering.
// CEP:STATUS: complete
// CEP:FAILURE: Silently clips at the buffer end; no panic and no error path.
// CEP:ASSUMES: none
// CEP:COST: O(rendered bytes).
// CEP:EVIDENCE: golden disassembly tests.
pub(crate) fn render_sse(out: &mut [u8; 96], name: &str, dst: u8, src: u8) -> usize {
    let mut n = copy_str(out, 0, name);
    n = copy_str(out, n, " x");
    n = write_num(out, n, dst as u64);
    n = copy_str(out, n, ", x");
    n = write_num(out, n, src as u64);
    n
}

// CEP:WHAT: Renders one SSE heap access with SIB addressing as `[r15+rN*scale+disp]`.
// CEP:WHY: Heap operands always address through r15 with an index register; the renderer exposes index, scale, and displacement for evidence.
// CEP:STATUS: complete
// CEP:FAILURE: Silently clips at the buffer end; no panic and no error path.
// CEP:ASSUMES: none
// CEP:COST: O(rendered bytes).
// CEP:EVIDENCE: golden disassembly tests.
pub(crate) fn render_sse_mem(out: &mut [u8; 96], name: &str, xmm: u8, index: u8, scale_bits: u8, disp: i32) -> usize {
    let mut n = copy_str(out, 0, name);
    n = copy_str(out, n, " x");
    n = write_num(out, n, xmm as u64);
    n = copy_str(out, n, ", [r15+r");
    n = write_num(out, n, index as u64);
    n = copy_str(out, n, "*");
    n = write_num(out, n, 1u64 << scale_bits);
    n = render_disp(out, n, disp);
    n
}
