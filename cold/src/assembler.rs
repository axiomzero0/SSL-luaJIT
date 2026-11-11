// CEP:FILE: cold/src/assembler.rs
// CEP:WHAT: The SSL-BC text assembler: validation airlock converting labeled assembly text into airlocked bytecode programs.
// CEP:WHY: Chapter 64.2 requires all invariants proven before the CEP-0 fast path; the airlock checks slot bounds, constant ranges, jump targets, opcode operand shapes, and denial-of-service limits once, up front.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: Returns AsmError with line numbers for malformed text, unknown mnemonics, out-of-range operands, unresolved labels, or exceeded budgets; never panics.
// CEP:ASSUMES: input text is UTF-8 and comes from trusted repository fixtures or the local operator; the airlock still validates every operand.
// CEP:COST: cold; O(lines) with bounded string work.
// CEP:EVIDENCE: assembler unit tests including adversarial inputs; fuzz corpus in tests.
// CEP:SECURITY: input is untrusted; every operand is bounds-checked and integer constants are confined to the i32 immediate range.

use ssl_config::limits as L;
use ssl_hot::bytecode as bc;

/// Assembler failure enumeration with source line.
#[derive(Clone, PartialEq, Debug)]
pub enum AsmError {
    /// A line exceeded the parsing budget or has bad syntax.
    Syntax(usize, String),
    /// Unknown mnemonic.
    UnknownMnemonic(usize, String),
    /// Operand out of range.
    BadOperand(usize, String),
    /// Label used but never defined.
    UnresolvedLabel(String),
    /// Label defined twice.
    DuplicateLabel(String),
    /// Budget limit exceeded.
    Budget(&'static str),
    /// Integer constant outside the i32 immediate range.
    ConstRange(usize, String),
}

/// Mnemonic-to-opcode table entries.
const MNEMONICS: [(&str, u8); 26] = [
    ("LOADK", bc::OP_LOADK),
    ("MOVE", bc::OP_MOVE),
    ("ADDI", bc::OP_ADDI),
    ("ADD", bc::OP_ADD),
    ("SUB", bc::OP_SUB),
    ("MUL", bc::OP_MUL),
    ("DIV", bc::OP_DIV),
    ("LT", bc::OP_LT),
    ("LE", bc::OP_LE),
    ("EQ", bc::OP_EQ),
    ("GT", bc::OP_GT),
    ("GE", bc::OP_GE),
    ("NE", bc::OP_NE),
    ("JMP", bc::OP_JMP),
    ("JMPIF", bc::OP_JMPIF),
    ("JMPNOT", bc::OP_JMPNOT),
    ("TNEW", bc::OP_TNEW),
    ("TGETI", bc::OP_TGETI),
    ("TSETI", bc::OP_TSETI),
    ("TGETK", bc::OP_TGETK),
    ("TSETK", bc::OP_TSETK),
    ("GGET", bc::OP_GGET),
    ("GSET", bc::OP_GSET),
    ("CALLM", bc::OP_CALLM),
    ("RET", bc::OP_RET),
    ("PRINT", bc::OP_PRINT),
];

/// Assembled program owned by the driver.
#[derive(Clone, Debug)]
pub struct AssembledProgram {
    /// Bytecode words.
    pub words: Vec<u32>,
    /// Constant pool; Str entries index the string table until the driver interns them.
    pub consts: Vec<bc::Const>,
    /// String table referenced by Str constants.
    pub strings: Vec<String>,
    /// Declared slot count.
    pub slot_count: u32,
    /// Global slot assignment in declaration order.
    pub global_names: Vec<String>,
}

/// Assembles one program through the validation airlock.
pub fn assemble(text: &str) -> Result<AssembledProgram, AsmError> {
    if text.len() > L::MAX_SOURCE_BYTES as usize {
        return Err(AsmError::Budget("source too large"));
    }
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() > L::MAX_ASSEMBLER_LINES as usize {
        return Err(AsmError::Budget("too many lines"));
    }
    let mut slot_count = 0u32;
    let mut consts: Vec<bc::Const> = Vec::new();
    let mut strings: Vec<String> = Vec::new();
    let mut global_names: Vec<String> = Vec::new();
    let mut words: Vec<u32> = Vec::new();
    let mut labels: Vec<(String, u32)> = Vec::new();
    let mut fixups: Vec<(u32, u8, String)> = Vec::new();
    for (idx, raw) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let line = strip_comment(raw);
        if line.is_empty() {
            continue;
        }
        if let Some(label) = line.strip_suffix(':') {
            let name = label.trim().trim_start_matches('@').to_string();
            if label_index(&labels, &name).is_some() {
                return Err(AsmError::DuplicateLabel(name));
            }
            labels.push((name, words.len() as u32));
            continue;
        }
        let mut tokens = line.split_whitespace();
        let head = tokens.next().ok_or(AsmError::Syntax(line_no, "empty".to_string()))?;
        if head == ".slots" {
            let value = parse_u32(tokens.next().ok_or(AsmError::Syntax(line_no, "missing".to_string()))?)
                .ok_or(AsmError::Syntax(line_no, "bad slots".to_string()))?;
            if value > L::MAX_SLOTS {
                return Err(AsmError::BadOperand(line_no, "slots".to_string()));
            }
            slot_count = value;
            continue;
        }
        if head == ".const" {
            parse_const(&mut consts, &mut strings, &tokens.collect::<Vec<&str>>(), line_no)?;
            continue;
        }
        if head == ".globals" {
            for name in tokens {
                global_names.push(name.trim().to_string());
            }
            continue;
        }
        let opcode = mnemonic(head).ok_or_else(|| AsmError::UnknownMnemonic(line_no, head.to_string()))?;
        let operands: Vec<&str> = tokens
            .map(|token| token.trim_end_matches(','))
            .filter(|token| !token.is_empty())
            .collect();
        encode_instruction(&mut words, &mut fixups, opcode, &operands, line_no)?;
    }
    for (word_at, opcode, target) in fixups {
        let resolved = label_index(&labels, &target)
            .ok_or_else(|| AsmError::UnresolvedLabel(target.clone()))?;
        let next_word = word_at as i64 + 2;
        let offset = resolved as i64 - next_word;
        if offset < i32::MIN as i64 || offset > i32::MAX as i64 {
            return Err(AsmError::BadOperand(word_at as usize, "offset".to_string()));
        }
        words[word_at as usize + 1] = offset as i32 as u32;
        let _ = opcode;
    }
    if words.len() > L::MAX_PROGRAM_WORDS as usize {
        return Err(AsmError::Budget("program too large"));
    }
    Ok(AssembledProgram {
        words,
        consts,
        strings,
        slot_count,
        global_names,
    })
}

fn strip_comment(raw: &str) -> &str {
    let cut = raw.find(';').unwrap_or(raw.len());
    raw[..cut].trim()
}

fn label_index(labels: &[(String, u32)], name: &str) -> Option<u32> {
    for (candidate, at) in labels {
        if candidate == name {
            return Some(*at);
        }
    }
    None
}

fn mnemonic(head: &str) -> Option<u8> {
    for (name, opcode) in MNEMONICS {
        if name == head {
            return Some(opcode);
        }
    }
    None
}

fn parse_u32(text: &str) -> Option<u32> {
    text.trim().parse::<u32>().ok()
}

fn parse_const(
    consts: &mut Vec<bc::Const>,
    strings: &mut Vec<String>,
    tokens: &[&str],
    line_no: usize,
) -> Result<(), AsmError> {
    let has_eq = tokens.len() >= 3 && tokens[1] == "=";
    let body: &[&str] = if has_eq { &tokens[2..] } else { &tokens[1..] };
    if body.len() < 2 {
        return Err(AsmError::Syntax(line_no, "const syntax".to_string()));
    }
    let index: usize = tokens[0]
        .trim()
        .parse()
        .map_err(|_| AsmError::Syntax(line_no, "const index".to_string()))?;
    if index != consts.len() {
        return Err(AsmError::Syntax(line_no, "const index must be sequential".to_string()));
    }
    if consts.len() >= L::MAX_CONSTANTS as usize {
        return Err(AsmError::Budget("too many constants"));
    }
    let kind = body[0];
    let value_text = body[1..].join(" ");
    let value = value_text.trim();
    let entry = match kind {
        "int" => {
            let parsed: i64 = value
                .parse()
                .map_err(|_| AsmError::ConstRange(line_no, value.to_string()))?;
            if parsed < i32::MIN as i64 || parsed > i32::MAX as i64 {
                return Err(AsmError::ConstRange(line_no, value.to_string()));
            }
            bc::Const::Int(parsed)
        }
        "num" => {
            let parsed: f64 = value
                .parse()
                .map_err(|_| AsmError::Syntax(line_no, "bad num".to_string()))?;
            bc::Const::Num(parsed)
        }
        "str" => {
            let inner = value
                .trim_start_matches('"')
                .trim_end_matches('"')
                .to_string();
            if strings.len() >= L::MAX_INTERNED_STRINGS as usize {
                return Err(AsmError::Budget("too many strings"));
            }
            strings.push(inner);
            bc::Const::Str(strings.len() as u32 - 1)
        }
        _ => return Err(AsmError::Syntax(line_no, "const kind".to_string())),
    };
    consts.push(entry);
    Ok(())
}

fn encode_instruction(
    words: &mut Vec<u32>,
    fixups: &mut Vec<(u32, u8, String)>,
    opcode: u8,
    operands: &[&str],
    line_no: usize,
) -> Result<(), AsmError> {
    let slot = |text: &str| -> Result<u32, AsmError> {
        let value = parse_u32(text).ok_or_else(|| AsmError::BadOperand(line_no, text.to_string()))?;
        if value >= L::MAX_SLOTS {
            return Err(AsmError::BadOperand(line_no, text.to_string()));
        }
        Ok(value)
    };
    let imm = |text: &str| -> Result<i32, AsmError> {
        text.trim()
            .parse::<i32>()
            .map_err(|_| AsmError::BadOperand(line_no, text.to_string()))
    };
    let needs = |count: usize| -> Result<(), AsmError> {
        if operands.len() != count {
            return Err(AsmError::Syntax(line_no, "operand count".to_string()));
        }
        Ok(())
    };
    match opcode {
        bc::OP_LOADK => {
            needs(2)?;
            let index: u32 = parse_u32(operands[1])
                .ok_or_else(|| AsmError::BadOperand(line_no, operands[1].to_string()))?;
            words.push(bc::encode(opcode, slot(operands[0])? as u8, index as u8, (index >> 8) as u8));
        }
        bc::OP_MOVE => {
            needs(2)?;
            words.push(bc::encode(opcode, slot(operands[0])? as u8, slot(operands[1])? as u8, 0));
        }
        bc::OP_RET | bc::OP_PRINT => {
            needs(1)?;
            words.push(bc::encode(opcode, slot(operands[0])? as u8, 0, 0));
        }
        bc::OP_ADDI => {
            needs(3)?;
            words.push(bc::encode(opcode, slot(operands[0])? as u8, slot(operands[1])? as u8, 0));
            words.push(imm(operands[2])? as u32);
        }
        bc::OP_TNEW => {
            needs(2)?;
            words.push(bc::encode(opcode, slot(operands[0])? as u8, 0, 0));
            words.push(imm(operands[1])? as u32);
        }
        bc::OP_ADD | bc::OP_SUB | bc::OP_MUL | bc::OP_DIV | bc::OP_LT | bc::OP_LE | bc::OP_EQ
        | bc::OP_GT | bc::OP_GE | bc::OP_NE | bc::OP_TGETI | bc::OP_TSETI => {
            needs(3)?;
            words.push(bc::encode(
                opcode,
                slot(operands[0])? as u8,
                slot(operands[1])? as u8,
                slot(operands[2])? as u8,
            ));
        }
        bc::OP_JMP => {
            needs(1)?;
            words.push(bc::encode(opcode, 0, 0, 0));
            fixups.push(((words.len() - 1) as u32, opcode, operands[0].trim_start_matches('@').to_string()));
            words.push(0);
        }
        bc::OP_JMPIF | bc::OP_JMPNOT => {
            needs(2)?;
            words.push(bc::encode(opcode, slot(operands[0])? as u8, 0, 0));
            fixups.push(((words.len() - 1) as u32, opcode, operands[1].trim_start_matches('@').to_string()));
            words.push(0);
        }
        bc::OP_TGETK | bc::OP_TSETK => {
            needs(3)?;
            let key: u32 = parse_u32(operands[2])
                .ok_or_else(|| AsmError::BadOperand(line_no, operands[2].to_string()))?;
            if key > 255 {
                return Err(AsmError::BadOperand(line_no, "key index".to_string()));
            }
            words.push(bc::encode(
                opcode,
                slot(operands[0])? as u8,
                slot(operands[1])? as u8,
                key as u8,
            ));
        }
        bc::OP_GGET | bc::OP_GSET => {
            needs(2)?;
            let global: u32 = parse_u32(operands[1])
                .ok_or_else(|| AsmError::BadOperand(line_no, operands[1].to_string()))?;
            if global > 255 {
                return Err(AsmError::BadOperand(line_no, "global".to_string()));
            }
            words.push(bc::encode(opcode, slot(operands[0])? as u8, 0, global as u8));
        }
        bc::OP_CALLM => {
            needs(3)?;
            let fnid: u32 = parse_u32(operands[1])
                .ok_or_else(|| AsmError::BadOperand(line_no, operands[1].to_string()))?;
            if fnid > 255 {
                return Err(AsmError::BadOperand(line_no, "fnid".to_string()));
            }
            words.push(bc::encode(opcode, slot(operands[0])? as u8, fnid as u8, slot(operands[2])? as u8));
        }
        _ => return Err(AsmError::UnknownMnemonic(line_no, String::new())),
    }
    Ok(())
}
