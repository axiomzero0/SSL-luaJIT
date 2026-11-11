// CEP:FILE: hot/src/bytecode.rs
// CEP:WHAT: The SSL-BC bytecode instruction set: opcode numbering, word encoding, constant pool, and program view.
// CEP:WHY: The interpreter, recorder, and assembler need one fixed protocol; explicit opcode numbers and word layouts keep the text assembler and the machine agreeable without reflection.
// CEP:CLASS: CEP-0
// CEP:STATUS: complete
// CEP:FAILURE: none; encoding helpers are total over u8 fields.
// CEP:ASSUMES: program words are little-endian u32 in host memory; enforced by round-trip tests.
// CEP:COST: encoding and decoding are single shift-or and shift-mask operations.
// CEP:EVIDENCE: unit tests ssl-tests::unit_bytecode; differential tests.

/// Load a constant into a slot.
pub const OP_LOADK: u8 = 1;
/// Copy one slot to another.
pub const OP_MOVE: u8 = 2;
/// Integer add with immediate.
pub const OP_ADDI: u8 = 3;
/// Numeric add with type specialization at runtime.
pub const OP_ADD: u8 = 4;
/// Numeric subtract.
pub const OP_SUB: u8 = 5;
/// Numeric multiply.
pub const OP_MUL: u8 = 6;
/// Float divide.
pub const OP_DIV: u8 = 7;
/// Less than compare producing a boolean.
pub const OP_LT: u8 = 8;
/// Less or equal compare.
pub const OP_LE: u8 = 9;
/// Equality compare.
pub const OP_EQ: u8 = 10;
/// Greater than compare.
pub const OP_GT: u8 = 11;
/// Greater or equal compare.
pub const OP_GE: u8 = 12;
/// Not equal compare.
pub const OP_NE: u8 = 13;
/// Unconditional jump.
pub const OP_JMP: u8 = 14;
/// Jump when the slot is truthy.
pub const OP_JMPIF: u8 = 15;
/// Jump when the slot is falsy.
pub const OP_JMPNOT: u8 = 16;
/// Allocate an array table with an immediate length.
pub const OP_TNEW: u8 = 17;
/// Array table get by integer slot key.
pub const OP_TGETI: u8 = 18;
/// Array table set by integer slot key.
pub const OP_TSETI: u8 = 19;
/// Property get by constant string key.
pub const OP_TGETK: u8 = 20;
/// Property set by constant string key.
pub const OP_TSETK: u8 = 21;
/// Global read by global slot id.
pub const OP_GGET: u8 = 22;
/// Global write by global slot id.
pub const OP_GSET: u8 = 23;
/// Math builtin call by function id.
pub const OP_CALLM: u8 = 24;
/// Return from the program.
pub const OP_RET: u8 = 25;
/// Print one slot value to the bounded output buffer.
pub const OP_PRINT: u8 = 26;
/// No operation slot reserved for pass rewrites.
pub const OP_NOP: u8 = 27;

/// Word field masks for the four-byte operand layout.
pub const FIELD_MASK: u32 = 0xFF;
/// Bit shift of the a field.
pub const SHIFT_A: u32 = 8;
/// Bit shift of the b field.
pub const SHIFT_B: u32 = 16;
/// Bit shift of the c field.
pub const SHIFT_C: u32 = 24;

/// Math builtin identifiers for OP_CALLM.
pub const MATH_SIN: u8 = 0;
/// Cosine builtin identifier.
pub const MATH_COS: u8 = 1;
/// Square root builtin identifier.
pub const MATH_SQRT: u8 = 2;
/// Absolute value builtin identifier.
pub const MATH_ABS: u8 = 3;
/// Floor builtin identifier.
pub const MATH_FLOOR: u8 = 4;

/// Constant pool entry, re-exported from the shared configuration crate.
pub use ssl_config::bytecode_consts::Const;

/// Borrowed view of an assembled program.
#[derive(Copy, Clone)]
pub struct Program<'a> {
    /// Bytecode words.
    pub words: &'a [u32],
    /// Constant pool.
    pub consts: &'a [Const],
    /// Number of addressable frame slots declared by the assembler.
    pub slot_count: u32,
}

/// Encodes one instruction word from the opcode and three byte fields.
pub const fn encode(op: u8, a: u8, b: u8, c: u8) -> u32 {
    op as u32 | (a as u32) << SHIFT_A | (b as u32) << SHIFT_B | (c as u32) << SHIFT_C
}

/// Decodes the opcode field of one instruction word.
pub const fn decode_op(word: u32) -> u8 {
    (word & FIELD_MASK) as u8
}

/// Decodes the a field of one instruction word.
pub const fn decode_a(word: u32) -> u8 {
    ((word >> SHIFT_A) & FIELD_MASK) as u8
}

/// Decodes the b field of one instruction word.
pub const fn decode_b(word: u32) -> u8 {
    ((word >> SHIFT_B) & FIELD_MASK) as u8
}

/// Decodes the c field of one instruction word.
pub const fn decode_c(word: u32) -> u8 {
    ((word >> SHIFT_C) & FIELD_MASK) as u8
}

/// Reports whether the opcode is a jump with an immediate offset word.
pub const fn is_jump(op: u8) -> bool {
    op == OP_JMP || op == OP_JMPIF || op == OP_JMPNOT
}

/// Reports whether the opcode takes one immediate word after the instruction word.
pub const fn has_immediate(op: u8) -> bool {
    is_jump(op) || op == OP_ADDI || op == OP_TNEW
}

/// Reports whether the instruction reads the conditional slot in field a.
pub const fn uses_condition_slot(op: u8) -> bool {
    op == OP_JMPIF || op == OP_JMPNOT
}
