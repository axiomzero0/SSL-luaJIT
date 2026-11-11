// CEP:FILE: config/src/bytecode_consts.rs
// CEP:WHAT: Shared constant-pool definition and math helper count used by the assembler, the interpreter, and the emitter.
// CEP:WHY: The emitter must resolve constant-pool indices to double bit patterns; one definition keeps the airlock, interpreter, and backend in agreement.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: none; declarations only.
// CEP:ASSUMES: constant indices are i32-ranged; enforced by the assembler airlock.
// CEP:COST: cold; declarations only.
// CEP:EVIDENCE: assembler round-trip tests.

/// Constant pool entry shared across the pipeline.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Const {
    /// Integer constant.
    Int(i64),
    /// Double constant.
    Num(f64),
    /// Interned string handle.
    Str(u32),
}

/// Number of math helper thunks emitted after each trace.
pub const MATH_HELPER_COUNT: u32 = 5;
