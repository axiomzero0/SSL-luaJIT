// CEP:FILE: cold/src/lua_frontend.rs
// CEP:WHAT: The Lua frontend facade: source text in, airlock-ready program out, with strings interned for the driver.
// CEP:WHY: The driver and CLI need one entry point that turns Lua source into the same assembled shape the text assembler produces.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: Returns FrontendError with a source line for lexing, parsing, and codegen failures; never panics.
// CEP:ASSUMES: string constants are interned with the same FNV-1a handle the text-assembler path uses, so table keys agree across both frontends.
// CEP:COST: cold; one lex, one parse, one linear codegen pass.
// CEP:EVIDENCE: end-to-end Lua program tests ssl-tests::unit_lua_programs.

use crate::lua_ast::FrontendError;
use crate::lua_codegen::{compile, CompiledProgram};
use crate::lua_parse;
use ssl_hot::bytecode as bc;

/// Compiles Lua source into a bytecode program with interned string constants.
pub fn compile_source(source: &str) -> Result<CompiledProgram, FrontendError> {
    let chunk = lua_parse::parse(source)?;
    compile(&chunk)
}

/// Converts the compiled program into the assembler-crate shape the driver consumes,
/// with Str constants replaced by FNV-1a interned handles (same rule as the text path).
pub fn to_assembled(
    program: &CompiledProgram,
) -> Result<crate::assembler::AssembledProgram, FrontendError> {
    let mut consts = program.consts.clone();
    for entry in consts.iter_mut() {
        if let bc::Const::Str(index) = entry {
            let text = program
                .strings
                .get(*index as usize)
                .cloned()
                .unwrap_or_default();
            *entry = bc::Const::Str(fnv1a(&text));
        }
    }
    Ok(crate::assembler::AssembledProgram {
        words: program.words.clone(),
        consts,
        strings: Vec::new(),
        slot_count: program.slot_count,
        global_names: program.global_names.clone(),
    })
}

/// Deterministic FNV-1a string handle; must match driver::hash_string.
pub fn fnv1a(text: &str) -> u32 {
    let mut hash: u32 = 0x811C_9DC5;
    for byte in text.bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}
