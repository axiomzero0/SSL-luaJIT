// CEP:FILE: tools/cep_lint/src/limits.rs
// CEP:WHAT: Named byte, encoding, and bound constants internal to the lint engine.
// CEP:WHY: Law 7 and section 11.3 ban magic numbers; the engine itself must express every byte comparison and bound as a named constant.
// CEP:CLASS: CEP-2
// CEP:STATUS: complete
// CEP:FAILURE: none; declarations only.
// CEP:ASSUMES: none
// CEP:COST: cold; compile-time only.
// CEP:EVIDENCE: self-lint gate `cep_lint tools/cep_lint/src` reports zero findings for this file.

pub const SPACE_BYTE: u8 = 32;
pub const TAB_BYTE: u8 = 9;
pub const NEWLINE_BYTE: u8 = 10;
pub const CR_BYTE: u8 = 13;
pub const ASCII_PRINTABLE_MIN: u8 = 32;
pub const HEX_RADIX: u32 = 16;
pub const HEX_DIGITS_U16: u32 = 4;
pub const UTF16_HIGH_MIN: u32 = 0xD800;
pub const UTF16_HIGH_MAX: u32 = 0xDBFF;
pub const UTF16_SHIFT: u32 = 10;
pub const SURROGATE_BIAS: u32 = 0x10000;
pub const REGEX_MAX_PATTERN_BYTES: usize = 512;
pub const REGEX_MAX_STEPS: u32 = 200_000;
pub const STATEMENT_MAX_LINES: usize = 12;
pub const SEVERITY_MIN: u32 = 0;
pub const SEVERITY_MAX: u32 = 3;
pub const EXIT_CLEAN: i32 = 0;
pub const EXIT_FINDINGS: i32 = 1;
pub const EXIT_BOOT: i32 = 2;
pub const EXIT_USAGE: i32 = 3;
pub const LINT_MAX_DEPTH: u32 = 64;
pub const LINT_MAX_CONFIG_BYTES: u32 = 1 << 20;
pub const LINT_MAX_SOURCE_BYTES: u32 = 1 << 20;
pub const ZERO: usize = 0;
pub const COMMENT_MARKER_BYTES: usize = 2;
pub const ESCAPE_PAIR_BYTES: usize = 2;
pub const ESCAPE_X_BYTES: usize = 3;
pub const ESCAPE_U_BYTES: usize = 7;
pub const UTF8_LEAD4: u8 = 0xF0;
pub const UTF8_LEAD3: u8 = 0xE0;
pub const UTF8_LEAD2: u8 = 0xC0;
pub const UTF8_EXTRA4: usize = 3;
pub const UTF8_EXTRA3: usize = 2;
pub const UTF8_EXTRA2: usize = 1;
pub const NONCAPTURE_SKIP: usize = 2;
pub const HEX_PREFIX_SKIP: usize = 2;
pub const QUOTE_CAPACITY_BYTES: usize = 2;
pub const GLOB_WILDCARD_PREFIX: &str = "**/";
pub const GLOB_WILDCARD_PREFIX_BYTES: usize = 3;
pub const DEFAULT_MAX_START_LINE: u32 = 20;
pub const DEFAULT_MIN_BODY_STATEMENTS: u32 = 2;
pub const BOOT_IO: u32 = 1;
pub const BOOT_JSON: u32 = 2;
pub const BOOT_CYCLE: u32 = 3;
pub const BOOT_MISSING_KEY: u32 = 4;
pub const BOOT_WRONG_TYPE: u32 = 5;
pub const BOOT_UNKNOWN_CHECK: u32 = 6;
pub const BOOT_BAD_SEVERITY: u32 = 7;
pub const BOOT_BAD_REGEX: u32 = 8;
