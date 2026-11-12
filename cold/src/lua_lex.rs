// CEP:FILE: cold/src/lua_lex.rs
// CEP:WHAT: The Lua 5.1-subset tokenizer: names, keywords, numbers, strings, operators, and line/block comments.
// CEP:WHY: The frontend compiles real Lua source into SSL-BC; a bounded tokenizer with source offsets lets every later stage report exact line numbers.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: Returns LexError with line numbers for unterminated strings, malformed numbers, unknown characters, and exceeded input budgets; never panics.
// CEP:ASSUMES: input is UTF-8; only ASCII operator and identifier characters are recognized, matching the numeric/table subset the VM ISA can express.
// CEP:COST: single left-to-right scan; O(n) with no allocation beyond the token vector.
// CEP:EVIDENCE: unit tests ssl-tests::unit_lua_lex including adversarial inputs.

use ssl_config::limits as L;

/// One token with its source line for diagnostics.
#[derive(Clone, Debug, PartialEq)]
pub struct Token {
    /// Token payload.
    pub kind: TokKind,
    /// One-based source line where the token starts.
    pub line: usize,
}

/// Token payload kinds.
#[derive(Clone, Debug, PartialEq)]
pub enum TokKind {
    /// Identifier or keyword text (keywords are filtered by the parser).
    Name(String),
    /// Integer literal (decimal or hex) that fits i64.
    IntLit(i64),
    /// Floating-point literal.
    NumLit(f64),
    /// String literal body with escapes already applied.
    StrLit(String),
    /// Keyword or symbol text from KEYWORDS/SYMBOLS.
    Punct(String),
    /// End of input.
    Eof,
}

/// Lua keywords recognized by the subset (goto is reserved so it errors clearly).
pub const KEYWORDS: [&str; 22] = [
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "goto", "if",
    "in", "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while",
];

/// Multi-character and single-character symbols, longest first for matching.
pub const SYMBOLS: [&str; 26] = [
    "==", "~=", "<=", ">=", "..", "--", "//", "+", "-", "*", "/", "%", "<", ">", "=", "(",
    ")", "[", "]", "{", "}", ";", ",", ".", "#", "^",
];

/// Lexical failure with source line.
#[derive(Clone, PartialEq, Debug)]
pub enum LexError {
    /// Unterminated string or invalid escape.
    BadString(usize, String),
    /// Malformed numeric literal.
    BadNumber(usize, String),
    /// Character not part of the subset.
    UnknownChar(usize, char),
    /// Input exceeded the assembler source budget.
    TooLarge,
}

/// Tokenizes one Lua source into a token vector terminated by Eof.
pub fn lex(source: &str) -> Result<Vec<Token>, LexError> {
    if source.len() > L::MAX_SOURCE_BYTES as usize {
        return Err(LexError::TooLarge);
    }
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    let mut line = 1usize;
    while i < bytes.len() {
        let ch = bytes[i];
        match ch {
            b'\n' => {
                line += 1;
                i += 1;
            }
            b' ' | b'\t' | b'\r' | 0x0b | 0x0c => {
                i += 1;
            }
            b'-' if starts_long_comment(bytes, i) => {
                i = skip_block_comment(bytes, i, &mut line)?;
            }
            b'-' => {
                if bytes.get(i + 1) == Some(&b'-') {
                    // Line comment: skip to end of line.
                    while i < bytes.len() && bytes[i] != b'\n' {
                        i += 1;
                    }
                } else {
                    tokens.push(Token { kind: TokKind::Punct("-".to_string()), line });
                    i += 1;
                }
            }
            b'"' | b'\'' => {
                let (text, next_i, next_line) = read_string(bytes, i, line)?;
                tokens.push(Token { kind: TokKind::StrLit(text), line });
                i = next_i;
                line = next_line;
            }
            b'0'..=b'9' => {
                let (kind, next_i) = read_number(bytes, i, line)?;
                tokens.push(Token { kind, line });
                i = next_i;
            }
            b'.' if bytes.get(i + 1).map(|c| c.is_ascii_digit()).unwrap_or(false) => {
                // Leading-dot float literal like .5.
                let (kind, next_i) = read_number(bytes, i, line)?;
                tokens.push(Token { kind, line });
                i = next_i;
            }
            b'_' | b'a'..=b'z' | b'A'..=b'Z' => {
                let start = i;
                while i < bytes.len() && is_name_char(bytes[i]) {
                    i += 1;
                }
                let text = &source[start..i];
                tokens.push(Token { kind: TokKind::Name(text.to_string()), line });
            }
            _ => {
                if let Some(sym) = match_symbol(bytes, i) {
                    tokens.push(Token { kind: TokKind::Punct(sym.to_string()), line });
                    i += sym.len();
                } else {
                    let bad = source[i..].chars().next().unwrap_or('?');
                    return Err(LexError::UnknownChar(line, bad));
                }
            }
        }
    }
    tokens.push(Token { kind: TokKind::Eof, line });
    Ok(tokens)
}

fn is_name_char(ch: u8) -> bool {
    matches!(ch, b'_' | b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9')
}

/// Reports whether position starts a long bracket comment '--[' '='* '[' at any level.
fn starts_long_comment(bytes: &[u8], i: usize) -> bool {
    if bytes.len() < i + 3 || bytes[i] != b'-' || bytes[i + 1] != b'-' || bytes[i + 2] != b'[' {
        return false;
    }
    let mut j = i + 3;
    while j < bytes.len() && bytes[j] == b'=' {
        j += 1;
    }
    j < bytes.len() && bytes[j] == b'['
}

/// Skips one long bracket comment at any '=' level: [[ ]], [=[ ]=], [==[ ]==], ...
fn skip_block_comment(bytes: &[u8], start: usize, line: &mut usize) -> Result<usize, LexError> {
    let mut i = start + 2; // skip '--'
    let mut level = 0usize;
    if i < bytes.len() && bytes[i] == b'[' {
        i += 1;
        while i < bytes.len() && bytes[i] == b'=' {
            level += 1;
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'[' {
            i += 1;
        } else {
            // '--[' not followed by a closing long bracket; the caller only routes
            // genuine long comments here, so this is unreachable defense.
            return Ok(i);
        }
    } else {
        return Ok(i);
    }
    let close: Vec<u8> = {
        let mut v = vec![b']'];
        v.extend(std::iter::repeat(b'=').take(level));
        v.push(b']');
        v
    };
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            *line += 1;
        }
        if bytes[i..].starts_with(&close) {
            return Ok(i + close.len());
        }
        i += 1;
    }
    Err(LexError::BadString(*line, "unterminated block comment".to_string()))
}

/// Reads one quoted string with escape handling; returns body, next index, and next line.
fn read_string(bytes: &[u8], start: usize, start_line: usize) -> Result<(String, usize, usize), LexError> {
    let quote = bytes[start];
    let mut i = start + 1;
    let mut line = start_line;
    let mut out = String::new();
    while i < bytes.len() {
        let ch = bytes[i];
        if ch == quote {
            return Ok((out, i + 1, line));
        }
        if ch == b'\n' {
            return Err(LexError::BadString(line, "unterminated string".to_string()));
        }
        if ch == b'\\' {
            i += 1;
            if i >= bytes.len() {
                return Err(LexError::BadString(line, "unterminated escape".to_string()));
            }
            match bytes[i] {
                b'n' => {
                    out.push('\n');
                    i += 1;
                }
                b't' => {
                    out.push('\t');
                    i += 1;
                }
                b'r' => {
                    out.push('\r');
                    i += 1;
                }
                b'a' => {
                    out.push('\u{07}');
                    i += 1;
                }
                b'b' => {
                    out.push('\u{08}');
                    i += 1;
                }
                b'f' => {
                    out.push('\u{0c}');
                    i += 1;
                }
                b'v' => {
                    out.push('\u{0b}');
                    i += 1;
                }
                b'\\' => {
                    out.push('\\');
                    i += 1;
                }
                b'"' => {
                    out.push('"');
                    i += 1;
                }
                b'\'' => {
                    out.push('\'');
                    i += 1;
                }
                b'\n' => {
                    line += 1;
                    out.push('\n');
                    i += 1;
                }
                b'z' => {
                    // \z skips following whitespace including newlines.
                    i += 1;
                    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c) {
                        if bytes[i] == b'\n' {
                            line += 1;
                        }
                        i += 1;
                    }
                }
                b'x' => {
                    // \xHH: exactly two hex digits.
                    let mut value: u32 = 0;
                    let mut digits = 0usize;
                    i += 1;
                    while digits < 2 && i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                        value = value * 16 + (bytes[i] as char).to_digit(16).unwrap_or(0);
                        digits += 1;
                        i += 1;
                    }
                    if digits != 2 {
                        return Err(LexError::BadString(line, "\\x escape needs two hex digits".to_string()));
                    }
                    out.push(value as u8 as char);
                }
                b'0'..=b'9' => {
                    // \ddd: one to three decimal digits forming one byte.
                    let mut value: u32 = 0;
                    let mut digits = 0usize;
                    while digits < 3 && i < bytes.len() && bytes[i].is_ascii_digit() {
                        value = value * 10 + (bytes[i] - b'0') as u32;
                        digits += 1;
                        i += 1;
                    }
                    if value > 255 {
                        return Err(LexError::BadString(line, "decimal escape exceeds 255".to_string()));
                    }
                    out.push(value as u8 as char);
                }
                b'u' if i + 1 < bytes.len() && bytes[i + 1] == b'{' => {
                    // \u{XXX}: one or more hex digits in braces.
                    i += 2;
                    let mut value: u32 = 0;
                    let mut digits = 0usize;
                    while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                        value = value.saturating_mul(16).saturating_add((bytes[i] as char).to_digit(16).unwrap_or(0));
                        digits += 1;
                        i += 1;
                    }
                    if digits == 0 || i >= bytes.len() || bytes[i] != b'}' {
                        return Err(LexError::BadString(line, "malformed \\u{...} escape".to_string()));
                    }
                    i += 1;
                    match char::from_u32(value) {
                        Some(decoded) => out.push(decoded),
                        None => return Err(LexError::BadString(line, "\\u escape out of range".to_string())),
                    }
                }
                _ => {
                    return Err(LexError::BadString(line, format!("unknown escape \\{}", bytes[i] as char)));
                }
            }
        } else {
            // Copy one UTF-8 character verbatim, bounds-checked.
            let len = utf8_len(bytes[i]);
            if i + len > bytes.len() {
                return Err(LexError::BadString(line, "truncated utf-8 sequence".to_string()));
            }
            let text = std::str::from_utf8(&bytes[i..i + len])
                .map_err(|_| LexError::BadString(line, "invalid utf-8".to_string()))?;
            out.push_str(text);
            i += len;
        }
    }
    Err(LexError::BadString(line, "unterminated string".to_string()))
}

fn utf8_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

/// Reads one numeric literal: decimal, hex, exponent, and trailing dot forms.
fn read_number(bytes: &[u8], start: usize, line: usize) -> Result<(TokKind, usize), LexError> {
    let mut i = start;
    let mut text = String::new();
    if bytes[i] == b'0' && i + 1 < bytes.len() && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
        i += 2;
        let hex_start = i;
        while i < bytes.len() && (bytes[i].is_ascii_hexdigit() || bytes[i] == b'_') {
            if bytes[i] != b'_' {
                text.push(bytes[i] as char);
            }
            i += 1;
        }
        if i == hex_start {
            return Err(LexError::BadNumber(line, "empty hex literal".to_string()));
        }
        let value = i64::from_str_radix(&text, 16)
            .map_err(|_| LexError::BadNumber(line, format!("hex 0x{} out of range", text)))?;
        return Ok((TokKind::IntLit(value), i));
    }
    let mut saw_dot = false;
    let mut saw_exp = false;
    while i < bytes.len() {
        let ch = bytes[i];
        if ch.is_ascii_digit() {
            text.push(ch as char);
            i += 1;
        } else if ch == b'.' && !saw_dot && !saw_exp {
            saw_dot = true;
            text.push('.');
            i += 1;
        } else if (ch == b'e' || ch == b'E') && !saw_exp && i > start {
            // Only treat as exponent when followed by digits or sign+digits.
            let next = bytes.get(i + 1).copied();
            let ok = match next {
                Some(d) if d.is_ascii_digit() => true,
                Some(sign @ (b'+' | b'-')) => {
                    bytes.get(i + 2).map(|d| d.is_ascii_digit()).unwrap_or(false)
                        && {
                            let _ = sign;
                            true
                        }
                }
                _ => false,
            };
            if !ok {
                break;
            }
            saw_exp = true;
            text.push('e');
            i += 1;
            if bytes[i] == b'+' || bytes[i] == b'-' {
                text.push(bytes[i] as char);
                i += 1;
            }
        } else {
            break;
        }
    }
    if saw_dot || saw_exp {
        let value: f64 = text
            .parse()
            .map_err(|_| LexError::BadNumber(line, format!("bad number {}", text)))?;
        Ok((TokKind::NumLit(value), i))
    } else {
        let value: i64 = text
            .parse()
            .map_err(|_| LexError::BadNumber(line, format!("integer {} out of range", text)))?;
        Ok((TokKind::IntLit(value), i))
    }
}

/// Matches the longest symbol at the position, if any.
fn match_symbol(bytes: &[u8], i: usize) -> Option<&'static str> {
    for sym in SYMBOLS {
        let sy = sym.as_bytes();
        if bytes.len() >= i + sy.len() && &bytes[i..i + sy.len()] == sy {
            return Some(sym);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexes_names_numbers_symbols() {
        let tokens = lex("local x1 = 42 0x2A 3.5 1e2").unwrap();
        assert_eq!(tokens[0].kind, TokKind::Name("local".into()));
        assert_eq!(tokens[1].kind, TokKind::Name("x1".into()));
        assert_eq!(tokens[2].kind, TokKind::Punct("=".into()));
        assert_eq!(tokens[3].kind, TokKind::IntLit(42));
        assert_eq!(tokens[4].kind, TokKind::IntLit(42));
        assert_eq!(tokens[5].kind, TokKind::NumLit(3.5));
        assert_eq!(tokens[6].kind, TokKind::NumLit(100.0));
    }

    #[test]
    fn skips_line_and_block_comments() {
        let src = "-- line\nlocal x = 1 --[[ block\ncomment ]] local y = 2 --[[= pad ]]";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens[0].line, 2);
        assert_eq!(tokens.last().unwrap().kind, TokKind::Eof);
    }

    #[test]
    fn strings_with_escapes() {
        let tokens = lex("'a\\n\"b\"'").unwrap();
        assert_eq!(tokens[0].kind, TokKind::StrLit("a\n\"b\"".into()));
        assert!(lex("'open").is_err());
    }

    #[test]
    fn rejects_unknown_characters() {
        assert!(lex("local x = 1 & 2").is_err());
    }

    #[test]
    fn long_bracket_comment_levels() {
        // Level-2 long comment must not degrade into a line comment.
        let tokens = lex("--[==[ still
comment ]==] local z = .5").unwrap();
        assert_eq!(tokens[0].kind, TokKind::Name("local".into()));
        assert_eq!(tokens[3].kind, TokKind::NumLit(0.5));
        // Unterminated level-1 long comment must error, not silently pass.
        assert!(lex("--[=[ open").is_err());
        // ' --[x' is a short comment in real Lua, not an error.
        assert!(lex("local w = 1 --[x fine").is_ok());
    }

    #[test]
    fn decimal_and_hex_escapes() {
        assert_eq!(lex("'a\\65b'").unwrap()[0].kind, TokKind::StrLit("aAb".into()));
        assert_eq!(lex("'\\x41'").unwrap()[0].kind, TokKind::StrLit("A".into()));
        assert!(lex("'\\400'").is_err());
        assert!(lex("'\\x1'").is_err());
    }

    #[test]
    fn leading_dot_floats() {
        let tokens = lex("local a = .5").unwrap();
        assert_eq!(tokens[3].kind, TokKind::NumLit(0.5));
    }

    #[test]
    fn truncated_utf8_in_string_errors() {
        let raw = unsafe { String::from_utf8_unchecked(b"local s = 'ab\xC3".to_vec()) };
        assert!(lex(&raw).is_err());
    }

    #[test]
    fn counts_lines_through_strings_and_comments() {
        let tokens = lex("a\n--[[x\ny]]\nb").unwrap();
        let names: Vec<&str> = tokens
            .iter()
            .filter_map(|t| match &t.kind {
                TokKind::Name(n) => Some(n.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(names, ["a", "b"]);
        assert_eq!(tokens[0].line, 1);
        assert_eq!(tokens[1].line, 4);
    }
}
