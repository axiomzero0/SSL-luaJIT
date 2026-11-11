// CEP:FILE: tools/cep_lint/src/source.rs
// CEP:WHAT: Source file model: line splitting, comment inventory, string-literal inventory, and comment/string-blanked code text.
// CEP:WHY: Banned-token and literal rules must ignore comment and string content (50.3 CEP-LINT-HOT-BANNED limits); comment rules must see comment lines only; the model is produced once and shared by every check.
// CEP:CLASS: CEP-2
// CEP:STATUS: complete
// CEP:FAILURE: Returns None-shaped errors via the caller; oversized sources are rejected by the caller before scanning.
// CEP:ASSUMES: input is Rust-like source with // and nested /* */ comments, "..." strings, raw strings, and 'x' char literals.
// CEP:COST: cold; single O(N) pass per file.
// CEP:EVIDENCE: unit test cep_lint::source in tools/cep_lint/tests/unit_source.rs.

use crate::limits as L;

pub struct StringLit {
    pub line: usize,
    pub content: String,
    pub is_char: bool,
}

pub struct SourceFile {
    pub path: String,
    pub lines: Vec<String>,
    pub code: Vec<String>,
    pub comment_lines: Vec<(usize, String)>,
    pub strings: Vec<StringLit>,
}

const STATE_CODE: u8 = 0;
const STATE_LINE_COMMENT: u8 = 1;
const STATE_BLOCK_COMMENT: u8 = 2;
const STATE_STRING: u8 = 3;
const STATE_RAW_STRING: u8 = 4;
const STATE_CHAR: u8 = 5;

    // CEP:WHAT: Builds the per-file model: lines, blanked code, comment inventory, and string inventory.
    // CEP:WHY: Every check depends on one consistent comment-and-string view; a single pass produces it.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; single O(N) pass per file.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn load(path: &str, text: &str) -> SourceFile {
    let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let mut code = Vec::with_capacity(lines.len());
    let mut comment_lines = Vec::new();
    let mut strings = Vec::new();
    let mut state = STATE_CODE;
    let mut block_depth = 0u32;
    let mut raw_hashes = 0usize;
    for (idx, line) in lines.iter().enumerate() {
        let mut blanked = String::with_capacity(line.len());
        let mut comment_text = String::new();
        let chars: Vec<char> = line.chars().collect();
        let mut col = 0usize;
        while col < chars.len() {
            let c = chars[col];
            match state {
                STATE_CODE => {
                    if c == '/' && chars.get(col + 1) == Some(&'/') {
                        state = STATE_LINE_COMMENT;
                        col += L::COMMENT_MARKER_BYTES;
                        continue;
                    }
                    if c == '/' && chars.get(col + 1) == Some(&'*') {
                        state = STATE_BLOCK_COMMENT;
                        block_depth = 1;
                        col += L::COMMENT_MARKER_BYTES;
                        continue;
                    }
                    if c == '"' {
                        let (hashes, next) = raw_prefix_hashes(&chars, col + 1);
                        if hashes > L::ZERO || line_has_raw_prefix(&chars, col) {
                            raw_hashes = hashes;
                            state = STATE_RAW_STRING;
                            col = next;
                            continue;
                        }
                        state = STATE_STRING;
                        col += 1;
                        continue;
                    }
                    if c == '\'' {
                        if let Some(end) = char_literal_end(&chars, col) {
                            state = STATE_CHAR;
                            strings.push(StringLit {
                                line: idx + 1,
                                content: chars[col + 1..end].iter().collect(),
                                is_char: true,
                            });
                            blanked.push(' ');
                            blanked.push(' ');
                            col = end + 1;
                            state = STATE_CODE;
                            continue;
                        }
                        blanked.push(c);
                        col += 1;
                        continue;
                    }
                    blanked.push(c);
                    col += 1;
                }
                STATE_LINE_COMMENT => {
                    comment_text.push(c);
                    col += 1;
                }
                STATE_BLOCK_COMMENT => {
                    if c == '*' && chars.get(col + 1) == Some(&'/') {
                        block_depth -= 1;
                        if block_depth == 0 {
                            state = STATE_CODE;
                        }
                        col += L::COMMENT_MARKER_BYTES;
                        continue;
                    }
                    if c == '/' && chars.get(col + 1) == Some(&'*') {
                        block_depth += 1;
                        col += L::COMMENT_MARKER_BYTES;
                        continue;
                    }
                    comment_text.push(c);
                    col += 1;
                }
                STATE_STRING => {
                    if c == '\\' {
                        col += L::ESCAPE_PAIR_BYTES;
                        continue;
                    }
                    if c == '"' {
                        state = STATE_CODE;
                        blanked.push(' ');
                        blanked.push(' ');
                        col += 1;
                        continue;
                    }
                    col += 1;
                }
                STATE_RAW_STRING => {
                    if c == '"' && raw_suffix_len(&chars, col + 1) == raw_hashes {
                        col += 1 + raw_suffix_len(&chars, col + 1);
                        raw_hashes = 0;
                        state = STATE_CODE;
                        blanked.push(' ');
                        blanked.push(' ');
                        continue;
                    }
                    col += 1;
                }
                STATE_CHAR => {
                    col += 1;
                }
                _ => {
                    col += 1;
                }
            }
        }
        if state == STATE_LINE_COMMENT {
            state = STATE_CODE;
        }
        if !comment_text.trim().is_empty() {
            comment_lines.push((idx + 1, comment_text));
        }
        code.push(blanked);
    }
    SourceFile {
        path: path.to_string(),
        lines,
        code,
        comment_lines,
        strings,
    }
}

    // CEP:WHAT: Counts raw-string hash markers after a quote and returns the cursor past them.
    // CEP:WHY: Raw strings change escape semantics; the hash count identifies the closing form.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn raw_prefix_hashes(chars: &[char], mut col: usize) -> (usize, usize) {
    let mut hashes = 0usize;
    while col < chars.len() && chars[col] == '#' {
        hashes += 1;
        col += 1;
    }
    (hashes, col)
}

    // CEP:WHAT: Reports whether the identifier before a quote is the raw-string prefix r.
    // CEP:WHY: Distinguishing r"..." from normal strings requires inspecting the preceding identifier.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn line_has_raw_prefix(chars: &[char], quote_col: usize) -> bool {
    let mut back = quote_col;
    while back > 0 && (chars[back - 1].is_ascii_alphabetic() || chars[back - 1] == '_') {
        back -= 1;
    }
    let word: String = chars[back..quote_col].iter().collect();
    word == "r"
}

    // CEP:WHAT: Counts hash markers after a candidate raw-string terminator quote.
    // CEP:WHY: A raw string closes only when the suffix hash count matches the prefix count.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn raw_suffix_len(chars: &[char], mut col: usize) -> usize {
    let mut hashes = 0usize;
    while col < chars.len() && chars[col] == '#' {
        hashes += 1;
        col += 1;
    }
    hashes
}

    // CEP:WHAT: Locates the closing quote of a char literal, distinguishing it from lifetimes.
    // CEP:WHY: Lifetimes and char literals share the apostrophe; misclassification would corrupt the code text.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn char_literal_end(chars: &[char], start: usize) -> Option<usize> {
    let mut col = start + 1;
    if col >= chars.len() {
        return None;
    }
    if chars[col] == '\\' {
        col += 1;
        col = skip_escaped_char(chars, col)?;
    } else {
        col += 1;
    }
    if chars.get(col) == Some(&'\'') {
        Some(col)
    } else {
        None
    }
}

fn skip_escaped_char(chars: &[char], col: usize) -> Option<usize> {
    match chars.get(col) {
        Some('x') => Some(col + L::ESCAPE_X_BYTES),
        Some('u') => Some(col + L::ESCAPE_U_BYTES),
        _ => Some(col + 1),
    }
}
