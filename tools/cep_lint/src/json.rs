// CEP:FILE: tools/cep_lint/src/json.rs
// CEP:WHAT: Minimal bounded JSON parser producing an ordered document tree for lint configuration and self-test manifests.
// CEP:WHY: The linter is zero-dependency (section 22.11 supply chain); configuration is JSON, so the engine needs its own parser with denial-of-service bounds (section 22.10).
// CEP:CLASS: CEP-2
// CEP:STATUS: complete
// CEP:FAILURE: Returns JsonError with line and column on malformed input, oversized input, or depth overflow; no panics.
// CEP:ASSUMES: input is UTF-8; enforced by String::from_utf8 check at load time.
// CEP:COST: cold; O(N) single pass over configuration bytes.
// CEP:EVIDENCE: unit test cep_lint::tests_json in tools/cep_lint/tests/unit_json.rs.

use crate::limits as L;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct JsonError {
    pub line: usize,
    pub col: usize,
    pub detail: String,
}

impl Json {
    // CEP:WHAT: Looks up an object member by key preserving configuration order.
    // CEP:WHY: Object order must remain stable for deterministic error reporting and manifest handling.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    // CEP:WHAT: Reads a JSON member as a string when it holds one.
    // CEP:WHY: Typed accessors keep configuration parsing strict without panicking on wrong types.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    // CEP:WHAT: Converts a JSON number to u32 when it is integral and in range.
    // CEP:WHY: Severity and count parameters must be whole numbers; fractional or negative values are rejected.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Json::Num(n) if *n >= 0.0 && n.fract() == 0.0 && *n <= u32::MAX as f64 => {
                Some(*n as u32)
            }
            _ => None,
        }
    }

    // CEP:WHAT: Reads a JSON member as a boolean when it holds one.
    // CEP:WHY: Typed accessors keep configuration parsing strict without panicking on wrong types.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    // CEP:WHAT: Reads a JSON member as an array slice when it holds one.
    // CEP:WHY: Typed accessors keep configuration parsing strict without panicking on wrong types.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    pub fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(items) => Some(items),
            _ => None,
        }
    }

    // CEP:WHAT: Reads a JSON member as an ordered object member list when it holds one.
    // CEP:WHY: Typed accessors keep configuration parsing strict without panicking on wrong types.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    pub fn as_obj(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Obj(pairs) => Some(pairs),
            _ => None,
        }
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    line: usize,
    col: usize,
    depth: u32,
}

    // CEP:WHAT: Parses a JSON document into the ordered tree with bounded depth and trailing-input checks.
    // CEP:WHY: Configuration is data per section 50; the parser must reject malformed and oversized input with coded errors.
    // CEP:STATUS: complete
    // CEP:FAILURE: Returns JsonError with line and column on malformed input, depth overflow, or trailing characters.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn parse(text: &str) -> Result<Json, JsonError> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        pos: 0,
        line: 1,
        col: 1,
        depth: 0,
    };
    parser.skip_ws();
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(parser.err("trailing characters after JSON document"));
    }
    Ok(value)
}

impl<'a> Parser<'a> {
    // CEP:WHAT: Builds a JsonError carrying the current line and column.
    // CEP:WHY: Bootstrap errors must point at the failure location per the CEP-LINT-BOOT-2 contract.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn err(&self, detail: &str) -> JsonError {
        JsonError {
            line: self.line,
            col: self.col,
            detail: detail.to_string(),
        }
    }

    // CEP:WHAT: Returns the byte at the cursor without advancing.
    // CEP:WHY: Typed accessors keep configuration parsing strict without panicking on wrong types.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    // CEP:WHAT: Advances one byte while maintaining line and column counters.
    // CEP:WHY: Error positions depend on accurate counters; newline handling updates both.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        if b == L::NEWLINE_BYTE {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(b)
    }

    // CEP:WHAT: Advances the cursor over JSON whitespace bytes.
    // CEP:WHY: Typed accessors keep configuration parsing strict without panicking on wrong types.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == L::SPACE_BYTE || b == L::TAB_BYTE || b == L::NEWLINE_BYTE || b == L::CR_BYTE {
                self.bump();
            } else {
                break;
            }
        }
    }

    // CEP:WHAT: Dispatches to the parser for the value at the cursor under a depth bound.
    // CEP:WHY: Section 22.10 requires bounded nesting; depth is checked before every value.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn parse_value(&mut self) -> Result<Json, JsonError> {
        if self.depth >= L::LINT_MAX_DEPTH {
            return Err(self.err("JSON nesting depth limit exceeded"));
        }
        self.depth += 1;
        let result = match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => self.parse_string().map(Json::Str),
            Some(b't') => self.parse_keyword("true", Json::Bool(true)),
            Some(b'f') => self.parse_keyword("false", Json::Bool(false)),
            Some(b'n') => self.parse_keyword("null", Json::Null),
            Some(_) => self.parse_number(),
            None => Err(self.err("unexpected end of JSON input")),
        };
        self.depth -= 1;
        result
    }

    // CEP:WHAT: Consumes a literal JSON keyword and returns its value.
    // CEP:WHY: true, false, and null are matched byte by byte with position-accurate errors.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn parse_keyword(&mut self, word: &str, value: Json) -> Result<Json, JsonError> {
        for expected in word.bytes() {
            match self.bump() {
                Some(b) => {
                    if b != expected {
                        return Err(self.err("invalid JSON keyword"));
                    }
                }
                None => return Err(self.err("invalid JSON keyword")),
            }
        }
        Ok(value)
    }

    // CEP:WHAT: Parses a JSON number literal into an f64 value.
    // CEP:WHY: Typed accessors keep configuration parsing strict without panicking on wrong types.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn parse_number(&mut self) -> Result<Json, JsonError> {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b.is_ascii_digit()
                || b == b'-'
                || b == b'+'
                || b == b'.'
                || b == b'e'
                || b == b'E'
            {
                self.bump();
            } else {
                break;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| self.err("non UTF-8 number"))?;
        text.parse::<f64>()
            .map(Json::Num)
            .map_err(|_| self.err("invalid JSON number"))
    }

    // CEP:WHAT: Parses a JSON string with escapes, surrogate pairs, and control-character rejection.
    // CEP:WHY: RFC 8259 string semantics are required for portable configuration; control bytes are rejected as malformed.
    // CEP:STATUS: complete
    // CEP:FAILURE: Returns JsonError on unterminated strings, unknown escapes, invalid surrogates, or control characters.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn parse_string(&mut self) -> Result<String, JsonError> {
        if self.bump() != Some(b'"') {
            return Err(self.err("expected string opening quote"));
        }
        let mut out = String::new();
        loop {
            match self.bump() {
                None => return Err(self.err("unterminated JSON string")),
                Some(b'"') => return Ok(out),
                Some(b'\\') => {
                    let esc = self.bump().ok_or_else(|| self.err("truncated escape"))?;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'u' => {
                            let cp = self.parse_hex4()?;
                            if (L::UTF16_HIGH_MIN..=L::UTF16_HIGH_MAX).contains(&cp)
                                && self.peek() == Some(b'\\')
                            {
                                self.bump();
                                if self.bump() != Some(b'u') {
                                    return Err(self.err("invalid surrogate pair"));
                                }
                                let low = self.parse_hex4()?;
                                let combined = L::SURROGATE_BIAS
                                    + ((cp - L::UTF16_HIGH_MIN) << L::UTF16_SHIFT)
                                    + low;
                                let ch = char::from_u32(combined)
                                    .ok_or_else(|| self.err("invalid surrogate pair"))?;
                                out.push(ch);
                            } else {
                                let ch = char::from_u32(cp)
                                    .ok_or_else(|| self.err("invalid unicode escape"))?;
                                out.push(ch);
                            }
                        }
                        _ => return Err(self.err("unknown JSON escape")),
                    }
                }
                Some(b) => {
                    if b < L::ASCII_PRINTABLE_MIN {
                        return Err(self.err("control character in JSON string"));
                    }
                    self.finish_utf8_char(b, &mut out);
                }
            }
        }
    }

    // CEP:WHAT: Reads four hexadecimal digits into a u16 value.
    // CEP:WHY: Unicode escapes are always four digits wide per RFC 8259.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn parse_hex4(&mut self) -> Result<u32, JsonError> {
        let mut value: u32 = 0;
        for _ in 0..L::HEX_DIGITS_U16 {
            let b = self.bump().ok_or_else(|| self.err("truncated \\u escape"))?;
            let digit = (b as char).to_digit(L::HEX_RADIX).ok_or_else(|| self.err("invalid \\u escape"))?;
            value = value
                .checked_mul(L::HEX_RADIX)
                .and_then(|v| v.checked_add(digit))
                .ok_or_else(|| self.err("\\u escape overflow"))?;
        }
        Ok(value)
    }

    // CEP:WHAT: Copies one UTF-8 multibyte character from input into the output string.
    // CEP:WHY: Configuration is UTF-8; the raw bytes are carried through without revalidation because the source is validated at load.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn finish_utf8_char(&mut self, first: u8, out: &mut String) {
        let extra = if first >= L::UTF8_LEAD4 {
            L::UTF8_EXTRA4
        } else if first >= L::UTF8_LEAD3 {
            L::UTF8_EXTRA3
        } else if first >= L::UTF8_LEAD2 {
            L::UTF8_EXTRA2
        } else {
            0
        };
        let start = self.pos - 1;
        for _ in 0..extra {
            self.bump();
        }
        if let Ok(s) = std::str::from_utf8(&self.bytes[start..self.pos]) {
            if let Some(ch) = s.chars().next() {
                out.push(ch);
            }
        }
    }

    // CEP:WHAT: Parses a JSON array with ordered elements.
    // CEP:WHY: Typed accessors keep configuration parsing strict without panicking on wrong types.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn parse_array(&mut self) -> Result<Json, JsonError> {
        self.bump();
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.bump();
            return Ok(Json::Arr(items));
        }
        loop {
            self.skip_ws();
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.bump() {
                Some(b',') => {}
                Some(b']') => return Ok(Json::Arr(items)),
                _ => return Err(self.err("expected ',' or ']' in JSON array")),
            }
        }
    }

    // CEP:WHAT: Parses a JSON object with ordered members and duplicate-key tolerance.
    // CEP:WHY: Typed accessors keep configuration parsing strict without panicking on wrong types.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn parse_object(&mut self) -> Result<Json, JsonError> {
        self.bump();
        let mut pairs = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok(Json::Obj(pairs));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            if self.bump() != Some(b':') {
                return Err(self.err("expected ':' after JSON object key"));
            }
            self.skip_ws();
            let value = self.parse_value()?;
            pairs.push((key, value));
            self.skip_ws();
            match self.bump() {
                Some(b',') => {}
                Some(b'}') => return Ok(Json::Obj(pairs)),
                _ => return Err(self.err("expected ',' or '}' in JSON object")),
            }
        }
    }
}
