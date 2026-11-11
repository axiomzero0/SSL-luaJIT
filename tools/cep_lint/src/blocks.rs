// CEP:FILE: tools/cep_lint/src/blocks.rs
// CEP:WHAT: Comment block inventory: contiguous comment-line runs, CEP field extraction, and file-class resolution shared by several checks.
// CEP:WHY: File headers, function blocks, and stub declarations are all contiguous comment blocks with CEP:FIELD content; one parser keeps schema semantics identical across checks.
// CEP:CLASS: CEP-2
// CEP:STATUS: complete
// CEP:FAILURE: none; pure extraction.
// CEP:ASSUMES: CEP fields are written as `// CEP:FIELD: value` on single lines; multiline field values are not supported (50.5 known limits).
// CEP:COST: cold; O(C) over comment lines.
// CEP:EVIDENCE: unit test cep_lint::blocks in tools/cep_lint/tests/unit_blocks.rs.

use crate::source::SourceFile;

#[derive(Debug, Clone)]
pub struct CommentBlock {
    pub start_line: usize,
    pub end_line: usize,
    pub fields: Vec<(String, String)>,
    pub lines: Vec<String>,
}

    // CEP:WHAT: Groups contiguous comment lines into blocks and attaches parsed CEP fields to each block.
    // CEP:WHY: File headers, function blocks, and stub declarations are all contiguous runs; one extractor keeps schema semantics consistent across checks.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn extract_blocks(src: &SourceFile) -> Vec<CommentBlock> {
    let mut blocks = Vec::new();
    let mut current: Option<CommentBlock> = None;
    let mut entries = src.comment_lines.iter().peekable();
    while let Some((line, text)) = entries.next() {
        let is_first = current.is_none();
        let contiguous = match &current {
            None => false,
            Some(block) => block.end_line + 1 == *line,
        };
        if !contiguous {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            current = Some(CommentBlock {
                start_line: *line,
                end_line: *line,
                fields: Vec::new(),
                lines: Vec::new(),
            });
        }
        let _ = is_first;
        let block = current.as_mut().expect("block initialized above");
        block.end_line = *line;
        block.lines.push(text.trim().to_string());
        if let Some((field, value)) = parse_field(text) {
            block.fields.push((field, value));
        }
    }
    if let Some(block) = current.take() {
        blocks.push(block);
    }
    blocks
}

    // CEP:WHAT: Parses one comment line into a CEP field name and value when it carries the CEP: prefix.
    // CEP:WHY: Non-CEP prose must never yield a field; the prefix requirement prevents colon prose from being misread.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn parse_field(text: &str) -> Option<(String, String)> {
    let trimmed = text.trim();
    let body = trimmed.strip_prefix("//").unwrap_or(trimmed).trim();
    let body = body.strip_prefix('*').unwrap_or(body).trim();
    let body = body.strip_prefix("CEP:")?;
    let (field, value) = body.split_once(':')?;
    let field = field.trim().to_string();
    let value = value.trim().to_string();
    if field.is_empty() {
        return None;
    }
    Some((field, value))
}

impl CommentBlock {
    pub fn has_field(&self, name: &str) -> bool {
        self.fields.iter().any(|(f, _)| f == name)
    }

    pub fn field_value(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(f, _)| f == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn declared_status(&self) -> Option<&str> {
        self.field_value("STATUS")
    }
}

    // CEP:WHAT: Returns the CEP:CLASS value declared in the first comment block of a file.
    // CEP:WHY: Class-based rules such as banned tokens and topology limits need the declared conformance class.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn file_class(src: &SourceFile) -> Option<String> {
    let blocks = extract_blocks(src);
    let first = blocks.first()?;
    first.field_value("CLASS").map(|s| s.to_string())
}
