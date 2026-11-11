// CEP:FILE: tools/cep_lint/src/checks_comment.rs
// CEP:WHAT: Comment-schema checks: file headers, status values, stub ownership, comment regex, and string-literal regex.
// CEP:WHY: Implements the check primitives comment_block_schema, comment_regex, and string_literal_regex defined by the rule catalog in section 50.3.
// CEP:CLASS: CEP-2
// CEP:STATUS: complete
// CEP:FAILURE: Invalid configured patterns are rejected during pattern compilation; checks themselves never panic.
// CEP:ASSUMES: block extraction and string inventories were produced by source.rs for the same file.
// CEP:COST: cold; linear in comment lines and string literals.
// CEP:EVIDENCE: self-test scenarios for the file header, status, stub, todo, and placeholder rules.

use crate::blocks::extract_blocks;
use crate::model::{regex_for, CompiledPatterns, Rule};
use crate::report::Finding;
use crate::source::SourceFile;

pub fn check_comment_block_schema(
    src: &SourceFile,
    rule_name: &str,
    rule: &Rule,
    findings: &mut Vec<Finding>,
) {
    match rule.mode.as_deref() {
        Some("file_header") => check_file_header(src, rule_name, rule, findings),
        Some("status_value") => check_status_value(src, rule_name, rule, findings),
        Some("stub_requirements") => check_stub_requirements(src, rule_name, rule, findings),
        _ => {}
    }
}

fn push(
    findings: &mut Vec<Finding>,
    src: &SourceFile,
    line: usize,
    rule_name: &str,
    rule: &Rule,
    detail: String,
) {
    findings.push(Finding {
        file: src.path.clone(),
        line,
        rule: rule_name.to_string(),
        severity: rule.severity,
        message: format!("{}: {}", rule.message, detail),
    });
}

    // CEP:WHAT: Validates that the first comment block is a complete CEP file header with a known class.
    // CEP:WHY: Section 35 requires the header to be the first content with nine fields; missing fields and late or misplaced headers are violations.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn check_file_header(src: &SourceFile, rule_name: &str, rule: &Rule, findings: &mut Vec<Finding>) {
    let max_start = crate::model::Config::param_u32(rule, "max_start_line", crate::limits::DEFAULT_MAX_START_LINE);
    let required = crate::model::Config::param_str_list(rule, "required_fields");
    let allowed_classes = crate::model::Config::param_str_list(rule, "allowed_classes");
    let blocks = extract_blocks(src);
    let first = match blocks.first() {
        Some(block) => block,
        None => {
            push(findings, src, 1, rule_name, rule, "no comment block found".to_string());
            return;
        }
    };
    if first.start_line != 1 {
        push(
            findings,
            src,
            1,
            rule_name,
            rule,
            "file header must be the first content of the file".to_string(),
        );
        return;
    }
    if first.start_line > max_start as usize {
        push(findings, src, first.start_line, rule_name, rule, "header starts too late".to_string());
    }
    for field in &required {
        if !first.has_field(field) {
            push(
                findings,
                src,
                first.start_line,
                rule_name,
                rule,
                format!("header missing field {}", field),
            );
        }
    }
    if let Some(class) = first.field_value("CLASS") {
        if !allowed_classes.iter().any(|c| c == class) {
            push(findings, src, first.start_line, rule_name, rule, format!("unknown class {}", class));
        }
    }
}

    // CEP:WHAT: Flags CEP:STATUS values outside the configured allowed set.
    // CEP:WHY: Section 10.5 restricts status to complete, partial, stub, and placeholder.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn check_status_value(src: &SourceFile, rule_name: &str, rule: &Rule, findings: &mut Vec<Finding>) {
    let allowed = crate::model::Config::param_str_list(rule, "allowed_values");
    for (line, text) in &src.comment_lines {
        if let Some(value) = parse_status_line(text) {
            if !allowed.iter().any(|a| a == &value) {
                push(findings, src, *line, rule_name, rule, format!("invalid status {}", value));
            }
        }
    }
}

    // CEP:WHAT: Extracts the status value from a CEP:STATUS comment line.
    // CEP:WHY: Status scanning works per line so stale or repeated status lines are all visible to the check.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn parse_status_line(text: &str) -> Option<String> {
    let idx = text.find("CEP:STATUS")?;
    let rest = &text[idx + "CEP:STATUS".len()..];
    let rest = rest.strip_prefix(':')?;
    Some(rest.trim().to_string())
}

    // CEP:WHAT: Requires ownership fields in blocks that declare stub, partial, or placeholder status.
    // CEP:WHY: Section 10.10 bans anonymous stubs; OWNER and TICKET must sit in the same block as the status.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn check_stub_requirements(src: &SourceFile, rule_name: &str, rule: &Rule, findings: &mut Vec<Finding>) {
    let statuses = crate::model::Config::param_str_list(rule, "statuses");
    let required = crate::model::Config::param_str_list(rule, "required_fields");
    let blocks = extract_blocks(src);
    for block in &blocks {
        let status = match block.declared_status() {
            Some(status) => status,
            None => continue,
        };
        if !statuses.iter().any(|s| s == status) {
            continue;
        }
        for field in &required {
            if !block.has_field(field) {
                push(
                    findings,
                    src,
                    block.start_line,
                    rule_name,
                    rule,
                    format!("status {} requires field {}", status, field),
                );
            }
        }
    }
}

    // CEP:WHAT: Runs the configured pattern over comment lines with an optional suppression pattern.
    // CEP:WHY: Implements the line-scoped comment_regex primitive used by the work marker and placeholder comment rules.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn check_comment_regex(
    src: &SourceFile,
    rule_name: &str,
    rule: &Rule,
    compiled: &CompiledPatterns,
    findings: &mut Vec<Finding>,
) {
    let regex = match regex_for(compiled, rule_name, "pattern") {
        Some(regex) => regex,
        None => return,
    };
    let suppression = regex_for(compiled, rule_name, "suppression_pattern");
    for (line, text) in &src.comment_lines {
        if let Some(sup) = suppression {
            if sup.is_match(text).unwrap_or(false) {
                continue;
            }
        }
        if regex.is_match(text).unwrap_or(false) {
            push(findings, src, *line, rule_name, rule, "violating comment content".to_string());
        }
    }
}

    // CEP:WHAT: Runs the configured pattern over string literal contents.
    // CEP:WHY: Implements the string_literal_regex primitive; placeholders must fail loudly instead of leaking into runtime strings.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn check_string_literal_regex(
    src: &SourceFile,
    rule_name: &str,
    rule: &Rule,
    compiled: &CompiledPatterns,
    findings: &mut Vec<Finding>,
) {
    let regex = match regex_for(compiled, rule_name, "pattern") {
        Some(regex) => regex,
        None => return,
    };
    for lit in &src.strings {
        if lit.is_char {
            continue;
        }
        if regex.is_match(&lit.content).unwrap_or(false) {
            push(findings, src, lit.line, rule_name, rule, "violating string literal".to_string());
        }
    }
}
