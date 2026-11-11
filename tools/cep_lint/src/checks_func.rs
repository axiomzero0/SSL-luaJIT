// CEP:FILE: tools/cep_lint/src/checks_func.rs
// CEP:WHAT: Function-level checks: CEP block requirement, empty-body stubs, snake_case naming, and constant-return detection.
// CEP:WHY: Implements the function_policy primitive in block, stub body, naming, and constant return modes per the rule catalog in section 50.3.
// CEP:CLASS: CEP-2
// CEP:STATUS: complete
// CEP:FAILURE: Invalid configured patterns are rejected during pattern compilation; extraction never panics on matched-free input.
// CEP:ASSUMES: brace matching on comment-and-string-blanked code text reflects Rust block structure for the repository dialect; trait declarations without bodies are skipped by the semicolon rule.
// CEP:COST: cold; O(N) brace scan per function, O(F) over functions.
// CEP:EVIDENCE: self-test scenarios for the function block, stub body, naming, and constant return rules.

use crate::blocks::extract_blocks;
use crate::model::{regex_for, CompiledPatterns, Rule};
use crate::report::Finding;
use crate::limits as L;
use crate::source::SourceFile;

pub struct FnDef {
    pub line: usize,
    pub name: String,
    pub body_open: usize,
    pub body_close: usize,
    pub statements: u32,
}

    // CEP:WHAT: Finds Rust function definitions with captured names and brace-matched bodies.
    // CEP:WHY: All four function_policy modes share one extractor so block, stub, naming, and constant-return checks stay consistent.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn find_functions(src: &SourceFile, rule_name: &str, compiled: &CompiledPatterns) -> Vec<FnDef> {
    let def_regex = match regex_for(compiled, rule_name, "fn_def_pattern") {
        Some(regex) => regex,
        None => return Vec::new(),
    };
    let mut defs = Vec::new();
    for idx in 0..src.code.len() {
        let hits = match def_regex.find_iter(&src.code[idx]) {
            Ok(hits) => hits,
            Err(_) => continue,
        };
        let caps = match hits.first() {
            Some(hit) => hit.caps.clone(),
            None => continue,
        };
        let name = caps.first().cloned().flatten().unwrap_or_default();
        let span = match body_span(&src.code, idx) {
            Some(span) => span,
            None => continue,
        };
        let statements = count_statements(&src.code[span.0..=span.1]);
        defs.push(FnDef {
            line: idx + 1,
            name,
            body_open: span.0 + 1,
            body_close: span.1 + 1,
            statements,
        });
    }
    defs
}

    // CEP:WHAT: Locates the brace-matched body of a function and rejects declarations without bodies.
    // CEP:WHY: Trait declarations end with a semicolon before any brace and must not be treated as definitions.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn body_span(code: &[String], start: usize) -> Option<(usize, usize)> {
    let mut open = None;
    let mut depth = 0i64;
    for idx in start..code.len() {
        for c in code[idx].chars() {
            match c {
                '{' => {
                    if open.is_none() {
                        open = Some(idx);
                    }
                    depth += 1;
                }
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return open.map(|o| (o, idx));
                    }
                }
                ';' => {
                    if open.is_none() {
                        return None;
                    }
                }
                _ => {}
            }
        }
    }
    None
}

    // CEP:WHAT: Counts top-level statements in a function body using semicolons, block keywords, and a trailing expression.
    // CEP:WHY: The catalog approximates nontrivial functions as two or more statements; block keywords count once each.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn count_statements(lines: &[String]) -> u32 {
    let interior = &lines[1..lines.len().saturating_sub(1)];
    let joined: String = interior.join("\n");
    let chars: Vec<char> = joined.chars().collect();
    let mut depth = 0i64;
    let mut statements = 0u32;
    let mut trailing = false;
    for idx in 0..chars.len() {
        let c = chars[idx];
        if c == '{' {
            depth += 1;
            if depth == 1 && preceding_word_is_block_keyword(&chars, idx) {
                statements += 1;
            }
            trailing = false;
            continue;
        }
        if c == '}' {
            depth = depth.saturating_sub(1);
            trailing = true;
            continue;
        }
        if depth == 0 {
            if c == ';' {
                statements += 1;
                trailing = false;
                continue;
            }
            if !c.is_whitespace() {
                trailing = true;
            }
        }
    }
    if trailing {
        statements += 1;
    }
    statements
}

    // CEP:WHAT: Reports whether the identifier immediately before a brace is a control-flow keyword.
    // CEP:WHY: Statement counting must classify if, match, for, while, loop, and unsafe blocks without comment noise.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn preceding_word_is_block_keyword(chars: &[char], brace_idx: usize) -> bool {
    let mut end = brace_idx;
    while end > 0 && !chars[end - 1].is_alphabetic() && chars[end - 1] != '_' {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && (chars[start - 1].is_alphabetic() || chars[start - 1] == '_') {
        start -= 1;
    }
    if start == end {
        return false;
    }
    let word: String = chars[start..end].iter().collect();
    matches!(word.as_str(), "if" | "match" | "for" | "while" | "loop" | "unsafe")
}

    // CEP:WHAT: Dispatches function_policy to the mode named by configuration.
    // CEP:WHY: One primitive serves four catalog rules; the mode selects the check body.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn check_function_policy(
    src: &SourceFile,
    rule_name: &str,
    rule: &Rule,
    compiled: &CompiledPatterns,
    findings: &mut Vec<Finding>,
) {
    let mode = rule.mode.as_deref().unwrap_or("block");
    let defs = find_functions(src, rule_name, compiled);
    match mode {
        "block" => check_block_mode(src, rule_name, rule, compiled, &defs, findings),
        "stub_body" => check_stub_body_mode(src, rule_name, rule, compiled, &defs, findings),
        "naming" => check_naming_mode(src, rule_name, rule, compiled, &defs, findings),
        "constant_return" => check_constant_return(src, rule_name, rule, compiled, &defs, findings),
        _ => {}
    }
}

fn push(findings: &mut Vec<Finding>, src: &SourceFile, line: usize, rule_name: &str, rule: &Rule, detail: String) {
    findings.push(Finding {
        file: src.path.clone(),
        line,
        rule: rule_name.to_string(),
        severity: rule.severity,
        message: format!("{}: {}", rule.message, detail),
    });
}

    // CEP:WHAT: Returns the nearest comment block above a function when only sanctioned gap lines separate them.
    // CEP:WHY: Section 50.3 allows attributes and qualifiers between block and definition; any other content breaks adjacency.
    // CEP:STATUS: complete
    // CEP:FAILURE: Returns None when no qualifying block exists; callers raise the finding.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn block_above(
    src: &SourceFile,
    fn_line: usize,
    gap_regex: &crate::regex_lite::Regex,
) -> Option<crate::blocks::CommentBlock> {
    let blocks = extract_blocks(src);
    let mut candidate: Option<crate::blocks::CommentBlock> = None;
    for block in &blocks {
        if block.end_line < fn_line {
            candidate = Some(block.clone());
        }
    }
    let block = candidate?;
    for line_idx in block.end_line..fn_line.saturating_sub(1) {
        let text = src.lines.get(line_idx)?.trim().to_string();
        if text.is_empty() {
            continue;
        }
        if !gap_regex.is_match(&text).unwrap_or(false) {
            return None;
        }
    }
    Some(block)
}

    // CEP:WHAT: Requires complete CEP blocks above nontrivial functions.
    // CEP:WHY: Implements CEP-LINT-FUNC-BLOCK with the configured field list and statement threshold.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn check_block_mode(
    src: &SourceFile,
    rule_name: &str,
    rule: &Rule,
    compiled: &CompiledPatterns,
    defs: &[FnDef],
    findings: &mut Vec<Finding>,
) {
    let min_statements = crate::model::Config::param_u32(rule, "min_body_statements", L::DEFAULT_MIN_BODY_STATEMENTS);
    let required = crate::model::Config::param_str_list(rule, "required_fields");
    let gap_regex = match regex_for(compiled, rule_name, "gap_pattern") {
        Some(regex) => regex,
        None => return,
    };
    for def in defs {
        if def.statements < min_statements {
            continue;
        }
        let block = match block_above(src, def.line, gap_regex) {
            Some(block) => block,
            None => {
                push(
                    findings,
                    src,
                    def.line,
                    rule_name,
                    rule,
                    format!("function {} lacks an adjacent CEP block", def.name),
                );
                continue;
            }
        };
        for field in &required {
            if !block.has_field(field) {
                push(
                    findings,
                    src,
                    def.line,
                    rule_name,
                    rule,
                    format!("function {} block missing field {}", def.name, field),
                );
            }
        }
    }
}

    // CEP:WHAT: Flags empty function bodies unless the adjacent block declares a suppressed status.
    // CEP:WHY: Implements CEP-LINT-STUB-BODY; empty special members should use default or delete forms in C++ and explicit statuses here.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn check_stub_body_mode(
    src: &SourceFile,
    rule_name: &str,
    rule: &Rule,
    compiled: &CompiledPatterns,
    defs: &[FnDef],
    findings: &mut Vec<Finding>,
) {
    let suppress = crate::model::Config::param_str_list(rule, "suppress_statuses");
    let gap_regex = match regex_for(compiled, rule_name, "gap_pattern") {
        Some(regex) => regex,
        None => return,
    };
    for def in defs {
        let interior: Vec<&String> = src
            .code
            .iter()
            .skip(def.body_open - 1)
            .take(def.body_close - def.body_open + 1)
            .collect();
        let blank = interior.iter().all(|l| l.trim().is_empty());
        if !blank {
            continue;
        }
        let declared = block_above(src, def.line, gap_regex)
            .and_then(|block| block.declared_status().map(|s| s.to_string()));
        let suppressed = declared
            .as_ref()
            .map(|status| suppress.iter().any(|s| s == status))
            .unwrap_or(false);
        if !suppressed {
            push(
                findings,
                src,
                def.line,
                rule_name,
                rule,
                format!("function {} has an empty body", def.name),
            );
        }
    }
}

    // CEP:WHAT: Flags function names that violate the configured snake_case pattern.
    // CEP:WHY: Implements CEP-LINT-NAMING-FUNC per section 33.13.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn check_naming_mode(
    src: &SourceFile,
    rule_name: &str,
    rule: &Rule,
    compiled: &CompiledPatterns,
    defs: &[FnDef],
    findings: &mut Vec<Finding>,
) {
    let name_regex = match regex_for(compiled, rule_name, "name_pattern") {
        Some(regex) => regex,
        None => return,
    };
    for def in defs {
        if def.name.is_empty() || !name_regex.is_match(&def.name).unwrap_or(false) {
            push(
                findings,
                src,
                def.line,
                rule_name,
                rule,
                format!("function name {} violates naming", def.name),
            );
        }
    }
}

    // CEP:WHAT: Flags single-statement bodies that return a constant.
    // CEP:WHY: Implements CEP-LINT-CONSTANT-RETURN; results must be computed from inputs.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn check_constant_return(
    src: &SourceFile,
    rule_name: &str,
    rule: &Rule,
    compiled: &CompiledPatterns,
    defs: &[FnDef],
    findings: &mut Vec<Finding>,
) {
    let pattern = match regex_for(compiled, rule_name, "pattern") {
        Some(regex) => regex,
        None => return,
    };
    for def in defs {
        if def.statements > 1 {
            continue;
        }
        let interior: String = src.code[def.body_open..def.body_close.saturating_sub(1)]
            .join("\n")
            .trim()
            .to_string();
        if pattern.is_match(&interior).unwrap_or(false) {
            push(
                findings,
                src,
                def.line,
                rule_name,
                rule,
                "body is a single constant return".to_string(),
            );
        }
    }
}
