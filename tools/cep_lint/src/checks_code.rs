// CEP:FILE: tools/cep_lint/src/checks_code.rs
// CEP:WHAT: Code-content checks: numeric literal policy, macro name prefix, banned hot-path tokens, and flat code regex.
// CEP:WHY: Implements the numeric_literal_policy, macro_prefix_policy, banned_token_policy, and flat_code_regex primitives per the rule catalog in section 50.3.
// CEP:CLASS: CEP-2
// CEP:STATUS: complete
// CEP:FAILURE: Invalid configured patterns are rejected during pattern compilation; checks never panic.
// CEP:ASSUMES: code lines are comment-and-string blanked; statement extraction is bounded to twelve lines per the catalog limit note.
// CEP:COST: cold; linear in code bytes with bounded statement windows.
// CEP:EVIDENCE: self-test scenarios for the magic number, macro prefix, hot banned, empty branch, naming type, and constant return rules.

use crate::blocks::file_class;
use crate::model::{regex_for, CompiledPatterns, Rule};
use crate::report::Finding;
use crate::source::SourceFile;
use crate::limits as L;

    // CEP:WHAT: Flags numeric literals outside the allowed values and sanctioned statement contexts.
    // CEP:WHY: Law 7 and section 11.3 ban magic numbers; the statement window and exempt contexts come from configuration.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn check_numeric_literals(
    src: &SourceFile,
    rule_name: &str,
    rule: &Rule,
    compiled: &CompiledPatterns,
    findings: &mut Vec<Finding>,
) {
    let literal_regex = match regex_for(compiled, rule_name, "literal_pattern") {
        Some(regex) => regex,
        None => return,
    };
    let allowed = crate::model::Config::param_str_list(rule, "allowed_values");
    let contexts = crate::model::Config::param_str_list(rule, "exempt_contexts");
    let mut compiled_contexts = Vec::new();
    for text in &contexts {
        if let Ok(regex) = crate::regex_lite::Regex::compile(text, false) {
            compiled_contexts.push(regex);
        }
    }
    for (idx, line) in src.code.iter().enumerate() {
        let hits = match literal_regex.find_iter(line) {
            Ok(hits) => hits,
            Err(_) => continue,
        };
        for hit in hits {
            if let Some(text) = literal_text(line, hit.start) {
                if allowed.iter().any(|a| numeric_equal(a, &text)) {
                    continue;
                }
            }
            let statement = statement_context(&src.code, idx);
            if compiled_contexts.iter().any(|re| re.is_match(&statement).unwrap_or(false)) {
                continue;
            }
            findings.push(Finding {
                file: src.path.clone(),
                line: idx + 1,
                rule: rule_name.to_string(),
                severity: rule.severity,
                message: format!("{}: magic number {}", rule.message, literal_text(line, hit.start).unwrap_or_default()),
            });
        }
    }
}

    // CEP:WHAT: Extends a numeric literal match to its full text including hex prefix, underscores, and one decimal point.
    // CEP:WHY: Value comparison is numeric, so 0x10 and 16 must resolve to the same literal text for allowed-value checks.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn literal_text(line: &str, start: usize) -> Option<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut end = start;
    let mut seen_digit = false;
    let mut seen_dot = false;
    while end < chars.len() {
        let c = chars[end];
        if c.is_ascii_alphanumeric() || c == '_' || (c == '.' && seen_digit && !seen_dot) {
            if c.is_ascii_digit() || c.is_ascii_hexdigit() {
                seen_digit = true;
            }
            if c == '.' {
                seen_dot = true;
            }
            end += 1;
        } else {
            break;
        }
    }
    if !seen_digit {
        return None;
    }
    Some(chars[start..end].iter().collect())
}

    // CEP:WHAT: Compares a configured allowed value with a literal numerically across decimal and hexadecimal forms.
    // CEP:WHY: The catalog requires value comparison, so 0x0 equals 0 and underscore separators are ignored.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn numeric_equal(configured: &str, literal: &str) -> bool {
    let clean = |s: &str| -> Option<f64> {
        let stripped = s.trim().replace('_', "");
        if stripped.starts_with("0x") || stripped.starts_with("0X") {
            u64::from_str_radix(&stripped[L::HEX_PREFIX_SKIP..], L::HEX_RADIX).ok().map(|v| v as f64)
        } else {
            stripped.parse::<f64>().ok()
        }
    };
    match (clean(configured), clean(literal)) {
        (Some(a), Some(b)) => (a - b).abs() < f64::EPSILON,
        _ => false,
    }
}

    // CEP:WHAT: Joins the lines forming the statement that contains a literal, bounded to the catalog window.
    // CEP:WHY: Sanctioned forms such as const declarations are detected on the joined statement, not the bare line.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn statement_context(code: &[String], literal_line: usize) -> String {
    let mut lo = literal_line;
    let mut hi = literal_line;
    let limit = literal_line.saturating_sub(L::STATEMENT_MAX_LINES);
    while lo > limit && !ends_statement(&code[lo - 1]) {
        lo -= 1;
    }
    let top = code.len().saturating_sub(1);
    while hi < top && hi - literal_line < L::STATEMENT_MAX_LINES && !ends_statement(&code[hi]) {
        hi += 1;
    }
    code[lo..=hi]
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<&str>>()
        .join(" ")
}

    // CEP:WHAT: Reports whether a code line terminates a statement by punctuation or emptiness.
    // CEP:WHY: The statement window walk uses terminators to stop extending in both directions.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn ends_statement(line: &str) -> bool {
    let trimmed = line.trim_end();
    trimmed.ends_with(';')
        || trimmed.ends_with('{')
        || trimmed.ends_with('}')
        || trimmed.ends_with("=>")
        || trimmed.is_empty()
}

    // CEP:WHAT: Flags macro definitions whose names violate the configured prefix and guard patterns.
    // CEP:WHY: Section 33.16 requires CEP_ naming; in Rust, macro_rules! definitions are the object-like macro analog.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn check_macro_prefix(
    src: &SourceFile,
    rule_name: &str,
    rule: &Rule,
    compiled: &CompiledPatterns,
    findings: &mut Vec<Finding>,
) {
    let def_regex = match regex_for(compiled, rule_name, "def_pattern") {
        Some(regex) => regex,
        None => return,
    };
    let name_regex = regex_for(compiled, rule_name, "name_pattern");
    let guard_regex = regex_for(compiled, rule_name, "guard_pattern");
    for (idx, line) in src.code.iter().enumerate() {
        let hits = match def_regex.find_iter(line) {
            Ok(hits) => hits,
            Err(_) => continue,
        };
        for hit in hits {
            let name = hit.caps.first().cloned().flatten().unwrap_or_default();
            let ok_name = name_regex
                .map(|re| re.is_match(&name).unwrap_or(false))
                .unwrap_or(false);
            let ok_guard = guard_regex
                .map(|re| re.is_match(&name).unwrap_or(false))
                .unwrap_or(false);
            if !ok_name && !ok_guard {
                findings.push(Finding {
                    file: src.path.clone(),
                    line: idx + 1,
                    rule: rule_name.to_string(),
                    severity: rule.severity,
                    message: format!("{}: macro name {} violates prefix policy", rule.message, name),
                });
            }
        }
    }
}

    // CEP:WHAT: Flags banned tokens in files whose declared class is in the hot-class list.
    // CEP:WHY: Section 5.1 and 25.3 ban allocating and dispatching constructs in CEP-0 hot code; tokens are matched on comment-and-string-blanked code.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn check_banned_tokens(
    src: &SourceFile,
    rule_name: &str,
    rule: &Rule,
    compiled: &CompiledPatterns,
    findings: &mut Vec<Finding>,
) {
    let applies = crate::model::Config::param_str_list(rule, "applies_to_classes");
    let class = file_class(src).unwrap_or_default();
    if !applies.iter().any(|c| c == &class) {
        return;
    }
    let token_regexes: Vec<(String, crate::regex_lite::Regex)> =
        crate::model::Config::param_str_list(rule, "tokens")
            .into_iter()
            .filter_map(|token| {
                crate::regex_lite::Regex::compile(&token, false)
                    .ok()
                    .map(|regex| (token, regex))
            })
            .collect();
    for (idx, line) in src.code.iter().enumerate() {
        for (token, regex) in &token_regexes {
            let hits = match regex.find_iter(line) {
                Ok(hits) => hits,
                Err(_) => continue,
            };
            for _hit in hits {
                findings.push(Finding {
                    file: src.path.clone(),
                    line: idx + 1,
                    rule: rule_name.to_string(),
                    severity: rule.severity,
                    message: format!("{}: banned token {}", rule.message, token),
                });
            }
        }
    }
}

    // CEP:WHAT: Runs a configured pattern over code lines with optional capture-name validation.
    // CEP:WHY: Implements the flat_code_regex primitive used by the empty branch, empty catch, and type naming rules.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn check_flat_code_regex(
    src: &SourceFile,
    rule_name: &str,
    rule: &Rule,
    compiled: &CompiledPatterns,
    findings: &mut Vec<Finding>,
) {
    let pattern = match regex_for(compiled, rule_name, "pattern") {
        Some(regex) => regex,
        None => return,
    };
    let name_pattern = regex_for(compiled, rule_name, "name_pattern");
    let name_group = crate::model::Config::param_u32(rule, "name_group", 1) as usize;
    for (idx, line) in src.code.iter().enumerate() {
        let hits = match pattern.find_iter(line) {
            Ok(hits) => hits,
            Err(_) => continue,
        };
        for hit in hits {
            let mut violation = true;
            if let Some(name_re) = name_pattern {
                let slot = name_group.saturating_sub(1);
                let captured = hit.caps.get(slot).cloned().flatten().unwrap_or_default();
                violation = captured.is_empty() || !name_re.is_match(&captured).unwrap_or(false);
            }
            if violation {
                findings.push(Finding {
                    file: src.path.clone(),
                    line: idx + 1,
                    rule: rule_name.to_string(),
                    severity: rule.severity,
                    message: rule.message.clone(),
                });
            }
        }
    }
}
