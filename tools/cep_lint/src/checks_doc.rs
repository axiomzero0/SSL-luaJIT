// CEP:FILE: tools/cep_lint/src/checks_doc.rs
// CEP:WHAT: DOC-SYNC check: standard document and lint configuration must agree on rule coverage and version.
// CEP:WHY: Implements the doc_rule_coverage primitive (50.3 CEP-LINT-DOC-SYNC); Law 8 makes document drift a mechanical failure in both coverage directions.
// CEP:CLASS: CEP-2
// CEP:STATUS: complete
// CEP:FAILURE: Returns RegexError-equivalent findings when the document is unreadable through the caller; duplicate or missing coverage is reported as findings.
// CEP:ASSUMES: the standard document uses `### Rule NAME` and `### cep_lint Rule: NAME` headings matched by the configured heading_pattern.
// CEP:COST: cold; single pass over the document.
// CEP:EVIDENCE: self-test DOC-SYNC scenarios; live gate over standard.md and .cep/cep_lint.json.

use crate::model::{regex_for, CompiledPatterns, Rule};
use crate::report::Finding;

pub struct DocInfo {
    pub path: String,
    pub text: String,
}

    // CEP:WHAT: Compares rule headings in the standard document with configured rules and validates the version line.
    // CEP:WHY: CEP-LINT-DOC-SYNC enforces Law 8 mechanically in both coverage directions per section 50.3.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn check_doc_sync(
    doc: &DocInfo,
    rule_name: &str,
    rule: &Rule,
    compiled: &CompiledPatterns,
    config_rule_names: &[String],
    standard_version: &str,
    findings: &mut Vec<Finding>,
) {
    let heading_regex = match regex_for(compiled, rule_name, "heading_pattern") {
        Some(regex) => regex,
        None => return,
    };
    let version_regex = match regex_for(compiled, rule_name, "version_pattern") {
        Some(regex) => regex,
        None => return,
    };
    let mut documented: Vec<(String, usize)> = Vec::new();
    for (idx, line) in doc.text.lines().enumerate() {
        let hits = match heading_regex.find_iter(line) {
            Ok(hits) => hits,
            Err(_) => continue,
        };
        for hit in hits {
            if let Some(name) = hit.caps.first().cloned().flatten() {
                documented.push((name, idx + 1));
            }
        }
    }
    let mut seen: Vec<String> = Vec::new();
    for (name, line) in &documented {
        if seen.iter().any(|n| n == name) {
            push_finding(
                findings,
                doc,
                *line,
                rule_name,
                rule,
                format!("duplicate rule heading {}", name),
            );
            continue;
        }
        seen.push(name.clone());
        if !config_rule_names.iter().any(|r| r == name) {
            push_finding(
                findings,
                doc,
                *line,
                rule_name,
                rule,
                format!("documented rule {} missing from configuration", name),
            );
        }
    }
    for name in config_rule_names {
        if !documented.iter().any(|(n, _)| n == name) {
            push_finding(
                findings,
                doc,
                1,
                rule_name,
                rule,
                format!("configured rule {} missing a Rule heading in the document", name),
            );
        }
    }
    let mut version_line: Option<String> = None;
    for line in doc.text.lines() {
        if let Ok(true) = version_regex.is_match(line) {
            if let Ok(hits) = version_regex.find_iter(line) {
                if let Some(hit) = hits.into_iter().next() {
                    if let Some(v) = hit.caps.into_iter().flatten().next() {
                        version_line = Some(v);
                    }
                }
            }
        }
    }
    match version_line {
        Some(version) => {
            if version != standard_version {
                push_finding(
                    findings,
                    doc,
                    1,
                    rule_name,
                    rule,
                    format!(
                        "document version {} does not equal configuration standard.version {}",
                        version, standard_version
                    ),
                );
            }
        }
        None => push_finding(
            findings,
            doc,
            1,
            rule_name,
            rule,
            "document has no Version: line".to_string(),
        ),
    }
}

fn push_finding(findings: &mut Vec<Finding>, doc: &DocInfo, line: usize, rule_name: &str, rule: &Rule, detail: String) {
    findings.push(Finding {
        file: doc.path.clone(),
        line,
        rule: rule_name.to_string(),
        severity: rule.severity,
        message: format!("{}: {}", rule.message, detail),
    });
}
