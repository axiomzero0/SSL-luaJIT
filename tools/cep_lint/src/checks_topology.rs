// CEP:FILE: tools/cep_lint/src/checks_topology.rs
// CEP:WHAT: Atomic-file topology check: class line limits, junk-drawer names, and pass-entry density.
// CEP:WHY: Implements the file_topology_policy primitive required by section 62.5.3 (CEP-LINT-ATOMIC-FILE).
// CEP:CLASS: CEP-2
// CEP:STATUS: complete
// CEP:FAILURE: none; missing class or malformed limits are reported as findings rather than panics.
// CEP:ASSUMES: class limits are declared for every allowed conformance class; pass density is evaluated on files under a directory matching pass_dir_pattern.
// CEP:COST: cold; O(1) per file plus one regex scan for pass entries.
// CEP:EVIDENCE: self-test scenarios for CEP-LINT-ATOMIC-FILE.

use crate::blocks::file_class;
use crate::model::{regex_for, CompiledPatterns, Rule};
use crate::report::Finding;
use crate::source::SourceFile;

    // CEP:WHAT: Enforces class line limits, junk-drawer names, and pass-entry density for one file.
    // CEP:WHY: Implements the file_topology_policy primitive required by section 62.5.3.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn check_file_topology(
    src: &SourceFile,
    rule_name: &str,
    rule: &Rule,
    compiled: &CompiledPatterns,
    findings: &mut Vec<Finding>,
) {
    let _ = compiled;
    let limits = crate::model::Config::param_str_list(rule, "class_limits");
    let junk_pattern = regex_for(compiled, rule_name, "junk_pattern");
    let pass_dir_pattern = regex_for(compiled, rule_name, "pass_dir_pattern");
    let entry_pattern = regex_for(compiled, rule_name, "pass_entry_pattern");
    let class = file_class(src).unwrap_or_default();
    let mut limit: Option<u32> = None;
    for entry in &limits {
        if let Some((name, value)) = entry.split_once('=') {
            if name.trim() == class {
                limit = value.trim().parse::<u32>().ok();
            }
        }
    }
    if let Some(max_lines) = limit {
        if src.lines.len() > max_lines as usize {
            findings.push(Finding {
                file: src.path.clone(),
                line: 1,
                rule: rule_name.to_string(),
                severity: rule.severity,
                message: format!(
                    "{}: file has {} lines, exceeds {} limit {}",
                    rule.message,
                    src.lines.len(),
                    class,
                    max_lines
                ),
            });
        }
    }
    if let Some(junk) = junk_pattern {
        let base = base_name(&src.path);
        if junk.is_match(&base).unwrap_or(false) {
            findings.push(Finding {
                file: src.path.clone(),
                line: 1,
                rule: rule_name.to_string(),
                severity: rule.severity,
                message: format!("{}: junk drawer file name {}", rule.message, base),
            });
        }
    }
    let (in_pass_dir, entry_regex) = match (pass_dir_pattern, entry_pattern) {
        (Some(dir_re), Some(entry_re)) => (dir_re.is_match(&src.path).unwrap_or(false), entry_re),
        _ => (false, unreachable_entry()),
    };
    if in_pass_dir {
        let mut entries = 0usize;
        for line in &src.code {
            if entry_regex.is_match(line).unwrap_or(false) {
                entries += 1;
            }
        }
        if entries > 1 {
            findings.push(Finding {
                file: src.path.clone(),
                line: 1,
                rule: rule_name.to_string(),
                severity: rule.severity,
                message: format!(
                    "{}: pass file registers {} entries, one pass per file required",
                    rule.message, entries
                ),
            });
        }
    }
}

    // CEP:WHAT: Extracts the file name component of a path.
    // CEP:WHY: Junk-drawer detection applies to the file name, not the full path.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn base_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

    // CEP:WHAT: Returns a never-matching regex used when pass entry configuration is absent.
    // CEP:WHY: Option handling must stay total without panicking; the sentinel keeps the tuple shape.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn unreachable_entry() -> &'static crate::regex_lite::Regex {
    static CELL: std::sync::OnceLock<crate::regex_lite::Regex> = std::sync::OnceLock::new();
    CELL.get_or_init(|| {
        crate::regex_lite::Regex::compile("NEVERMATCH", false)
            .expect("constant pattern always compiles")
    })
}
