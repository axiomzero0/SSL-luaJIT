// CEP:FILE: tools/cep_lint/src/engine.rs
// CEP:WHAT: Check dispatcher: routes each configured rule to its check primitive for one source file.
// CEP:WHY: Section 50.3 keeps mechanism in the engine and policy in the configuration; the dispatcher is the only place that maps check names to implementations.
// CEP:CLASS: CEP-2
// CEP:STATUS: complete
// CEP:FAILURE: Unknown check names are rejected at configuration load, so the dispatcher always finds a branch.
// CEP:ASSUMES: compiled patterns match the rules being dispatched.
// CEP:COST: cold; dispatch overhead is O(1) per rule.
// CEP:EVIDENCE: self-test scenarios exercise every configured rule through this dispatcher.

use crate::checks_code;
use crate::checks_comment;
use crate::checks_func;
use crate::checks_topology;
use crate::model::{CompiledPatterns, Config, Rule};
use crate::report::Finding;
use crate::source::SourceFile;

pub fn run_file(
    src: &SourceFile,
    config: &Config,
    compiled: &CompiledPatterns,
    findings: &mut Vec<Finding>,
) {
    for (name, rule) in &config.rules {
        dispatch_rule(src, name, rule, compiled, findings);
    }
}

fn dispatch_rule(
    src: &SourceFile,
    name: &str,
    rule: &Rule,
    compiled: &CompiledPatterns,
    findings: &mut Vec<Finding>,
) {
    match rule.check.as_str() {
        "comment_block_schema" => {
            checks_comment::check_comment_block_schema(src, name, rule, findings)
        }
        "comment_regex" => {
            checks_comment::check_comment_regex(src, name, rule, compiled, findings)
        }
        "string_literal_regex" => {
            checks_comment::check_string_literal_regex(src, name, rule, compiled, findings)
        }
        "function_policy" => {
            checks_func::check_function_policy(src, name, rule, compiled, findings)
        }
        "numeric_literal_policy" => {
            checks_code::check_numeric_literals(src, name, rule, compiled, findings)
        }
        "macro_prefix_policy" => {
            checks_code::check_macro_prefix(src, name, rule, compiled, findings)
        }
        "banned_token_policy" => {
            checks_code::check_banned_tokens(src, name, rule, compiled, findings)
        }
        "flat_code_regex" => {
            checks_code::check_flat_code_regex(src, name, rule, compiled, findings)
        }
        "file_topology_policy" => {
            checks_topology::check_file_topology(src, name, rule, compiled, findings)
        }
        "doc_rule_coverage" => {}
        _ => {}
    }
}
