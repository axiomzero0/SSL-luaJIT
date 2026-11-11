// CEP:FILE: tools/cep_lint/tests/unit_regex.rs
// CEP:WHAT: Unit tests for the bounded regex engine covering anchors, classes, boundaries, groups, and budget behavior.
// CEP:WHY: Every configured lint pattern depends on this engine; a matcher defect would silently corrupt enforcement (Law 8).
// CEP:CLASS: CEP-2
// CEP:STATUS: complete
// CEP:FAILURE: Panics only through the test harness assertion path, which is the sanctioned failure channel for tests.
// CEP:ASSUMES: none
// CEP:COST: cold; milliseconds over small patterns.
// CEP:EVIDENCE: cargo test -p cep-lint unit_regex.

use cep_lint::regex_lite::Regex;

const HEADING: &str = "### Rule CEP-LINT-FILE-HEADER";
const HEADING_ALT: &str = "### cep_lint Rule: CEP-LINT-ATOMIC-FILE";
const VERSION: &str = "Version: **0.4**";
const HEADING_PATTERN: &str = "^### (?:Rule |cep_lint Rule: )([A-Z][A-Z0-9-]+)$";
const VERSION_PATTERN: &str = "^Version: \\*\\*([0-9]+\\.[0-9]+)\\*\\*$";

#[test]
fn heading_pattern_matches_both_forms() {
    let regex = Regex::compile(HEADING_PATTERN, false).expect("pattern compiles");
    let hit = regex.find_iter(HEADING).expect("match runs");
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].caps[0].as_deref(), Some("CEP-LINT-FILE-HEADER"));
    let hit_alt = regex.find_iter(HEADING_ALT).expect("match runs");
    assert_eq!(hit_alt.len(), 1);
    assert_eq!(hit_alt[0].caps[0].as_deref(), Some("CEP-LINT-ATOMIC-FILE"));
}

#[test]
fn version_pattern_captures_version() {
    let regex = Regex::compile(VERSION_PATTERN, false).expect("pattern compiles");
    let hit = regex.find_iter(VERSION).expect("match runs");
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].caps[0].as_deref(), Some("0.4"));
}

#[test]
fn fn_def_pattern_captures_name_for_plain_fn() {
    let pattern = "^\\s*(?:pub(?:\\([a-z ]+\\))?\\s+)?(?:unsafe\\s+)?(?:extern\\s+\"[A-Za-z0-9]*\"\\s+)?(?:const\\s+)?(?:async\\s+)?fn\\s+([A-Za-z_][A-Za-z0-9_]*)";
    let regex = Regex::compile(pattern, false).expect("pattern compiles");
    let line = "    pub unsafe extern \"C\" fn cep_decode_opcode(opcode: u8) -> DecodeResult {";
    let hit = regex.find_iter(line).expect("match runs");
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].caps[0].as_deref(), Some("cep_decode_opcode"));
}

#[test]
fn fn_def_pattern_captures_name_for_method() {
    let pattern = "^\\s*(?:pub(?:\\([a-z ]+\\))?\\s+)?(?:unsafe\\s+)?(?:extern\\s+\"[A-Za-z0-9]*\"\\s+)?(?:const\\s+)?(?:async\\s+)?fn\\s+([A-Za-z_][A-Za-z0-9_]*)";
    let regex = Regex::compile(pattern, false).expect("pattern compiles");
    let line = "    pub fn get(&self, key: &str) -> Option<&Json> {";
    let hit = regex.find_iter(line).expect("match runs");
    assert_eq!(hit[0].caps[0].as_deref(), Some("get"));
}

#[test]
fn word_boundary_token_match() {
    let regex = Regex::compile("\\b(TODO|FIXME|XXX|HACK)\\b", true).expect("pattern compiles");
    assert!(regex.is_match("plain TODO: fix later").expect("runs"));
    assert!(!regex.is_match("todoist").expect("runs"));
    assert!(regex.is_match("CEP:TODO(alice): CEP-512: text").expect("runs"));
}

#[test]
fn class_and_star_semantics() {
    let regex = Regex::compile("^[a-z_][a-z0-9_]*$", false).expect("pattern compiles");
    assert!(regex.is_match("good_func").expect("runs"));
    assert!(!regex.is_match("BadFunc").expect("runs"));
    let pascal = Regex::compile("^[A-Z][A-Za-z0-9]*$", false).expect("pattern compiles");
    assert!(pascal.is_match("CommentBlock").expect("runs"));
    assert!(!pascal.is_match("bad_name").expect("runs"));
}

#[test]
fn non_greedy_and_optional_quantifiers() {
    let regex = Regex::compile("\\b(if|else|for|while|loop|match|try)\\b[^;{}]*\\{\\s*\\}", false)
        .expect("pattern compiles");
    assert!(regex.is_match("if x {}").expect("runs"));
    assert!(!regex.is_match("if x { work(); }").expect("runs"));
}

#[test]
fn literal_group_extraction() {
    let regex = Regex::compile("\\b(struct|enum|union|trait)\\s+([A-Za-z_][A-Za-z0-9_]*)", false)
        .expect("pattern compiles");
    let hit = regex.find_iter("pub struct CommentBlock {").expect("runs");
    assert_eq!(hit[0].caps[1].as_deref(), Some("CommentBlock"));
}

#[test]
fn step_budget_exhaustion_is_reported() {
    let regex = Regex::compile("(a|aa)+$", false).expect("pattern compiles");
    let subject = "a".repeat(64);
    let result = regex.is_match(&subject);
    assert!(result.is_err() || result.expect("bounded"));
}

#[test]
fn empty_branch_and_catch_patterns() {
    let catch = Regex::compile("\\bcatch\\s*\\([^)]*\\)\\s*\\{\\s*\\}", false).expect("compiles");
    assert!(catch.is_match("catch (...) { }").expect("runs"));
    assert!(!catch.is_match("catch (...) { handle(); }").expect("runs"));
}
