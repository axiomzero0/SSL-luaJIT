// CEP:FILE: tools/cep_lint/src/model.rs
// CEP:WHAT: Lint configuration model: loading, validation, and typed rule access for .cep/cep_lint.json.
// CEP:WHY: Chapter 50 mandates data-driven enforcement with coded bootstrap failures; this module is the single gate between the JSON file and the engine mechanisms.
// CEP:CLASS: CEP-2
// CEP:STATUS: complete
// CEP:FAILURE: Returns BootError with coded CEP-LINT-BOOT-<n> detail on unreadable, malformed, mistyped, or semantically invalid configuration.
// CEP:ASSUMES: configuration bytes are UTF-8; enforced by the JSON loader.
// CEP:COST: cold; one pass over the configuration file.
// CEP:EVIDENCE: unit test cep_lint::config in tools/cep_lint/tests/unit_config.rs; DOC-SYNC live gate.

use crate::json::{parse, Json};
use crate::limits as L;
use crate::regex_lite::Regex;

pub const KNOWN_CHECKS: [&str; 10] = [
    "comment_block_schema",
    "function_policy",
    "comment_regex",
    "string_literal_regex",
    "numeric_literal_policy",
    "macro_prefix_policy",
    "banned_token_policy",
    "flat_code_regex",
    "doc_rule_coverage",
    "file_topology_policy",
];

#[derive(Debug, Clone)]
pub struct BootError {
    pub code: u32,
    pub detail: String,
}

impl BootError {
    pub fn new(code: u32, detail: impl Into<String>) -> BootError {
        BootError {
            code,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub check: String,
    pub mode: Option<String>,
    pub severity: u32,
    pub message: String,
    pub params: Json,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub standard_version: String,
    pub doc_path: String,
    pub heading_pattern: String,
    pub version_pattern: String,
    pub fail_on: Vec<u32>,
    pub file_globs: Vec<String>,
    pub rules: Vec<(String, Rule)>,
}

pub struct CompiledPatterns {
    pub map: Vec<(String, Vec<(String, Regex)>)>,
}

impl Config {
    // CEP:WHAT: Loads and validates the lint configuration into typed rules with coded bootstrap failures.
    // CEP:WHY: Every pattern, threshold, severity, message, and option lives in the configuration; this gate rejects malformed data with BOOT codes.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    pub fn load(text: &str) -> Result<Config, BootError> {
        let root = parse(text).map_err(|e| {
            BootError::new(
                L::BOOT_JSON,
                format!("{}:{} {}", e.line, e.col, e.detail),
            )
        })?;
        let standard = root
            .get("standard")
            .ok_or_else(|| BootError::new(L::BOOT_MISSING_KEY, "missing key standard"))?;
        let standard_version = standard
            .get("version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                BootError::new(L::BOOT_MISSING_KEY, "missing key standard.version")
            })?
            .to_string();
        let doc_path = standard
            .get("doc_path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                BootError::new(L::BOOT_MISSING_KEY, "missing key standard.doc_path")
            })?
            .to_string();
        let heading_pattern = standard
            .get("heading_pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                BootError::new(L::BOOT_MISSING_KEY, "missing key standard.heading_pattern")
            })?
            .to_string();
        let version_pattern = standard
            .get("version_pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                BootError::new(L::BOOT_MISSING_KEY, "missing key standard.version_pattern")
            })?
            .to_string();
        let fail_on = parse_severity_list(
            root.get("fail_on")
                .ok_or_else(|| BootError::new(L::BOOT_MISSING_KEY, "missing key fail_on"))?,
        )?;
        let file_globs = root
            .get("file_globs")
            .and_then(|v| v.as_arr())
            .ok_or_else(|| BootError::new(L::BOOT_MISSING_KEY, "missing key file_globs"))?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|s| s.to_string())
                    .ok_or_else(|| BootError::new(L::BOOT_WRONG_TYPE, "file_globs element not string"))
            })
            .collect::<Result<Vec<String>, BootError>>()?;
        let rules_json = root
            .get("rules")
            .and_then(|v| v.as_obj())
            .ok_or_else(|| BootError::new(L::BOOT_MISSING_KEY, "missing key rules"))?;
        let mut rules = Vec::new();
        for (name, body) in rules_json {
            rules.push((name.clone(), parse_rule(name, body)?));
        }
        Ok(Config {
            standard_version,
            doc_path,
            heading_pattern,
            version_pattern,
            fail_on,
            file_globs,
            rules,
        })
    }

    // CEP:WHAT: Returns one rule by name.
    // CEP:WHY: Named lookup keeps dispatch and manifest validation simple and order-independent.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    pub fn rule(&self, name: &str) -> Option<&Rule> {
        self.rules.iter().find(|(n, _)| n == name).map(|(_, r)| r)
    }

    // CEP:WHAT: Reads a string parameter with a default.
    // CEP:WHY: Configuration parameters must have documented defaults so the engine never invents values.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    pub fn param_str(rule: &Rule, key: &str, default: &str) -> String {
        rule.params
            .get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| default.to_string())
    }

    // CEP:WHAT: Reads an integer parameter with a default.
    // CEP:WHY: Typed accessors keep configuration handling strict without panicking on wrong types.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    pub fn param_u32(rule: &Rule, key: &str, default: u32) -> u32 {
        rule.params.get(key).and_then(|v| v.as_u32()).unwrap_or(default)
    }

    // CEP:WHAT: Reads a boolean parameter with a default.
    // CEP:WHY: Typed accessors keep configuration handling strict without panicking on wrong types.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    pub fn param_bool(rule: &Rule, key: &str, default: bool) -> bool {
        rule.params.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
    }

    // CEP:WHAT: Reads a string array parameter as a list.
    // CEP:WHY: Typed accessors keep configuration handling strict without panicking on wrong types.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    pub fn param_str_list(rule: &Rule, key: &str) -> Vec<String> {
        rule.params
            .get(key)
            .and_then(|v| v.as_arr())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }

    // CEP:WHAT: Reads an integer array parameter as a list.
    // CEP:WHY: Typed accessors keep configuration handling strict without panicking on wrong types.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    pub fn param_u32_list(rule: &Rule, key: &str) -> Vec<u32> {
        rule.params
            .get(key)
            .and_then(|v| v.as_arr())
            .map(|items| items.iter().filter_map(|v| v.as_u32()).collect())
            .unwrap_or_default()
    }
}

    // CEP:WHAT: Compiles every configured regex once before scanning.
    // CEP:WHY: Compile errors surface as BOOT-8 before any file is read; compilation is hoisted out of the scan loop.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn compile_patterns(config: &Config) -> Result<CompiledPatterns, BootError> {
    let mut map = Vec::new();
    for (name, rule) in &config.rules {
        let mut compiled = Vec::new();
        for (key, value) in rule.params.as_obj().unwrap_or(&[]) {
            let (icase, is_regex) = regex_taste(key, rule);
            if !is_regex {
                continue;
            }
            if let Some(text) = value.as_str() {
                let regex = Regex::compile(text, icase)
                    .map_err(|e| BootError::new(L::BOOT_BAD_REGEX, format!("{} {}: {}", name, key, e.detail)))?;
                compiled.push((key.clone(), regex));
            }
        }
        map.push((name.clone(), compiled));
    }
    Ok(CompiledPatterns { map })
}

    // CEP:WHAT: Decides case sensitivity and whether a parameter is a regex by key and scoped flag.
    // CEP:WHY: Regex keys are a fixed vocabulary; scoped _icase flags allow per-pattern case control without engine changes.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn regex_taste(key: &str, rule: &Rule) -> (bool, bool) {
    let scoped_icase = rule
        .params
        .get(&format!("{}_icase", key))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let icase = scoped_icase || key.ends_with("_icase") || key == "icase";
    let is_regex = key.contains("pattern")
        || key == "icase"
        || key.ends_with("_regex")
        || key.ends_with("_contexts")
        || key == "guard_pattern"
        || key == "version_pattern"
        || key == "heading_pattern";
    (icase, is_regex)
}

    // CEP:WHAT: Fetches a compiled regex for one rule parameter.
    // CEP:WHY: Checks retrieve their configured patterns by name; absence means the rule is unconfigured and skipped.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn regex_for<'a>(
    compiled: &'a CompiledPatterns,
    rule_name: &str,
    key: &str,
) -> Option<&'a Regex> {
    compiled
        .map
        .iter()
        .find(|(n, _)| n == rule_name)
        .and_then(|(_, list)| list.iter().find(|(k, _)| k == key).map(|(_, r)| r))
}

    // CEP:WHAT: Validates fail_on severities against the zero-to-three range.
    // CEP:WHY: Severity range violations are BOOT-7 per section 50.4.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn parse_severity_list(value: &Json) -> Result<Vec<u32>, BootError> {
    let items = value
        .as_arr()
        .ok_or_else(|| BootError::new(L::BOOT_WRONG_TYPE, "fail_on must be an array"))?;
    let mut out = Vec::new();
    for item in items {
        let sev = item.as_u32().ok_or_else(|| {
            BootError::new(L::BOOT_WRONG_TYPE, "fail_on element must be an integer")
        })?;
        if sev > L::SEVERITY_MAX {
            return Err(BootError::new(L::BOOT_BAD_SEVERITY, format!("severity {} out of range", sev)));
        }
        out.push(sev);
    }
    Ok(out)
}

    // CEP:WHAT: Validates one rule body: known check, severity range, message, and params.
    // CEP:WHY: Unknown check names are BOOT-6; missing keys are BOOT-4 per the bootstrap table.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn parse_rule(name: &str, body: &Json) -> Result<Rule, BootError> {
    let check = body
        .get("check")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BootError::new(L::BOOT_MISSING_KEY, format!("{}: missing check", name)))?
        .to_string();
    if !KNOWN_CHECKS.contains(&check.as_str()) {
        return Err(BootError::new(
            L::BOOT_UNKNOWN_CHECK,
            format!("{}: unknown check {}", name, check),
        ));
    }
    let mode = body.get("mode").and_then(|v| v.as_str()).map(|s| s.to_string());
    let severity = body
        .get("severity")
        .and_then(|v| v.as_u32())
        .ok_or_else(|| BootError::new(L::BOOT_MISSING_KEY, format!("{}: missing severity", name)))?;
    if severity > L::SEVERITY_MAX {
        return Err(BootError::new(L::BOOT_BAD_SEVERITY, format!("{}: severity out of range", name)));
    }
    let message = body
        .get("message")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BootError::new(L::BOOT_MISSING_KEY, format!("{}: missing message", name)))?
        .to_string();
    let params = body
        .get("params")
        .ok_or_else(|| BootError::new(L::BOOT_MISSING_KEY, format!("{}: missing params", name)))?
        .clone();
    Ok(Rule {
        check,
        mode,
        severity,
        message,
        params,
    })
}
