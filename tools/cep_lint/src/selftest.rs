// CEP:FILE: tools/cep_lint/src/selftest.rs
// CEP:WHAT: Self-test manifest runner: applies per-scenario configuration overrides, lints virtual scenario files, and compares per-rule finding counts with expected values.
// CEP:WHY: Section 50.6 item 3 requires --self-test to validate every configured rule with one violating and one compliant scenario and exact expected counts.
// CEP:CLASS: CEP-2
// CEP:STATUS: complete
// CEP:FAILURE: Returns failure through scenario results; a mismatch prints the scenario name and expected versus actual counts.
// CEP:ASSUMES: manifest JSON follows the documented schema with base_config, scenarios, files, overrides, and expected counts.
// CEP:COST: cold; linear in scenario count times file size.
// CEP:EVIDENCE: cargo test -p cep-lint plus the live `cep_lint --self-test` gate.

use crate::engine;
use crate::json::Json;
use crate::limits as L;
use crate::model::{compile_patterns, Config};
use crate::report::{sort_findings, Finding};
use crate::source;

pub struct ScenarioResult {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

pub struct Manifest {
    pub base_config_text: String,
    pub scenarios: Vec<Scenario>,
}

pub struct Scenario {
    pub name: String,
    pub rule: String,
    pub files: Vec<(String, String)>,
    pub overrides: Vec<(String, String)>,
    pub violating_expected: u32,
    pub compliant_expected: u32,
}

    // CEP:WHAT: Parses the self-test manifest into scenarios with base configuration, files, and expected counts.
    // CEP:WHY: Section 50.6 item 3 defines the manifest contract; parsing must be strict so drift fails loudly.
    // CEP:STATUS: complete
    // CEP:FAILURE: Returns None when required keys or shapes are missing; the caller raises BOOT-4.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn parse_manifest(root: &Json) -> Option<Manifest> {
    let base = root.get("base_config")?.as_str()?.to_string();
    let mut scenarios = Vec::new();
    for item in root.get("scenarios")?.as_arr()? {
        let name = item.get("name")?.as_str()?.to_string();
        let rule = item.get("rule")?.as_str()?.to_string();
        let mut files = Vec::new();
        for file in item.get("files")?.as_arr()? {
            let file_name = file.get("name")?.as_str()?.to_string();
            let content = file.get("content")?.as_str()?.to_string();
            files.push((file_name, content));
        }
        let violating = item
            .get("violating")
            .and_then(|v| v.get("expected_findings"))
            .and_then(|v| v.as_u32())
            .unwrap_or(0);
        let compliant = item
            .get("compliant")
            .and_then(|v| v.get("expected_findings"))
            .and_then(|v| v.as_u32())
            .unwrap_or(0);
        let mut overrides = Vec::new();
        if let Some(over) = item.get("config_overrides").and_then(|v| v.as_obj()) {
            for (key, value) in over {
                if let Some(text) = value.as_str() {
                    overrides.push((key.clone(), text.to_string()));
                }
            }
        }
        scenarios.push(Scenario {
            name,
            rule,
            files,
            overrides,
            violating_expected: violating,
            compliant_expected: compliant,
        });
    }
    Some(Manifest {
        base_config_text: base,
        scenarios,
    })
}

    // CEP:WHAT: Runs every scenario and returns one result each.
    // CEP:WHY: The self-test gate reports pass and fail per scenario with exact counts.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn run_manifest(manifest: &Manifest) -> Vec<ScenarioResult> {
    let mut results = Vec::new();
    for scenario in &manifest.scenarios {
        results.push(run_scenario(manifest, scenario));
    }
    results
}

    // CEP:WHAT: Runs the violating and compliant variants and compares both with expected counts.
    // CEP:WHY: Both directions must match exactly; a single-sided check would tolerate regressions.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn run_scenario(manifest: &Manifest, scenario: &Scenario) -> ScenarioResult {
    let run_violating = run_variant(manifest, scenario, true);
    let run_compliant = run_variant(manifest, scenario, false);
    let ok = run_violating == scenario.violating_expected
        && run_compliant == scenario.compliant_expected;
    ScenarioResult {
        name: scenario.name.clone(),
        ok,
        detail: format!(
            "violating {} (expected {}), compliant {} (expected {})",
            run_violating, scenario.violating_expected, run_compliant, scenario.compliant_expected
        ),
    }
}

    // CEP:WHAT: Lints one variant's files under the scenario configuration and counts findings for the scenario rule.
    // CEP:WHY: Per-rule counting keeps fixtures independent of unrelated rule noise.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn run_variant(manifest: &Manifest, scenario: &Scenario, violating: bool) -> u32 {
    let config_text = apply_overrides(&manifest.base_config_text, &scenario.overrides);
    let config = match Config::load(&config_text) {
        Ok(config) => config,
        Err(_) => return u32::MAX,
    };
    let compiled = match compile_patterns(&config) {
        Ok(compiled) => compiled,
        Err(_) => return u32::MAX,
    };
    let mut findings: Vec<Finding> = Vec::new();
    let mut variant = "violating";
    if !violating {
        variant = "compliant";
    }
    let wanted: Vec<(String, String)> = scenario
        .files
        .iter()
        .filter(|(name, _)| variant_file_kind(name) == variant)
        .cloned()
        .collect();
    if scenario.rule == "CEP-LINT-DOC-SYNC" {
        return run_doc_sync_variant(&config, &compiled, &wanted, &mut findings, scenario);
    }
    for (name, content) in &wanted {
        let src = source::load(name, content);
        engine::run_file(&src, &config, &compiled, &mut findings);
    }
    sort_findings(&mut findings);
    findings
        .iter()
        .filter(|f| f.rule == scenario.rule)
        .count() as u32
}

    // CEP:WHAT: Runs the DOC-SYNC comparison against scenario-provided document fixtures.
    // CEP:WHY: The DOC-SYNC scenario needs virtual documents instead of the live repository file.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn run_doc_sync_variant(
    config: &Config,
    compiled: &crate::model::CompiledPatterns,
    wanted: &[(String, String)],
    findings: &mut Vec<Finding>,
    scenario: &Scenario,
) -> u32 {
    let rule = match config.rule(scenario.rule.as_str()) {
        Some(rule) => rule,
        None => return u32::MAX,
    };
    for (name, content) in wanted {
        let doc = crate::checks_doc::DocInfo {
            path: name.clone(),
            text: content.clone(),
        };
        let names: Vec<String> = config.rules.iter().map(|(n, _)| n.clone()).collect();
        crate::checks_doc::check_doc_sync(
            &doc,
            scenario.rule.as_str(),
            rule,
            compiled,
            &names,
            &config.standard_version,
            findings,
        );
    }
    sort_findings(findings);
    findings
        .iter()
        .filter(|f| f.rule == scenario.rule)
        .count() as u32
}

    // CEP:WHAT: Classifies scenario files by embedded variant marker in the file name.
    // CEP:WHY: Scenario files carry their variant in the name so one file list serves both runs.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn variant_file_kind(name: &str) -> &str {
    if name.contains("__violating") {
        "violating"
    } else if name.contains("__compliant") {
        "compliant"
    } else {
        "shared"
    }
}

    // CEP:WHAT: Applies dotted-path configuration overrides to a copy of the base configuration.
    // CEP:WHY: Scenario-specific behavior, such as virtual document paths, is data not engine code.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn apply_overrides(config_text: &str, overrides: &[(String, String)]) -> String {
    let mut root = match crate::json::parse(config_text) {
        Ok(root) => root,
        Err(_) => return config_text.to_string(),
    };
    for (path, value) in overrides {
        set_json_path(&mut root, path, &Json::Str(value.clone()));
    }
    serialize_json(&root)
}

    // CEP:WHAT: Sets one nested JSON member addressed by a dotted path.
    // CEP:WHY: Override paths address standard and rule parameters without ad hoc mutation logic.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn set_json_path(node: &mut Json, path: &str, value: &Json) {
    let (head, tail) = match path.split_once('.') {
        Some((head, tail)) => (head, tail),
        None => (path, ""),
    };
    if let Json::Obj(pairs) = node {
        for (key, slot) in pairs.iter_mut() {
            if key == head {
                if tail.is_empty() {
                    *slot = value.clone();
                } else {
                    set_json_path(slot, tail, value);
                }
                return;
            }
        }
        if !tail.is_empty() {
            return;
        }
        pairs.push((head.to_string(), value.clone()));
    }
}

    // CEP:WHAT: Serializes the JSON tree back to text with stable ordering.
    // CEP:WHY: Overrides must round-trip deterministically for repeatable self-test runs.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

pub fn serialize_json(node: &Json) -> String {
    match node {
        Json::Null => "null".to_string(),
        Json::Bool(b) => b.to_string(),
        Json::Num(n) => format!("{}", n),
        Json::Str(s) => serialize_string(s),
        Json::Arr(items) => {
            let parts: Vec<String> = items.iter().map(serialize_json).collect();
            format!("[{}]", parts.join(","))
        }
        Json::Obj(pairs) => {
            let parts: Vec<String> = pairs
                .iter()
                .map(|(k, v)| format!("{}:{}", serialize_string(k), serialize_json(v)))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

    // CEP:WHAT: Serializes one JSON string with RFC escaping.
    // CEP:WHY: Manifest and configuration round-trips must escape quotes and control bytes deterministically.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn serialize_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + L::QUOTE_CAPACITY_BYTES);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}
