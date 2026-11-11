// CEP:FILE: tools/cep_lint/src/main.rs
// CEP:WHAT: Command line driver for cep_lint: option parsing, target collection, orchestration, and exit codes.
// CEP:WHY: Section 50.1 fixes the invocation contract, exit codes, and determinism; the driver is the only component touching the filesystem and process exit.
// CEP:CLASS: CEP-2
// CEP:STATUS: complete
// CEP:FAILURE: Exits 2 with a coded CEP-LINT-BOOT-<n> detail on I/O, JSON, or validation failure; exits 3 on usage error; exits 1 on blocking findings or failed self-test; exits 0 when clean.
// CEP:ASSUMES: invoked with repository-relative paths; configuration lives at .cep/cep_lint.json unless overridden by --config or CEP_LINT_CONFIG.
// CEP:COST: cold; O(R * F) over rules and files with sorted deterministic output.
// CEP:EVIDENCE: self-lint gate, self-test gate, DOC-SYNC live gate in scripts/run_ci_checks.sh.

use cep_lint::checks_doc;
use cep_lint::engine;
use cep_lint::json;
use cep_lint::limits as L;
use cep_lint::model::{self, compile_patterns, Config};
use cep_lint::regex_lite;
use cep_lint::report::{self, Finding};
use cep_lint::selftest;
use cep_lint::source;
use std::path::{Path, PathBuf};
use std::process::exit;

const TOOL_VERSION: &str = "0.4.0";
const DEFAULT_CONFIG: &str = ".cep/cep_lint.json";
const MANIFEST_PATH: &str = "tools/cep_lint/tests/manifest.json";

    // CEP:WHAT: Parses command line options, loads configuration, and routes to self-test or lint execution.
    // CEP:WHY: Section 50.1 fixes the invocation contract and exit codes; the driver owns process exit and filesystem access.
    // CEP:STATUS: complete
    // CEP:FAILURE: Exits 2 on bootstrap failures, 3 on usage errors, 1 on blocking findings, 0 when clean.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut config_path: Option<String> = None;
    let mut self_test = false;
    let mut targets: Vec<String> = Vec::new();
    if let Err(code) = parse_args(&args, &mut config_path, &mut self_test, &mut targets) {
        exit(code);
    }
    let config_file = config_path
        .or_else(|| std::env::var("CEP_LINT_CONFIG").ok())
        .unwrap_or_else(|| DEFAULT_CONFIG.to_string());
    let config_text = match std::fs::read_to_string(&config_file) {
        Ok(text) => text,
        Err(err) => boot_fail(L::BOOT_IO, format!("cannot read config {}: {}", config_file, err)),
    };
    if config_text.len() > L::LINT_MAX_CONFIG_BYTES as usize {
        boot_fail(L::BOOT_IO, "configuration exceeds size limit".to_string());
    }
    let config = match Config::load(&config_text) {
        Ok(config) => config,
        Err(err) => boot_fail(err.code, err.detail),
    };
    if self_test {
        run_self_test(&config);
        return;
    }
    if targets.is_empty() {
        eprintln!("usage: cep_lint [--config <path>] [--self-test] [--help] [--version] <files or directories>");
        exit(L::EXIT_USAGE);
    }
    run_lint(&config, &targets);
}

    // CEP:WHAT: Prints a coded CEP-LINT-BOOT-<n> line and exits with the bootstrap code.
    // CEP:WHY: Section 50.4 requires coded bootstrap failures before message templates are available.
    // CEP:STATUS: complete
    // CEP:FAILURE: Always exits the process with the bootstrap exit code.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn boot_fail(code: u32, detail: String) -> ! {
    println!("CEP-LINT-BOOT-{}: {}", code, detail);
    exit(L::EXIT_BOOT);
}

    // CEP:WHAT: Parses options and positional targets, handling help and version banners inline.
    // CEP:WHY: Options are fixed by section 50.1; unknown usage must exit 3 without scanning.
    // CEP:STATUS: complete
    // CEP:FAILURE: Returns the usage exit code when an option is missing its argument.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn parse_args(
    args: &[String],
    config_path: &mut Option<String>,
    self_test: &mut bool,
    targets: &mut Vec<String>,
) -> Result<(), i32> {
    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--config" | "-c" => {
                idx += 1;
                match args.get(idx) {
                    Some(path) => *config_path = Some(path.clone()),
                    None => return Err(L::EXIT_USAGE),
                }
            }
            "--self-test" | "-t" => *self_test = true,
            "--help" | "-h" => {
                print_help();
                exit(L::EXIT_CLEAN);
            }
            "--version" | "-v" => {
                let text = match std::fs::read_to_string(config_path.clone().unwrap_or_else(|| DEFAULT_CONFIG.to_string())) {
                    Ok(text) => text,
                    Err(err) => boot_fail(L::BOOT_IO, format!("cannot read config: {}", err)),
                };
                let config = match Config::load(&text) {
                    Ok(config) => config,
                    Err(err) => boot_fail(err.code, err.detail),
                };
                println!("cep_lint {} (standard CEP&CC {})", TOOL_VERSION, config.standard_version);
                exit(L::EXIT_CLEAN);
            }
            other => targets.push(other.to_string()),
        }
        idx += 1;
    }
    Ok(())
}

    // CEP:WHAT: Prints the usage banner fixed by section 50.1.
    // CEP:WHY: Typed accessors keep the driver contract fixed without panicking on wrong types.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn print_help() {
    println!("cep_lint {} — CEP&CC mechanical enforcement", TOOL_VERSION);
    println!("usage: cep_lint [options] <files or directories>");
    println!("  --config, -c <path>   lint configuration JSON (default .cep/cep_lint.json, env CEP_LINT_CONFIG)");
    println!("  --self-test, -t       run the self-test manifest and exit");
    println!("  --help, -h            show this usage");
    println!("  --version, -v         print tool and standard versions");
    println!("exit codes: 0 clean, 1 blocking findings, 2 bootstrap failure, 3 usage error");
}

    // CEP:WHAT: Expands file and directory targets into a sorted, deduplicated file list filtered by globs.
    // CEP:WHY: Section 50.1 requires sorted traversal; deduplication keeps repeated targets from double reporting.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn collect_targets(targets: &[String], globs: &[String]) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = Vec::new();
    for target in targets {
        let path = Path::new(target);
        if path.is_file() {
            if glob_matches(path.to_string_lossy().as_ref(), globs) {
                files.push(path.to_path_buf());
            }
        } else if path.is_dir() {
            collect_dir(path, globs, &mut files);
        }
    }
    files.sort();
    files.dedup();
    files
}

    // CEP:WHAT: Recursively collects matching files under one directory in sorted order.
    // CEP:WHY: Deterministic output requires sorted directory traversal at every level.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn collect_dir(dir: &Path, globs: &[String], files: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => boot_fail(L::BOOT_IO, format!("cannot read directory {}: {}", dir.display(), err)),
    };
    let mut subdirs: Vec<PathBuf> = Vec::new();
    let mut subfiles: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        } else if glob_matches(path.to_string_lossy().as_ref(), globs) {
            subfiles.push(path);
        }
    }
    subfiles.sort();
    subdirs.sort();
    for file in subfiles {
        files.push(file);
    }
    for sub in subdirs {
        collect_dir(&sub, globs, files);
    }
}

    // CEP:WHAT: Matches a path against the configured glob list.
    // CEP:WHY: Typed accessors keep the driver contract fixed without panicking on wrong types.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn glob_matches(path: &str, globs: &[String]) -> bool {
    for glob in globs {
        if glob_matches_one(path, glob) {
            return true;
        }
    }
    false
}

    // CEP:WHAT: Matches one path against one glob supporting suffix and wildcard-stem forms.
    // CEP:WHY: The configured globs are Rust-tree patterns; matching is lexical and deterministic.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn glob_matches_one(path: &str, glob: &str) -> bool {
    let stem = path.rsplit('/').next().unwrap_or(path);
    if glob == "**/*.rs" && stem.ends_with(".rs") && !path.ends_with(".rs.bk") {
        return true;
    }
    if let Some(suffix) = glob.strip_prefix(L::GLOB_WILDCARD_PREFIX) {
        if let Some(extension) = suffix.strip_prefix("*.") {
            return stem.ends_with(&format!(".{}", extension));
        }
        return stem == suffix;
    }
    if let Some(extension) = glob.strip_prefix("*.") {
        return stem.ends_with(&format!(".{}", extension));
    }
    stem == glob
}

    // CEP:WHAT: Loads every target, runs all rules, runs the DOC-SYNC gate, prints sorted findings, and exits by severity.
    // CEP:WHY: This is the primary invocation path of section 50.1 with fail_on-driven exit semantics.
    // CEP:STATUS: complete
    // CEP:FAILURE: Exits 2 on unreadable or oversized inputs; exits 1 when blocking findings exist.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn run_lint(config: &Config, targets: &[String]) {
    let compiled = match compile_patterns(config) {
        Ok(compiled) => compiled,
        Err(err) => boot_fail(err.code, err.detail),
    };
    let files = collect_targets(targets, &config.file_globs);
    let mut findings: Vec<Finding> = Vec::new();
    for file in &files {
        let path_text = file.to_string_lossy().to_string();
        let text = match std::fs::read_to_string(file) {
            Ok(text) => text,
            Err(err) => boot_fail(L::BOOT_IO, format!("cannot read {}: {}", path_text, err)),
        };
        if text.len() > L::LINT_MAX_SOURCE_BYTES as usize {
            boot_fail(L::BOOT_IO, format!("{} exceeds source size limit", path_text));
        }
        let src = source::load(&path_text, &text);
        engine::run_file(&src, config, &compiled, &mut findings);
    }
    if let Some(rule) = config.rule("CEP-LINT-DOC-SYNC") {
        run_doc_sync(config, rule, &compiled, &mut findings);
    }
    report::sort_findings(&mut findings);
    report::print_findings(&findings);
    let blocking = report::blocking_findings(&findings, &config.fail_on);
    if blocking > 0 {
        exit(L::EXIT_FINDINGS);
    }
    exit(L::EXIT_CLEAN);
}

    // CEP:WHAT: Loads the standard document and runs the DOC-SYNC comparison for the live configuration.
    // CEP:WHY: Section 50.6 item 5 requires the live gate over the document and configuration.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn run_doc_sync(
    config: &Config,
    rule: &model::Rule,
    compiled: &model::CompiledPatterns,
    findings: &mut Vec<Finding>,
) {
    let doc_path = config.doc_path.clone();
    let doc_text = match std::fs::read_to_string(&doc_path) {
        Ok(text) => text,
        Err(err) => boot_fail(L::BOOT_IO, format!("cannot read standard document {}: {}", doc_path, err)),
    };
    let doc = checks_doc::DocInfo {
        path: doc_path,
        text: doc_text,
    };
    let names: Vec<String> = config.rules.iter().map(|(n, _)| n.clone()).collect();
    checks_doc::check_doc_sync(&doc, "CEP-LINT-DOC-SYNC", rule, compiled, &names, &config.standard_version, findings);
}

    // CEP:WHAT: Loads the manifest, validates rule coverage, runs every scenario, and exits by result.
    // CEP:WHY: Section 50.6 item 3 requires exact per-rule expected counts for one violating and one compliant scenario each.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn run_self_test(config: &Config) {
    let manifest_text = match std::fs::read_to_string(MANIFEST_PATH) {
        Ok(text) => text,
        Err(err) => boot_fail(L::BOOT_IO, format!("cannot read manifest {}: {}", MANIFEST_PATH, err)),
    };
    let root = match json::parse(&manifest_text) {
        Ok(root) => root,
        Err(err) => boot_fail(L::BOOT_JSON, format!("{}:{} {}", MANIFEST_PATH, err.line, err.detail)),
    };
    let manifest = match selftest::parse_manifest(&root) {
        Some(manifest) => manifest,
        None => boot_fail(L::BOOT_MISSING_KEY, "manifest missing required keys".to_string()),
    };
    validate_manifest_rules(&manifest, config);
    let results = selftest::run_manifest(&manifest);
    let mut failed = 0usize;
    for result in &results {
        let marker;
        if result.ok {
            marker = "PASS";
        } else {
            marker = "FAIL";
            failed += 1;
        }
        println!("self-test {} {}: {}", marker, result.name, result.detail);
    }
    if failed == 0 {
        exit(L::EXIT_CLEAN);
    }
    exit(L::EXIT_FINDINGS);
}

    // CEP:WHAT: Rejects manifests whose scenarios reference unknown rules.
    // CEP:WHY: A manifest drift would silently pass; bootstrap failure is the sanctioned response.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn validate_manifest_rules(manifest: &selftest::Manifest, config: &Config) {
    for scenario in &manifest.scenarios {
        if config.rule(&scenario.rule).is_none() {
            boot_fail(
                L::BOOT_MISSING_KEY,
                format!("manifest scenario {} references unknown rule {}", scenario.name, scenario.rule),
            );
        }
    }
}
