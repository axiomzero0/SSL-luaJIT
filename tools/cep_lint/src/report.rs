// CEP:FILE: tools/cep_lint/src/report.rs
// CEP:WHAT: Finding record, deterministic sorting, human-readable printing, and exit-code decision.
// CEP:WHY: Section 50.1 requires issues sorted by file, line, rule, and message with configured failure severities; centralizing this keeps every check output-identical.
// CEP:CLASS: CEP-2
// CEP:STATUS: complete
// CEP:FAILURE: none; pure data transformation.
// CEP:ASSUMES: findings carry accurate file, line, rule, severity, and message.
// CEP:COST: cold; O(F log F) sort over findings.
// CEP:EVIDENCE: unit test cep_lint::report in tools/cep_lint/tests/unit_report.rs.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub rule: String,
    pub severity: u32,
    pub message: String,
}

pub fn sort_findings(findings: &mut Vec<Finding>) {
    findings.sort();
}

pub fn blocking_findings(findings: &[Finding], fail_on: &[u32]) -> usize {
    findings
        .iter()
        .filter(|f| fail_on.contains(&f.severity))
        .count()
}

pub fn print_findings(findings: &[Finding]) {
    for finding in findings {
        println!(
            "{}:{}: {} (severity {}): {}",
            finding.file, finding.line, finding.rule, finding.severity, finding.message
        );
    }
}
