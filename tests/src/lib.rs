// CEP:FILE: tests/src/lib.rs
// CEP:WHAT: Library root of the conformance test crate; declares the shared test harness helpers.
// CEP:WHY: Tests mirror source per section 32.8; the root module keeps fixture loading and report rendering available to every suite.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: none; declarations only.
// CEP:ASSUMES: none
// CEP:COST: cold; declarations only.
// CEP:EVIDENCE: cargo test -p ssl-tests.
