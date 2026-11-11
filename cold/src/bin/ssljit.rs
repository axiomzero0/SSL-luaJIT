// CEP:FILE: cold/src/bin/ssljit.rs
// CEP:WHAT: Command line entry point: assembles one SSL-BC program, runs it under the JIT, and prints the observable output.
// CEP:WHY: Section 50-style tooling requires a stable, deterministic CLI; the binary is a thin cold wrapper around the driver.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: Prints an error line and exits non-zero on assembly or runtime failure; never panics.
// CEP:ASSUMES: the argument is a UTF-8 path to an SSL-BC assembly file.
// CEP:COST: cold; dominated by program execution.
// CEP:EVIDENCE: CLI round trip in tests/cli smoke.

use ssl_cold::driver::{Driver, DriverError};
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: ssljit <program.ssl>");
        exit(2);
    }
    let text = match std::fs::read_to_string(&args[0]) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("error: cannot read {}: {}", args[0], err);
            exit(2);
        }
    };
    let mut driver = match Driver::new(&text) {
        Ok(driver) => driver,
        Err(err) => fail(err),
    };
    match driver.run() {
        Ok(report) => {
            for value in &report.out {
                println!("{}", render(value));
            }
            eprintln!(
                "steps={} traces={} sides={} minor-gc={} major-gc={}",
                report.steps,
                report.traces_compiled,
                report.side_traces,
                report.minor_gcs,
                report.major_gcs
            );
        }
        Err(err) => fail(err),
    }
}

fn fail(err: DriverError) -> ! {
    eprintln!("error: {:?}", err);
    exit(1);
}

fn render(value: &ssl_hot::vm_value::SslValue) -> String {
    use ssl_hot::vm_value::*;
    if value.is_int() {
        format!("{}", value.as_int())
    } else if value.is_num() {
        format!("{}", value.as_num())
    } else if value.tag == TAG_BOOL {
        format!("{}", value.payload != 0)
    } else if value.is_table() {
        format!("table#{}", value.as_handle())
    } else if value.tag == TAG_STR {
        format!("str#{}", value.as_handle())
    } else {
        "nil".to_string()
    }
}
