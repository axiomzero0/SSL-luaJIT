// CEP:FILE: cold/src/bin/ssljit.rs
// CEP:WHAT: Command line entry point: compiles a Lua program or assembles an SSL-BC text program, runs it under the JIT, and prints the observable output.
// CEP:WHY: Section 50-style tooling requires a stable, deterministic CLI; the binary is a thin cold wrapper around the driver with both frontends reachable.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: Prints an error line and exits non-zero on frontend, assembly, or runtime failure; a faulting trace prints its signal, fault address, and rip, then exits 9; never panics.
// CEP:ASSUMES: the argument is a UTF-8 path; .lua files go through the Lua frontend, .ssl files through the text assembler.
// CEP:COST: cold; dominated by program execution.
// CEP:EVIDENCE: CLI round trip in tests/cli smoke; Lua CLI round trip in ssl-tests.

use ssl_cold::driver::{Driver, DriverError};
use std::process::exit;

#[repr(C)]
struct SigAction {
    handler: usize,
    flags: usize,
    restorer: usize,
    mask: [u64; 16],
}

extern "C" {
    fn sigaction(signum: i32, act: *const SigAction, oldact: *mut SigAction) -> i32;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
}

extern "C" fn on_fault(sig: i32, info: *mut usize, ctx: *mut usize) {
    unsafe {
        let addr = *info.add(2);
        let rip = *ctx.add(21);
        let msg = format!("FAULT sig={} fault_addr={:#x} rip={:#x}\n", sig, addr, rip);
        write(2, msg.as_ptr(), msg.len());
    }
    exit(9);
}

fn install_fault_handler() {
    let act = SigAction {
        handler: on_fault as *const () as usize,
        flags: 4,
        restorer: 0,
        mask: [0; 16],
    };
    unsafe {
        sigaction(11, &act, std::ptr::null_mut());
        sigaction(7, &act, std::ptr::null_mut());
    }
}

fn main() {
    install_fault_handler();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: ssljit <program.ssl | program.lua>");
        exit(2);
    }
    let text = match std::fs::read_to_string(&args[0]) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("error: cannot read {}: {}", args[0], err);
            exit(2);
        }
    };
    let is_lua = args[0].ends_with(".lua");
    let mut driver = match if is_lua { Driver::from_lua(&text) } else { Driver::new(&text) } {
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
            if !report.completed {
                // BudgetSpent is a hard run bound: partial output must not look
                // like success to scripts and benchmarks.
                eprintln!("error: step budget exhausted before completion");
                exit(1);
            }
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
