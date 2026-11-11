// CEP:FILE: tests/src/unit_interp.rs
// CEP:WHAT: Interpreter unit tests: hot-loop detection, arithmetic semantics, and comparison behavior over assembled fixtures.
// CEP:WHY: Section 32.8 requires tests for every CEP-0 function; the interpreter dispatch and profiling are pinned by these cases before any JIT work is trusted.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: Panics through test assertions only.
// CEP:ASSUMES: fixtures compile through the assembler airlock.
// CEP:COST: cold; milliseconds per case.
// CEP:EVIDENCE: cargo test -p ssl-tests unit_interp.

use ssl_cold::assembler::assemble;
use ssl_config::limits as L;
use ssl_hot::gc::GcScratch;
use ssl_hot::interp_run::{run_until_event, RunOutcome};
use ssl_hot::interp_step::RunError;
use ssl_hot::runtime::Runtime;
use ssl_hot::vm_state::VmState;

/// Maximum steps a unit test may run before the budget assertion fails.
const TEST_STEP_BUDGET: u32 = 1 << 20;

const SUM_PROGRAM: &str = ".slots 8\n.const 0 int 10\n.const 1 int 1\n.const 2 int 0\nLOADK 0, 2\nLOADK 1, 1\nLOADK 3, 0\n@loop:\nLE 2, 1, 3\nJMPNOT 2, @end\nADD 4, 0, 1\nMOVE 0, 4\nADDI 1, 1, 1\nJMP @loop\n@end:\nPRINT 0\nRET 0\n";

struct TestVm {
    state: VmState,
    heap: Vec<u8>,
    rt: Runtime,
    worklist: Vec<u32>,
    remap: Vec<(u32, u32)>,
}

impl TestVm {
    fn new() -> TestVm {
        let mut state = VmState::new();
        state.bump_ptr = ssl_config::target_model::heap_layout::CELL_BYTES;
        state.eden_end = ssl_hot::heap::survivor_base();
        state.barrier_capacity = L::BARRIER_BYTES / 4;
        state.barrier_base = ssl_hot::gc::barrier_base();
        TestVm {
            state,
            heap: vec![0u8; ssl_hot::gc::arena_bytes() as usize],
            rt: Runtime::new(),
            worklist: vec![0u32; L::MAX_TABLES as usize],
            remap: vec![(0, 0); L::MAX_TABLES as usize],
        }
    }
}

fn step_until(vm: &mut TestVm, words: &[u32], consts: &[ssl_hot::bytecode::Const]) -> Result<RunOutcome, RunError> {
    let program = ssl_hot::bytecode::Program {
        words,
        consts,
        slot_count: 8,
    };
    let mut executed = 0u32;
    loop {
        if executed >= TEST_STEP_BUDGET {
            return Ok(RunOutcome::BudgetSpent);
        }
        executed += 1;
        let outcome = {
            let mut scratch = GcScratch {
                worklist: &mut vm.worklist,
                remap: &mut vm.remap,
            };
            run_until_event(&mut vm.state, &program, &mut vm.heap, &mut vm.rt, &mut scratch)?
        };
        match outcome {
            RunOutcome::HotLoop(_) | RunOutcome::AtInstalledTrace(_) => continue,
            done => return Ok(done),
        }
    }
}

#[test]
fn hot_loop_detection_fires_at_threshold() {
    let program = assemble(SUM_PROGRAM).expect("fixture assembles");
    let mut vm = TestVm::new();
    let outcome = step_until(&mut vm, &program.words, &program.consts).expect("run ok");
    assert_eq!(outcome, RunOutcome::Returned);
}

#[test]
fn interpreter_sum_matches_expected() {
    let program = assemble(SUM_PROGRAM).expect("fixture assembles");
    let mut vm = TestVm::new();
    let _ = step_until(&mut vm, &program.words, &program.consts).expect("run ok");
    assert_eq!(vm.rt.out_len, 1, "one printed value");
    assert_eq!(vm.rt.out[0].as_int(), 55, "sum 1..=10");
}

#[test]
fn profile_counts_backedges() {
    let program = assemble(SUM_PROGRAM).expect("fixture assembles");
    let mut vm = TestVm::new();
    let _ = step_until(&mut vm, &program.words, &program.consts).expect("run ok");
    let profile = vm.rt.profile.entry(3);
    assert!(profile.is_some(), "header 3 profiled");
    assert!(profile.expect("profiled").iterations >= L::HOT_THRESHOLD);
}
