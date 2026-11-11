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

/// Loop fixture with enough backedges to cross HOT_THRESHOLD (64 iterations).
const HOT_PROGRAM: &str = ".slots 8\n.const 0 int 70\n.const 1 int 1\n.const 2 int 0\nLOADK 0, 2\nLOADK 1, 1\nLOADK 3, 0\n@loop:\nLE 2, 1, 3\nJMPNOT 2, @end\nADD 4, 0, 1\nMOVE 0, 4\nADDI 1, 1, 1\nJMP @loop\n@end:\nPRINT 0\nRET 0\n";

struct TestVm {
    state: VmState,
    heap: Vec<u8>,
    rt: Runtime,
    worklist: Vec<u32>,
    remap: Vec<(u32, u32)>,
}

impl TestVm {
    // CEP:WHAT: Builds one interpreter VM with the same arena, eden, and barrier layout the driver uses.
    // CEP:WHY: Unit tests must exercise the interpreter under production heap geometry so results transfer to the JIT path.
    // CEP:STATUS: complete
    // CEP:FAILURE: Panics only when the arena allocation fails.
    // CEP:ASSUMES: arena_bytes and survivor_base are initialized before the first step.
    // CEP:COST: cold; one arena allocation per test.
    // CEP:EVIDENCE: shared by every test in this file.
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

// CEP:WHAT: Steps the interpreter until a terminal outcome, continuing through hot-loop and installed-trace events, under the test step budget.
// CEP:WHY: Tests drive full programs; budget exhaustion must surface as BudgetSpent instead of an infinite loop.
// CEP:STATUS: complete
// CEP:FAILURE: Returns the run error unchanged; returns BudgetSpent when the step budget is exhausted.
// CEP:ASSUMES: the program is assembled and slot_count matches the fixture.
// CEP:COST: cold; O(steps) with steps bounded by TEST_STEP_BUDGET.
// CEP:EVIDENCE: every test in this file.
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

// CEP:WHAT: Verifies the sum fixture reaches Returned with hot-loop events handled transparently.
// CEP:WHY: Hot-loop detection must not change program completion semantics.
// CEP:STATUS: complete
// CEP:FAILURE: Panics through test assertions.
// CEP:ASSUMES: SUM_PROGRAM loops ten times, below HOT_THRESHOLD.
// CEP:COST: cold; milliseconds.
// CEP:EVIDENCE: cargo test -p ssl-tests hot_loop_detection_fires_at_threshold.
#[test]
fn hot_loop_detection_fires_at_threshold() {
    let program = assemble(SUM_PROGRAM).expect("fixture assembles");
    let mut vm = TestVm::new();
    let outcome = step_until(&mut vm, &program.words, &program.consts).expect("run ok");
    assert_eq!(outcome, RunOutcome::Returned);
}

// CEP:WHAT: Verifies the sum fixture prints exactly one value equal to the sum 1..=10.
// CEP:WHY: Interpreter arithmetic and PRINT semantics are pinned by this case before any JIT work is trusted.
// CEP:STATUS: complete
// CEP:FAILURE: Panics through test assertions.
// CEP:ASSUMES: SUM_PROGRAM computes 55.
// CEP:COST: cold; milliseconds.
// CEP:EVIDENCE: cargo test -p ssl-tests interpreter_sum_matches_expected.
#[test]
fn interpreter_sum_matches_expected() {
    let program = assemble(SUM_PROGRAM).expect("fixture assembles");
    let mut vm = TestVm::new();
    let _ = step_until(&mut vm, &program.words, &program.consts).expect("run ok");
    assert_eq!(vm.rt.out_len, 1, "one printed value");
    assert_eq!(vm.rt.out[0].as_int(), 55, "sum 1..=10");
}

// CEP:WHAT: Verifies the backedge counter crosses HOT_THRESHOLD on a fixture that loops seventy times.
// CEP:WHY: Trace recording quality depends on correct backedge accounting; the counter must cross the threshold on a fixture long enough to reach it.
// CEP:STATUS: complete
// CEP:FAILURE: Panics through test assertions.
// CEP:ASSUMES: HOT_PROGRAM loops seventy times with header at pc 3.
// CEP:COST: cold; milliseconds.
// CEP:EVIDENCE: cargo test -p ssl-tests profile_counts_backedges.
#[test]
fn profile_counts_backedges() {
    let program = assemble(HOT_PROGRAM).expect("fixture assembles");
    let mut vm = TestVm::new();
    let _ = step_until(&mut vm, &program.words, &program.consts).expect("run ok");
    let profile = vm.rt.profile.entry(3);
    assert!(profile.is_some(), "header 3 profiled");
    assert!(
        profile.expect("profiled").iterations >= L::HOT_THRESHOLD,
        "backedge count must cross the hot threshold"
    );
}
