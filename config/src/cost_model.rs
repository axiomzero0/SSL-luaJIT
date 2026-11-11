// CEP:FILE: config/src/cost_model.rs
// CEP:WHAT: Named instruction cost facts for the x86-64 target used by DP instruction selection and the vectorizer cost gate.
// CEP:WHY: Chapter 38.31 forbids magic cost numbers; every latency, throughput, and penalty used by a pass must be named and sourced here.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: none; declarations only.
// CEP:ASSUMES: cost figures target modern x86-64 cores at ISA level SSE2; measured artifacts in benches/artifacts re-validate the two values the selector actually trades off.
// CEP:COST: cold; compile-time only.
// CEP:EVIDENCE: bench artifact benches/artifacts/bench_isel_cost.json.

/// Cost in selector units of a register-register integer ALU tile.
pub const COST_ALU_RR: u16 = 1;
/// Cost in selector units of a register-immediate integer ALU tile.
pub const COST_ALU_RI: u16 = 1;
/// Cost in selector units of a 64-bit immediate load tile (mov r, imm64 costs more than ALU forms).
pub const COST_MOV_IMM: u16 = 2;
/// Cost in selector units of a scalar SSE2 double tile.
pub const COST_SSE_SCALAR: u16 = 2;
/// Cost in selector units of a packed SSE2 double tile.
pub const COST_SSE_PACKED: u16 = 3;
/// Cost in selector units of a memory load tile touching the state frame.
pub const COST_LOAD_FRAME: u16 = 2;
/// Cost in selector units of a memory store tile touching the state frame.
pub const COST_STORE_FRAME: u16 = 2;
/// Cost in selector units of a compare-and-branch guard tile.
pub const COST_GUARD: u16 = 2;
/// Port pressure penalty added when consecutive tiles contend on one port class (52.3.1).
pub const COST_PORT_PRESSURE_PENALTY: u16 = 1;
/// Vectorization amortization gate: vector tile cost divided across this many lanes.
pub const VECTOR_LANES_F64_SSE2: u32 = 2;
/// Estimated interpreter step cost fraction above which JIT compilation is skipped.
pub const COMPILE_BUDGET_FRACTION: u32 = 1;
