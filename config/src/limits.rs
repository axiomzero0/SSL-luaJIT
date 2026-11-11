// CEP:FILE: config/src/limits.rs
// CEP:WHAT: Named capacity and budget limits for every bounded structure in the compiler and VM.
// CEP:WHY: Law 7 bans hard-coded assumptions; every loop bound, arena capacity, and denial-of-service limit must be a named constant so reviews and fuzz budgets reference one place.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: none; declarations only.
// CEP:ASSUMES: capacities fit in u32 index space; enforced by static assertions below.
// CEP:COST: cold; compile-time only.
// CEP:EVIDENCE: unit test ssl-tests::unit_config_nameconstants asserts bound relationships.

/// Maximum bytecode words loaded into one program (denial-of-service bound for the assembler).
pub const MAX_PROGRAM_WORDS: u32 = 1 << 18;
/// Maximum constant-pool entries per program.
pub const MAX_CONSTANTS: u32 = 1 << 14;
/// Maximum value slots per frame (bytecode operand width is one byte).
pub const MAX_SLOTS: u32 = 256;
/// Maximum recorded operations in one trace buffer.
pub const MAX_TRACE_OPS: u32 = 256;
/// Maximum SoA IR nodes per trace (graphifier arena capacity).
pub const MAX_IR_NODES: u32 = 1024;
/// Maximum MIR instructions per trace (machine IR capacity).
pub const MAX_MIR_INSNS: u32 = 2048;
/// Maximum virtual registers per trace.
pub const MAX_VREGS: u32 = 512;
/// Maximum guards (and therefore side exits and snapshots) per root trace.
pub const MAX_GUARDS: u32 = 64;
/// Maximum live slots tracked by one snapshot.
pub const MAX_SNAPSHOT_SLOTS: u32 = MAX_SLOTS;
/// Maximum open-addressing slots in the GVN dedup table; must be a power of two.
pub const MAX_GVN_SLOTS: u32 = 2048;
/// Interpreter loop iterations before a loop header is hot and recording starts.
pub const HOT_THRESHOLD: u32 = 64;
/// Interpreter iterations on a side exit before that exit records a side trace.
pub const SIDE_HOT_THRESHOLD: u32 = 16;
/// Maximum traces installed per program run.
pub const MAX_TRACES: u32 = 128;
/// Maximum GC work items processed per incremental collector quantum.
pub const GC_QUANTUM_ITEMS: u32 = 512;
/// Interpreter steps between collector quanta.
pub const GC_QUANTUM_STEPS: u32 = 512;
/// Hard step budget for one program run (worst-case execution time bound, 38.12).
pub const MAX_RUN_STEPS: u32 = 1 << 26;
/// Float arithmetic votes required to raise the vectorization hint.
pub const HINT_FLOAT_VOTES: u32 = 2;
/// Table traffic votes required to raise the vectorization hint.
pub const HINT_SHAPE_VOTES: u32 = 1;
/// Eden (young generation) arena size in bytes; bump-pointer fast path budget.
pub const EDEN_BYTES: u32 = 1 << 20;
/// Survivor space size in bytes for minor-collection copying.
pub const SURVIVOR_BYTES: u32 = 1 << 20;
/// Old generation arena size in bytes.
pub const OLD_GEN_BYTES: u32 = 1 << 22;
/// Write-barrier remembered-set region size in bytes (u32 entries).
pub const BARRIER_BYTES: u32 = 1 << 12;
/// Eden headroom that triggers a minor collection.
pub const GC_EDEN_HEADROOM: u32 = 4096;
/// Old-generation headroom that triggers the major marking phase.
pub const GC_OLD_HEADROOM: u32 = 65536;
/// Survivor usage that triggers promotion evacuation during minor collection.
pub const GC_SURVIVOR_PROMOTE: u32 = 786432;
/// Maximum array cells per table object.
pub const MAX_TABLE_CELLS: u32 = 1024;
/// Arena byte offset of the write-barrier region (Eden plus Survivor plus OldGen).
pub const BARRIER_ARENA_OFFSET: u32 = EDEN_BYTES + SURVIVOR_BYTES + OLD_GEN_BYTES;
/// JIT code cache bound in bytes (38.39 budget).
pub const CODE_CACHE_BYTES: u32 = 1 << 22;
/// Fallback page size used only when sysconf fails; named because Law 7 bans silent assumptions.
pub const FALLBACK_PAGE_BYTES: u32 = 4096;
/// Guard exit identifier for the allocation slow path reentry.
pub const EXIT_GUARD_LIMIT: u32 = 64;
/// Reserved isel scratch general register A (r10); excluded from the allocator pool.
pub const SCRATCH_GPR_A: u8 = 10;
/// Reserved isel scratch general register B (r11); excluded from the allocator pool.
pub const SCRATCH_GPR_B: u8 = 11;
/// Maximum string table entries interned before startup validation fails.
pub const MAX_INTERNED_STRINGS: u32 = 1 << 14;
/// Maximum source bytes accepted by the assembler airlock.
pub const MAX_SOURCE_BYTES: u32 = 1 << 20;
/// Maximum assembler nesting/line depth accepted by the airlock.
pub const MAX_ASSEMBLER_LINES: u32 = 1 << 16;
/// Taylor series terms for the deterministic sine builtin.
pub const MATH_TERMS: u32 = 12;
/// Newton iterations for the deterministic square root builtin.
pub const SQRT_TERMS: u32 = 64;
/// Math helper id: sine.
pub const MATH_ID_SIN: u8 = 0;
/// Math helper id: cosine.
pub const MATH_ID_COS: u8 = 1;
/// Math helper id: square root.
pub const MATH_ID_SQRT: u8 = 2;
/// Math helper id: absolute value.
pub const MATH_ID_ABS: u8 = 3;
/// Math helper id: floor.
pub const MATH_ID_FLOOR: u8 = 4;
/// Number of math helper thunks emitted after each trace.
pub const MATH_HELPER_COUNT: u32 = 5;
/// Maximum unrolling factor the vectorizer may emit.
pub const MAX_UNROLL_FACTOR: u32 = 8;
/// Minimum loop iterations for vectorization to be profitable (amortization bound).
pub const MIN_VECTOR_TRIP_COUNT: u32 = 8;
/// Maximum recursion depth for the lint JSON and regex parsers (denial-of-service bound).
pub const LINT_MAX_DEPTH: u32 = 64;
/// Maximum lint configuration file size in bytes.
pub const LINT_MAX_CONFIG_BYTES: u32 = 1 << 20;
/// Maximum linted source file size in bytes.
pub const LINT_MAX_SOURCE_BYTES: u32 = 1 << 20;
/// Root heap arena object count reserved for tables at startup.
pub const MAX_TABLES: u32 = 1 << 14;
/// Bytes per string-keyed property pair (key cell plus value cell).
pub const PROP_PAIR_BYTES: u32 = 32;
/// Maximum program bytecoded words per recorded side trace.
pub const MAX_SIDE_TRACES: u32 = 64;
/// Exit identifier meaning the trace ran to its backedge without a guard failure.
pub const EXIT_COMPLETE: u32 = 0;
/// Exit identifier base for guard failures; the guard index is added.
pub const EXIT_GUARD_BASE: u32 = 1;
/// Exit identifier for the inline allocation slow path.
pub const EXIT_ALLOC: u32 = 0xFFFF_FFFE;

const _: () = assert!(MAX_SLOTS <= 256, "slot operands are one byte wide");
const _: () = assert!(
    MAX_GVN_SLOTS.is_power_of_two(),
    "open addressing requires power-of-two capacity"
);
const _: () = assert!(
    MAX_IR_NODES <= MAX_GVN_SLOTS,
    "GVN table must hold every IR node id"
);
const _: () = assert!(
    MAX_SNAPSHOT_SLOTS <= MAX_SLOTS,
    "snapshots cannot track more slots than the frame has"
);
