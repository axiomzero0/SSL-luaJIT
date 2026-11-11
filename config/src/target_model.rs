// CEP:FILE: config/src/target_model.rs
// CEP:WHAT: x86-64 target facts: register classes, ABI reservations, heap object layout offsets, and ISA feature level.
// CEP:WHY: Chapter 38.30 requires all target-specific behavior behind named target configuration; generic hot code must never embed target constants.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: static assertions reject impossible layout relationships at compile time.
// CEP:ASSUMES: target is x86-64 SysV ABI, little endian, ISA level x86-64-v1 plus SSE2; enforced by the static assertions in this file.
// CEP:COST: cold; compile-time only.
// CEP:EVIDENCE: unit test ssl-tests::unit_config_nameconstants; ffi layout tests validate runtime offsets.

/// ISA feature level fixed at emission time for deterministic output (38.10).
pub const ISA_LEVEL_SSE2: u8 = 1;

/// JitState field offsets in bytes, used by the emitted code via the reserved state pointer.
pub mod jit_state_layout {
    /// Offset of the frame slot array (SslValue records, 16 bytes each).
    pub const SLOTS: u32 = 0;
    /// Offset of the bytecode program counter word.
    pub const PC: u32 = 4096;
    /// Offset of the exit identifier word returned by guard stubs.
    pub const EXIT_ID: u32 = 4100;
    /// Offset of the bump allocation pointer for the Eden arena.
    pub const BUMP_PTR: u32 = 4104;
    /// Offset of the Eden limit used by the inline allocation check.
    pub const EDEN_END: u32 = 4108;
    /// Offset of the heap base pointer used for absolute table addressing.
    pub const HEAP_BASE: u32 = 4112;
    /// Offset of the per-trace installed entry table pointer.
    pub const TRACE_TABLE: u32 = 4116;
    /// Offset of the write-barrier remembered-set insert cursor.
    pub const BARRIER_CURSOR: u32 = 4120;
    /// Offset of the write-barrier remembered-set capacity.
    pub const BARRIER_CAPACITY: u32 = 4124;
    /// Offset of the write-barrier remembered-set base pointer.
    pub const BARRIER_BASE: u32 = 4128;
    /// Offset of the global variable array (one value per global slot).
    pub const GLOBALS: u32 = 4136;
}

/// Heap object header and table layout facts shared by the VM and the emitter.
pub mod heap_layout {
    /// Bytes per heap value cell (tagged integer or double payload plus tag).
    pub const CELL_BYTES: u32 = 16;
    /// Header bytes in front of every heap object (mark byte, shape byte, array length, pad).
    pub const HEADER_BYTES: u32 = 16;
    /// Fixed cell count allocated per small table by the allocation fast path.
    pub const SMALL_TABLE_CELLS: u32 = 8;
    /// Bytes allocated per small table including header.
    pub const SMALL_TABLE_BYTES: u32 = HEADER_BYTES + SMALL_TABLE_CELLS * CELL_BYTES;
}

const _: () = assert!(
    jit_state_layout::SLOTS + 256 * 16 <= jit_state_layout::PC,
    "slot array must fit before the pc field"
);
const _: () = assert!(
    heap_layout::CELL_BYTES == 16,
    "heap cells are 16 bytes: payload plus tag word"
);

/// Allocatable general purpose register identifiers used by the register allocator pool.
pub mod gpr_pool {
    /// Physical register encodings for the allocatable 64-bit general registers.
    pub const RAX: u8 = 0;
    pub const RCX: u8 = 1;
    pub const RDX: u8 = 2;
    pub const RSI: u8 = 6;
    pub const RDI: u8 = 7;
    pub const R8: u8 = 8;
    pub const R9: u8 = 9;
    pub const R12: u8 = 12;
    /// Count of allocatable general registers.
    pub const COUNT: u8 = 8;
}

/// Vector register pool (xmm) identifiers; all are caller-saved under SysV.
pub mod xmm_pool {
    /// Physical encodings xmm0 through xmm7.
    pub const XMM0: u8 = 0;
    pub const XMM1: u8 = 1;
    pub const XMM2: u8 = 2;
    pub const XMM3: u8 = 3;
    pub const XMM4: u8 = 4;
    pub const XMM5: u8 = 5;
    pub const XMM6: u8 = 6;
    pub const XMM7: u8 = 7;
    /// Count of allocatable vector registers.
    pub const COUNT: u8 = 8;
}

/// Reserved (ABI) registers excluded from the allocator pool per design.md Part 7.
pub mod abi_reservation {
    /// Register carrying the state pointer argument at trace entry (SysV rdi).
    pub const STATE_PTR_ARG_GPR: u8 = 7;
    /// Reserved base register holding the JitState pointer (callee-saved rbx).
    pub const STATE_PTR_GPR: u8 = 3;
    /// Reserved register holding the heap base (callee-saved r15).
    pub const HEAP_BASE_GPR: u8 = 15;
    /// Reserved register holding the trace allocation start (callee-saved r13).
    pub const ALLOC_START_GPR: u8 = 13;
    /// Reserved register holding the live allocation cursor (callee-saved r14).
    pub const ALLOC_CURSOR_GPR: u8 = 14;
    /// Reserved stack pointer register (rsp).
    pub const STACK_PTR_GPR: u8 = 4;
    /// Reserved frame pointer register (rbp) kept as a boundary.
    pub const FRAME_PTR_GPR: u8 = 5;
    /// Callee-saved allocatable registers that the prologue must preserve (r12).
    pub const CALLEE_SAVED_ALLOCATABLE: [u8; 1] = [12];
}
