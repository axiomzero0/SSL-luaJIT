// CEP:FILE: hot/src/vm_state.rs
// CEP:WHAT: The VM state structure shared byte-for-byte between the Rust interpreter and the emitted machine code.
// CEP:WHY: design.md Part 9 requires perfect state reconstruction on deoptimization; a single repr(C) layout with asserted offsets makes guard stubs and interpreter slots the same memory.
// CEP:CLASS: CEP-0
// CEP:STATUS: complete
// CEP:FAILURE: Field accessors return None on out-of-bounds slot indices; structural access cannot fail.
// CEP:ASSUMES: field offsets equal config::jit_state_layout constants; enforced by static offset assertions here and layout tests in tests.
// CEP:COST: slot access is one base-plus-displacement load or store in emitted code; identical cost in the interpreter.
// CEP:EVIDENCE: ffi layout tests; differential tests interpreter versus JIT.

use crate::vm_value::SslValue;
use ssl_config::target_model::jit_state_layout as layout;
use ssl_config::limits as L;

/// VM state: frame slots, execution cursor, exit channel, heap cursors, globals, and trace table.
#[repr(C)]
pub struct VmState {
    /// Frame slots visible to bytecode operands and guard snapshots.
    pub slots: [SslValue; L::MAX_SLOTS as usize],
    /// Bytecode program counter in words.
    pub pc: u32,
    /// Exit identifier written by guard stubs and allocation checks.
    pub exit_id: u32,
    /// Bump allocation cursor of the Eden arena.
    pub bump_ptr: u32,
    /// Eden limit checked by inline allocation.
    pub eden_end: u32,
    /// Heap arena base handle (byte offset zero of the arena).
    pub heap_base: u32,
    /// Installed trace entry table pointer (byte offset into the code buffer).
    pub trace_table: u32,
    /// Write-barrier remembered-set cursor.
    pub barrier_cursor: u32,
    /// Write-barrier remembered-set capacity.
    pub barrier_capacity: u32,
    /// Write-barrier remembered-set base pointer.
    pub barrier_base: u32,
    /// Global variable slots addressed by assembler-assigned global ids.
    pub globals: [SslValue; L::MAX_SLOTS as usize],
}

impl VmState {
    pub fn new() -> VmState {
        VmState {
            slots: [SslValue::nil(); L::MAX_SLOTS as usize],
            pc: 0,
            exit_id: 0,
            bump_ptr: 0,
            eden_end: 0,
            heap_base: 0,
            trace_table: 0,
            barrier_cursor: 0,
            barrier_capacity: 0,
            barrier_base: 0,
            globals: [SslValue::nil(); L::MAX_SLOTS as usize],
        }
    }

    pub fn global(&self, index: u32) -> Option<&SslValue> {
        self.globals.get(index as usize)
    }

    pub fn set_global(&mut self, index: u32, value: SslValue) {
        if let Some(slot) = self.globals.get_mut(index as usize) {
            *slot = value;
        }
    }

    pub fn slot(&self, index: u32) -> Option<&SslValue> {
        self.slots.get(index as usize)
    }

    pub fn slot_mut(&mut self, index: u32) -> Option<&mut SslValue> {
        self.slots.get_mut(index as usize)
    }

    pub fn set_slot(&mut self, index: u32, value: SslValue) {
        if let Some(slot) = self.slots.get_mut(index as usize) {
            *slot = value;
        }
    }
}

impl Default for VmState {
    fn default() -> VmState {
        VmState::new()
    }
}

const _: () = assert!(core::mem::offset_of!(VmState, slots) as u32 == layout::SLOTS);
const _: () = assert!(core::mem::offset_of!(VmState, pc) as u32 == layout::PC);
const _: () = assert!(core::mem::offset_of!(VmState, exit_id) as u32 == layout::EXIT_ID);
const _: () = assert!(core::mem::offset_of!(VmState, bump_ptr) as u32 == layout::BUMP_PTR);
const _: () = assert!(core::mem::offset_of!(VmState, eden_end) as u32 == layout::EDEN_END);
const _: () = assert!(core::mem::offset_of!(VmState, heap_base) as u32 == layout::HEAP_BASE);
const _: () = assert!(core::mem::offset_of!(VmState, trace_table) as u32 == layout::TRACE_TABLE);
const _: () = assert!(core::mem::offset_of!(VmState, barrier_cursor) as u32 == layout::BARRIER_CURSOR);
const _: () = assert!(
    core::mem::offset_of!(VmState, barrier_capacity) as u32 == layout::BARRIER_CAPACITY
);
const _: () = assert!(core::mem::offset_of!(VmState, barrier_base) as u32 == layout::BARRIER_BASE);
const _: () = assert!(core::mem::offset_of!(VmState, globals) as u32 == layout::GLOBALS);
