// CEP:FILE: hot/src/heap.rs
// CEP:WHAT: Flat heap arena management: region layout, bump allocation for Eden, Survivor, and OldGen, and address math.
// CEP:WHY: design.md Part 8 requires bump-pointer young allocation with a pure fast path; arena slices are preallocated by the cold driver so hot code never touches the global allocator (section 25.5).
// CEP:CLASS: CEP-0
// CEP:STATUS: complete
// CEP:FAILURE: Allocation returns None when the target region cannot fit the object; callers run collection or report heap exhaustion.
// CEP:ASSUMES: the arena is one contiguous byte slice laid out Eden, Survivor, OldGen in that order; regions are bump allocated and compacted by the collector, so no free list exists.
// CEP:COST: fast-path allocation is one bump advance plus one compare; no locks, no syscalls.
// CEP:EVIDENCE: unit tests ssl-tests::unit_heap; allocation fast path exercised by emitted traces in differential tests.

use crate::vm_state::VmState;
use crate::vm_table;
use ssl_config::limits as L;

/// Byte offset where the Survivor region begins.
pub const fn survivor_base() -> u32 {
    L::EDEN_BYTES
}

/// Byte offset where the OldGen region begins.
pub const fn old_base() -> u32 {
    L::EDEN_BYTES + L::SURVIVOR_BYTES
}

/// Byte offset where the OldGen region ends.
pub const fn old_end() -> u32 {
    L::EDEN_BYTES + L::SURVIVOR_BYTES + L::OLD_GEN_BYTES
}

/// Total arena bytes required by the configured region sizes.
pub const fn arena_bytes() -> u32 {
    old_end()
}

/// Allocates one table in Eden with the bump pointer carried in VmState.
pub fn alloc_table_eden(heap: &mut [u8], state: &mut VmState, len: u32) -> Option<u32> {
    let size = vm_table::object_total_bytes(len);
    let next = state.bump_ptr.checked_add(size)?;
    if next > state.eden_end || next > survivor_base() {
        return None;
    }
    let handle = handle_from_offset(state.bump_ptr)?;
    vm_table::init_table(heap, handle, len)?;
    state.bump_ptr = next;
    Some(handle)
}

/// Allocates one table in the Survivor region with a collector-owned bump cursor.
pub fn alloc_table_survivor(heap: &mut [u8], bump: &mut u32, len: u32) -> Option<u32> {
    alloc_in_region(heap, bump, survivor_base(), old_base(), len)
}

/// Allocates one table in the OldGen region with a collector-owned bump cursor.
pub fn alloc_table_old(heap: &mut [u8], bump: &mut u32, len: u32) -> Option<u32> {
    alloc_in_region(heap, bump, old_base(), old_end(), len)
}

fn alloc_in_region(
    heap: &mut [u8],
    bump: &mut u32,
    region_base: u32,
    region_end: u32,
    len: u32,
) -> Option<u32> {
    let size = vm_table::object_total_bytes(len);
    let aligned = align_cell(*bump);
    let next = aligned.checked_add(size)?;
    if aligned < region_base || next > region_end {
        return None;
    }
    let handle = handle_from_offset(aligned)?;
    vm_table::init_table(heap, handle, len)?;
    *bump = next;
    Some(handle)
}

/// Rounds a byte offset up to the cell stride used by handles.
pub const fn align_cell(offset: u32) -> u32 {
    let stride = crate::vm_value::VALUE_BYTES;
    (offset + stride - 1) / stride * stride
}

/// Converts a byte offset inside the arena into a cell-strided handle.
pub fn handle_from_offset(offset: u32) -> Option<u32> {
    if offset % crate::vm_value::VALUE_BYTES != 0 {
        return None;
    }
    Some(offset / crate::vm_value::VALUE_BYTES)
}

/// Converts a handle back to its byte offset.
pub const fn offset_from_handle(handle: u32) -> u32 {
    handle * crate::vm_value::VALUE_BYTES
}

const _: () = assert!(old_base() > survivor_base());
