// CEP:FILE: hot/src/gc.rs
// CEP:WHAT: Generational garbage collector: Eden/Survivor copying minor collection, incremental old-generation marking with slide compaction, write barrier, and quantum stepping.
// CEP:WHY: design.md Part 8 requires a generational collector with bump allocation, barriers, and incremental work; phases run in deterministic quanta between interpreter steps so collections never change program semantics.
// CEP:CLASS: CEP-1
// CEP:STATUS: partial
// CEP:OWNER: axiomzero0
// CEP:TICKET: CEP-701
// CEP:FAILURE: Returns RunError::HeapExhausted when a collection cannot free enough space or a scratch bound is exceeded; never panics and never moves objects the mutator observes mid-step.
// CEP:ASSUMES: scratch worklist and remap capacity equal MAX_TABLES, which bounds every collection by construction; collection points are interpreter quantum boundaries only, so no concurrent mutator exists; the barrier region lives inside the arena so Rust and emitted code share one address space.
// CEP:COST: minor collection O(live); major marking amortized GC_QUANTUM_ITEMS per quantum; compaction one bounded pass over OldGen.
// CEP:EVIDENCE: unit tests ssl-tests::unit_gc; allocation survival across collections in differential tests.
// CEP:SECURITY: collection operates only on the preallocated arena and scratch; no untrusted input is parsed.
// CEP:KNOWN-GAP: concurrent sweeping and read-barrier concurrent compaction are not implemented; collection is stop-the-world at quantum boundaries (docs/gc.md, ticket CEP-701).

use crate::heap;
use crate::interp_step::RunError;
use crate::runtime::{GcPhase, Runtime};
use crate::vm_state::VmState;
use crate::vm_table::{self, header};
use crate::vm_value::VALUE_BYTES;
use crate::vm_value::{SslValue, TAG_TBL};
use ssl_config::limits as L;

/// Mark byte value for a live object.
pub const MARK_LIVE: u8 = 2;
/// Mark byte value for an evacuated object whose first cell holds the forwarding handle.
pub const MARK_FORWARDED: u8 = 3;

/// Byte offset where the write-barrier region begins.
pub const fn barrier_base() -> u32 {
    heap::old_end()
}

/// Total arena bytes including the barrier region.
pub const fn arena_bytes() -> u32 {
    barrier_base() + L::BARRIER_BYTES
}

/// Caller-provided scratch buffers for collection worklists and remapping.
pub struct GcScratch<'a> {
    /// Pending-object worklist sized MAX_TABLES.
    pub worklist: &'a mut [u32],
    /// Compaction remap pairs sized MAX_TABLES.
    pub remap: &'a mut [(u32, u32)],
}

/// Called at interpreter quantum boundaries to advance collection work.
pub fn collector_quantum(
    state: &mut VmState,
    heap: &mut [u8],
    rt: &mut Runtime,
    scratch: &mut GcScratch,
) -> Result<(), RunError> {
    let eden_remaining = state.eden_end.saturating_sub(state.bump_ptr);
    if eden_remaining < L::GC_EDEN_HEADROOM {
        minor_collect(state, heap, rt, scratch)?;
        return Ok(());
    }
    let old_remaining = heap::old_end().saturating_sub(rt.old_bump);
    if rt.gc.phase == GcPhase::Idle && old_remaining < L::GC_OLD_HEADROOM {
        start_major_mark(state, heap, rt, scratch)?;
        return Ok(());
    }
    if rt.gc.phase == GcPhase::Marking {
        mark_quantum(state, heap, rt, scratch, L::GC_QUANTUM_ITEMS)?;
        return Ok(());
    }
    if rt.gc.phase == GcPhase::Compacting {
        compact_old(state, heap, rt, scratch)?;
        rt.gc.phase = GcPhase::Idle;
        rt.gc.major_count = rt.gc.major_count.saturating_add(1);
        barrier_reset(state);
    }
    Ok(())
}

/// Begins the incremental marking phase with a freshly seeded worklist.
fn start_major_mark(
    state: &mut VmState,
    heap: &mut [u8],
    rt: &mut Runtime,
    scratch: &mut GcScratch,
) -> Result<(), RunError> {
    reset_marks(heap, 0, heap.len() as u32);
    rt.gc.mark_cursor = 0;
    rt.gc.marked = 0;
    rt.gc.phase = GcPhase::Marking;
    let mut worklist = Worklist::resume(&mut scratch.worklist[..], 0);
    seed_mark_roots(state, heap, rt, &mut worklist)?;
    rt.gc.mark_cursor = worklist.len as u32;
    Ok(())
}

/// Marks one bounded batch of pending objects, resuming the persistent worklist.
fn mark_quantum(
    state: &mut VmState,
    heap: &mut [u8],
    rt: &mut Runtime,
    scratch: &mut GcScratch,
    budget: u32,
) -> Result<(), RunError> {
    let mut worklist = Worklist::resume(&mut scratch.worklist[..], rt.gc.mark_cursor as usize);
    let mut processed = 0u32;
    while processed < budget {
        match worklist.pop() {
            None => {
                rt.gc.mark_cursor = 0;
                rt.gc.phase = GcPhase::Compacting;
                return Ok(());
            }
            Some(handle) => {
                mark_object(heap, handle);
                rt.gc.marked = rt.gc.marked.saturating_add(1);
                push_children(heap, &mut worklist, handle)?;
            }
        }
        processed += 1;
    }
    rt.gc.mark_cursor = worklist.len as u32;
    let _ = state;
    Ok(())
}

/// Runs the complete major collection immediately (tests and allocation slow path).
pub fn major_collect_now(
    state: &mut VmState,
    heap: &mut [u8],
    rt: &mut Runtime,
    scratch: &mut GcScratch,
) -> Result<(), RunError> {
    start_major_mark(state, heap, rt, scratch)?;
    loop {
        match rt.gc.phase {
            GcPhase::Marking => mark_quantum(state, heap, rt, scratch, L::GC_QUANTUM_ITEMS)?,
            GcPhase::Compacting => {
                compact_old(state, heap, rt, scratch)?;
                rt.gc.phase = GcPhase::Idle;
                rt.gc.major_count = rt.gc.major_count.saturating_add(1);
                barrier_reset(state);
                return Ok(());
            }
            GcPhase::Idle => return Ok(()),
        }
    }
}

/// Persistent worklist cursor over the scratch array.
struct Worklist<'a> {
    items: &'a mut [u32],
    len: usize,
}

impl<'a> Worklist<'a> {
    fn resume(items: &'a mut [u32], len: usize) -> Worklist<'a> {
        let capped = len.min(items.len());
        Worklist { items, len: capped }
    }

    fn push(&mut self, handle: u32) -> Result<(), RunError> {
        let len = self.len;
        for idx in 0..len {
            if self.items[idx] == handle {
                return Ok(());
            }
        }
        if self.len >= self.items.len() {
            return Err(RunError::HeapExhausted);
        }
        self.items[self.len] = handle;
        self.len += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<u32> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        let handle = self.items[self.len];
        self.items[self.len] = 0;
        Some(handle)
    }
}

/// Seeds the marking worklist from every root: slots, globals, output buffer, and remembered set.
fn seed_mark_roots(
    state: &mut VmState,
    heap: &mut [u8],
    rt: &mut Runtime,
    worklist: &mut Worklist,
) -> Result<(), RunError> {
    for value in state.slots.iter() {
        push_root(worklist, value)?;
    }
    for value in state.globals.iter() {
        push_root(worklist, value)?;
    }
    for value in rt.out.iter() {
        push_root(worklist, value)?;
    }
    let start = barrier_base() as usize;
    let stop = (start + L::BARRIER_BYTES as usize).min(heap.len());
    if start < stop {
        let entries = (stop - start) / 4;
        for idx in 0..entries {
            let off = start + idx * 4;
            let bytes = [heap[off], heap[off + 1], heap[off + 2], heap[off + 3]];
            let handle = u32::from_le_bytes(bytes);
            if handle != 0 && vm_table::object_base(heap.len() as u32, handle).is_some() {
                worklist.push(handle)?;
            }
        }
    }
    Ok(())
}

/// Marks all objects reachable from roots; the worklist is drained completely.
fn mark_all(
    state: &mut VmState,
    heap: &mut [u8],
    rt: &mut Runtime,
    scratch: &mut GcScratch,
) -> Result<(), RunError> {
    reset_marks(heap, 0, heap.len() as u32);
    let mut worklist = Worklist::resume(&mut scratch.worklist[..], 0);
    seed_mark_roots(state, heap, rt, &mut worklist)?;
    while let Some(handle) = worklist.pop() {
        mark_object(heap, handle);
        push_children(heap, &mut worklist, handle)?;
    }
    Ok(())
}

/// Runs one full minor collection: evacuate live Eden objects and promote crowded Survivor contents.
pub fn minor_collect(
    state: &mut VmState,
    heap: &mut [u8],
    rt: &mut Runtime,
    scratch: &mut GcScratch,
) -> Result<(), RunError> {
    mark_all(state, heap, rt, scratch)?;
    // Eden's first object starts at one cell (handle 0 is invalid); evacuating
    // from offset 0 would reject the first handle and skip every live object.
    let eden_first = ssl_config::target_model::heap_layout::CELL_BYTES;
    evacuate_region(heap, rt, scratch, eden_first, state.bump_ptr, false)?;
    state.bump_ptr = eden_first;
    let survivor_used = rt.survivor_bump - heap::survivor_base();
    if survivor_used > L::GC_SURVIVOR_PROMOTE {
        evacuate_region(heap, rt, scratch, heap::survivor_base(), rt.survivor_bump, true)?;
        rt.survivor_bump = heap::survivor_base();
    }
    fixup_all_handles(state, heap, rt, scratch)?;
    rt.gc.minor_count = rt.gc.minor_count.saturating_add(1);
    barrier_reset(state);
    Ok(())
}

/// Evacuates every live object of one region, leaving forwarding marks and first-cell forwarding handles.
fn evacuate_region(
    heap: &mut [u8],
    rt: &mut Runtime,
    _scratch: &mut GcScratch,
    region_lo: u32,
    region_hi: u32,
    force_old: bool,
) -> Result<(), RunError> {
    let mut offset = heap::align_cell(region_lo);
    while offset < region_hi {
        let handle = match heap::handle_from_offset(offset) {
            Some(handle) => handle,
            None => break,
        };
        let base = match vm_table::object_base(heap.len() as u32, handle) {
            Some(base) => base,
            None => break,
        };
        let len = vm_table::read_u32(heap, base + header::LEN).unwrap_or(0);
        let size = vm_table::object_total_bytes(len.min(L::MAX_TABLE_CELLS));
        if heap[base as usize] == MARK_LIVE && len <= L::MAX_TABLE_CELLS {
            let dest = if force_old {
                heap::alloc_table_old(heap, &mut rt.old_bump, len).ok_or(RunError::HeapExhausted)?
            } else {
                match heap::alloc_table_survivor(heap, &mut rt.survivor_bump, len) {
                    Some(dest) => dest,
                    None => heap::alloc_table_old(heap, &mut rt.old_bump, len)
                        .ok_or(RunError::HeapExhausted)?,
                }
            };
            copy_object_bytes(heap, handle, dest, len)?;
            heap[base as usize] = MARK_FORWARDED;
            let _ = vm_table::write_cell(heap, base + vm_table::cell_offset(0), SslValue::table(dest));
        }
        offset += size;
    }
    Ok(())
}

/// Copies header, cells, and property bytes from one object to another.
fn copy_object_bytes(heap: &mut [u8], src: u32, dst: u32, len: u32) -> Result<(), RunError> {
    let src_base = vm_table::object_base(heap.len() as u32, src).ok_or(RunError::BadTable)?;
    let dst_base = vm_table::object_base(heap.len() as u32, dst).ok_or(RunError::BadTable)?;
    let total = vm_table::object_total_bytes(len.min(L::MAX_TABLE_CELLS)) as usize;
    for idx in 0..total {
        heap[dst_base as usize + idx] = heap[src_base as usize + idx];
    }
    Ok(())
}

/// Rewrites every reachable handle after evacuation using forwarding marks.
fn fixup_all_handles(
    state: &mut VmState,
    heap: &mut [u8],
    rt: &mut Runtime,
    scratch: &mut GcScratch,
) -> Result<(), RunError> {
    fixup_value_slice(&mut state.slots, heap);
    fixup_value_slice(&mut state.globals, heap);
    fixup_value_slice(&mut rt.out, heap);
    fixup_region_handles(heap, scratch, 0, heap::survivor_base())?;
    fixup_region_handles(heap, scratch, heap::survivor_base(), heap::old_base())?;
    fixup_region_handles(heap, scratch, heap::old_base(), heap::old_end())?;
    Ok(())
}

/// Rewrites table handles inside one value slice.
fn fixup_value_slice(values: &mut [SslValue], heap: &[u8]) {
    for value in values.iter_mut() {
        if value.tag == TAG_TBL && value.as_handle() != 0 {
            value.payload = forwarded_handle(heap, value.as_handle()) as u64;
        }
    }
}

/// Rewrites table references inside one region; forwarded objects are skipped because their live copies were fixed at destination.
fn fixup_region_handles(
    heap: &mut [u8],
    scratch: &mut GcScratch,
    lo: u32,
    hi: u32,
) -> Result<(), RunError> {
    let _ = scratch;
    let mut offset = heap::align_cell(lo);
    while offset < hi {
        let handle = match heap::handle_from_offset(offset) {
            Some(handle) => handle,
            None => break,
        };
        let base = match vm_table::object_base(heap.len() as u32, handle) {
            Some(base) => base,
            None => break,
        };
        let mark = heap[base as usize];
        let len = vm_table::read_u32(heap, base + header::LEN).unwrap_or(0);
        let size = vm_table::object_total_bytes(len.min(L::MAX_TABLE_CELLS));
        if mark != MARK_FORWARDED && len <= L::MAX_TABLE_CELLS {
            rewrite_object_refs(heap, handle, len)?;
        }
        offset += size;
    }
    Ok(())
}

/// Rewrites all cell references of one live object.
fn rewrite_object_refs(heap: &mut [u8], handle: u32, len: u32) -> Result<(), RunError> {
    let base = match vm_table::object_base(heap.len() as u32, handle) {
        Some(base) => base,
        None => return Ok(()),
    };
    for idx in 0..len.min(L::MAX_TABLE_CELLS) {
        let cell_offset = base + vm_table::cell_offset(idx);
        if let Some(cell) = vm_table::read_cell(heap, cell_offset) {
            if cell.tag == TAG_TBL && cell.as_handle() != 0 {
                let new_handle = forwarded_handle(heap, cell.as_handle());
                let _ = vm_table::write_cell(heap, cell_offset, SslValue::table(new_handle));
            }
        }
    }
    Ok(())
}

/// Resolves one handle through the forwarding mark left by evacuation.
fn forwarded_handle(heap: &[u8], handle: u32) -> u32 {
    if let Some(base) = vm_table::object_base(heap.len() as u32, handle) {
        if heap[base as usize] == MARK_FORWARDED {
            if let Some(cell) = vm_table::read_cell(heap, base + vm_table::cell_offset(0)) {
                if cell.tag == TAG_TBL && cell.as_handle() != 0 {
                    return cell.as_handle();
                }
            }
        }
    }
    handle
}

/// Pushes one root table handle onto the worklist.
fn push_root(worklist: &mut Worklist, value: &SslValue) -> Result<(), RunError> {
    if value.tag == TAG_TBL && value.as_handle() != 0 {
        worklist.push(value.as_handle())?;
    }
    Ok(())
}

/// Pushes table children of one object onto the worklist.
fn push_children(heap: &mut [u8], worklist: &mut Worklist, handle: u32) -> Result<(), RunError> {
    let base = match vm_table::object_base(heap.len() as u32, handle) {
        Some(base) => base,
        None => return Ok(()),
    };
    let len = match vm_table::read_u32(heap, base + header::LEN) {
        Some(len) => len,
        None => return Ok(()),
    };
    for idx in 0..len.min(L::MAX_TABLE_CELLS) {
        if let Some(cell) = vm_table::read_cell(heap, base + vm_table::cell_offset(idx)) {
            if cell.tag == TAG_TBL && cell.as_handle() != 0 {
                worklist.push(cell.as_handle())?;
            }
        }
    }
    Ok(())
}

/// Marks one object live in its header byte.
fn mark_object(heap: &mut [u8], handle: u32) {
    if let Some(base) = vm_table::object_base(heap.len() as u32, handle) {
        heap[base as usize] = MARK_LIVE;
    }
}

/// Clears mark bytes across the arena, walking the object stride.
fn reset_marks(heap: &mut [u8], lo: u32, hi: u32) {
    let start = heap::align_cell(lo) as usize;
    let stop = hi.min(heap.len() as u32) as usize;
    let mut offset = start;
    while offset < stop {
        if heap[offset] == MARK_LIVE {
            heap[offset] = 0;
        }
        offset += VALUE_BYTES as usize;
    }
}

/// Slides live old-generation objects to the region start and remaps every reference.
fn compact_old(
    state: &mut VmState,
    heap: &mut [u8],
    rt: &mut Runtime,
    scratch: &mut GcScratch,
) -> Result<(), RunError> {
    scratch.remap.fill((0, 0));
    let mut moved = 0usize;
    let mut write_offset = heap::old_base();
    let mut scan_offset = heap::old_base();
    while scan_offset < rt.old_bump {
        let handle = match heap::handle_from_offset(scan_offset) {
            Some(handle) => handle,
            None => break,
        };
        let base = match vm_table::object_base(heap.len() as u32, handle) {
            Some(base) => base,
            None => break,
        };
        let len = vm_table::read_u32(heap, base + header::LEN).unwrap_or(0);
        let size = vm_table::object_total_bytes(len.min(L::MAX_TABLE_CELLS));
        if heap[base as usize] == MARK_LIVE && len <= L::MAX_TABLE_CELLS {
            let new_handle = heap::handle_from_offset(heap::align_cell(write_offset))
                .ok_or(RunError::HeapExhausted)?;
            if new_handle != handle {
                move_object_block(heap, handle, new_handle, len)?;
            }
            if moved < scratch.remap.len() {
                scratch.remap[moved] = (handle, new_handle);
                moved += 1;
            }
            write_offset = heap::align_cell(write_offset) + size;
        }
        scan_offset += size;
    }
    rt.old_bump = write_offset;
    rewrite_after_compaction(state, heap, rt, scratch)
}

/// Moves one object block within the arena, copying byte by byte in the overlap-safe direction.
fn move_object_block(heap: &mut [u8], src: u32, dst: u32, len: u32) -> Result<(), RunError> {
    let src_base = vm_table::object_base(heap.len() as u32, src).ok_or(RunError::BadTable)?;
    let dst_base = vm_table::object_base(heap.len() as u32, dst).ok_or(RunError::BadTable)?;
    let total = vm_table::object_total_bytes(len.min(L::MAX_TABLE_CELLS)) as usize;
    if src_base < dst_base {
        let mut idx = total;
        while idx > 0 {
            idx -= 1;
            heap[dst_base as usize + idx] = heap[src_base as usize + idx];
        }
    } else {
        for idx in 0..total {
            heap[dst_base as usize + idx] = heap[src_base as usize + idx];
        }
    }
    Ok(())
}

/// Rewrites roots and every live object reference after old-generation compaction.
fn rewrite_after_compaction(
    state: &mut VmState,
    heap: &mut [u8],
    rt: &mut Runtime,
    scratch: &mut GcScratch,
) -> Result<(), RunError> {
    rewrite_slice(&mut state.slots, scratch);
    rewrite_slice(&mut state.globals, scratch);
    rewrite_slice(&mut rt.out, scratch);
    let mut offset = heap::align_cell(heap::old_base());
    while offset < rt.old_bump {
        let handle = match heap::handle_from_offset(offset) {
            Some(handle) => handle,
            None => break,
        };
        let base = match vm_table::object_base(heap.len() as u32, handle) {
            Some(base) => base,
            None => break,
        };
        let len = vm_table::read_u32(heap, base + header::LEN).unwrap_or(0);
        let size = vm_table::object_total_bytes(len.min(L::MAX_TABLE_CELLS));
        rewrite_object_refs_compacted(heap, scratch, handle, len)?;
        offset += size;
    }
    Ok(())
}

/// Rewrites table handles inside one value slice through the compaction remap.
fn rewrite_slice(values: &mut [SslValue], scratch: &GcScratch) {
    for value in values.iter_mut() {
        if value.tag == TAG_TBL && value.as_handle() != 0 {
            value.payload = remapped_handle(scratch, value.as_handle()) as u64;
        }
    }
}

/// Rewrites cell references of one compacted object through the remap.
fn rewrite_object_refs_compacted(
    heap: &mut [u8],
    scratch: &mut GcScratch,
    handle: u32,
    len: u32,
) -> Result<(), RunError> {
    let base = match vm_table::object_base(heap.len() as u32, handle) {
        Some(base) => base,
        None => return Ok(()),
    };
    for idx in 0..len.min(L::MAX_TABLE_CELLS) {
        let cell_offset = base + vm_table::cell_offset(idx);
        if let Some(cell) = vm_table::read_cell(heap, cell_offset) {
            if cell.tag == TAG_TBL && cell.as_handle() != 0 {
                let new_handle = remapped_handle(scratch, cell.as_handle());
                let _ = vm_table::write_cell(heap, cell_offset, SslValue::table(new_handle));
            }
        }
    }
    Ok(())
}

/// Looks one handle up in the compaction remap table.
fn remapped_handle(scratch: &GcScratch, handle: u32) -> u32 {
    for (old, new) in scratch.remap.iter() {
        if *old == handle && *new != 0 {
            return *new;
        }
    }
    handle
}

/// Records one reference-bearing table into the remembered set (write barrier).
pub fn barrier_record(state: &mut VmState, heap: &mut [u8], table: u32) -> bool {
    if state.barrier_cursor >= state.barrier_capacity {
        return false;
    }
    let base = barrier_base() as usize;
    let idx = base + (state.barrier_cursor as usize) * 4;
    if idx + 4 > heap.len() {
        return false;
    }
    heap[idx..idx + 4].copy_from_slice(&table.to_le_bytes());
    state.barrier_cursor += 1;
    true
}

/// Clears the remembered set after a collection.
pub fn barrier_reset(state: &mut VmState) {
    state.barrier_cursor = 0;
}

const _: () = assert!(L::MAX_TABLE_CELLS <= L::MAX_TABLES);
