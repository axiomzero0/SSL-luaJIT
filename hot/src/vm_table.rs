// CEP:FILE: hot/src/vm_table.rs
// CEP:WHAT: Table object accessors over the flat heap arena: headers, array cells, shape, and linear property pairs.
// CEP:WHY: design.md Part 2 requires shape profiling (array-only, hash-only, mixed); tables are arena objects addressed by u32 handles, never pointers, per the zero-pointer-chase mandate.
// CEP:CLASS: CEP-0
// CEP:STATUS: complete
// CEP:FAILURE: Accessors return None on out-of-range handles or keys; callers convert to guards or errors.
// CEP:ASSUMES: heap byte layout matches config::heap_layout; enforced by layout tests in tests.
// CEP:COST: array cells are one 16-byte load or store; property lookup is a bounded linear scan over MAX_TABLE_PROPS pairs.
// CEP:EVIDENCE: unit tests ssl-tests::unit_table; differential tests interpreter versus JIT.

use crate::vm_value::{SslValue, TAG_NIL, TAG_STR};
use ssl_config::target_model::heap_layout;
use ssl_config::limits as L;

/// Shape classification recorded by the profiler per design.md Part 2.
pub const SHAPE_ARRAY_ONLY: u8 = 0;
/// Shape for tables that only hold string keys.
pub const SHAPE_HASH_ONLY: u8 = 1;
/// Shape for tables holding both integer and string keys.
pub const SHAPE_MIXED: u8 = 2;

/// Maximum string-keyed property pairs stored per table (bounded hash part).
pub const MAX_TABLE_PROPS: u32 = 8;

/// Header words in front of every table object.
pub mod header {
    /// Offset of the mark byte used by the collectors.
    pub const MARK: u32 = 0;
    /// Offset of the shape byte.
    pub const SHAPE: u32 = 1;
    /// Offset of the array length word.
    pub const LEN: u32 = 4;
    /// Offset of the property pair count word.
    pub const PROP_COUNT: u32 = 8;
}

/// Reads the array length of a table object.
pub fn array_len(heap: &[u8], obj: u32) -> Option<u32> {
    let base = object_base(heap.len() as u32, obj)?;
    read_u32(heap, base + header::LEN)
}

/// Reads the property pair count of a table object.
pub fn prop_count(heap: &[u8], obj: u32) -> Option<u32> {
    let base = object_base(heap.len() as u32, obj)?;
    read_u32(heap, base + header::PROP_COUNT)
}

/// Reads the shape byte of a table object.
pub fn shape(heap: &[u8], obj: u32) -> Option<u8> {
    let base = object_base(heap.len() as u32, obj)?;
    heap.get((base + header::SHAPE) as usize).copied()
}

/// Writes the shape byte of a table object.
pub fn set_shape(heap: &mut [u8], obj: u32, value: u8) -> Option<()> {
    let base = object_base(heap.len() as u32, obj)?;
    let idx = (base + header::SHAPE) as usize;
    if idx >= heap.len() {
        return None;
    }
    heap[idx] = value;
    Some(())
}

/// Reads one array cell of a table.
pub fn get_cell(heap: &[u8], obj: u32, index: u32) -> Option<SslValue> {
    let base = object_base(heap.len() as u32, obj)?;
    let len = read_u32(heap, base + header::LEN)?;
    if index >= len {
        return None;
    }
    read_cell(heap, base + cell_offset(index))
}

/// Writes one array cell of a table.
pub fn set_cell(heap: &mut [u8], obj: u32, index: u32, value: SslValue) -> Option<()> {
    let base = object_base(heap.len() as u32, obj)?;
    let len = read_u32(heap, base + header::LEN)?;
    if index >= len {
        return None;
    }
    write_cell(heap, base + cell_offset(index), value)
}

/// Byte offset of the string-property pair area: immediately after the array
/// cells, which grow with the table length. The old fixed offset
/// (SMALL_TABLE_CELLS * CELL_BYTES) overlapped array cells 7 and 8.
fn pairs_base(heap: &[u8], base: u32) -> Option<u32> {
    let len = read_u32(heap, base + header::LEN)?;
    Some(base + heap_layout::HEADER_BYTES + len * heap_layout::CELL_BYTES)
}

/// Reads a string-keyed property by linear scan over the pair area.
pub fn get_prop(heap: &[u8], obj: u32, key: u32) -> Option<SslValue> {
    let base = object_base(heap.len() as u32, obj)?;
    let count = read_u32(heap, base + header::PROP_COUNT)?;
    if count > MAX_TABLE_PROPS {
        return None;
    }
    let pairs = pairs_base(heap, base)?;
    for idx in 0..count {
        let entry = pairs + idx * (L::PROP_PAIR_BYTES);
        let stored = read_cell(heap, entry)?;
        if stored.tag == TAG_STR && stored.as_handle() == key {
            return read_cell(heap, entry + heap_layout::CELL_BYTES);
        }
    }
    Some(SslValue::nil())
}

/// Writes a string-keyed property, appending a new pair when capacity allows.
pub fn set_prop(heap: &mut [u8], obj: u32, key: u32, value: SslValue) -> Option<()> {
    let base = object_base(heap.len() as u32, obj)?;
    let count = read_u32(heap, base + header::PROP_COUNT)?;
    if count > MAX_TABLE_PROPS {
        return None;
    }
    let pairs = pairs_base(heap, base)?;
    for idx in 0..count {
        let entry = pairs + idx * (L::PROP_PAIR_BYTES);
        let stored = read_cell(heap, entry)?;
        if stored.tag == TAG_STR && stored.as_handle() == key {
            return write_cell(heap, entry + heap_layout::CELL_BYTES, value);
        }
    }
    if count >= MAX_TABLE_PROPS {
        return None;
    }
    write_cell(heap, pairs + count * (L::PROP_PAIR_BYTES), SslValue::string(key))?;
    write_cell(heap, pairs + count * (L::PROP_PAIR_BYTES) + heap_layout::CELL_BYTES, value)?;
    write_u32(heap, base + header::PROP_COUNT, count + 1)
}

/// Initializes a freshly allocated table object with the given array length.
pub fn init_table(heap: &mut [u8], obj: u32, len: u32) -> Option<()> {
    let base = object_base(heap.len() as u32, obj)?;
    if base + object_total_bytes(len) > heap.len() as u32 {
        return None;
    }
    heap[(base + header::MARK) as usize] = 0;
    heap[(base + header::SHAPE) as usize] = SHAPE_ARRAY_ONLY;
    write_u32(heap, base + header::LEN, len)?;
    write_u32(heap, base + header::PROP_COUNT, 0)?;
    for idx in 0..len {
        write_cell(heap, base + cell_offset(idx), SslValue::nil())?;
    }
    Some(())
}

/// Reshapes a table when a string property is written to an array-only table.
pub fn note_prop_write(heap: &mut [u8], obj: u32) -> Option<()> {
    let base = object_base(heap.len() as u32, obj)?;
    let current = *heap.get((base + header::SHAPE) as usize)?;
    let next = if current == SHAPE_ARRAY_ONLY {
        SHAPE_MIXED
    } else {
        SHAPE_HASH_ONLY
    };
    heap[(base + header::SHAPE) as usize] = next;
    Some(())
}

/// Computes the byte offset of one array cell relative to the object base.
pub const fn cell_offset(index: u32) -> u32 {
    heap_layout::HEADER_BYTES + index * heap_layout::CELL_BYTES
}

/// Computes the total byte size of a table object with the given array length.
pub const fn object_total_bytes(len: u32) -> u32 {
    heap_layout::HEADER_BYTES
        + len * heap_layout::CELL_BYTES
        + MAX_TABLE_PROPS * L::PROP_PAIR_BYTES
}

/// Validates and resolves a heap handle to a byte offset.
pub fn object_base(heap_bytes: u32, obj: u32) -> Option<u32> {
    if obj == 0 || heap_bytes == 0 {
        return None;
    }
    let base = obj * heap_layout::CELL_BYTES;
    if base >= heap_bytes {
        return None;
    }
    Some(base)
}

pub fn read_u32(heap: &[u8], offset: u32) -> Option<u32> {
    let idx = offset as usize;
    if idx + 4 > heap.len() {
        return None;
    }
    let bytes = [
        heap[idx],
        heap[idx + 1],
        heap[idx + 2],
        heap[idx + 3],
    ];
    Some(u32::from_le_bytes(bytes))
}

pub fn write_u32(heap: &mut [u8], offset: u32, value: u32) -> Option<()> {
    let idx = offset as usize;
    if idx + 4 > heap.len() {
        return None;
    }
    let bytes = value.to_le_bytes();
    heap[idx..idx + 4].copy_from_slice(&bytes);
    Some(())
}

pub fn read_cell(heap: &[u8], offset: u32) -> Option<SslValue> {
    let idx = offset as usize;
    if idx + heap_layout::CELL_BYTES as usize > heap.len() {
        return None;
    }
    let mut tag_bytes = [0u8; 8];
    let mut payload_bytes = [0u8; 8];
    tag_bytes.copy_from_slice(&heap[idx..idx + 8]);
    payload_bytes.copy_from_slice(&heap[idx + 8..idx + heap_layout::CELL_BYTES as usize]);
    Some(SslValue {
        tag: u64::from_le_bytes(tag_bytes),
        payload: u64::from_le_bytes(payload_bytes),
    })
}

pub fn write_cell(heap: &mut [u8], offset: u32, value: SslValue) -> Option<()> {
    let idx = offset as usize;
    let total = heap_layout::CELL_BYTES as usize;
    if idx + total > heap.len() {
        return None;
    }
    heap[idx..idx + 8].copy_from_slice(&value.tag.to_le_bytes());
    heap[idx + 8..idx + total].copy_from_slice(&value.payload.to_le_bytes());
    Some(())
}

const _: () = assert!(TAG_NIL == 0 && TAG_STR == 4);
