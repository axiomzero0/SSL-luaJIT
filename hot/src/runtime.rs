// CEP:FILE: hot/src/runtime.rs
// CEP:WHAT: Interpreter-owned runtime state: profile table, bounded output buffer, heap bump cursors, GC bookkeeping, and installed trace headers.
// CEP:WHY: The interpreter and collector share mutable bookkeeping that must live outside VmState; one struct keeps ownership explicit and every array preallocated by the driver.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: none; struct construction is total.
// CEP:ASSUMES: buffers are preallocated before the run loop starts; hot code reads them as fixed slices.
// CEP:COST: cold structure; field access is one load.
// CEP:EVIDENCE: unit tests ssl-tests::unit_runtime; driver wiring in cold/src/driver.rs.

use crate::profile::{ProfileTable, MAX_LOOP_HEADERS};
use crate::vm_value::SslValue;
use ssl_config::limits as L;

/// Capacity of the bounded print output buffer.
pub const OUT_CAP: u32 = 256;

/// Collector phase machine for incremental old-generation marking.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum GcPhase {
    /// No collection work pending.
    Idle,
    /// Incremental marking in progress with a bounded work cursor.
    Marking,
    /// Compaction pending after marking completes.
    Compacting,
}

/// Garbage collection bookkeeping.
#[derive(Copy, Clone)]
pub struct GcState {
    /// Current collector phase.
    pub phase: GcPhase,
    /// Worklist cursor during marking.
    pub mark_cursor: u32,
    /// Marked-object count for the current cycle.
    pub marked: u32,
    /// Step counter driving quantum boundaries.
    pub steps_since_quantum: u32,
    /// Minor collections performed.
    pub minor_count: u32,
    /// Major collections performed.
    pub major_count: u32,
}

impl GcState {
    pub const fn new() -> GcState {
        GcState {
            phase: GcPhase::Idle,
            mark_cursor: 0,
            marked: 0,
            steps_since_quantum: 0,
            minor_count: 0,
            major_count: 0,
        }
    }
}

/// Installed trace header bookkeeping used by the interpreter to enter machine code.
pub struct TraceBookkeeping {
    /// Word indices of installed loop headers.
    pub headers: [u32; L::MAX_TRACES as usize],
    /// Installed trace count.
    pub count: u32,
}

impl TraceBookkeeping {
    pub const fn new() -> TraceBookkeeping {
        TraceBookkeeping {
            headers: [0; L::MAX_TRACES as usize],
            count: 0,
        }
    }

    /// Records one installed header when capacity allows.
    pub fn install(&mut self, header_pc: u32) -> bool {
        for idx in 0..self.count as usize {
            if self.headers[idx] == header_pc {
                return true;
            }
        }
        if self.count >= L::MAX_TRACES {
            return false;
        }
        self.headers[self.count as usize] = header_pc;
        self.count += 1;
        true
    }

    /// Reports whether a word index is an installed header.
    pub fn is_installed(&self, header_pc: u32) -> bool {
        for idx in 0..self.count as usize {
            if self.headers[idx] == header_pc {
                return true;
            }
        }
        false
    }
}

/// Interpreter-side runtime bookkeeping.
pub struct Runtime {
    /// Loop and vectorization profiles.
    pub profile: ProfileTable,
    /// Bounded print output values.
    pub out: [SslValue; OUT_CAP as usize],
    /// Output cursor.
    pub out_len: u32,
    /// Survivor region bump cursor.
    pub survivor_bump: u32,
    /// OldGen region bump cursor.
    pub old_bump: u32,
    /// Collector state.
    pub gc: GcState,
    /// Installed trace headers.
    pub traces: TraceBookkeeping,
}

impl Runtime {
    pub fn new() -> Runtime {
        Runtime {
            profile: ProfileTable::new(),
            out: [SslValue::nil(); OUT_CAP as usize],
            out_len: 0,
            survivor_bump: crate::heap::survivor_base(),
            old_bump: crate::heap::old_base(),
            gc: GcState::new(),
            traces: TraceBookkeeping::new(),
        }
    }

    /// Appends one value to the bounded output buffer.
    pub fn push_out(&mut self, value: SslValue) -> bool {
        if self.out_len >= OUT_CAP {
            return false;
        }
        let idx = self.out_len as usize;
        self.out[idx] = value;
        self.out_len += 1;
        true
    }
}

impl Default for Runtime {
    fn default() -> Runtime {
        Runtime::new()
    }
}

const _: () = assert!(MAX_LOOP_HEADERS <= 128);
