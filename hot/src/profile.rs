// CEP:FILE: hot/src/profile.rs
// CEP:WHAT: Loop, branch, type, shape, and vectorization-hint profiling tables maintained by the interpreter.
// CEP:WHY: design.md Part 2 makes the interpreter the primary profiling engine; hot counters trigger recording and vectorization hints let the JIT skip alias analysis on proven stride-one float streams.
// CEP:CLASS: CEP-0
// CEP:STATUS: complete
// CEP:FAILURE: none; profiling writes are bounded by table capacity and cannot fail.
// CEP:ASSUMES: loop headers are identified by backward jump targets; at most MAX_LOOP_HEADERS distinct headers are tracked per run.
// CEP:COST: one array update per backward edge; branch and type votes are bounded writes.
// CEP:EVIDENCE: unit tests ssl-tests::unit_profile; trace recording triggered by these counters in differential tests.

use crate::vm_value::TAG_NIL;
use ssl_config::limits as L;

/// Maximum loop headers tracked per program run.
pub const MAX_LOOP_HEADERS: u32 = 32;

/// Profiling entry for one loop header.
#[derive(Copy, Clone)]
pub struct LoopProfile {
    /// Backward edges taken at this header.
    pub iterations: u32,
    /// Type tags observed for the induction-adjacent float slots.
    pub float_votes: u32,
    /// Total arith votes observed at this header.
    pub arith_votes: u32,
    /// Shape votes for tables accessed in the loop body.
    pub shape_votes: u32,
    /// Set when the loop accesses one table with a stride-one induction key.
    pub vec_hint: bool,
    /// Word index of the loop header instruction.
    pub header_pc: u32,
}

impl LoopProfile {
    pub const fn new() -> LoopProfile {
        LoopProfile {
            iterations: 0,
            float_votes: 0,
            arith_votes: 0,
            shape_votes: 0,
            vec_hint: false,
            header_pc: 0,
        }
    }
}

/// Profile table over all observed loop headers.
pub struct ProfileTable {
    entries: [LoopProfile; MAX_LOOP_HEADERS as usize],
    count: u32,
}

impl ProfileTable {
    pub fn new() -> ProfileTable {
        ProfileTable {
            entries: [LoopProfile::new(); MAX_LOOP_HEADERS as usize],
            count: 0,
        }
    }

    /// Returns the profile for a header, creating the entry when first observed.
    pub fn entry_mut(&mut self, header_pc: u32) -> Option<&mut LoopProfile> {
        for idx in 0..self.count as usize {
            if self.entries[idx].header_pc == header_pc {
                return self.entries.get_mut(idx);
            }
        }
        if self.count >= MAX_LOOP_HEADERS {
            return None;
        }
        let slot = &mut self.entries[self.count as usize];
        slot.header_pc = header_pc;
        self.count += 1;
        Some(slot)
    }

    /// Returns the profile snapshot for a header if it exists.
    pub fn entry(&self, header_pc: u32) -> Option<LoopProfile> {
        for idx in 0..self.count as usize {
            if self.entries[idx].header_pc == header_pc {
                return Some(self.entries[idx]);
            }
        }
        None
    }

    /// Counts one backward edge and reports whether the header is hot.
    pub fn tick_backedge(&mut self, header_pc: u32) -> bool {
        let entry = match self.entry_mut(header_pc) {
            Some(entry) => entry,
            None => return false,
        };
        entry.iterations = entry.iterations.saturating_add(1);
        entry.iterations >= L::HOT_THRESHOLD
    }

    /// Votes one float arithmetic observation for the vectorization hint.
    pub fn vote_float(&mut self, header_pc: u32) {
        if let Some(entry) = self.entry_mut(header_pc) {
            entry.float_votes = entry.float_votes.saturating_add(1);
            entry.arith_votes = entry.arith_votes.saturating_add(1);
        }
    }

    /// Votes one table shape observation for the loop body.
    pub fn vote_shape(&mut self, header_pc: u32) {
        if let Some(entry) = self.entry_mut(header_pc) {
            entry.shape_votes = entry.shape_votes.saturating_add(1);
        }
    }

    /// Sets the vectorization hint when the stride-one induction pattern is proven.
    pub fn set_vec_hint(&mut self, header_pc: u32) {
        if let Some(entry) = self.entry_mut(header_pc) {
            entry.vec_hint = true;
        }
    }

    /// Clears all entries between compilation runs for determinism.
    pub fn reset(&mut self) {
        for idx in 0..self.entries.len() {
            self.entries[idx] = LoopProfile::new();
        }
        self.count = 0;
    }
}

impl Default for ProfileTable {
    fn default() -> ProfileTable {
        ProfileTable::new()
    }
}

const _: () = assert!(TAG_NIL == 0);
