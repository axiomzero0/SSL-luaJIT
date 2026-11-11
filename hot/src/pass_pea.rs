// CEP:FILE: hot/src/pass_pea.rs
// CEP:WHAT: Partial escape analysis: tracks non-escaping TNEW allocations, scalar-replaces their field traffic, and erases the physical allocation.
// CEP:WHY: design.md Part 5.2 requires eliminating allocation and GC overhead for tables that never escape the trace; the sweep is one forward pass with a bounded virtual-table pool.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns the number of eliminated allocations; capacity exhaustion simply stops tracking, which is conservative and legal.
// CEP:ASSUMES: constant indices are CONST_I nodes; memory chains are rebuilt by the shared rebuild helper after node deletion.
// CEP:COST: O(N) forward sweep plus one operand rewrite pass.
// CEP:EVIDENCE: golden IR tests pea_01; unit tests ssl-tests::unit_pass_pea.

use crate::ir::*;

/// Maximum fields tracked per virtual table.
pub const PEA_FIELDS: usize = 8;
/// Maximum simultaneously tracked virtual tables.
pub const PEA_TABLES: usize = 16;

/// One virtual allocation tracked by the sweep.
#[derive(Copy, Clone)]
struct VirtualTable {
    tnew: u16,
    fields: [u16; PEA_FIELDS],
    escaped: bool,
}

/// Runs partial escape analysis over one trace; returns the number of scalar-replaced allocations.
pub fn run_pea(trace: &mut IrTrace) -> u32 {
    let mut virtuals: [VirtualTable; PEA_TABLES] = empty_virtuals();
    let mut virtual_count = 0usize;
    let mut replacements = [NO_OPERAND; ssl_config::limits::MAX_IR_NODES as usize];
    for idx in 0..trace.count as usize {
        match trace.op[idx] {
            OP_TNEW => {
                let len = trace.imm[idx];
                if len >= 0 && len <= PEA_FIELDS as i32 && virtual_count < PEA_TABLES {
                    virtuals[virtual_count] = VirtualTable {
                        tnew: idx as u16,
                        fields: [NO_OPERAND; PEA_FIELDS],
                        escaped: false,
                    };
                    virtual_count += 1;
                }
            }
            OP_TGETI => {
                let table = trace.in0[idx];
                let index = trace.in1[idx];
                if let Some(virtual_idx) = virtual_index(&virtuals, virtual_count, table) {
                    if let Some(field_index) = const_field(trace, index) {
                        if !virtuals[virtual_idx].escaped {
                            let value = virtuals[virtual_idx].fields[field_index];
                            replacements[idx] = if value == NO_OPERAND { NO_OPERAND } else { value };
                            continue;
                        }
                    }
                }
                escape_virtual(&mut virtuals, virtual_count, table);
            }
            OP_TSETI => {
                let table = trace.in0[idx];
                let index = trace.in1[idx];
                let value = trace.in2[idx];
                if let Some(virtual_idx) = virtual_index(&virtuals, virtual_count, table) {
                    if let Some(field_index) = const_field(trace, index) {
                        if !virtuals[virtual_idx].escaped {
                            virtuals[virtual_idx].fields[field_index] = value;
                            continue;
                        }
                    }
                }
                escape_virtual(&mut virtuals, virtual_count, table);
            }
            _ => {
                for operand in [trace.in0[idx], trace.in1[idx], trace.in2[idx]] {
                    escape_virtual(&mut virtuals, virtual_count, operand);
                }
            }
        }
    }
    apply_scalar_replacement(trace, &virtuals, virtual_count, &mut replacements)
}

fn empty_virtuals() -> [VirtualTable; PEA_TABLES] {
    [VirtualTable {
        tnew: NO_OPERAND,
        fields: [NO_OPERAND; PEA_FIELDS],
        escaped: true,
    }; PEA_TABLES]
}

fn virtual_index(virtuals: &[VirtualTable; PEA_TABLES], count: usize, node: u16) -> Option<usize> {
    for idx in 0..count {
        if virtuals[idx].tnew == node && !virtuals[idx].escaped {
            return Some(idx);
        }
    }
    None
}

fn const_field(trace: &IrTrace, index: u16) -> Option<usize> {
    if index == NO_OPERAND {
        return None;
    }
    let idx = index as usize;
    if trace.op[idx] != OP_CONST_I || trace.imm[idx] < 0 {
        return None;
    }
    let field = trace.imm[idx] as usize;
    if field >= PEA_FIELDS {
        return None;
    }
    Some(field)
}

fn escape_virtual(virtuals: &mut [VirtualTable; PEA_TABLES], count: usize, node: u16) {
    for idx in 0..count {
        if virtuals[idx].tnew == node {
            virtuals[idx].escaped = true;
        }
    }
}

/// Deletes eliminated allocations and rewrites operand references to scalar values.
fn apply_scalar_replacement(
    trace: &mut IrTrace,
    virtuals: &[VirtualTable; PEA_TABLES],
    count: usize,
    replacements: &mut [u16; ssl_config::limits::MAX_IR_NODES as usize],
) -> u32 {
    let mut eliminated = 0u32;
    let mut load_remap = [NO_OPERAND; ssl_config::limits::MAX_IR_NODES as usize];
    for idx in 0..trace.count as usize {
        if trace.op[idx] == OP_NOP {
            continue;
        }
        for slot in 0..3usize {
            let at = [trace.in0[idx], trace.in1[idx], trace.in2[idx]][slot];
            if at == NO_OPERAND || at as usize >= replacements.len() {
                continue;
            }
            if replacements[at as usize] == usize::MAX as u16 {
                continue;
            }
            if replacements[at as usize] != NO_OPERAND {
                set_operand(trace, idx, slot, replacements[at as usize]);
            }
        }
    }
    for entry in &virtuals[..count] {
        if entry.escaped {
            continue;
        }
        trace.op[entry.tnew as usize] = OP_NOP;
        eliminated += 1;
    }
    for idx in 0..trace.count as usize {
        let op = trace.op[idx];
        if op == OP_NOP {
            continue;
        }
        let table = trace.in0[idx];
        let mut killed = false;
        for entry in &virtuals[..count] {
            if entry.escaped {
                continue;
            }
            if (op == OP_TGETI || op == OP_TSETI) && table == entry.tnew {
                if op == OP_TGETI {
                    load_remap[idx] = replacements[idx];
                }
                killed = true;
            }
        }
        if killed {
            drop_operands(trace, idx);
            trace.op[idx] = OP_NOP;
        }
    }
    rebuild_mem_chain(trace);
    eliminated
}

fn set_operand(trace: &mut IrTrace, node: usize, slot: usize, value: u16) {
    match slot {
        0 => trace.in0[node] = value,
        1 => trace.in1[node] = value,
        _ => trace.in2[node] = value,
    }
}

fn drop_operands(trace: &mut IrTrace, idx: usize) {
    drop_use(trace, trace.in0[idx]);
    drop_use(trace, trace.in1[idx]);
    drop_use(trace, trace.in2[idx]);
    trace.in0[idx] = NO_OPERAND;
    trace.in1[idx] = NO_OPERAND;
    trace.in2[idx] = NO_OPERAND;
}
