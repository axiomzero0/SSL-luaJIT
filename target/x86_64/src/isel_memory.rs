// CEP:FILE: target/x86_64/src/isel_memory.rs
// CEP:WHAT: Instruction selection for memory traffic: frame slots, array cells, globals, inline allocation, and write barriers.
// CEP:WHY: design.md Part 3 routes all memory through abstract state and Part 8 requires inline allocation fast paths plus barriers only where escapes dictate them; all address math lives here.
// CEP:CLASS: HPC-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns false on machine buffer rejection; callers abort compilation deterministically.
// CEP:ASSUMES: rbx holds VmState, r15 the heap base, r13 the trace allocation start, r14 the live allocation cursor, r10 and r11 are isel scratch; the barrier region lives inside the arena at the configured offset.
// CEP:COST: slot traffic is one or two base-plus-displacement moves; array traffic adds two shifts and one add for address formation.
// CEP:EVIDENCE: layout tests in tests; differential JIT execution.
// CEP:SECURITY: array indices are range-guarded by trace guards; the barrier append bounds-checks the cursor before writing.
// CEP:UNSAFE: none in this module; the encoder writes bytes into owned buffers only.

use crate::isa_def::*;
use crate::machine::MachineFunction;
use ssl_config::target_model::heap_layout as hlayout;
use ssl_config::target_model::jit_state_layout as layout;
use ssl_hot::mir::MirInsn;
use ssl_hot::mir_build as kinds;
use ssl_hot::vm_value::{TAG_BOOL, TAG_INT, TAG_NUM, TAG_STR, TAG_TBL};

/// Lowers one memory-class MIR instruction into machine tiles.
pub fn lower_memory(mir: &MirInsn, machine: &mut MachineFunction) -> bool {
    match mir.op {
        ssl_hot::mir::M_LOAD_SLOT => lower_load_slot(mir, machine),
        ssl_hot::mir::M_STORE_SLOT => lower_store_slot(mir, machine),
        ssl_hot::mir::M_LOAD_ARR_SLOT => lower_load_arr_slot(mir, machine),
        ssl_hot::mir::M_STORE_ARR_SLOT => lower_store_arr_slot(mir, machine),
        ssl_hot::mir::M_LOAD_G_SLOT => lower_load_global(mir, machine),
        ssl_hot::mir::M_STORE_G_SLOT => lower_store_global(mir, machine),
        ssl_hot::mir::M_NEW_TABLE => lower_new_table(mir, machine),
        ssl_hot::mir::M_ALLOC_CHECK => lower_alloc_check(mir, machine),
        ssl_hot::mir::M_LOAD_SLOT_F => {
            let mut load = MachineInsn::new(X_MOVSD_STATE_M2X);
            load.dst = mir.dst;
            load.imm = slot_payload_disp(mir.imm);
            machine.push(load)
        }
        ssl_hot::mir::M_STORE_SLOT_F => {
            let mut store = MachineInsn::new(X_MOVSD_STATE_X2M);
            store.src0 = mir.src0;
            store.imm = slot_payload_disp(mir.imm);
            machine.push(store)
        }
        _ => false,
    }
}

/// Byte displacement of one slot payload inside VmState.
pub const fn slot_payload_disp(slot: i32) -> i32 {
    layout::SLOTS as i32 + slot * (hlayout::CELL_BYTES as i32) + 8
}

/// Byte displacement of one slot tag inside VmState.
pub const fn slot_tag_disp(slot: i32) -> i32 {
    layout::SLOTS as i32 + slot * (hlayout::CELL_BYTES as i32)
}

/// Byte displacement of one global payload inside VmState.
pub const fn global_payload_disp(slot: i32) -> i32 {
    layout::GLOBALS as i32 + slot * (hlayout::CELL_BYTES as i32) + 8
}

/// Byte displacement of one global tag inside VmState.
pub const fn global_tag_disp(slot: i32) -> i32 {
    layout::GLOBALS as i32 + slot * (hlayout::CELL_BYTES as i32)
}

fn lower_load_slot(mir: &MirInsn, machine: &mut MachineFunction) -> bool {
    let mut insn = MachineInsn::new(X_MOV_SLOT_R);
    insn.dst = mir.dst;
    insn.imm = slot_payload_disp(mir.imm);
    machine.push(insn)
}

fn lower_store_slot(mir: &MirInsn, machine: &mut MachineFunction) -> bool {
    let mut tag = MachineInsn::new(X_MOV_SLOT_TAG);
    tag.imm = slot_tag_disp(mir.imm);
    tag.imm2 = kind_tag(mir.aux as u8) as i32;
    if !machine.push(tag) {
        return false;
    }
    let mut payload = MachineInsn::new(X_MOV_R_SLOT);
    payload.src0 = mir.src0;
    payload.imm = slot_payload_disp(mir.imm);
    machine.push(payload)
}

fn lower_load_arr_slot(mir: &MirInsn, machine: &mut MachineFunction) -> bool {
    let scratch = cell_address(mir.src0, mir.src1, machine);
    // The loaded values land in scratch2, NOT in the address register: the
    // first load clobbering scratch (its own index register) made the second
    // load read the object header instead of the cell payload.
    let value = machine.scratch_gpr2();
    let mut tag = MachineInsn::new(X_LOAD_IDX);
    tag.dst = value;
    tag.src1 = scratch;
    tag.imm = hlayout::HEADER_BYTES as i32;
    if !machine.push(tag) {
        return false;
    }
    let mut store_tag = MachineInsn::new(X_MOV_R_SLOT);
    store_tag.src0 = value;
    store_tag.imm = slot_tag_disp(mir.imm);
    if !machine.push(store_tag) {
        return false;
    }
    let mut payload = MachineInsn::new(X_LOAD_IDX);
    payload.dst = value;
    payload.src1 = scratch;
    payload.imm = hlayout::HEADER_BYTES as i32 + 8;
    if !machine.push(payload) {
        return false;
    }
    let mut store_payload = MachineInsn::new(X_MOV_R_SLOT);
    store_payload.src0 = value;
    store_payload.imm = slot_payload_disp(mir.imm);
    machine.push(store_payload)
}

fn lower_store_arr_slot(mir: &MirInsn, machine: &mut MachineFunction) -> bool {
    let scratch = cell_address(mir.src0, mir.src1, machine);
    if mir.aux != 0 {
        let mut payload = MachineInsn::new(X_STORE_IDX);
        payload.src0 = mir.aux;
        payload.src1 = scratch;
        payload.imm = hlayout::HEADER_BYTES as i32 + 8;
        if !machine.push(payload) {
            return false;
        }
        if machine.vreg_kind(mir.aux) == kinds::KIND_TBL {
            return emit_barrier(machine, mir.aux);
        }
        return true;
    }
    if mir.imm < 0 {
        return false;
    }
    // The value temp must not be the address register (scratch): the slot
    // loads would destroy the heap address before the cell stores use it.
    let scratch_gpr = machine.scratch_gpr2();
    let mut tag = MachineInsn::new(X_MOV_SLOT_R);
    tag.dst = scratch_gpr;
    tag.imm = slot_tag_disp(mir.imm);
    if !machine.push(tag) {
        return false;
    }
    let mut store_tag = MachineInsn::new(X_STORE_IDX);
    store_tag.src0 = scratch_gpr;
    store_tag.src1 = scratch;
    store_tag.imm = hlayout::HEADER_BYTES as i32;
    if !machine.push(store_tag) {
        return false;
    }
    let mut payload = MachineInsn::new(X_MOV_SLOT_R);
    payload.dst = scratch_gpr;
    payload.imm = slot_payload_disp(mir.imm);
    if !machine.push(payload) {
        return false;
    }
    let mut store_payload = MachineInsn::new(X_STORE_IDX);
    store_payload.src0 = scratch_gpr;
    store_payload.src1 = scratch;
    store_payload.imm = hlayout::HEADER_BYTES as i32 + 8;
    machine.push(store_payload)
}

fn lower_load_global(mir: &MirInsn, machine: &mut MachineFunction) -> bool {
    let scratch = machine.scratch_gpr();
    let mut tag = MachineInsn::new(X_MOV_SLOT_R);
    tag.dst = scratch;
    tag.imm = global_tag_disp(mir.imm);
    if !machine.push(tag) {
        return false;
    }
    let mut store_tag = MachineInsn::new(X_MOV_R_SLOT);
    store_tag.src0 = scratch;
    store_tag.imm = slot_tag_disp(mir.aux as i32);
    if !machine.push(store_tag) {
        return false;
    }
    let mut payload = MachineInsn::new(X_MOV_SLOT_R);
    payload.dst = scratch;
    payload.imm = global_payload_disp(mir.imm);
    if !machine.push(payload) {
        return false;
    }
    let mut store_payload = MachineInsn::new(X_MOV_R_SLOT);
    store_payload.src0 = scratch;
    store_payload.imm = slot_payload_disp(mir.aux as i32);
    machine.push(store_payload)
}

fn lower_store_global(mir: &MirInsn, machine: &mut MachineFunction) -> bool {
    // Two conventions:
    //   src0 != 0: store from a vreg payload with a static tag (imm = global id,
    //              aux = value kind);
    //   src0 == 0: legacy slot-to-slot copy (imm = source slot, aux = global id).
    if mir.src0 != 0 {
        let scratch = machine.scratch_gpr();
        let mut tag = MachineInsn::new(X_MOV_IR);
        tag.dst = scratch;
        tag.imm = kind_tag(mir.aux as u8) as i32;
        if !machine.push(tag) {
            return false;
        }
        let mut store_tag = MachineInsn::new(X_MOV_R_SLOT);
        store_tag.src0 = scratch;
        store_tag.imm = global_tag_disp(mir.imm);
        if !machine.push(store_tag) {
            return false;
        }
        let mut payload = MachineInsn::new(X_MOV_R_SLOT);
        payload.src0 = mir.src0;
        payload.imm = global_payload_disp(mir.imm);
        return machine.push(payload);
    }
    let scratch = machine.scratch_gpr();
    let mut tag = MachineInsn::new(X_MOV_SLOT_R);
    tag.dst = scratch;
    tag.imm = slot_tag_disp(mir.imm);
    if !machine.push(tag) {
        return false;
    }
    let mut store_tag = MachineInsn::new(X_MOV_R_SLOT);
    store_tag.src0 = scratch;
    store_tag.imm = global_tag_disp(mir.aux as i32);
    if !machine.push(store_tag) {
        return false;
    }
    let mut payload = MachineInsn::new(X_MOV_SLOT_R);
    payload.dst = scratch;
    payload.imm = slot_payload_disp(mir.imm);
    if !machine.push(payload) {
        return false;
    }
    let mut store_payload = MachineInsn::new(X_MOV_R_SLOT);
    store_payload.src0 = scratch;
    store_payload.imm = global_payload_disp(mir.aux as i32);
    machine.push(store_payload)
}

fn lower_new_table(mir: &MirInsn, machine: &mut MachineFunction) -> bool {
    let alloc_cursor = PHYS_ALLOC_CURSOR;
    let mut handle = MachineInsn::new(X_MOV_RR);
    handle.dst = mir.dst;
    handle.src0 = alloc_cursor;
    if !machine.push(handle) {
        return false;
    }
    let mut shr = MachineInsn::new(X_SHR_IR);
    shr.dst = mir.dst;
    shr.imm = 4;
    if !machine.push(shr) {
        return false;
    }
    let mut zero_header_a = MachineInsn::new(X_STORE_ZERO_IDX);
    zero_header_a.src0 = alloc_cursor;
    zero_header_a.imm = 0;
    if !machine.push(zero_header_a) {
        return false;
    }
    let mut zero_header_b = MachineInsn::new(X_STORE_ZERO_IDX);
    zero_header_b.src0 = alloc_cursor;
    zero_header_b.imm = 8;
    if !machine.push(zero_header_b) {
        return false;
    }
    let cells = mir.imm.max(0).min(8) as i32;
    let mut cell = 0i32;
    while cell < cells {
        let mut zero_cell = MachineInsn::new(X_STORE_ZERO_IDX);
        zero_cell.src0 = alloc_cursor;
        zero_cell.imm = hlayout::HEADER_BYTES as i32 + cell * (hlayout::CELL_BYTES as i32);
        if !machine.push(zero_cell) {
            return false;
        }
        cell += 1;
    }
    let mut advance = MachineInsn::new(X_ADD_IR);
    advance.dst = alloc_cursor;
    advance.imm = table_bytes(mir.imm);
    machine.push(advance)
}

fn lower_alloc_check(mir: &MirInsn, machine: &mut MachineFunction) -> bool {
    let scratch = machine.scratch_gpr();
    let mut bump = MachineInsn::new(X_MOV_SLOT_R);
    bump.dst = scratch;
    bump.imm = layout::BUMP_PTR as i32;
    if !machine.push(bump) {
        return false;
    }
    let mut set_cursor = MachineInsn::new(X_MOV_RR);
    set_cursor.dst = PHYS_ALLOC_CURSOR;
    set_cursor.src0 = scratch;
    if !machine.push(set_cursor) {
        return false;
    }
    let mut add = MachineInsn::new(X_ADD_IR);
    add.dst = scratch;
    add.imm = mir.imm;
    if !machine.push(add) {
        return false;
    }
    let mut limit = MachineInsn::new(X_MOV_SLOT_R);
    limit.dst = machine.scratch_gpr2();
    limit.imm = layout::EDEN_END as i32;
    if !machine.push(limit) {
        return false;
    }
    let mut cmp = MachineInsn::new(X_CMP_RR);
    cmp.src0 = scratch;
    cmp.src1 = machine.scratch_gpr2();
    if !machine.push(cmp) {
        return false;
    }
    let mut commit = MachineInsn::new(X_MOV_R_SLOT);
    commit.src0 = scratch;
    commit.imm = layout::BUMP_PTR as i32;
    if !machine.push(commit) {
        return false;
    }
    let mut branch = MachineInsn::new(X_JCC_REL);
    branch.imm = 0x2;
    branch.aux = crate::machine::LABEL_ALLOC_STUB;
    machine.push(branch)
}

/// Physical cursor register reference that bypasses allocation.
pub const PHYS_ALLOC_CURSOR: u16 = PHYS_BASE + ssl_config::target_model::abi_reservation::ALLOC_CURSOR_GPR as u16;

/// Forms the scratch address of one cell and returns the scratch vreg id.
pub fn cell_address(table: u16, index: u16, machine: &mut MachineFunction) -> u16 {
    let scratch = machine.scratch_gpr();
    let scratch2 = machine.scratch_gpr2();
    let mut load = MachineInsn::new(X_MOV_RR);
    load.dst = scratch;
    load.src0 = table;
    if !machine.push(load) {
        return scratch;
    }
    let mut shift = MachineInsn::new(X_SHL_IR);
    shift.dst = scratch;
    shift.imm = 4;
    if !machine.push(shift) {
        return scratch;
    }
    let mut load_index = MachineInsn::new(X_MOV_RR);
    load_index.dst = scratch2;
    load_index.src0 = index;
    if !machine.push(load_index) {
        return scratch;
    }
    let mut shift_index = MachineInsn::new(X_SHL_IR);
    shift_index.dst = scratch2;
    shift_index.imm = 4;
    if !machine.push(shift_index) {
        return scratch;
    }
    let mut combine = MachineInsn::new(X_ADD_RR);
    combine.dst = scratch;
    combine.src0 = scratch;
    // src1 carries the addend (X_ADD_RR computes dst = src0 + src1); leaving
    // it at the zero-initialized vreg id made the heap address depend on an
    // unrelated live value instead of the scaled index.
    combine.src1 = scratch2;
    let _ = machine.push(combine);
    scratch
}

/// Total allocation bytes for one table of the given cell length.
pub const fn table_bytes(len: i32) -> i32 {
    hlayout::HEADER_BYTES as i32
        + len * (hlayout::CELL_BYTES as i32)
        + 8 * (ssl_config::limits::PROP_PAIR_BYTES as i32)
}

/// Maps a slot kind to its runtime tag constant.
pub const fn kind_tag(kind: u8) -> u64 {
    match kind {
        kinds::KIND_INT => TAG_INT,
        kinds::KIND_NUM => TAG_NUM,
        kinds::KIND_BOOL => TAG_BOOL,
        kinds::KIND_STR => TAG_STR,
        kinds::KIND_NIL => 0,
        _ => TAG_TBL,
    }
}

/// Emits the write-barrier append for one reference-valued register.
fn emit_barrier(machine: &mut MachineFunction, handle_vreg: u16) -> bool {
    let scratch = machine.scratch_gpr();
    let scratch2 = machine.scratch_gpr2();
    let mut cursor = MachineInsn::new(X_MOV_SLOT_R);
    cursor.dst = scratch;
    cursor.imm = layout::BARRIER_CURSOR as i32;
    if !machine.push(cursor) {
        return false;
    }
    let mut capacity = MachineInsn::new(X_MOV_SLOT_R);
    capacity.dst = scratch2;
    capacity.imm = layout::BARRIER_CAPACITY as i32;
    if !machine.push(capacity) {
        return false;
    }
    let mut cmp = MachineInsn::new(X_CMP_RR);
    cmp.src0 = scratch;
    cmp.src1 = scratch2;
    if !machine.push(cmp) {
        return false;
    }
    let skip = match machine.alloc_label() {
        Some(label) => label,
        None => return false,
    };
    let mut branch = MachineInsn::new(X_JCC_REL);
    branch.imm = 0x3;
    branch.aux = skip;
    if !machine.push(branch) {
        return false;
    }
    let mut store = MachineInsn::new(X_STORE_IDX);
    store.src0 = handle_vreg;
    store.src1 = scratch;
    store.imm = ssl_config::limits::BARRIER_ARENA_OFFSET as i32;
    store.aux = 2;
    if !machine.push(store) {
        return false;
    }
    let mut advance = MachineInsn::new(X_ADD_IR);
    advance.dst = scratch;
    advance.imm = 1;
    if !machine.push(advance) {
        return false;
    }
    let mut commit = MachineInsn::new(X_MOV_R_SLOT);
    commit.src0 = scratch;
    commit.imm = layout::BARRIER_CURSOR as i32;
    if !machine.push(commit) {
        return false;
    }
    let mut bind = MachineInsn::new(X_BIND_LABEL);
    bind.aux = skip;
    machine.push(bind)
}
