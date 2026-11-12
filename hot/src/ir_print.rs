// CEP:FILE: hot/src/ir_print.rs
// CEP:WHAT: Deterministic text printer for the SoA IR used by golden tests, remarks, and debugging.
// CEP:WHY: Chapter 38.17 requires printable, hashable IR with stable ordering; the printer renders nodes in index order into a caller-provided buffer.
// CEP:CLASS: HPC-1
// CEP:STATUS: complete
// CEP:FAILURE: Truncates at buffer capacity; never panics.
// CEP:ASSUMES: the buffer is caller-provided and large enough for review use; golden tests pin the exact rendering.
// CEP:COST: cold; O(N) over nodes with bounded integer formatting.
// CEP:EVIDENCE: golden IR tests in tests/golden.

use crate::ir::*;

/// Renders the IR to a caller-provided byte buffer; returns the written length.
pub fn render(trace: &IrTrace, out: &mut [u8]) -> usize {
    let mut cursor = 0usize;
    for idx in 0..trace.count as usize {
        if trace.op[idx] == OP_NOP {
            continue;
        }
        cursor = write_str(out, cursor, "n");
        cursor = write_u16(out, cursor, idx as u16);
        cursor = write_str(out, cursor, " = ");
        cursor = write_str(out, cursor, op_name(trace.op[idx]));
        if trace.op[idx] == OP_PARAM || trace.op[idx] == OP_PHI {
            cursor = write_str(out, cursor, " s");
            cursor = write_u16(out, cursor, trace.aux[idx]);
        }
        for operand in [trace.in0[idx], trace.in1[idx], trace.in2[idx]] {
            if operand != NO_OPERAND {
                cursor = write_str(out, cursor, " n");
                cursor = write_u16(out, cursor, operand);
            }
        }
        if trace.op[idx] == OP_TNEW || trace.imm[idx] != 0 {
            cursor = write_str(out, cursor, " imm=");
            cursor = write_i32(out, cursor, trace.imm[idx]);
        }
        cursor = write_str(out, cursor, " ty=");
        cursor = write_str(out, cursor, ty_name(trace.ty[idx]));
        if (trace.flags[idx] & FLAG_MEMORY) != 0 {
            cursor = write_str(out, cursor, " mem");
        }
        cursor = write_str(out, cursor, "\n");
        if cursor >= out.len() {
            return out.len();
        }
    }
    cursor
}

fn op_name(op: u16) -> &'static str {
    match op {
        OP_CONST_I => "const_i",
        OP_CONST_F => "const_f",
        OP_PARAM => "param",
        OP_PHI => "phi",
        OP_COPY_S => "copy_s",
        OP_ADD_I => "add_i",
        OP_SUB_I => "sub_i",
        OP_MUL_I => "mul_i",
        OP_ADD_F => "add_f",
        OP_SUB_F => "sub_f",
        OP_MUL_F => "mul_f",
        OP_DIV_F => "div_f",
        OP_LT_I => "lt_i",
        OP_LE_I => "le_i",
        OP_EQ_I => "eq_i",
        OP_NE_I => "ne_i",
        OP_LT_F => "lt_f",
        OP_LE_F => "le_f",
        OP_EQ_F => "eq_f",
        OP_NE_F => "ne_f",
        OP_GUARD_INT => "guard_int",
        OP_GUARD_NUM => "guard_num",
        OP_GUARD_SHAPE => "guard_shape",
        OP_GUARD_BOOL => "guard_bool",
        OP_TNEW => "tnew",
        OP_TGETI => "tgeti",
        OP_TSETI => "tseti",
        OP_GLOAD => "gload",
        OP_GSTORE => "gstore",
        OP_CALLM => "callm",
        OP_INT2F => "int2f",
        OP_VLOAD_F => "vload_f",
        OP_VSTORE_F => "vstore_f",
        OP_VADD_F => "vadd_f",
        OP_VSUB_F => "vsub_f",
        OP_VMUL_F => "vmul_f",
        OP_VPACK => "vpack",
        OP_HADD_F => "hadd_f",
        OP_VSPLAT_F => "vsplat_f",
        _ => "unknown",
    }
}

fn ty_name(ty: u8) -> &'static str {
    match ty {
        TY_INT => "int",
        TY_NUM => "num",
        TY_BOOL => "bool",
        TY_TBL => "tbl",
        TY_VEC => "vec",
        _ => "any",
    }
}

fn write_str(out: &mut [u8], cursor: usize, text: &str) -> usize {
    let mut at = cursor;
    for byte in text.bytes() {
        if at >= out.len() {
            return out.len();
        }
        out[at] = byte;
        at += 1;
    }
    at
}

fn write_u16(out: &mut [u8], cursor: usize, mut value: u16) -> usize {
    let mut scratch = [0u8; 5];
    let mut len = 0usize;
    if value == 0 {
        scratch[0] = b'0';
        len = 1;
    }
    while value > 0 {
        scratch[len] = b'0' + (value % 10) as u8;
        value /= 10;
        len += 1;
    }
    let mut at = cursor;
    while len > 0 {
        len -= 1;
        if at >= out.len() {
            return out.len();
        }
        out[at] = scratch[len];
        at += 1;
    }
    at
}

fn write_i32(out: &mut [u8], cursor: usize, value: i32) -> usize {
    let mut at = cursor;
    let unsigned = if value < 0 {
        at = write_str(out, at, "-");
        (value as i64).unsigned_abs() as u32
    } else {
        value as u32
    };
    write_u16(out, at, unsigned as u16)
}
