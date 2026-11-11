// CEP:FILE: hot/src/interp_step.rs
// CEP:WHAT: Single-step bytecode execution engine with a structured step record consumed by both the interpreter loop and the trace recorder.
// CEP:WHY: design.md Part 2 requires one interpreter as the profiling and recording engine; a shared step function guarantees the recorder observes exactly the semantics the interpreter executes.
// CEP:CLASS: CEP-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns RunError for malformed bytecode, bad slot or constant indices, table key range violations, global range violations, unknown math ids, and heap exhaustion; never panics.
// CEP:ASSUMES: program words were validated by the cold assembler airlock; the step function re-checks every index defensively because bytecode is untrusted until proven.
// CEP:COST: one dispatch per executed instruction; arithmetic uses integer fast paths with no allocation.
// CEP:EVIDENCE: unit tests ssl-tests::unit_interp; differential tests interpreter versus JIT.

use crate::bytecode as bc;
use crate::heap;
use crate::vm_state::VmState;
use crate::vm_table;
use crate::vm_value::SslValue;
use ssl_config::limits as L;

/// Runtime failure enumeration; no panics escape this module.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum RunError {
    /// Program counter left the word range.
    PcOutOfRange,
    /// Opcode number is not part of SSL-BC v1.
    BadOpcode,
    /// Slot operand exceeded the declared slot count.
    BadSlot,
    /// Constant index exceeded the constant pool.
    BadConst,
    /// Table array index exceeded the array length.
    TableIndexOutOfRange,
    /// Table handle invalid or object malformed.
    BadTable,
    /// Property capacity exceeded on a string-keyed write.
    PropCapacityExceeded,
    /// Global slot id exceeded the global array.
    GlobalOutOfRange,
    /// Math builtin identifier unknown.
    BadMathFn,
    /// Heap could not serve the allocation.
    HeapExhausted,
    /// Output buffer cursor exceeded its bound.
    OutputOverflow,
}

/// Effects observed by the recorder for one executed instruction.
#[derive(Copy, Clone, Debug)]
pub struct StepRecord {
    /// Opcode executed.
    pub op: u8,
    /// Destination slot when the instruction writes one.
    pub dst: u8,
    /// First operand slot when present.
    pub lhs: u8,
    /// Second operand slot when present.
    pub rhs: u8,
    /// Left operand value observed this execution.
    pub lhs_val: SslValue,
    /// Right operand value observed this execution.
    pub rhs_val: SslValue,
    /// Result value written this execution.
    pub result: SslValue,
    /// Table handle observed for table operations.
    pub table: u32,
    /// Immediate word observed for jumps and immediates.
    pub imm: i32,
    /// Instruction word index of this step.
    pub pc: u32,
    /// Total words consumed by this instruction.
    pub width: u32,
}

/// Executes one instruction, applying its effects and returning the observation record.
pub fn step(
    state: &mut VmState,
    prog: &bc::Program,
    heap: &mut [u8],
    survivor_bump: &mut u32,
    out_cursor: &mut u32,
    out_cap: u32,
) -> Result<StepRecord, RunError> {
    let pc = state.pc as usize;
    if pc >= prog.words.len() {
        return Err(RunError::PcOutOfRange);
    }
    let word = prog.words[pc];
    let op = bc::decode_op(word);
    let a = bc::decode_a(word);
    let b = bc::decode_b(word);
    let c = bc::decode_c(word);
    let width = if bc::has_immediate(op) { 2 } else { 1 };
    let imm = if bc::has_immediate(op) && pc + 1 < prog.words.len() {
        prog.words[pc + 1] as i32
    } else {
        0
    };
    let mut record = StepRecord {
        op,
        dst: a,
        lhs: b,
        rhs: c,
        lhs_val: SslValue::nil(),
        rhs_val: SslValue::nil(),
        result: SslValue::nil(),
        table: 0,
        imm,
        pc: pc as u32,
        width,
    };
    match op {
        bc::OP_LOADK => {
            let value = const_value(prog, b as u32 | (c as u32) << 8)?;
            state.set_slot(a as u32, value);
            record.result = value;
        }
        bc::OP_MOVE => {
            let value = slot_value(state, b as u32)?;
            state.set_slot(a as u32, value);
            record.result = value;
        }
        bc::OP_ADDI => {
            let lhs = slot_value(state, b as u32)?;
            let sum = int_op(lhs.as_int(), imm as i64, |x, y| x.wrapping_add(y));
            let value = SslValue::integer(sum);
            state.set_slot(a as u32, value);
            record.lhs_val = lhs;
            record.rhs_val = SslValue::integer(imm as i64);
            record.result = value;
        }
        bc::OP_ADD | bc::OP_SUB | bc::OP_MUL | bc::OP_DIV => {
            let lhs = slot_value(state, b as u32)?;
            let rhs = slot_value(state, c as u32)?;
            let value = numeric_op(op, lhs, rhs)?;
            state.set_slot(a as u32, value);
            record.lhs_val = lhs;
            record.rhs_val = rhs;
            record.result = value;
        }
        bc::OP_LT | bc::OP_LE | bc::OP_EQ | bc::OP_GT | bc::OP_GE | bc::OP_NE => {
            let lhs = slot_value(state, b as u32)?;
            let rhs = slot_value(state, c as u32)?;
            let value = compare_op(op, lhs, rhs);
            state.set_slot(a as u32, value);
            record.lhs_val = lhs;
            record.rhs_val = rhs;
            record.result = value;
        }
        bc::OP_JMP => {
            state.pc = jump_target(pc as u32, imm)?;
            return Ok(record);
        }
        bc::OP_JMPIF | bc::OP_JMPNOT => {
            let cond = slot_value(state, a as u32)?;
            record.lhs_val = cond;
            let taken = if op == bc::OP_JMPIF {
                cond.is_truthy()
            } else {
                !cond.is_truthy()
            };
            if taken {
                state.pc = jump_target(pc as u32, imm)?;
                return Ok(record);
            }
        }
        bc::OP_TNEW => {
            let len = imm as u32;
            let handle = heap::alloc_table_eden(heap, state, len).ok_or(RunError::HeapExhausted)?;
            state.set_slot(a as u32, SslValue::table(handle));
            record.result = SslValue::table(handle);
        }
        bc::OP_TGETI => {
            let tab = slot_value(state, b as u32)?;
            let idx = slot_value(state, c as u32)?;
            record.lhs_val = tab;
            record.rhs_val = idx;
            let value = table_get_index(heap, tab, idx)?;
            state.set_slot(a as u32, value);
            record.result = value;
        }
        bc::OP_TSETI => {
            let val = slot_value(state, a as u32)?;
            let tab = slot_value(state, b as u32)?;
            let idx = slot_value(state, c as u32)?;
            record.lhs_val = tab;
            record.rhs_val = idx;
            record.result = val;
            table_set_index(heap, tab, idx, val)?;
        }
        bc::OP_TGETK => {
            let tab = slot_value(state, b as u32)?;
            let key = const_value(prog, c as u32)?;
            let key_handle = if key.tag == crate::vm_value::TAG_STR {
                key.as_handle()
            } else {
                return Err(RunError::BadConst);
            };
            let value = vm_table::get_prop(heap, tab.as_handle(), key_handle)
                .ok_or(RunError::BadTable)?;
            state.set_slot(a as u32, value);
            record.lhs_val = tab;
            record.result = value;
        }
        bc::OP_TSETK => {
            let val = slot_value(state, a as u32)?;
            let tab = slot_value(state, b as u32)?;
            let key = const_value(prog, c as u32)?;
            let key_handle = if key.tag == crate::vm_value::TAG_STR {
                key.as_handle()
            } else {
                return Err(RunError::BadConst);
            };
            vm_table::set_prop(heap, tab.as_handle(), key_handle, val)
                .ok_or(RunError::PropCapacityExceeded)?;
            vm_table::note_prop_write(heap, tab.as_handle()).ok_or(RunError::BadTable)?;
            record.lhs_val = tab;
            record.result = val;
        }
        bc::OP_GGET => {
            let value = *state.global(c as u32).ok_or(RunError::GlobalOutOfRange)?;
            state.set_slot(a as u32, value);
            record.result = value;
        }
        bc::OP_GSET => {
            let value = slot_value(state, a as u32)?;
            let index = c as u32;
            if index >= L::MAX_SLOTS {
                return Err(RunError::GlobalOutOfRange);
            }
            state.set_global(index, value);
            record.result = value;
        }
        bc::OP_CALLM => {
            let arg = slot_value(state, c as u32)?;
            let value = math_value(b, arg).ok_or(RunError::BadMathFn)?;
            state.set_slot(a as u32, value);
            record.lhs_val = arg;
            record.result = value;
        }
        bc::OP_PRINT => {
            let value = slot_value(state, a as u32)?;
            if *out_cursor >= out_cap {
                return Err(RunError::OutputOverflow);
            }
            record.result = value;
        }
        bc::OP_RET => {}
        _ => return Err(RunError::BadOpcode),
    }
    if op != bc::OP_JMP {
        state.pc = (pc as u32) + width;
    }
    Ok(record)
}

/// Reads one slot with defensive bounds checking.
pub fn slot_value(state: &VmState, index: u32) -> Result<SslValue, RunError> {
    state
        .slot(index)
        .copied()
        .ok_or(RunError::BadSlot)
}

/// Reads one constant with defensive bounds checking.
pub fn const_value(prog: &bc::Program, index: u32) -> Result<SslValue, RunError> {
    match prog.consts.get(index as usize) {
        Some(bc::Const::Int(v)) => Ok(SslValue::integer(*v)),
        Some(bc::Const::Num(v)) => Ok(SslValue::number(*v)),
        Some(bc::Const::Str(h)) => Ok(SslValue::string(*h)),
        None => Err(RunError::BadConst),
    }
}

/// Applies one integer arithmetic combinator.
fn int_op(lhs: i64, rhs: i64, comb: fn(i64, i64) -> i64) -> i64 {
    comb(lhs, rhs)
}

/// Type-specializes numeric arithmetic per the dual-number model; overflow widens to double.
fn numeric_op(op: u8, lhs: SslValue, rhs: SslValue) -> Result<SslValue, RunError> {
    if lhs.is_int() && rhs.is_int() && op != bc::OP_DIV {
        let a = lhs.as_int();
        let b = rhs.as_int();
        let checked = match op {
            bc::OP_ADD => a.checked_add(b),
            bc::OP_SUB => a.checked_sub(b),
            _ => a.checked_mul(b),
        };
        if let Some(result) = checked {
            return Ok(SslValue::integer(result));
        }
    }
    let a = value_as_num(lhs);
    let b = value_as_num(rhs);
    let result = match op {
        bc::OP_ADD => a + b,
        bc::OP_SUB => a - b,
        bc::OP_MUL => a * b,
        _ => a / b,
    };
    Ok(SslValue::number(result))
}

/// Widens any numeric value to double for the float path.
pub fn value_as_num(value: SslValue) -> f64 {
    if value.is_int() {
        value.as_int() as f64
    } else {
        value.as_num()
    }
}

/// Executes one comparison per the mixed int and double ordering rules.
fn compare_op(op: u8, lhs: SslValue, rhs: SslValue) -> SslValue {
    let ordered = if lhs.is_int() && rhs.is_int() {
        let (a, b) = (lhs.as_int(), rhs.as_int());
        match op {
            bc::OP_LT => a < b,
            bc::OP_LE => a <= b,
            bc::OP_EQ => a == b,
            bc::OP_GT => a > b,
            bc::OP_GE => a >= b,
            _ => a != b,
        }
    } else {
        let (a, b) = (value_as_num(lhs), value_as_num(rhs));
        match op {
            bc::OP_LT => a < b,
            bc::OP_LE => a <= b,
            bc::OP_EQ => a == b,
            bc::OP_GT => a > b,
            bc::OP_GE => a >= b,
            _ => a != b,
        }
    };
    SslValue::boolean(ordered)
}

/// Computes one math builtin; integer abs stays integral.
pub fn math_value(fnid: u8, arg: SslValue) -> Option<SslValue> {
    match fnid {
        bc::MATH_SIN => Some(SslValue::number(sin_approx(value_as_num(arg)))),
        bc::MATH_COS => Some(SslValue::number(cos_approx(value_as_num(arg)))),
        bc::MATH_SQRT => Some(SslValue::number(sqrt_approx(value_as_num(arg)))),
        bc::MATH_ABS => {
            if arg.is_int() {
                Some(SslValue::integer(arg.as_int().abs()))
            } else {
                Some(SslValue::number(value_as_num(arg).abs()))
            }
        }
        bc::MATH_FLOOR => Some(SslValue::integer(value_as_num(arg).floor() as i64)),
        _ => None,
    }
}

/// Deterministic double-precision sine (platform libm replaced for target-independent output).
fn sin_approx(x: f64) -> f64 {
    // Range-reduced Taylor series with documented error bound; see docs/compiler/math_builtins.md.
    let pi2 = core::f64::consts::PI * 2.0;
    let mut y = x % pi2;
    if y > core::f64::consts::PI {
        y -= pi2;
    }
    if y < -core::f64::consts::PI {
        y += pi2;
    }
    let x2 = y * y;
    let mut term = y;
    let mut sum = 0.0;
    let mut k = 1.0;
    let mut sign = 1.0;
    let mut iter = 0;
    while iter < L::MATH_TERMS {
        sum += sign * term;
        term *= x2 / ((k + 1.0) * (k + 2.0));
        sign = -sign;
        k += 2.0;
        iter += 1;
    }
    sum
}

/// Deterministic double-precision cosine via the quarter-period shift identity.
fn cos_approx(x: f64) -> f64 {
    sin_approx(x + core::f64::consts::FRAC_PI_2)
}

/// Deterministic double-precision square root via the Newton iteration with proof bound.
fn sqrt_approx(x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    let mut guess = x;
    let mut iter = 0;
    while iter < L::SQRT_TERMS {
        guess = 0.5 * (guess + x / guess);
        iter += 1;
    }
    guess
}

/// Public sine wrapper shared with emitted traces.
pub fn math_sin_public(x: f64) -> f64 {
    sin_approx(x)
}

/// Public cosine wrapper shared with emitted traces.
pub fn math_cos_public(x: f64) -> f64 {
    cos_approx(x)
}

/// Public square root wrapper shared with emitted traces.
pub fn math_sqrt_public(x: f64) -> f64 {
    sqrt_approx(x)
}

/// Public absolute value wrapper shared with emitted traces.
pub fn math_fabs_public(x: f64) -> f64 {
    if x < 0.0 {
        -x
    } else {
        x
    }
}

/// Public floor wrapper shared with emitted traces.
pub fn math_floor_public(x: f64) -> f64 {
    value_as_num(SslValue::number(x)).floor()
}

/// Resolves the absolute word target of one relative jump.
pub fn jump_target(pc: u32, offset: i32) -> Result<u32, RunError> {
    let next = pc + 2;
    let target = next as i64 + offset as i64;
    if target < 0 || target > u32::MAX as i64 {
        return Err(RunError::PcOutOfRange);
    }
    Ok(target as u32)
}

/// Reads one array cell, returning nil for holes above the length.
pub fn table_get_index(heap: &[u8], tab: SslValue, idx: SslValue) -> Result<SslValue, RunError> {
    if !tab.is_table() {
        return Err(RunError::BadTable);
    }
    if !idx.is_int() {
        return Err(RunError::TableIndexOutOfRange);
    }
    let index = idx.as_int();
    if index < 0 {
        return Err(RunError::TableIndexOutOfRange);
    }
    Ok(vm_table::get_cell(heap, tab.as_handle(), index as u32).unwrap_or(SslValue::nil()))
}

/// Writes one array cell with defensive bounds checking.
pub fn table_set_index(
    heap: &mut [u8],
    tab: SslValue,
    idx: SslValue,
    value: SslValue,
) -> Result<(), RunError> {
    if !tab.is_table() {
        return Err(RunError::BadTable);
    }
    if !idx.is_int() {
        return Err(RunError::TableIndexOutOfRange);
    }
    let index = idx.as_int();
    if index < 0 {
        return Err(RunError::TableIndexOutOfRange);
    }
    vm_table::set_cell(heap, tab.as_handle(), index as u32, value)
        .ok_or(RunError::TableIndexOutOfRange)
}
