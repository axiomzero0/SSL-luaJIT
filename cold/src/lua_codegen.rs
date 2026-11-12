// CEP:FILE: cold/src/lua_codegen.rs
// CEP:WHAT: The AST-to-bytecode compiler: slot allocation with scopes, constant-pool dedup, label fixups, and lowered control flow for the SSL-BC ISA.
// CEP:WHY: The frontend must emit the exact instruction shapes the interpreter and recorder execute; one compiler keeps Lua semantics and ISA constraints in agreement.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: Returns FrontendError for slot, constant, global, and jump-range overflows, string comparisons outside the string==string subset, zero for-steps, and nil comparisons needing truthiness lowering; never panics.
// CEP:ASSUMES: ISA word layout from bytecode.rs; jump offsets are relative to the word after the immediate; slots default to nil; ADDI is emitted only when the induction variable starts as an integer literal and the step fits i32; ordering comparisons on string literals are rejected because the ISA compares numerically; == and ~= lower to interned-handle equality only when both operands are string literals.
// CEP:COST: O(AST size); linear emit with back-patched jumps.
// CEP:EVIDENCE: differential tests ssl-tests::unit_lua_codegen and unit_lua_programs; reviewer-verified traces of sum/table/condition programs.

use crate::lua_ast::*;
use ssl_config::limits as L;
use ssl_hot::bytecode as bc;
use std::collections::HashMap;

/// Assembled output mirroring the assembler crate's program shape.
#[derive(Clone, Debug)]
pub struct CompiledProgram {
    /// Bytecode words.
    pub words: Vec<u32>,
    /// Constant pool.
    pub consts: Vec<bc::Const>,
    /// String table referenced by Str constants (pre-interning).
    pub strings: Vec<String>,
    /// Highest slot used, including the reserved nil-source slot 0.
    pub slot_count: u32,
    /// Global names in assignment order.
    pub global_names: Vec<String>,
}

/// Compiles one parsed chunk to bytecode.
pub fn compile(chunk: &Chunk) -> Result<CompiledProgram, FrontendError> {
    let mut gen = CodeGen::new();
    gen.compile_chunk(chunk)?;
    let slot_count = gen.slots.high_water();
    let words_len = gen.words.len();
    if words_len > L::MAX_PROGRAM_WORDS as usize {
        return Err(FrontendError::new(0, "program exceeds MAX_PROGRAM_WORDS"));
    }
    Ok(CompiledProgram {
        words: gen.words,
        consts: gen.consts,
        strings: gen.strings,
        slot_count,
        global_names: gen.global_names,
    })
}

/// Loop context for break resolution.
struct LoopCtx {
    break_label: usize,
}

/// Conditional compilation targets: either a jump label or fall-through.
#[derive(Clone, Copy)]
enum CondSide {
    Jump(usize),
    FallThrough,
}

/// Code generator state.
struct CodeGen {
    words: Vec<u32>,
    consts: Vec<bc::Const>,
    strings: Vec<String>,
    const_keys: HashMap<ConstKey, usize>,
    slots: SlotAlloc,
    scopes: Vec<HashMap<String, u32>>,
    globals: HashMap<String, u32>,
    global_names: Vec<String>,
    labels: Vec<Option<u32>>,
    fixups: Vec<(u32, usize)>,
    loops: Vec<LoopCtx>,
    next_label: usize,
}

/// Dedup key for the constant pool.
#[derive(Clone, PartialEq, Eq, Hash)]
enum ConstKey {
    Int(i64),
    NumBits(u64),
    Str(String),
}

/// Scoped slot allocator; slot 0 is reserved as the nil source.
struct SlotAlloc {
    next: u32,
    free: Vec<u32>,
    scope_slots: Vec<Vec<u32>>,
    high_water: u32,
}

impl SlotAlloc {
    fn new() -> SlotAlloc {
        SlotAlloc { next: 1, free: Vec::new(), scope_slots: Vec::new(), high_water: 1 }
    }

    fn alloc(&mut self) -> Result<u32, FrontendError> {
        let slot = match self.free.pop() {
            Some(s) => s,
            None => {
                let s = self.next;
                self.next += 1;
                s
            }
        };
        if slot >= L::MAX_SLOTS {
            return Err(FrontendError::new(0, "slot budget exceeded (max 256 slots)"));
        }
        if slot >= self.high_water {
            self.high_water = slot + 1;
        }
        if let Some(scope) = self.scope_slots.last_mut() {
            scope.push(slot);
        }
        Ok(slot)
    }

    /// Releases one slot; it must belong to the innermost scope.
    fn release(&mut self, slot: u32) {
        if let Some(scope) = self.scope_slots.last_mut() {
            if let Some(pos) = scope.iter().position(|s| *s == slot) {
                scope.swap_remove(pos);
            }
        }
        self.free.push(slot);
    }

    fn push_scope(&mut self) {
        self.scope_slots.push(Vec::new());
    }

    fn pop_scope(&mut self) {
        if let Some(scope) = self.scope_slots.pop() {
            for slot in scope {
                self.free.push(slot);
            }
        }
    }

    fn high_water(&self) -> u32 {
        self.high_water
    }
}

/// How the hidden loop slot is incremented each iteration.
enum StepSrc {
    /// Compile-time constant increment that fits the ADDI immediate and an
    /// integer start literal; ADDI keeps the hidden slot an integer.
    Addi(i32),
    /// Constant step that does not fit ADDI (or non-integer start); loaded
    /// into a hidden slot and applied with ADD so floats widen correctly.
    ConstSlot(u32),
    /// Runtime step expression in a hidden slot (sign selected per iteration).
    Runtime(u32),
}

impl CodeGen {
    fn new() -> CodeGen {
        CodeGen {
            words: Vec::new(),
            consts: Vec::new(),
            strings: Vec::new(),
            const_keys: HashMap::new(),
            slots: SlotAlloc::new(),
            scopes: vec![HashMap::new()],
            globals: HashMap::new(),
            global_names: Vec::new(),
            labels: Vec::new(),
            fixups: Vec::new(),
            loops: Vec::new(),
            next_label: 0,
        }
    }

    // ---- labels and jumps ----

    fn new_label(&mut self) -> usize {
        let id = self.next_label;
        self.next_label += 1;
        self.labels.push(None);
        id
    }

    /// Binds a label at the current word index and patches pending fixups.
    fn bind(&mut self, label: usize) {
        let at = self.words.len() as u32;
        self.labels[label] = Some(at);
        let mut remaining = Vec::new();
        for (fixup_at, target) in std::mem::take(&mut self.fixups) {
            if target == label {
                let offset = at as i64 - (fixup_at as i64 + 2);
                // Unreachable: programs are capped at MAX_PROGRAM_WORDS (2^18), so
                // every offset fits i32 with a huge margin.
                debug_assert!(offset >= i32::MIN as i64 && offset <= i32::MAX as i64);
                // The offset lands in the immediate word AFTER the jump word.
                self.words[fixup_at as usize + 1] = offset as i32 as u32;
            } else {
                remaining.push((fixup_at, target));
            }
        }
        self.fixups = remaining;
    }

    /// Emits one jump to a label, patching immediately when already bound.
    fn emit_jump(&mut self, op: u8, cond_slot: Option<u32>, label: usize) -> Result<(), FrontendError> {
        let at = self.words.len() as u32;
        let word = match cond_slot {
            Some(s) => bc::encode(op, s as u8, 0, 0),
            None => bc::encode(op, 0, 0, 0),
        };
        self.words.push(word);
        match self.labels[label] {
            Some(target) => {
                let offset = target as i64 - (at as i64 + 2);
                if offset < i32::MIN as i64 || offset > i32::MAX as i64 {
                    return Err(FrontendError::new(0, "jump offset out of range"));
                }
                self.words.push(offset as i32 as u32);
            }
            None => {
                self.words.push(0);
                self.fixups.push((at, label));
            }
        }
        Ok(())
    }

    // ---- constants ----

    fn const_int(&mut self, value: i64) -> Result<usize, FrontendError> {
        if let Some(idx) = self.const_keys.get(&ConstKey::Int(value)) {
            return Ok(*idx);
        }
        self.push_const(ConstKey::Int(value), bc::Const::Int(value))
    }

    fn const_num(&mut self, value: f64) -> Result<usize, FrontendError> {
        let key = ConstKey::NumBits(value.to_bits());
        if let Some(idx) = self.const_keys.get(&key) {
            return Ok(*idx);
        }
        self.push_const(key, bc::Const::Num(value))
    }

    /// Registers a string constant; returns (pool index, string-table index).
    fn const_str(&mut self, value: &str) -> Result<usize, FrontendError> {
        let key = ConstKey::Str(value.to_string());
        if let Some(idx) = self.const_keys.get(&key) {
            return Ok(*idx);
        }
        if self.strings.len() >= L::MAX_INTERNED_STRINGS as usize {
            return Err(FrontendError::new(0, "string table budget exceeded"));
        }
        self.strings.push(value.to_string());
        let idx = self.const_keys.len();
        self.consts.push(bc::Const::Str(self.strings.len() as u32 - 1));
        self.const_keys.insert(key, idx);
        Ok(idx)
    }

    fn push_const(&mut self, key: ConstKey, entry: bc::Const) -> Result<usize, FrontendError> {
        if self.consts.len() >= L::MAX_CONSTANTS as usize {
            return Err(FrontendError::new(0, "constant pool budget exceeded"));
        }
        let idx = self.consts.len();
        self.consts.push(entry);
        self.const_keys.insert(key, idx);
        Ok(idx)
    }

    /// Emits LOADK with the 16-bit constant index split across b and c.
    fn emit_loadk(&mut self, dst: u32, const_idx: usize) -> Result<(), FrontendError> {
        if const_idx > 0xFFFF {
            return Err(FrontendError::new(0, "constant index out of range"));
        }
        self.words.push(bc::encode(bc::OP_LOADK, dst as u8, const_idx as u8, (const_idx >> 8) as u8));
        Ok(())
    }

    // ---- variables ----

    fn declare_local(&mut self, name: &str, slot: u32) {
        let scope = self.scopes.last_mut().expect("scope stack never empty");
        scope.insert(name.to_string(), slot);
    }

    fn resolve_local(&self, name: &str) -> Option<u32> {
        for scope in self.scopes.iter().rev() {
            if let Some(slot) = scope.get(name) {
                return Some(*slot);
            }
        }
        None
    }

    /// Opens a name scope; must be paired with pop_name_scope exactly where
    /// push_scope/pop_scope bracket the same region, or block-local names
    /// would dangle onto recycled slots after their block ends.
    fn push_name_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }

    /// Closes the innermost name scope.
    fn pop_name_scope(&mut self) {
        self.scopes.pop();
    }

    fn global_id(&mut self, name: &str) -> Result<u32, FrontendError> {
        if let Some(id) = self.globals.get(name) {
            return Ok(*id);
        }
        if self.globals.len() >= 256 {
            return Err(FrontendError::new(0, "global budget exceeded (max 256 globals)"));
        }
        let id = self.globals.len() as u32;
        self.globals.insert(name.to_string(), id);
        self.global_names.push(name.to_string());
        Ok(id)
    }

    // ---- chunk and statements ----

    fn compile_chunk(&mut self, chunk: &Chunk) -> Result<(), FrontendError> {
        // Body block: locals live in the root scope.
        self.slots.push_scope();
        self.compile_block(&chunk.body)?;
        self.slots.pop_scope();
        // Programs always end with RET; nil-source slot 0 is a harmless operand.
        self.words.push(bc::encode(bc::OP_RET, 0, 0, 0));
        Ok(())
    }

    fn compile_block(&mut self, block: &Block) -> Result<(), FrontendError> {
        for stmt in &block.stmts {
            self.compile_stmt(stmt)?;
        }
        if let Some(expr) = &block.ret {
            let slot = self.slots.alloc()?;
            self.compile_expr(expr, slot)?;
            self.words.push(bc::encode(bc::OP_RET, slot as u8, 0, 0));
            self.slots.release(slot);
        }
        Ok(())
    }

    fn compile_stmt(&mut self, stmt: &Stmt) -> Result<(), FrontendError> {
        match stmt {
            Stmt::Local { names, exprs } => self.compile_local(names, exprs),
            Stmt::Assign { targets, exprs } => self.compile_assign(targets, exprs),
            Stmt::If { branches } => self.compile_if(branches),
            Stmt::While { cond, body } => self.compile_while(cond, body),
            Stmt::Repeat { body, cond } => self.compile_repeat(body, cond),
            Stmt::ForNum { var, start, limit, step, body, line } => {
                self.compile_for(var, start, limit, step.as_ref(), body, *line)
            }
            Stmt::Break { line } => {
                let label = match self.loops.last() {
                    Some(ctx) => ctx.break_label,
                    None => return Err(FrontendError::new(*line, "'break' outside of a loop")),
                };
                self.emit_jump(bc::OP_JMP, None, label)
            }
            Stmt::Do(block) => {
                self.slots.push_scope();
                self.push_name_scope();
                let result = self.compile_block(block);
                self.pop_name_scope();
                self.slots.pop_scope();
                result
            }
            Stmt::ExprStmt(expr) => match expr {
                Expr::Call { callee: Callee::Print, arg, .. } => {
                    let tmp = self.slots.alloc()?;
                    self.compile_expr(arg, tmp)?;
                    self.words.push(bc::encode(bc::OP_PRINT, tmp as u8, 0, 0));
                    self.slots.release(tmp);
                    Ok(())
                }
                Expr::Call { .. } => {
                    let tmp = self.slots.alloc()?;
                    self.compile_expr(expr, tmp)?;
                    self.slots.release(tmp);
                    Ok(())
                }
                other => {
                    let line = expr_line(other);
                    Err(FrontendError::new(line, "expression is not a statement"))
                }
            },
        }
    }

    fn compile_local(&mut self, names: &[(String, usize)], exprs: &[Expr]) -> Result<(), FrontendError> {
        // Evaluate all initializers into temps first so later RHS values see the
        // previous binding of same-named locals.
        let mut values: Vec<u32> = Vec::new();
        for expr in exprs {
            let tmp = self.slots.alloc()?;
            self.compile_expr(expr, tmp)?;
            values.push(tmp);
        }
        for (index, (name, _line)) in names.iter().enumerate() {
            let slot = self.slots.alloc()?;
            match values.get(index) {
                Some(tmp) => {
                    self.words.push(bc::encode(bc::OP_MOVE, slot as u8, *tmp as u8, 0));
                }
                None => {
                    // Missing initializer: nil (slot 0 is the reserved nil source).
                    self.words.push(bc::encode(bc::OP_MOVE, slot as u8, 0, 0));
                }
            }
            self.declare_local(name, slot);
        }
        for tmp in values {
            self.slots.release(tmp);
        }
        Ok(())
    }

    fn compile_assign(&mut self, targets: &[Target], exprs: &[Expr]) -> Result<(), FrontendError> {
        // Lua semantics: evaluate all RHS first, then store to targets left-to-right.
        let mut values: Vec<u32> = Vec::new();
        for expr in exprs {
            let tmp = self.slots.alloc()?;
            self.compile_expr(expr, tmp)?;
            values.push(tmp);
        }
        // Extra values are evaluated and discarded (Lua 5.1 behavior).
        for (index, target) in targets.iter().enumerate() {
            let value = match values.get(index) {
                Some(v) => *v,
                None => {
                    let tmp = self.slots.alloc()?;
                    self.words.push(bc::encode(bc::OP_MOVE, tmp as u8, 0, 0));
                    tmp
                }
            };
            self.store_target(target, value)?;
        }
        for tmp in values {
            self.slots.release(tmp);
        }
        Ok(())
    }

    fn store_target(&mut self, target: &Target, value: u32) -> Result<(), FrontendError> {
        match target {
            Target::Name { name, .. } => {
                if let Some(slot) = self.resolve_local(name) {
                    self.words.push(bc::encode(bc::OP_MOVE, slot as u8, value as u8, 0));
                } else {
                    let gid = self.global_id(name)?;
                    self.words.push(bc::encode(bc::OP_GSET, value as u8, 0, gid as u8));
                }
                Ok(())
            }
            Target::Index { table, key, line } => {
                let tab = self.slots.alloc()?;
                self.compile_expr(table, tab)?;
                match key {
                    Expr::StrLit(text, _) => {
                        let idx = self.const_str(text.as_str())?;
                        if idx > 0xFF {
                            return Err(FrontendError::new(
                                *line,
                                "string key constant index exceeds 255 (TSETK field width)",
                            ));
                        }
                        self.words.push(bc::encode(bc::OP_TSETK, value as u8, tab as u8, idx as u8));
                    }
                    key_expr => {
                        let key_slot = self.slots.alloc()?;
                        self.compile_expr(key_expr, key_slot)?;
                        self.words.push(bc::encode(
                            bc::OP_TSETI,
                            value as u8,
                            tab as u8,
                            key_slot as u8,
                        ));
                        self.slots.release(key_slot);
                    }
                }
                self.slots.release(tab);
                Ok(())
            }
        }
    }

    fn compile_if(&mut self, branches: &[(Expr, Block)]) -> Result<(), FrontendError> {
        let end_label = self.new_label();
        let last = branches.len() - 1;
        for (index, (cond, body)) in branches.iter().enumerate() {
            let is_else = index == last && matches!(cond, Expr::True(_));
            if is_else {
                self.slots.push_scope();
                self.push_name_scope();
                let result = self.compile_block(body);
                self.pop_name_scope();
                self.slots.pop_scope();
                result?;
                break;
            }
            let next_label = if index == last { end_label } else { self.new_label() };
            self.compile_cond(cond, CondSide::FallThrough, CondSide::Jump(next_label))?;
            self.slots.push_scope();
            self.push_name_scope();
            let result = self.compile_block(body);
            self.pop_name_scope();
            self.slots.pop_scope();
            result?;
            if index < last {
                self.emit_jump(bc::OP_JMP, None, end_label)?;
                self.bind(next_label);
            }
        }
        self.bind(end_label);
        Ok(())
    }

    fn compile_while(&mut self, cond: &Expr, body: &Block) -> Result<(), FrontendError> {
        let cond_label = self.new_label();
        let end_label = self.new_label();
        self.bind(cond_label);
        // Condition bool slots must survive the whole loop: the JIT deopt writeback
        // restores them when a guard exit resumes at the branch instruction.
        let mut keep = Vec::new();
        self.compile_cond_keep(cond, CondSide::FallThrough, CondSide::Jump(end_label), &mut keep)?;
        self.slots.push_scope();
        self.push_name_scope();
        self.loops.push(LoopCtx { break_label: end_label });
        let result = self.compile_block(body);
        self.loops.pop();
        self.pop_name_scope();
        self.slots.pop_scope();
        result?;
        self.emit_jump(bc::OP_JMP, None, cond_label)?;
        self.bind(end_label);
        for slot in keep {
            self.slots.release(slot);
        }
        Ok(())
    }

    fn compile_repeat(&mut self, body: &Block, cond: &Expr) -> Result<(), FrontendError> {
        let body_label = self.new_label();
        let end_label = self.new_label();
        self.bind(body_label);
        // The repeat scope covers the body AND the until-condition (Lua scoping).
        let mut keep = Vec::new();
        self.slots.push_scope();
        self.push_name_scope();
        self.loops.push(LoopCtx { break_label: end_label });
        let stmt_result = (|| -> Result<(), FrontendError> {
            for stmt in &body.stmts {
                self.compile_stmt(stmt)?;
            }
            if let Some(expr) = &body.ret {
                let slot = self.slots.alloc()?;
                self.compile_expr(expr, slot)?;
                self.words.push(bc::encode(bc::OP_RET, slot as u8, 0, 0));
                self.slots.release(slot);
            }
            self.compile_cond_keep(cond, CondSide::Jump(end_label), CondSide::FallThrough, &mut keep)
        })();
        self.loops.pop();
        // The condition slots live in the repeat scope; pop_scope already returns
        // them to the free list, so they must not be released a second time here
        // (a double free would hand one slot to two different allocations).
        self.pop_name_scope();
        self.slots.pop_scope();
        stmt_result?;
        self.emit_jump(bc::OP_JMP, None, body_label)?;
        self.bind(end_label);
        let _ = keep;
        Ok(())
    }

    fn compile_for(
        &mut self,
        var: &str,
        start: &Expr,
        limit: &Expr,
        step: Option<&Expr>,
        body: &Block,
        line: usize,
    ) -> Result<(), FrontendError> {
        let cond_label = self.new_label();
        let body_label = self.new_label();
        let end_label = self.new_label();
        self.slots.push_scope(); // loop scope: hidden slots + loop variable
        self.push_name_scope();

        let iv = self.slots.alloc()?;
        let lim = self.slots.alloc()?;
        // Start value evaluated into a temp, then moved (the loop slot is hidden).
        let init_tmp = self.slots.alloc()?;
        self.compile_expr(start, init_tmp)?;
        self.words.push(bc::encode(bc::OP_MOVE, iv as u8, init_tmp as u8, 0));
        self.slots.release(init_tmp);
        self.compile_expr(limit, lim)?;

        // Compile-time step when the source gives a literal; zero is a Lua error.
        let const_step: Option<i64> = match step {
            Some(Expr::IntLit(v, _)) => Some(*v),
            Some(Expr::Neg(inner, _)) => match inner.as_ref() {
                Expr::IntLit(v, _) => Some(-v),
                _ => None,
            },
            Some(_) => None,
            None => Some(1),
        };
        if const_step == Some(0) {
            return Err(FrontendError::new(line, "'for' step is zero"));
        }

        // ADDI is an integer immediate: it is sound only when the induction
        // variable starts as an integer literal (so the slot holds TAG_INT and
        // stays integer) AND the step fits i32. Otherwise ADD widens floats.
        let int_start = match start {
            Expr::IntLit(v, _) => i32::try_from(*v).is_ok(),
            Expr::Neg(inner, _) => matches!(
                inner.as_ref(),
                Expr::IntLit(v, _) if i32::try_from(*v).is_ok()
            ),
            _ => false,
        };

        let step_src = match const_step {
            Some(v) => {
                if int_start {
                    match i32::try_from(v) {
                        Ok(imm) => StepSrc::Addi(imm),
                        // Step too wide for the ADDI immediate: fall back to a
                        // slot and ADD, which stays exact in i64.
                        Err(_) => {
                            let stp = self.slots.alloc()?;
                            let idx = self.const_int(v)?;
                            self.emit_loadk(stp, idx)?;
                            StepSrc::ConstSlot(stp)
                        }
                    }
                } else {
                    let stp = self.slots.alloc()?;
                    let idx = self.const_int(v)?;
                    self.emit_loadk(stp, idx)?;
                    StepSrc::ConstSlot(stp)
                }
            }
            None => {
                let stp = self.slots.alloc()?;
                let step_expr = step.expect("runtime step present");
                self.compile_expr(step_expr, stp)?;
                StepSrc::Runtime(stp)
            }
        };

        // Runtime steps need a one-time sign probe before the loop header so
        // each iteration can select iv<=lim (step>0) or iv>=lim (step<=0).
        let gt_t = if let StepSrc::Runtime(stp) = &step_src {
            let zero_t = self.slots.alloc()?;
            let zidx = self.const_int(0)?;
            self.emit_loadk(zero_t, zidx)?;
            let gt = self.slots.alloc()?;
            self.words.push(bc::encode(bc::OP_GT, gt as u8, *stp as u8, zero_t as u8));
            self.slots.release(zero_t);
            Some(gt)
        } else {
            None
        };
        let cond_t = self.slots.alloc()?;

        self.bind(cond_label);
        if let (Some(gt_t), StepSrc::Runtime(stp)) = (gt_t, &step_src) {
            let le_label = self.new_label();
            let done_label = self.new_label();
            self.emit_jump(bc::OP_JMPIF, Some(gt_t), le_label)?;
            self.words.push(bc::encode(bc::OP_GE, cond_t as u8, iv as u8, lim as u8));
            self.emit_jump(bc::OP_JMP, None, done_label)?;
            self.bind(le_label);
            self.words.push(bc::encode(bc::OP_LE, cond_t as u8, iv as u8, lim as u8));
            self.bind(done_label);
        } else {
            let cmp_op = match const_step {
                Some(v) if v > 0 => bc::OP_LE,
                _ => bc::OP_GE,
            };
            self.words.push(bc::encode(cmp_op, cond_t as u8, iv as u8, lim as u8));
        }
        self.emit_jump(bc::OP_JMPNOT, Some(cond_t), end_label)?;
        self.bind(body_label);

        // Body: the user-visible loop variable is a fresh copy each iteration.
        self.loops.push(LoopCtx { break_label: end_label });
        let ui = self.slots.alloc()?;
        self.words.push(bc::encode(bc::OP_MOVE, ui as u8, iv as u8, 0));
        self.declare_local(var, ui);
        let body_result = self.compile_block(body);
        self.loops.pop();
        body_result?;

        match step_src {
            StepSrc::Addi(imm) => {
                self.words.push(bc::encode(bc::OP_ADDI, iv as u8, iv as u8, 0));
                self.words.push(imm as i32 as u32);
            }
            StepSrc::ConstSlot(stp) | StepSrc::Runtime(stp) => {
                self.words.push(bc::encode(bc::OP_ADD, iv as u8, iv as u8, stp as u8));
            }
        }
        self.emit_jump(bc::OP_JMP, None, cond_label)?;
        self.bind(end_label);
        // The condition slot stays loop-stable for the JIT deopt writeback;
        // pop_scope returns every loop-scoped slot (iv, lim, cond_t, gt_t,
        // step slot, and the user loop-variable copy) to the free list.
        self.slots.pop_scope();
        self.pop_name_scope();
        Ok(())
    }

    // ---- conditional compilation ----

    /// Compiles a condition as a branch (single evaluation; if/elseif contexts).
    fn compile_cond(&mut self, cond: &Expr, true_side: CondSide, false_side: CondSide) -> Result<(), FrontendError> {
        let mut keep = Vec::new();
        let result = self.compile_cond_keep(cond, true_side, false_side, &mut keep);
        for slot in keep {
            self.slots.release(slot);
        }
        result
    }

    /// Compiles a condition as a branch; bool result slots are returned in `keep`
    /// so loop contexts can keep them alive until the loop ends (JIT deopt
    /// restores these slots when a guard exit resumes at the branch).
    fn compile_cond_keep(
        &mut self,
        cond: &Expr,
        true_side: CondSide,
        false_side: CondSide,
        keep: &mut Vec<u32>,
    ) -> Result<(), FrontendError> {
        match cond {
            Expr::Bin { op, lhs, rhs, line } if is_compare(op) => {
                // nil comparisons lower to truthiness tests (EQ against nil is
                // numeric garbage in the ISA); ordering against nil is a Lua error.
                if matches!(lhs.as_ref(), Expr::Nil(_)) || matches!(rhs.as_ref(), Expr::Nil(_)) {
                    if op != "==" && op != "~=" {
                        return Err(FrontendError::new(*line, "attempt to order-compare with nil"));
                    }
                    let operand = if matches!(lhs.as_ref(), Expr::Nil(_)) { rhs.as_ref() } else { lhs.as_ref() };
                    // x == nil is true when x is falsy; x ~= nil is true when truthy.
                    let side_truthy = if op == "==" { false_side } else { true_side };
                    let side_falsy = if op == "==" { true_side } else { false_side };
                    return self.compile_cond_keep(operand, side_truthy, side_falsy, keep);
                }
                check_string_compare(op, lhs.as_ref(), rhs.as_ref(), *line)?;
                let a = self.slots.alloc()?;
                self.compile_expr(lhs, a)?;
                let b = self.slots.alloc()?;
                self.compile_expr(rhs, b)?;
                let t = self.slots.alloc()?;
                let cmp_op = compare_opcode(op)?;
                self.words.push(bc::encode(cmp_op, t as u8, a as u8, b as u8));
                self.slots.release(b);
                self.slots.release(a);
                self.branch_on_slot(t, true_side, false_side)?;
                keep.push(t);
                Ok(())
            }
            Expr::And(lhs, rhs, _line) => {
                // a and b as a condition: a falsy decides false; otherwise b decides.
                // When the false side is a fall-through, a falsy must SKIP the rhs
                // code (not fall into it), so branch over it with an internal label.
                if matches!(false_side, CondSide::FallThrough) {
                    let skip_label = self.new_label();
                    self.compile_cond_keep(lhs, CondSide::FallThrough, CondSide::Jump(skip_label), keep)?;
                    self.compile_cond_keep(rhs, true_side, false_side, keep)?;
                    self.bind(skip_label);
                    Ok(())
                } else {
                    self.compile_cond_keep(lhs, CondSide::FallThrough, false_side, keep)?;
                    self.compile_cond_keep(rhs, true_side, false_side, keep)
                }
            }
            Expr::Or(lhs, rhs, _line) => {
                // a or b as a condition: a truthy decides true; otherwise b decides.
                // When the true side is a fall-through, a truthy must SKIP the rhs
                // code (not fall into it), so branch over it with an internal label.
                if matches!(true_side, CondSide::FallThrough) {
                    let skip_label = self.new_label();
                    self.compile_cond_keep(lhs, CondSide::Jump(skip_label), CondSide::FallThrough, keep)?;
                    self.compile_cond_keep(rhs, true_side, false_side, keep)?;
                    self.bind(skip_label);
                    Ok(())
                } else {
                    self.compile_cond_keep(lhs, true_side, CondSide::FallThrough, keep)?;
                    self.compile_cond_keep(rhs, true_side, false_side, keep)
                }
            }
            Expr::Not(inner, _line) => self.compile_cond_keep(inner, false_side, true_side, keep),
            other => {
                let slot = self.slots.alloc()?;
                self.compile_expr(other, slot)?;
                self.branch_on_slot(slot, true_side, false_side)?;
                keep.push(slot);
                Ok(())
            }
        }
    }

    /// Emits the branch for one already-evaluated slot.
    fn branch_on_slot(&mut self, slot: u32, true_side: CondSide, false_side: CondSide) -> Result<(), FrontendError> {
        match (true_side, false_side) {
            (CondSide::Jump(t), CondSide::FallThrough) => self.emit_jump(bc::OP_JMPIF, Some(slot), t),
            (CondSide::FallThrough, CondSide::Jump(f)) => self.emit_jump(bc::OP_JMPNOT, Some(slot), f),
            (CondSide::Jump(t), CondSide::Jump(f)) => {
                self.emit_jump(bc::OP_JMPIF, Some(slot), t)?;
                self.emit_jump(bc::OP_JMP, None, f)
            }
            (CondSide::FallThrough, CondSide::FallThrough) => Ok(()),
        }
    }

    // ---- expression compilation ----

    /// Compiles one expression so its value lands in `dst`.
    fn compile_expr(&mut self, expr: &Expr, dst: u32) -> Result<(), FrontendError> {
        match expr {
            Expr::IntLit(v, _line) => {
                let idx = match i32::try_from(*v) {
                    Ok(_) => self.const_int(*v)?,
                    Err(_) => {
                        let idx = self.const_num(*v as f64)?;
                        idx
                    }
                };
                self.emit_loadk(dst, idx)
            }
            Expr::NumLit(v, _line) => {
                let idx = self.const_num(*v)?;
                self.emit_loadk(dst, idx)
            }
            Expr::StrLit(s, _line) => {
                let idx = self.const_str(s)?;
                if idx > 0xFFFF {
                    return Err(FrontendError::new(0, "constant index out of range"));
                }
                self.emit_loadk(dst, idx)
            }
            Expr::Nil(_) => {
                self.words.push(bc::encode(bc::OP_MOVE, dst as u8, 0, 0));
                Ok(())
            }
            Expr::True(_) => {
                self.emit_bool(dst, true)
            }
            Expr::False(_) => {
                self.emit_bool(dst, false)
            }
            Expr::Name(name, _line) => {
                if let Some(slot) = self.resolve_local(name) {
                    self.words.push(bc::encode(bc::OP_MOVE, dst as u8, slot as u8, 0));
                } else {
                    let gid = self.global_id(name)?;
                    self.words.push(bc::encode(bc::OP_GGET, dst as u8, 0, gid as u8));
                }
                Ok(())
            }
            Expr::Neg(inner, _line) => {
                let zero_t = self.slots.alloc()?;
                let idx = self.const_int(0)?;
                self.emit_loadk(zero_t, idx)?;
                let operand = self.slots.alloc()?;
                self.compile_expr(inner, operand)?;
                self.words.push(bc::encode(bc::OP_SUB, dst as u8, zero_t as u8, operand as u8));
                self.slots.release(operand);
                self.slots.release(zero_t);
                Ok(())
            }
            Expr::Bin { op, lhs, rhs, line } => match op.as_str() {
                "and" | "or" => unreachable!("and/or are handled in conditions and rvalue lowering"),
                "%" => self.compile_mod(lhs, rhs, dst),
                "+" | "-" | "*" | "/" => {
                    let a = self.slots.alloc()?;
                    self.compile_expr(lhs, a)?;
                    let b = self.slots.alloc()?;
                    self.compile_expr(rhs, b)?;
                    let op_code = match op.as_str() {
                        "+" => bc::OP_ADD,
                        "-" => bc::OP_SUB,
                        "*" => bc::OP_MUL,
                        _ => bc::OP_DIV,
                    };
                    self.words.push(bc::encode(op_code, dst as u8, a as u8, b as u8));
                    self.slots.release(b);
                    self.slots.release(a);
                    Ok(())
                }
                "==" | "~=" | "<" | "<=" | ">" | ">=" => {
                    // Equality with nil lowers to a truthiness test; ordering with
                    // nil is rejected (invalid Lua).
                    if matches!(lhs.as_ref(), Expr::Nil(_)) || matches!(rhs.as_ref(), Expr::Nil(_)) {
                        if op != "==" && op != "~=" {
                            return Err(FrontendError::new(*line, "attempt to order-compare with nil"));
                        }
                        let operand = if matches!(lhs.as_ref(), Expr::Nil(_)) { rhs.as_ref() } else { lhs.as_ref() };
                        let operand_t = self.slots.alloc()?;
                        self.compile_expr(operand, operand_t)?;
                        self.nil_compare_rvalue(dst, operand_t, op == "==")?;
                        self.slots.release(operand_t);
                        return Ok(());
                    }
                    check_string_compare(op, lhs.as_ref(), rhs.as_ref(), *line)?;
                    let a = self.slots.alloc()?;
                    self.compile_expr(lhs, a)?;
                    let b = self.slots.alloc()?;
                    self.compile_expr(rhs, b)?;
                    let cmp_op = compare_opcode(op)?;
                    self.words.push(bc::encode(cmp_op, dst as u8, a as u8, b as u8));
                    self.slots.release(b);
                    self.slots.release(a);
                    Ok(())
                }
                other => Err(FrontendError::new(*line, format!("operator '{}' is not supported", other))),
            },
            Expr::And(lhs, rhs, _line) => {
                // a and b: if a truthy -> result is b else a.
                self.compile_expr(lhs, dst)?;
                let take_label = self.new_label();
                let end_label = self.new_label();
                self.emit_jump(bc::OP_JMPIF, Some(dst), take_label)?;
                self.emit_jump(bc::OP_JMP, None, end_label)?;
                self.bind(take_label);
                self.compile_expr(rhs, dst)?;
                self.bind(end_label);
                Ok(())
            }
            Expr::Or(lhs, rhs, _line) => {
                self.compile_expr(lhs, dst)?;
                let end_label = self.new_label();
                self.emit_jump(bc::OP_JMPIF, Some(dst), end_label)?;
                self.compile_expr(rhs, dst)?;
                self.bind(end_label);
                Ok(())
            }
            Expr::Not(inner, _line) => {
                let operand = self.slots.alloc()?;
                self.compile_expr(inner, operand)?;
                // dst = false; if operand truthy -> done; else dst = true.
                self.emit_bool(dst, false)?;
                let end_label = self.new_label();
                self.emit_jump(bc::OP_JMPIF, Some(operand), end_label)?;
                self.emit_bool(dst, true)?;
                self.bind(end_label);
                self.slots.release(operand);
                Ok(())
            }
            Expr::Index { table, key, line } => {
                let tab = self.slots.alloc()?;
                self.compile_expr(table, tab)?;
                match key.as_ref() {
                    Expr::StrLit(text, _) => {
                        let idx = self.const_str(text)?;
                        if idx > 0xFF {
                            return Err(FrontendError::new(
                                *line,
                                "string key constant index exceeds 255 (TGETK field width)",
                            ));
                        }
                        self.words.push(bc::encode(bc::OP_TGETK, dst as u8, tab as u8, idx as u8));
                    }
                    key_expr => {
                        let key_slot = self.slots.alloc()?;
                        self.compile_expr(key_expr, key_slot)?;
                        self.words.push(bc::encode(bc::OP_TGETI, dst as u8, tab as u8, key_slot as u8));
                        self.slots.release(key_slot);
                    }
                }
                self.slots.release(tab);
                Ok(())
            }
            Expr::TableCtor { fields, line } => {
                // Lua constructor elements live at 1-based indices; the VM array
                // is 0-based with a fixed length, so allocate one spare cell
                // beyond the highest index the constructor can touch: the last
                // positional item, or any literal integer [key] field.
                let positional = fields
                    .iter()
                    .filter(|f| matches!(f, TableField::Pos(_)))
                    .count();
                let mut array_len = positional;
                for field in fields {
                    if let TableField::Keyed(key, _, _) = field {
                        if let Expr::IntLit(k, _) = key.as_ref() {
                            if *k >= 0 && (*k as usize) > array_len {
                                array_len = *k as usize;
                            }
                        }
                    }
                }
                let total_cells = array_len + 1;
                if total_cells > L::MAX_TABLE_CELLS as usize {
                    return Err(FrontendError::new(
                        *line,
                        format!("table constructor exceeds the {}-cell VM limit", L::MAX_TABLE_CELLS),
                    ));
                }
                self.words.push(bc::encode(bc::OP_TNEW, dst as u8, 0, 0));
                self.words.push(total_cells as u32);
                let idx_slot = self.slots.alloc()?;
                let mut positional = 0usize;
                for field in fields {
                    match field {
                        TableField::Pos(item) => {
                            positional += 1;
                            let cidx = self.const_int(positional as i64)?;
                            self.emit_loadk(idx_slot, cidx)?;
                            let val_slot = self.slots.alloc()?;
                            self.compile_expr(item, val_slot)?;
                            self.words.push(bc::encode(
                                bc::OP_TSETI,
                                val_slot as u8,
                                dst as u8,
                                idx_slot as u8,
                            ));
                            self.slots.release(val_slot);
                        }
                        TableField::Named(name, value, fline) => {
                            let kidx = self.const_str(name)?;
                            if kidx > 0xFF {
                                return Err(FrontendError::new(
                                    *fline,
                                    "string key constant index exceeds 255 (TSETK field width)",
                                ));
                            }
                            let val_slot = self.slots.alloc()?;
                            self.compile_expr(value, val_slot)?;
                            self.words.push(bc::encode(
                                bc::OP_TSETK,
                                val_slot as u8,
                                dst as u8,
                                kidx as u8,
                            ));
                            self.slots.release(val_slot);
                        }
                        TableField::Keyed(key, value, fline) => match key.as_ref() {
                            Expr::StrLit(text, _) => {
                                let kidx = self.const_str(text)?;
                                if kidx > 0xFF {
                                    return Err(FrontendError::new(
                                        *fline,
                                        "string key constant index exceeds 255 (TSETK field width)",
                                    ));
                                }
                                let val_slot = self.slots.alloc()?;
                                self.compile_expr(value, val_slot)?;
                                self.words.push(bc::encode(
                                    bc::OP_TSETK,
                                    val_slot as u8,
                                    dst as u8,
                                    kidx as u8,
                                ));
                                self.slots.release(val_slot);
                            }
                            key_expr => {
                                let key_slot = self.slots.alloc()?;
                                self.compile_expr(key_expr, key_slot)?;
                                let val_slot = self.slots.alloc()?;
                                self.compile_expr(value, val_slot)?;
                                self.words.push(bc::encode(
                                    bc::OP_TSETI,
                                    val_slot as u8,
                                    dst as u8,
                                    key_slot as u8,
                                ));
                                self.slots.release(val_slot);
                                self.slots.release(key_slot);
                            }
                        },
                    }
                }
                self.slots.release(idx_slot);
                Ok(())
            }
            Expr::Call { callee, arg, line } => match callee {
                Callee::Print => Err(FrontendError::new(*line, "print has no return value; call it as a statement")),
                Callee::Sin | Callee::Cos | Callee::Sqrt | Callee::Abs | Callee::Floor => {
                    let fnid = match callee {
                        Callee::Sin => bc::MATH_SIN,
                        Callee::Cos => bc::MATH_COS,
                        Callee::Sqrt => bc::MATH_SQRT,
                        Callee::Abs => bc::MATH_ABS,
                        Callee::Floor => bc::MATH_FLOOR,
                        Callee::Print => unreachable!(),
                    };
                    let operand = self.slots.alloc()?;
                    self.compile_expr(arg, operand)?;
                    self.words.push(bc::encode(bc::OP_CALLM, dst as u8, fnid, operand as u8));
                    self.slots.release(operand);
                    Ok(())
                }
            },
        }
    }

    /// Emits a boolean constant into dst via the zero-slot equality trick
    /// (the ISA constant pool has no bool entries; EQ(0,0) is true, NE(0,0) false).
    fn emit_bool(&mut self, dst: u32, value: bool) -> Result<(), FrontendError> {
        let zero_t = self.slots.alloc()?;
        let idx = self.const_int(0)?;
        self.emit_loadk(zero_t, idx)?;
        let op = if value { bc::OP_EQ } else { bc::OP_NE };
        self.words.push(bc::encode(op, dst as u8, zero_t as u8, zero_t as u8));
        self.slots.release(zero_t);
        Ok(())
    }

    /// Lowers `x == nil` / `x ~= nil` as an rvalue into dst via truthiness branching.
    fn nil_compare_rvalue(&mut self, dst: u32, operand: u32, is_eq: bool) -> Result<(), FrontendError> {
        // is_eq: dst = NOT truthy(operand); otherwise dst = truthy(operand).
        if is_eq {
            // dst = false; operand truthy keeps false; operand falsy sets true.
            self.emit_bool(dst, false)?;
            let end_label = self.new_label();
            self.emit_jump(bc::OP_JMPIF, Some(operand), end_label)?;
            self.emit_bool(dst, true)?;
            self.bind(end_label);
        } else {
            // dst = true; operand truthy keeps true; operand falsy sets false.
            self.emit_bool(dst, true)?;
            let end_label = self.new_label();
            self.emit_jump(bc::OP_JMPIF, Some(operand), end_label)?;
            self.emit_bool(dst, false)?;
            self.bind(end_label);
        }
        Ok(())
    }

    /// Compiles `a % b` as `a - floor(a / b) * b` (Lua definition).
    fn compile_mod(&mut self, lhs: &Expr, rhs: &Expr, dst: u32) -> Result<(), FrontendError> {
        let a = self.slots.alloc()?;
        self.compile_expr(lhs, a)?;
        let b = self.slots.alloc()?;
        self.compile_expr(rhs, b)?;
        let q = self.slots.alloc()?;
        self.words.push(bc::encode(bc::OP_DIV, q as u8, a as u8, b as u8));
        self.words.push(bc::encode(bc::OP_CALLM, q as u8, bc::MATH_FLOOR, q as u8));
        self.words.push(bc::encode(bc::OP_MUL, q as u8, q as u8, b as u8));
        self.words.push(bc::encode(bc::OP_SUB, dst as u8, a as u8, q as u8));
        self.slots.release(q);
        self.slots.release(b);
        self.slots.release(a);
        Ok(())
    }
}

/// Maps a comparison operator to its opcode.
fn compare_opcode(op: &str) -> Result<u8, FrontendError> {
    Ok(match op {
        "<" => bc::OP_LT,
        "<=" => bc::OP_LE,
        "==" => bc::OP_EQ,
        ">" => bc::OP_GT,
        ">=" => bc::OP_GE,
        "~=" => bc::OP_NE,
        _ => return Err(FrontendError::new(0, format!("unknown comparison '{}'", op))),
    })
}

fn is_compare(op: &str) -> bool {
    matches!(op, "==" | "~=" | "<" | "<=" | ">" | ">=")
}

/// Guards comparisons against the ISA's numeric-only compare: ordering with any
/// string operand is rejected outright, and == / ~= are allowed only when both
/// operands are string literals (interned handles then compare by content).
fn check_string_compare(op: &str, lhs: &Expr, rhs: &Expr, line: usize) -> Result<(), FrontendError> {
    let lhs_str = matches!(lhs, Expr::StrLit(_, _));
    let rhs_str = matches!(rhs, Expr::StrLit(_, _));
    if !lhs_str && !rhs_str {
        return Ok(());
    }
    if op != "==" && op != "~=" {
        return Err(FrontendError::new(
            line,
            "ordering comparison on strings is not supported by the SSL-BC subset",
        ));
    }
    if !lhs_str || !rhs_str {
        return Err(FrontendError::new(
            line,
            "string equality is only supported between two string literals in this subset",
        ));
    }
    Ok(())
}

/// Best-effort source line of an expression.
fn expr_line(expr: &Expr) -> usize {
    expr.line()
}
