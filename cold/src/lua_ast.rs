// CEP:FILE: cold/src/lua_ast.rs
// CEP:WHAT: The abstract syntax tree for the Lua subset the frontend compiles, plus frontend error types.
// CEP:WHY: The parser and code generator share one fixed tree so unsupported constructs fail at parse time with line numbers instead of miscompiling.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: none; data declarations only.
// CEP:ASSUMES: expressions are single-value; the VM ISA has no calls, closures, varargs, or string concatenation, so the tree has no such nodes.
// CEP:COST: cold; declarations only.
// CEP:EVIDENCE: parser unit tests ssl-tests::unit_lua_parse.

/// Frontend failure carrying a source line.
#[derive(Clone, PartialEq, Debug)]
pub struct FrontendError {
    /// One-based source line.
    pub line: usize,
    /// Human-readable cause.
    pub message: String,
}

impl FrontendError {
    /// Builds one error at a line.
    pub fn new(line: usize, message: impl Into<String>) -> FrontendError {
        FrontendError { line, message: message.into() }
    }
}

/// Top-level program: a statement block plus one optional trailing return.
#[derive(Clone, Debug)]
pub struct Chunk {
    /// Statements of the main block.
    pub body: Block,
}

/// A scoped statement list; every block owns its local scope.
#[derive(Clone, Debug, Default)]
pub struct Block {
    /// Statements in source order.
    pub stmts: Vec<Stmt>,
    /// Trailing `return expr` of the block, if present.
    pub ret: Option<Expr>,
}

/// Statements in the supported subset.
#[derive(Clone, Debug)]
pub enum Stmt {
    /// `local a, b = e1, e2` (initializer list optional per name).
    Local {
        /// Declared names with their source line.
        names: Vec<(String, usize)>,
        /// Right-hand expressions, possibly fewer than names.
        exprs: Vec<Expr>,
    },
    /// Assignment to one or more targets: locals, globals, or table slots.
    Assign {
        /// Assignment targets in source order.
        targets: Vec<Target>,
        /// Right-hand expressions.
        exprs: Vec<Expr>,
    },
    /// `if cond then block (elseif cond then block)* (else block)? end`
    If {
        /// Ordered cond/body pairs; the last body is the else branch when present.
        branches: Vec<(Expr, Block)>,
    },
    /// `while cond do block end`
    While {
        /// Loop condition.
        cond: Expr,
        /// Loop body.
        body: Block,
    },
    /// `repeat block until cond`; the condition sees the body scope.
    Repeat {
        /// Loop body.
        body: Block,
        /// Exit condition.
        cond: Expr,
    },
    /// `for i = a, b [, c] do body end` (numeric form only).
    ForNum {
        /// Loop variable name.
        var: String,
        /// Start expression.
        start: Expr,
        /// Limit expression.
        limit: Expr,
        /// Optional step expression (default 1).
        step: Option<Expr>,
        /// Body block.
        body: Block,
        /// Source line for diagnostics.
        line: usize,
    },
    /// `break` (nearest enclosing loop).
    Break {
        /// Source line for diagnostics.
        line: usize,
    },
    /// A bare `do ... end` block with its own local scope.
    Do(Block),
    /// An expression statement; only builtin calls are meaningful here.
    ExprStmt(Expr),
}

/// Assignment target kinds.
#[derive(Clone, Debug)]
pub enum Target {
    /// Assignment to a local or global by name.
    Name {
        /// Variable name.
        name: String,
        /// Source line.
        line: usize,
    },
    /// Assignment to `t[k]`.
    Index {
        /// Table expression.
        table: Expr,
        /// Key expression.
        key: Expr,
        /// Source line.
        line: usize,
    },
}

/// Expressions in the supported subset.
#[derive(Clone, Debug)]
pub enum Expr {
    /// Integer literal.
    IntLit(i64, usize),
    /// Float literal.
    NumLit(f64, usize),
    /// String literal.
    StrLit(String, usize),
    /// `nil`.
    Nil(usize),
    /// `true`.
    True(usize),
    /// `false`.
    False(usize),
    /// Local or global read by name.
    Name(String, usize),
    /// Binary arithmetic or comparison: `+ - * / %` and `== ~= < <= > >=`.
    Bin {
        /// Operator text.
        op: String,
        /// Left operand.
        lhs: Box<Expr>,
        /// Right operand.
        rhs: Box<Expr>,
        /// Source line.
        line: usize,
    },
    /// Short-circuit conjunction.
    And(Box<Expr>, Box<Expr>, usize),
    /// Short-circuit disjunction.
    Or(Box<Expr>, Box<Expr>, usize),
    /// Logical negation.
    Not(Box<Expr>, usize),
    /// Unary minus.
    Neg(Box<Expr>, usize),
    /// Table indexing `t[k]` or `t.k`.
    Index {
        /// Table expression.
        table: Box<Expr>,
        /// Key expression.
        key: Box<Expr>,
        /// Source line.
        line: usize,
    },
    /// Table constructor with positional, named, and keyed fields.
    TableCtor {
        /// Fields in source order.
        fields: Vec<TableField>,
        /// Source line.
        line: usize,
    },
    /// Builtin call: `print(e)` or `math.sin|cos|sqrt|abs|floor(e)`.
    Call {
        /// Callee kind.
        callee: Callee,
        /// Single argument.
        arg: Box<Expr>,
        /// Source line.
        line: usize,
    },
}

/// Recognized builtin callees.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Callee {
    /// `print`: one value to the bounded output buffer.
    Print,
    /// `math.sin`.
    Sin,
    /// `math.cos`.
    Cos,
    /// `math.sqrt`.
    Sqrt,
    /// `math.abs`.
    Abs,
    /// `math.floor`.
    Floor,
}

/// One table constructor field.
#[derive(Clone, Debug)]
pub enum TableField {
    /// Positional item: assigned to t[1], t[2], ... in source order.
    Pos(Expr),
    /// Named field `name = value`.
    Named(String, Expr, usize),
    /// Explicit key field `[key] = value`.
    Keyed(Box<Expr>, Box<Expr>, usize),
}

impl Expr {
    /// Source line of the expression's outermost node.
    pub fn line(&self) -> usize {
        match self {
            Expr::IntLit(_, l)
            | Expr::NumLit(_, l)
            | Expr::StrLit(_, l)
            | Expr::Nil(l)
            | Expr::True(l)
            | Expr::False(l)
            | Expr::Name(_, l)
            | Expr::Bin { line: l, .. }
            | Expr::And(_, _, l)
            | Expr::Or(_, _, l)
            | Expr::Not(_, l)
            | Expr::Neg(_, l)
            | Expr::Index { line: l, .. }
            | Expr::TableCtor { line: l, .. }
            | Expr::Call { line: l, .. } => *l,
        }
    }
}
