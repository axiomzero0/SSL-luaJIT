// CEP:FILE: cold/src/lua_parse.rs
// CEP:WHAT: Recursive-descent parser for the Lua subset: statements, expressions with Lua operator precedence, and strict subset enforcement.
// CEP:WHY: Unsupported constructs (calls, closures, concat, pow, length) must fail at parse time with a line number; a silent miscompile is forbidden.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: Returns FrontendError with line numbers for syntax errors, unsupported syntax, malformed blocks, and nesting beyond the depth budget; never panics.
// CEP:ASSUMES: token vector comes from lua_lex and ends with Eof; two tokens of lookahead suffice for the subset grammar.
// CEP:COST: O(tokens) recursive descent with expression and block nesting bounded by MAX_PARSE_DEPTH.
// CEP:EVIDENCE: parser unit tests ssl-tests::unit_lua_parse including error cases and depth-budget cases.

use crate::lua_ast::*;
use crate::lua_lex::{TokKind, Token, KEYWORDS};

/// Maximum expression and block nesting depth; bounds parser recursion on adversarial input.
pub const MAX_PARSE_DEPTH: usize = 200;

/// Parser over a token vector.
pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    depth: usize,
}

/// Parses one Lua source chunk into the AST.
pub fn parse(source: &str) -> Result<Chunk, FrontendError> {
    let tokens = crate::lua_lex::lex(source).map_err(|e| match e {
        crate::lua_lex::LexError::BadString(line, msg) => FrontendError::new(line, msg),
        crate::lua_lex::LexError::BadNumber(line, msg) => FrontendError::new(line, msg),
        crate::lua_lex::LexError::UnknownChar(line, ch) => {
            FrontendError::new(line, format!("unexpected character '{}'", ch))
        }
        crate::lua_lex::LexError::TooLarge => FrontendError::new(0, "source too large"),
    })?;
    let mut parser = Parser { tokens, pos: 0, depth: 0 };
    let body = parser.parse_block()?;
    let token = parser.peek().clone();
    match token.kind {
        TokKind::Eof => Ok(Chunk { body }),
        _ => Err(FrontendError::new(token.line, "expected end of file")),
    }
}

impl Parser {
    fn peek(&self) -> &Token {
        &self.tokens[self.pos.min(self.tokens.len() - 1)]
    }

    fn advance(&mut self) -> Token {
        let token = self.peek().clone();
        if self.pos < self.tokens.len() - 1 {
            self.pos += 1;
        }
        token
    }

    fn line(&self) -> usize {
        self.peek().line
    }

    fn is_punct(&self, text: &str) -> bool {
        matches!(&self.peek().kind, TokKind::Punct(p) if p == text)
    }

    fn eat_punct(&mut self, text: &str) -> bool {
        if self.is_punct(text) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn expect_punct(&mut self, text: &str) -> Result<Token, FrontendError> {
        if self.is_punct(text) {
            Ok(self.advance())
        } else {
            Err(FrontendError::new(self.line(), format!("expected '{}'", text)))
        }
    }

    fn is_keyword(&self, word: &str) -> bool {
        matches!(&self.peek().kind, TokKind::Name(n) if n == word)
    }

    /// Enters one recursion level; errors beyond the depth budget.
    fn enter(&mut self, what: &str) -> Result<(), FrontendError> {
        self.depth += 1;
        if self.depth > MAX_PARSE_DEPTH {
            return Err(FrontendError::new(
                self.line(),
                format!("{} nesting exceeds the {}-level parser budget", what, MAX_PARSE_DEPTH),
            ));
        }
        Ok(())
    }

    /// Leaves one recursion level.
    fn leave(&mut self) {
        self.depth -= 1;
    }

    fn eat_keyword(&mut self, word: &str) -> bool {
        if self.is_keyword(word) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn expect_keyword(&mut self, word: &str) -> Result<Token, FrontendError> {
        if self.is_keyword(word) {
            Ok(self.advance())
        } else {
            Err(FrontendError::new(self.line(), format!("expected '{}'", word)))
        }
    }

    fn is_block_end(&self) -> bool {
        self.is_keyword("end")
            || self.is_keyword("else")
            || self.is_keyword("elseif")
            || self.is_keyword("until")
            || matches!(self.peek().kind, TokKind::Eof)
    }

    /// Parses statements until a block terminator keyword or EOF; captures a trailing return.
    fn parse_block(&mut self) -> Result<Block, FrontendError> {
        self.enter("block")?;
        let mut block = Block::default();
        loop {
            if self.is_block_end() {
                break;
            }
            // Lua grammar allows ';' as a statement.
            if self.eat_punct(";") {
                continue;
            }
            if self.is_keyword("return") {
                self.advance();
                // Optional expression list; the subset returns the first value.
                let value = if self.is_block_end() || self.is_punct(";") {
                    Expr::Nil(self.line())
                } else {
                    self.parse_expr()?
                };
                if self.is_punct(",") {
                    return Err(FrontendError::new(
                        self.line(),
                        "multiple return values are not supported; return one value",
                    ));
                }
                let _ = self.eat_punct(";");
                block.ret = Some(value);
                break;
            }
            let stmt = self.parse_stmt()?;
            block.stmts.push(stmt);
            let _ = self.eat_punct(";");
        }
        self.leave();
        Ok(block)
    }

    fn parse_stmt(&mut self) -> Result<Stmt, FrontendError> {
        if self.is_keyword("local") {
            return self.parse_local();
        }
        if self.is_keyword("if") {
            return self.parse_if();
        }
        if self.is_keyword("do") {
            self.advance();
            let body = self.parse_block()?;
            self.expect_keyword("end")?;
            return Ok(Stmt::Do(body));
        }
        if self.is_keyword("goto") {
            return Err(FrontendError::new(
                self.line(),
                "goto and labels are not supported by the SSL-BC subset",
            ));
        }
        if self.is_keyword("while") {
            self.advance();
            let cond = self.parse_expr()?;
            self.expect_keyword("do")?;
            let body = self.parse_block()?;
            self.expect_keyword("end")?;
            return Ok(Stmt::While { cond, body });
        }
        if self.is_keyword("repeat") {
            self.advance();
            let body = self.parse_block()?;
            self.expect_keyword("until")?;
            let cond = self.parse_expr()?;
            return Ok(Stmt::Repeat { body, cond });
        }
        if self.is_keyword("for") {
            return self.parse_for();
        }
        if self.is_keyword("break") {
            let token = self.advance();
            return Ok(Stmt::Break { line: token.line });
        }
        if self.is_keyword("function") {
            return Err(FrontendError::new(
                self.line(),
                "function definitions are not supported by the SSL-BC subset",
            ));
        }
        // Assignment or expression statement.
        let line = self.line();
        let first = self.parse_suffixed_expr()?;
        if self.is_punct("=") || self.is_punct(",") {
            let mut targets = vec![self.expr_into_target(first, line)?];
            while self.eat_punct(",") {
                let next_line = self.line();
                let next = self.parse_suffixed_expr()?;
                targets.push(self.expr_into_target(next, next_line)?);
            }
            self.expect_punct("=")?;
            let mut exprs = vec![self.parse_expr()?];
            while self.eat_punct(",") {
                exprs.push(self.parse_expr()?);
            }
            return Ok(Stmt::Assign { targets, exprs });
        }
        match &first {
            Expr::Call { .. } => Ok(Stmt::ExprStmt(first)),
            Expr::Name(name, eline) => Err(FrontendError::new(
                *eline,
                format!("standalone variable '{}' is not a statement", name),
            )),
            _ => Err(FrontendError::new(
                line,
                "only assignment or builtin call statements are supported",
            )),
        }
    }

    /// Converts a suffixed expression to an assignment target; rejects non-targets.
    fn expr_into_target(&self, expr: Expr, line: usize) -> Result<Target, FrontendError> {
        match expr {
            Expr::Name(name, eline) => Ok(Target::Name { name, line: eline }),
            Expr::Index { table, key, line: eline } => Ok(Target::Index { table: *table, key: *key, line: eline }),
            _ => Err(FrontendError::new(line, "invalid assignment target")),
        }
    }

    fn parse_local(&mut self) -> Result<Stmt, FrontendError> {
        self.expect_keyword("local")?;
        let mut names = Vec::new();
        loop {
            let token = self.peek().clone();
            match token.kind {
                TokKind::Name(n) => {
                    if crate::lua_lex::KEYWORDS.contains(&n.as_str()) {
                        return Err(FrontendError::new(token.line, format!("'{}' is a keyword", n)));
                    }
                    self.advance();
                    names.push((n, token.line));
                }
                _ => return Err(FrontendError::new(token.line, "expected name after 'local'")),
            }
            if !self.eat_punct(",") {
                break;
            }
        }
        let mut exprs = Vec::new();
        if self.eat_punct("=") {
            loop {
                exprs.push(self.parse_expr()?);
                if !self.eat_punct(",") {
                    break;
                }
            }
        }
        // Lua discards extra initializers; codegen pads missing ones with nil.
        Ok(Stmt::Local { names, exprs })
    }

    fn parse_if(&mut self) -> Result<Stmt, FrontendError> {
        self.expect_keyword("if")?;
        let mut branches = Vec::new();
        let cond = self.parse_expr()?;
        self.expect_keyword("then")?;
        let body = self.parse_block()?;
        branches.push((cond, body));
        loop {
            if self.eat_keyword("elseif") {
                let cond = self.parse_expr()?;
                self.expect_keyword("then")?;
                let body = self.parse_block()?;
                branches.push((cond, body));
            } else if self.eat_keyword("else") {
                // Keep the else token's line for the constant-true condition.
                let else_line = self.line();
                let body = self.parse_block()?;
                branches.push((Expr::True(else_line), body));
                self.expect_keyword("end")?;
                return Ok(Stmt::If { branches });
            } else {
                self.expect_keyword("end")?;
                return Ok(Stmt::If { branches });
            }
        }
    }

    fn parse_for(&mut self) -> Result<Stmt, FrontendError> {
        self.expect_keyword("for")?;
        let var_token = self.peek().clone();
        let var = match var_token.kind {
            TokKind::Name(n) => {
                if crate::lua_lex::KEYWORDS.contains(&n.as_str()) {
                    return Err(FrontendError::new(var_token.line, format!("'{}' is a keyword", n)));
                }
                self.advance();
                n
            }
            _ => return Err(FrontendError::new(var_token.line, "expected loop variable name")),
        };
        if self.is_keyword("in") {
            return Err(FrontendError::new(
                self.line(),
                "generic for (in) is not supported; only the numeric form is",
            ));
        }
        self.expect_punct("=")?;
        let start = self.parse_expr()?;
        self.expect_punct(",")?;
        let limit = self.parse_expr()?;
        let step = if self.eat_punct(",") {
            Some(self.parse_expr()?)
        } else {
            None
        };
        self.expect_keyword("do")?;
        let body = self.parse_block()?;
        self.expect_keyword("end")?;
        Ok(Stmt::ForNum { var, start, limit, step, body, line: var_token.line })
    }

    /// Parses one full expression with Lua precedence (lowest first).
    fn parse_expr(&mut self) -> Result<Expr, FrontendError> {
        self.enter("expression")?;
        // `or` has the lowest precedence and is left-associative.
        let mut lhs = self.parse_and()?;
        while self.is_keyword("or") {
            let token = self.advance();
            let rhs = self.parse_and()?;
            lhs = Expr::Or(Box::new(lhs), Box::new(rhs), token.line);
        }
        self.leave();
        Ok(lhs)
    }

    /// Parses `and` expressions.
    fn parse_and(&mut self) -> Result<Expr, FrontendError> {
        let mut lhs = self.parse_comparison()?;
        while self.is_keyword("and") {
            let token = self.advance();
            let rhs = self.parse_comparison()?;
            lhs = Expr::And(Box::new(lhs), Box::new(rhs), token.line);
        }
        Ok(lhs)
    }

    /// Parses one non-associative comparison (Lua rejects chains like a < b < c).
    fn parse_comparison(&mut self) -> Result<Expr, FrontendError> {
        let lhs = self.parse_arith()?;
        if is_compare_op(self.peek_text()) {
            let token = self.advance();
            let rhs = self.parse_arith()?;
            if is_compare_op(self.peek_text()) {
                return Err(FrontendError::new(
                    self.line(),
                    "comparison chains like a < b < c are not allowed in Lua",
                ));
            }
            return Ok(Expr::Bin {
                op: token.kind_text(),
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                line: token.line,
            });
        }
        Ok(lhs)
    }

    /// Returns the current token's punct text when it is a plain symbol.
    fn peek_text(&self) -> Option<String> {
        match &self.peek().kind {
            TokKind::Punct(p) => Some(p.clone()),
            _ => None,
        }
    }

    /// Parses additive `+ -` expressions.
    fn parse_arith(&mut self) -> Result<Expr, FrontendError> {
        let mut lhs = self.parse_term()?;
        loop {
            let op = match self.peek_text() {
                Some(text) if text == ".." => {
                    return Err(FrontendError::new(
                        self.line(),
                        "string concatenation '..' is not supported by the SSL-BC subset",
                    ));
                }
                Some(text) if text == "+" || text == "-" => text,
                _ => break,
            };
            let token = self.advance();
            let rhs = self.parse_term()?;
            lhs = Expr::Bin { op, lhs: Box::new(lhs), rhs: Box::new(rhs), line: token.line };
        }
        Ok(lhs)
    }

    /// Parses multiplicative `* / // %` expressions; pow and length error here.
    fn parse_term(&mut self) -> Result<Expr, FrontendError> {
        let mut lhs = self.parse_unary()?;
        loop {
            let op = match self.peek_text() {
                Some(text) if text == "*" || text == "/" || text == "%" => text,
                Some(text) if text == "//" => {
                    return Err(FrontendError::new(
                        self.line(),
                        "floor division '//' is not supported by the SSL-BC subset",
                    ));
                }
                Some(text) if text == "^" => {
                    return Err(FrontendError::new(
                        self.line(),
                        "exponentiation '^' is not supported by the SSL-BC subset",
                    ));
                }
                _ => break,
            };
            let token = self.advance();
            let rhs = self.parse_unary()?;
            lhs = Expr::Bin { op, lhs: Box::new(lhs), rhs: Box::new(rhs), line: token.line };
        }
        Ok(lhs)
    }

    /// Parses unary minus, `not`, and rejects the length operator; `not` binds like unary minus,
    /// above comparisons: `not a == b` parses as `(not a) == b` per Lua.
    fn parse_unary(&mut self) -> Result<Expr, FrontendError> {
        self.enter("expression")?;
        let result = if self.is_punct("-") {
            let token = self.advance();
            let operand = self.parse_unary()?;
            Ok(Expr::Neg(Box::new(operand), token.line))
        } else if self.is_keyword("not") {
            let token = self.advance();
            let operand = self.parse_unary()?;
            Ok(Expr::Not(Box::new(operand), token.line))
        } else if self.is_punct("#") {
            Err(FrontendError::new(
                self.line(),
                "length operator '#' is not supported by the SSL-BC subset",
            ))
        } else {
            self.parse_suffixed_expr()
        };
        self.leave();
        result
    }

    /// Parses a primary expression followed by indexing/call suffixes.
    fn parse_suffixed_expr(&mut self) -> Result<Expr, FrontendError> {
        let mut expr = self.parse_primary()?;
        loop {
            if self.is_punct(".") {
                self.advance();
                let name_token = self.peek().clone();
                let name = match name_token.kind {
                    TokKind::Name(n) => {
                        if crate::lua_lex::KEYWORDS.contains(&n.as_str()) {
                            return Err(FrontendError::new(name_token.line, format!("'{}' is a keyword", n)));
                        }
                        self.advance();
                        n
                    }
                    _ => return Err(FrontendError::new(name_token.line, "expected field name after '.'")),
                };
                expr = Expr::Index {
                    table: Box::new(expr),
                    key: Box::new(Expr::StrLit(name, name_token.line)),
                    line: name_token.line,
                };
            } else if self.is_punct("[") {
                self.advance();
                let key = self.parse_expr()?;
                self.expect_punct("]")?;
                let line = self.line();
                expr = Expr::Index { table: Box::new(expr), key: Box::new(key), line };
            } else if self.is_punct("(") {
                return self.parse_call(expr);
            } else {
                break;
            }
        }
        Ok(expr)
    }

    /// Parses a call suffix on the given callee expression.
    fn parse_call(&mut self, callee_expr: Expr) -> Result<Expr, FrontendError> {
        let line = self.line();
        let callee = match &callee_expr {
            Expr::Name(name, _) => match name.as_str() {
                "print" => Callee::Print,
                _ => {
                    return Err(FrontendError::new(
                        line,
                        format!("calls to '{}' are not supported; only print and math.* builtins are", name),
                    ))
                }
            },
            Expr::Index { table, key, .. } => match (table.as_ref(), key.as_ref()) {
                (Expr::Name(base, _), Expr::StrLit(field, _)) if base == "math" => match field.as_str() {
                    "sin" => Callee::Sin,
                    "cos" => Callee::Cos,
                    "sqrt" => Callee::Sqrt,
                    "abs" => Callee::Abs,
                    "floor" => Callee::Floor,
                    _ => {
                        return Err(FrontendError::new(
                            line,
                            format!("math.{} is not a supported builtin", field),
                        ))
                    }
                },
                _ => {
                    return Err(FrontendError::new(
                        line,
                        "only print(...) and math.*(...) builtin calls are supported",
                    ))
                }
            },
            _ => {
                return Err(FrontendError::new(
                    line,
                    "only builtin calls are supported by the SSL-BC subset",
                ))
            }
        };
        self.expect_punct("(")?;
        let mut args = Vec::new();
        if !self.is_punct(")") {
            loop {
                args.push(self.parse_expr()?);
                if !self.eat_punct(",") {
                    break;
                }
            }
        }
        self.expect_punct(")")?;
        if args.len() != 1 {
            return Err(FrontendError::new(line, "builtin calls take exactly one argument"));
        }
        Ok(Expr::Call { callee, arg: Box::new(args.remove(0)), line })
    }

    fn parse_primary(&mut self) -> Result<Expr, FrontendError> {
        let token = self.peek().clone();
        let line = token.line;
        match token.kind {
            TokKind::IntLit(v) => {
                self.advance();
                Ok(Expr::IntLit(v, line))
            }
            TokKind::NumLit(v) => {
                self.advance();
                Ok(Expr::NumLit(v, line))
            }
            TokKind::StrLit(s) => {
                self.advance();
                Ok(Expr::StrLit(s, line))
            }
            TokKind::Name(ref n) => {
                if KEYWORDS.contains(&n.as_str()) {
                    match n.as_str() {
                        "nil" => {
                            self.advance();
                            Ok(Expr::Nil(line))
                        }
                        "true" => {
                            self.advance();
                            Ok(Expr::True(line))
                        }
                        "false" => {
                            self.advance();
                            Ok(Expr::False(line))
                        }
                        "function" => Err(FrontendError::new(
                            line,
                            "function expressions are not supported by the SSL-BC subset",
                        )),
                        _ => Err(FrontendError::new(line, format!("unexpected keyword '{}'", n))),
                    }
                } else {
                    self.advance();
                    Ok(Expr::Name(n.clone(), line))
                }
            }
            TokKind::Punct(ref p) if p == "(" => {
                self.advance();
                let inner = self.parse_expr()?;
                self.expect_punct(")")?;
                Ok(inner)
            }
            TokKind::Punct(ref p) if p == "{" => self.parse_table_ctor(),
            TokKind::Eof => Err(FrontendError::new(line, "unexpected end of input")),
            _ => Err(FrontendError::new(line, "unexpected token")),
        }
    }

    /// Parses one table constructor with positional, named, and keyed fields.
    fn parse_table_ctor(&mut self) -> Result<Expr, FrontendError> {
        self.enter("table constructor")?;
        let open = self.expect_punct("{")?;
        let mut fields = Vec::new();
        loop {
            if self.is_punct("}") {
                break;
            }
            if self.is_punct("[") {
                // [expr] = value
                self.advance();
                let key = self.parse_expr()?;
                self.expect_punct("]")?;
                self.expect_punct("=")?;
                let value = self.parse_expr()?;
                let line = key.line();
                fields.push(TableField::Keyed(Box::new(key), Box::new(value), line));
            } else {
                let token = self.peek().clone();
                if matches!(token.kind, TokKind::Name(ref n)
                    if !crate::lua_lex::KEYWORDS.contains(&n.as_str()))
                    && self.peek2_is_punct("=")
                {
                    // name = value
                    self.advance();
                    self.advance();
                    let value = self.parse_expr()?;
                    let name = match token.kind {
                        TokKind::Name(n) => n,
                        _ => unreachable!(),
                    };
                    fields.push(TableField::Named(name, value, token.line));
                } else {
                    let item = self.parse_expr()?;
                    fields.push(TableField::Pos(item));
                }
            }
            if !self.eat_punct(",") && !self.eat_punct(";") {
                break;
            }
        }
        self.expect_punct("}")?;
        self.leave();
        if fields.len() > ssl_config::limits::MAX_TABLE_CELLS as usize - 1 {
            return Err(FrontendError::new(
                open.line,
                format!(
                    "table constructor exceeds the {}-cell VM limit (max {} items)",
                    ssl_config::limits::MAX_TABLE_CELLS,
                    ssl_config::limits::MAX_TABLE_CELLS - 1
                ),
            ));
        }
        Ok(Expr::TableCtor { fields, line: open.line })
    }

    /// Reports whether the token after the current one is the given punct.
    fn peek2_is_punct(&self, text: &str) -> bool {
        match self.tokens.get(self.pos + 1) {
            Some(Token { kind: TokKind::Punct(p), .. }) => p == text,
            _ => false,
        }
    }
}

/// Reports whether the punct text is a comparison operator.
fn is_compare_op(text: Option<String>) -> bool {
    matches!(
        text.as_deref(),
        Some("==") | Some("~=") | Some("<") | Some("<=") | Some(">") | Some(">=")
    )
}

/// Convenience accessor used by parse_not to get operator text from a token.
trait TokenText {
    fn kind_text(&self) -> String;
}

impl TokenText for Token {
    fn kind_text(&self) -> String {
        match &self.kind {
            TokKind::Punct(p) => p.clone(),
            _ => String::new(),
        }
    }
}
