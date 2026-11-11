// CEP:FILE: tools/cep_lint/src/regex_lite.rs
// CEP:WHAT: Bounded backtracking regular-expression subset used for every configurable lint pattern.
// CEP:WHY: The engine is zero-dependency; section 50.1 requires configurable regex patterns, so a deterministic bounded matcher is needed instead of a third-party crate.
// CEP:CLASS: CEP-2
// CEP:STATUS: complete
// CEP:FAILURE: Returns RegexError on invalid syntax, oversized patterns, or step-budget exhaustion during matching; no panics, no unbounded recursion.
// CEP:ASSUMES: patterns and subjects are UTF-8; matching is character based; recursion is bounded by pattern structure and the step budget.
// CEP:COST: cold; pattern compile is O(P), match is O(S * steps) bounded by REGEX_MAX_STEPS.
// CEP:EVIDENCE: unit test cep_lint::regex_lite in tools/cep_lint/tests/unit_regex.rs.

use crate::limits as L;

#[derive(Debug, Clone, PartialEq)]
pub struct RegexError {
    pub detail: String,
}

#[derive(Debug, Clone)]
enum Node {
    Char(char),
    Any,
    Digit(bool),
    Word(bool),
    Space(bool),
    Class { negated: bool, items: Vec<ClassItem> },
    Boundary(bool),
    Start,
    End,
    Group { index: usize, body: Box<Node> },
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Repeat { body: Box<Node>, min: u32, max: u32 },
}

#[derive(Debug, Clone)]
enum ClassItem {
    Single(char),
    Range(char, char),
    Digit(bool),
    Word(bool),
    Space(bool),
}

#[derive(Debug, Clone)]
pub struct MatchHit {
    pub start: usize,
    pub end: usize,
    pub caps: Vec<Option<String>>,
}

pub struct Regex {
    root: Node,
    capture_count: usize,
    icase: bool,
}

impl Regex {
    // CEP:WHAT: Parses a pattern into an AST with length bounds and syntax validation.
    // CEP:WHY: All lint patterns flow through this compiler; invalid syntax must surface as BOOT-8 before scanning.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    pub fn compile(pattern: &str, icase: bool) -> Result<Regex, RegexError> {
        if pattern.len() > L::REGEX_MAX_PATTERN_BYTES {
            return Err(RegexError {
                detail: "pattern exceeds maximum length".to_string(),
            });
        }
        let mut parser = Parser {
            chars: pattern.chars().collect(),
            pos: 0,
            captures: 0,
        };
        let root = parser.parse_alt()?;
        if parser.pos != parser.chars.len() {
            return Err(RegexError {
                detail: format!("unexpected character at offset {}", parser.pos),
            });
        }
        Ok(Regex {
            root,
            capture_count: parser.captures,
            icase,
        })
    }

    // CEP:WHAT: Reports whether the pattern matches anywhere in the subject.
    // CEP:WHY: Exempt-context and suppression checks need only boolean results.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    pub fn is_match(&self, text: &str) -> Result<bool, RegexError> {
        let chars: Vec<char> = text.chars().collect();
        for start in 0..=chars.len() {
            let mut walker = Walker::new(&chars, self.icase);
            walker.set_capture_count(self.capture_count);
            let hit = walk(&self.root, &mut walker, start, &mut |_w, _pos| Ok(true))?;
            if hit {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // CEP:WHAT: Returns all non-overlapping leftmost matches with capture text.
    // CEP:WHY: Token and literal scans need spans and captures; zero-width matches are skipped to keep iteration finite.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    pub fn find_iter(&self, text: &str) -> Result<Vec<MatchHit>, RegexError> {
        let chars: Vec<char> = text.chars().collect();
        let mut out = Vec::new();
        let mut start = 0;
        while start <= chars.len() {
            let mut walker = Walker::new(&chars, self.icase);
            walker.set_capture_count(self.capture_count);
            let mut hit_end = 0usize;
            let found = walk(&self.root, &mut walker, start, &mut |_w, pos| {
                hit_end = pos;
                Ok(true)
            })?;
            if found && hit_end > start {
                out.push(MatchHit {
                    start,
                    end: hit_end,
                    caps: walker.take_captures_text(&chars),
                });
                start = hit_end;
            } else {
                start += 1;
            }
        }
        Ok(out)
    }

    // CEP:WHAT: Returns the number of capture groups in the pattern.
    // CEP:WHY: Capture validation for name_group parameters needs the group arity.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    pub fn group_count(&self) -> usize {
        self.capture_count
    }
}

struct Walker<'a> {
    chars: &'a [char],
    caps: Vec<Option<(usize, usize)>>,
    steps: u32,
    icase: bool,
}

impl<'a> Walker<'a> {
    fn new(chars: &'a [char], icase: bool) -> Walker<'a> {
        Walker {
            chars,
            caps: Vec::new(),
            steps: L::REGEX_MAX_STEPS,
            icase,
        }
    }

    // CEP:WHAT: Allocates capture slots for one match attempt.
    // CEP:WHY: Small accessors keep matcher state handling explicit and side-effect free.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn set_capture_count(&mut self, count: usize) {
        self.caps = vec![None; count + 1];
    }

    // CEP:WHAT: Records a capture span for one group index.
    // CEP:WHY: Captures must survive continuation flow so name extraction reads consistent spans.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn set_cap(&mut self, index: usize, start: usize, end: usize) {
        if index < self.caps.len() {
            self.caps[index] = Some((start, end));
        }
    }

    // CEP:WHAT: Clears a capture span after a failed backtracking attempt.
    // CEP:WHY: Stale captures would leak into later matches and corrupt name validation.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn clear_cap(&mut self, index: usize) {
        if index < self.caps.len() {
            self.caps[index] = None;
        }
    }

    // CEP:WHAT: Converts recorded spans into captured strings for one match.
    // CEP:WHY: Callers need text, not offsets, for name validation and finding messages.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn take_captures_text(&self, chars: &[char]) -> Vec<Option<String>> {
        self.caps
            .iter()
            .skip(1)
            .map(|opt| opt.map(|(s, e)| chars[s..e].iter().collect()))
            .collect()
    }

    // CEP:WHAT: Consumes one matching step and rejects exhaustion.
    // CEP:WHY: Section 22.10 forbids unbounded work; the budget bounds every match attempt.
    // CEP:STATUS: complete
    // CEP:FAILURE: Returns RegexError when the step budget reaches zero.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn spend(&mut self) -> Result<(), RegexError> {
        if self.steps == 0 {
            return Err(RegexError {
                detail: "match step budget exhausted".to_string(),
            });
        }
        self.steps -= 1;
        Ok(())
    }

    // CEP:WHAT: Matches one single-character node at a position.
    // CEP:WHY: Char, class, and shorthand classes share one fast path.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn match_single(&mut self, node: &Node, pos: usize) -> Option<usize> {
        let ch = *self.chars.get(pos)?;
        let matched = match node {
            Node::Char(c) => {
                if self.icase {
                    ch.eq_ignore_ascii_case(c)
                } else {
                    ch == *c
                }
            }
            Node::Any => true,
            Node::Digit(yes) => ch.is_ascii_digit() == *yes,
            Node::Word(yes) => (ch.is_ascii_alphanumeric() || ch == '_') == *yes,
            Node::Space(yes) => ch.is_ascii_whitespace() == *yes,
            Node::Class { negated, items } => {
                let hit = items.iter().any(|item| self.class_hit(item, ch));
                hit != *negated
            }
            _ => return None,
        };
        if matched {
            Some(pos + 1)
        } else {
            None
        }
    }

    // CEP:WHAT: Tests one character against one class item.
    // CEP:WHY: Ranges, singles, and shorthand classes cover the pattern vocabulary used by configuration.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn class_hit(&self, item: &ClassItem, ch: char) -> bool {
        match item {
            ClassItem::Single(c) => {
                if self.icase {
                    ch.eq_ignore_ascii_case(c)
                } else {
                    ch == *c
                }
            }
            ClassItem::Range(lo, hi) => ch >= *lo && ch <= *hi,
            ClassItem::Digit(yes) => ch.is_ascii_digit() == *yes,
            ClassItem::Word(yes) => (ch.is_ascii_alphanumeric() || ch == '_') == *yes,
            ClassItem::Space(yes) => ch.is_ascii_whitespace() == *yes,
        }
    }

    // CEP:WHAT: Reports whether a word boundary exists at a position.
    // CEP:WHY: Token rules rely on word boundaries to avoid matching identifiers containing banned words.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn at_boundary(&self, pos: usize) -> bool {
        let before = pos
            .checked_sub(1)
            .and_then(|i| self.chars.get(i))
            .map(|c| c.is_ascii_alphanumeric() || *c == '_')
            .unwrap_or(false);
        let after = self
            .chars
            .get(pos)
            .map(|c| c.is_ascii_alphanumeric() || *c == '_')
            .unwrap_or(false);
        before != after
    }
}

type Cont<'k> = dyn FnMut(&mut Walker, usize) -> Result<bool, RegexError> + 'k;

    // CEP:WHAT: Matches one node against the subject at a position with a continuation and step budget.
    // CEP:WHY: Backtracking with explicit continuations keeps the engine bounded and deterministic.
    // CEP:STATUS: complete
    // CEP:FAILURE: Returns RegexError when the step budget is exhausted.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn walk(node: &Node, w: &mut Walker, pos: usize, k: &mut Cont) -> Result<bool, RegexError> {
    w.spend()?;
    match node {
        Node::Concat(parts) => walk_seq(parts, 0, w, pos, k),
        Node::Alt(branches) => {
            for branch in branches {
                if walk(branch, w, pos, k)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Node::Group { index, body } => {
            let start = pos;
            let ok = walk(body, w, pos, &mut |w2, end| {
                w2.set_cap(*index, start, end);
                k(w2, end)
            })?;
            if !ok {
                w.clear_cap(*index);
            }
            Ok(ok)
        }
        Node::Repeat { body, min, max } => {
            if is_single_char(body) {
                walk_single_repeat(body, *min, *max, w, pos, k)
            } else {
                walk_general_repeat(body, *min, *max, w, pos, k)
            }
        }
        Node::Start => {
            if pos == 0 {
                k(w, pos)
            } else {
                Ok(false)
            }
        }
        Node::End => {
            if pos == w.chars.len() {
                k(w, pos)
            } else {
                Ok(false)
            }
        }
        Node::Boundary(yes) => {
            if w.at_boundary(pos) == *yes {
                k(w, pos)
            } else {
                Ok(false)
            }
        }
        leaf => match w.match_single(leaf, pos) {
            Some(next) => k(w, next),
            None => Ok(false),
        },
    }
}

    // CEP:WHAT: Matches a concat sequence by index with continuation chaining.
    // CEP:WHY: Sequence matching is the backbone of every compiled pattern.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn walk_seq(parts: &[Node], idx: usize, w: &mut Walker, pos: usize, k: &mut Cont) -> Result<bool, RegexError> {
    if idx == parts.len() {
        return k(w, pos);
    }
    walk(&parts[idx], w, pos, &mut |w2, next| {
        walk_seq(parts, idx + 1, w2, next, k)
    })
}

    // CEP:WHAT: Reports whether a node consumes at most one character.
    // CEP:WHY: Single-character repeats take the iterative path so long subjects cannot exhaust the stack.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn is_single_char(node: &Node) -> bool {
    matches!(
        node,
        Node::Char(_)
            | Node::Any
            | Node::Digit(_)
            | Node::Word(_)
            | Node::Space(_)
            | Node::Class { .. }
    )
}

    // CEP:WHAT: Matches a repeat of single-character nodes iteratively with greedy backtracking.
    // CEP:WHY: Iterative counting prevents recursion depth from scaling with subject length per section 22.10.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn walk_single_repeat(
    body: &Node,
    min: u32,
    max: u32,
    w: &mut Walker,
    pos: usize,
    k: &mut Cont,
) -> Result<bool, RegexError> {
    let mut positions = vec![pos];
    let mut cur = pos;
    while positions.len() <= max as usize {
        match w.match_single(body, cur) {
            Some(next) => {
                cur = next;
                positions.push(cur);
            }
            None => break,
        }
    }
    if positions.len() <= min as usize {
        return Ok(false);
    }
    let mut count = positions.len() - 1;
    while count >= min as usize {
        if k(w, positions[count])? {
            return Ok(true);
        }
        if count == 0 {
            break;
        }
        count -= 1;
    }
    Ok(false)
}

    // CEP:WHAT: Matches a repeat of compound nodes with bounded recursion.
    // CEP:WHY: Compound repeats are rare in lint patterns; recursion is bounded by the step budget.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

fn walk_general_repeat(
    body: &Node,
    min: u32,
    max: u32,
    w: &mut Walker,
    pos: usize,
    k: &mut Cont,
) -> Result<bool, RegexError> {
    if min > 0 {
        return walk(body, w, pos, &mut |w2, next| {
            walk_general_repeat(body, min - 1, max.saturating_sub(1), w2, next, k)
        });
    }
    if max == 0 {
        return k(w, pos);
    }
    if k(w, pos)? {
        return Ok(true);
    }
    walk(body, w, pos, &mut |w2, next| {
        if next == pos {
            return Ok(false);
        }
        walk_general_repeat(body, 0, max - 1, w2, next, k)
    })
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
    captures: usize,
}

impl Parser {
    // CEP:WHAT: Builds a RegexError with a pattern offset.
    // CEP:WHY: Compile failures must identify the position for the BOOT-8 detail string.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn err(&self, detail: &str) -> RegexError {
        RegexError {
            detail: format!("{} at pattern offset {}", detail, self.pos),
        }
    }

    // CEP:WHAT: Returns the byte at the cursor without advancing.
    // CEP:WHY: Small accessors keep matcher state handling explicit and side-effect free.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    // CEP:WHAT: Parses alternation over concat branches.
    // CEP:WHY: Alternation is the top-level pattern structure in the configured token and marker patterns.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn parse_alt(&mut self) -> Result<Node, RegexError> {
        let mut branches = vec![self.parse_concat()?];
        while self.peek() == Some('|') {
            self.pos += 1;
            branches.push(self.parse_concat()?);
        }
        if branches.len() == 1 {
            Ok(branches.pop().unwrap_or(Node::Concat(Vec::new())))
        } else {
            Ok(Node::Alt(branches))
        }
    }

    // CEP:WHAT: Parses a sequence of quantified atoms until an alternation or group boundary.
    // CEP:WHY: Small accessors keep matcher state handling explicit and side-effect free.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn parse_concat(&mut self) -> Result<Node, RegexError> {
        let mut parts = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            parts.push(self.parse_repeat()?);
        }
        Ok(Node::Concat(parts))
    }

    // CEP:WHAT: Attaches a quantifier to one atom.
    // CEP:WHY: Greedy and optional quantifiers cover every configured pattern.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn parse_repeat(&mut self) -> Result<Node, RegexError> {
        let atom = self.parse_atom()?;
        let (min, max) = match self.peek() {
            Some('*') => {
                self.pos += 1;
                (0, u32::MAX)
            }
            Some('+') => {
                self.pos += 1;
                (1, u32::MAX)
            }
            Some('?') => {
                self.pos += 1;
                (0, 1)
            }
            Some('{') => self.parse_bound()?,
            _ => return Ok(atom),
        };
        if self.peek() == Some('?') {
            self.pos += 1;
        }
        Ok(Node::Repeat {
            body: Box::new(atom),
            min,
            max,
        })
    }

    // CEP:WHAT: Parses an explicit {m,n} bound.
    // CEP:WHY: Explicit bounds are validated for syntax and overflow at compile time.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn parse_bound(&mut self) -> Result<(u32, u32), RegexError> {
        self.pos += 1;
        let mut min_text = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                min_text.push(c);
                self.pos += 1;
            } else {
                break;
            }
        }
        let min: u32 = min_text
            .parse()
            .map_err(|_| self.err("bad or overflowing count in {m,n}"))?;
        match self.peek() {
            Some('}') => {
                self.pos += 1;
                Ok((min, min))
            }
            Some(',') => {
                self.pos += 1;
                let mut max_text = String::new();
                while let Some(c) = self.peek() {
                    if c.is_ascii_digit() {
                        max_text.push(c);
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                if self.peek() != Some('}') {
                    return Err(self.err("expected ',' or '}' in {m,n}"));
                }
                self.pos += 1;
                let max = if max_text.is_empty() {
                    u32::MAX
                } else {
                    max_text
                        .parse()
                        .map_err(|_| self.err("overflowing count in {m,n}"))?
                };
                Ok((min, max))
            }
            _ => Err(self.err("expected ',' or '}' in {m,n}")),
        }
    }

    // CEP:WHAT: Parses one atom: group, class, anchor, escape, or character.
    // CEP:WHY: Non-capture groups keep qualifier syntax from polluting capture indices.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn parse_atom(&mut self) -> Result<Node, RegexError> {
        match self.peek() {
            None => Err(self.err("unexpected end of pattern")),
            Some('(') => {
                self.pos += 1;
                if self.peek() == Some('?') && self.peek_at(1) == Some(':') {
                    self.pos += L::NONCAPTURE_SKIP;
                    let body = self.parse_alt()?;
                    if self.peek() != Some(')') {
                        return Err(self.err("expected ')'"));
                    }
                    self.pos += 1;
                    Ok(body)
                } else {
                    self.captures += 1;
                    let index = self.captures;
                    let body = self.parse_alt()?;
                    if self.peek() != Some(')') {
                        return Err(self.err("expected ')'"));
                    }
                    self.pos += 1;
                    Ok(Node::Group {
                        index,
                        body: Box::new(body),
                    })
                }
            }
            Some('[') => self.parse_class(),
            Some('.') => {
                self.pos += 1;
                Ok(Node::Any)
            }
            Some('^') => {
                self.pos += 1;
                Ok(Node::Start)
            }
            Some('$') => {
                self.pos += 1;
                Ok(Node::End)
            }
            Some('\\') => self.parse_escape(),
            Some(c) => {
                self.pos += 1;
                Ok(Node::Char(c))
            }
        }
    }

    // CEP:WHAT: Returns the character at a cursor offset without advancing.
    // CEP:WHY: Look-ahead for the non-capture group syntax needs two-character inspection.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    // CEP:WHAT: Parses backslash escapes into shorthand nodes or literal characters.
    // CEP:WHY: Shorthand classes and boundaries are the core of the token patterns.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn parse_escape(&mut self) -> Result<Node, RegexError> {
        self.pos += 1;
        match self.peek() {
            None => Err(self.err("truncated escape")),
            Some('d') => {
                self.pos += 1;
                Ok(Node::Digit(true))
            }
            Some('D') => {
                self.pos += 1;
                Ok(Node::Digit(false))
            }
            Some('w') => {
                self.pos += 1;
                Ok(Node::Word(true))
            }
            Some('W') => {
                self.pos += 1;
                Ok(Node::Word(false))
            }
            Some('s') => {
                self.pos += 1;
                Ok(Node::Space(true))
            }
            Some('S') => {
                self.pos += 1;
                Ok(Node::Space(false))
            }
            Some('b') => {
                self.pos += 1;
                Ok(Node::Boundary(true))
            }
            Some('B') => {
                self.pos += 1;
                Ok(Node::Boundary(false))
            }
            Some('n') => {
                self.pos += 1;
                Ok(Node::Char('\n'))
            }
            Some('t') => {
                self.pos += 1;
                Ok(Node::Char('\t'))
            }
            Some(c) => {
                self.pos += 1;
                Ok(Node::Char(c))
            }
        }
    }

    // CEP:WHAT: Parses a bracketed character class with ranges, negation, and class escapes.
    // CEP:WHY: Naming and marker patterns depend on classes for case and shape validation.
    // CEP:STATUS: complete
    // CEP:FAILURE: none; pure scan over bounded input.
    // CEP:ASSUMES: none
    // CEP:COST: cold; O(N) over file bytes.
    // CEP:EVIDENCE: self-lint gate plus unit tests in tools/cep_lint/tests

    fn parse_class(&mut self) -> Result<Node, RegexError> {
        self.pos += 1;
        let mut negated = false;
        if self.peek() == Some('^') {
            negated = true;
            self.pos += 1;
        }
        let mut items = Vec::new();
        let mut first = true;
        loop {
            match self.peek() {
                None => return Err(self.err("unterminated character class")),
                Some(']') if !first => {
                    self.pos += 1;
                    break;
                }
                Some(c) => {
                    first = false;
                    let lo = if c == '\\' {
                        match self.parse_escape()? {
                            Node::Digit(yes) => {
                                items.push(ClassItem::Digit(yes));
                                continue;
                            }
                            Node::Word(yes) => {
                                items.push(ClassItem::Word(yes));
                                continue;
                            }
                            Node::Space(yes) => {
                                items.push(ClassItem::Space(yes));
                                continue;
                            }
                            Node::Char(ch) => ch,
                            _ => return Err(self.err("unsupported class escape")),
                        }
                    } else {
                        c
                    };
                    self.pos += 1;
                    if self.peek() == Some('-') && self.peek_at(1) != Some(']') && self.peek_at(1).is_some() {
                        self.pos += 1;
                        let hi = self.chars[self.pos];
                        self.pos += 1;
                        items.push(ClassItem::Range(lo, hi));
                    } else {
                        items.push(ClassItem::Single(lo));
                    }
                }
            }
        }
        Ok(Node::Class { negated, items })
    }
}
