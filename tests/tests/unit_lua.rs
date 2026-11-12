// CEP:FILE: tests/tests/unit_lua.rs
// CEP:WHAT: Differential tests for the Lua frontend: lexing, parsing errors, codegen shapes, and end-to-end program results under interpreter and JIT execution.
// CEP:WHY: The frontend must produce the exact observable semantics of the supported Lua subset; every lowering path is exercised against hand-computed results.
// CEP:CLASS: CEP-1
// CEP:STATUS: complete
// CEP:FAILURE: Any failing assertion or unexpected runtime error fails the test; no panics escape the driver.
// CEP:ASSUMES: interpreter-only cases toggle machine execution on the driver instance (set_machine_exec), never through process-global environment variables; JIT cases need writable code memory.
// CEP:COST: bounded small programs; each run is sub-millisecond except the hot-loop cases.
// CEP:EVIDENCE: this file; includes regression tests for reviewer-found blockers (condition-context or/and, block scoping, ADDI loop guards, string compares, table prop overlap, parser depth budget).

use ssl_cold::driver::Driver;
use ssl_cold::lua_frontend::compile_source;

/// Runs one Lua program with the JIT enabled and returns the printed values.
fn run_jit(source: &str) -> Result<Vec<String>, String> {
    let mut driver = Driver::from_lua(source).map_err(|e| format!("{:?}", e))?;
    let report = driver.run().map_err(|e| format!("{:?}", e))?;
    assert!(report.completed, "program did not complete: {}", source);
    Ok(report.out.iter().map(render).collect())
}

/// Runs one Lua program with machine-code execution disabled (interpreter only).
fn run_interp(source: &str) -> Result<Vec<String>, String> {
    let mut driver = Driver::from_lua(source).map_err(|e| format!("{:?}", e))?;
    driver.set_machine_exec(false);
    let report = driver.run().map_err(|e| format!("{:?}", e))?;
    assert!(report.completed, "program did not complete: {}", source);
    Ok(report.out.iter().map(render).collect())
}

fn render(value: &ssl_hot::vm_value::SslValue) -> String {
    use ssl_hot::vm_value::*;
    if value.is_int() {
        format!("{}", value.as_int())
    } else if value.is_num() {
        format!("{}", value.as_num())
    } else if value.tag == TAG_BOOL {
        format!("{}", value.payload != 0)
    } else if value.is_table() {
        format!("table#{}", value.as_handle())
    } else if value.tag == TAG_STR {
        format!("str#{}", value.as_handle())
    } else {
        "nil".to_string()
    }
}

/// Asserts both execution paths print exactly the expected lines.
fn assert_both(source: &str, expected: &[&str]) {
    let jit = run_jit(source).expect("jit run");
    assert_eq!(jit, expected, "jit mismatch for:\n{}", source);
    let interp = run_interp(source).expect("interp run");
    assert_eq!(interp, expected, "interp mismatch for:\n{}", source);
}

#[test]
fn unit_lua_lex_keywords_and_numbers() {
    let tokens = ssl_cold::lua_lex::lex("local x = 0xFF 1e2 3.5 's' -- c\n").unwrap();
    let kinds: Vec<String> = tokens
        .iter()
        .map(|t| match &t.kind {
            ssl_cold::lua_lex::TokKind::Name(n) => format!("name:{}", n),
            ssl_cold::lua_lex::TokKind::IntLit(v) => format!("int:{}", v),
            ssl_cold::lua_lex::TokKind::NumLit(v) => format!("num:{}", v),
            ssl_cold::lua_lex::TokKind::StrLit(s) => format!("str:{}", s),
            ssl_cold::lua_lex::TokKind::Punct(p) => format!("p:{}", p),
            ssl_cold::lua_lex::TokKind::Eof => "eof".to_string(),
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            "name:local", "name:x", "p:=", "int:255", "num:100", "num:3.5", "str:s", "eof"
        ]
    );
}

#[test]
fn unit_lua_parse_rejects_unsupported_syntax() {
    for (src, needle) in [
        ("local f = function() end", "function"),
        ("return 1 .. 2", "concatenation"),
        ("local x = 2 ^ 3", "exponentiation"),
        ("local n = #t", "length"),
        ("for k in t do end", "generic for"),
        ("local x = f(1)", "calls to 'f'"),
        ("local a = 1 < 2 < 3", "comparison chains"),
    ] {
        let err = compile_source(src).expect_err(src);
        assert!(
            err.message.contains(needle),
            "expected '{}' in error for {}: {:?}",
            needle,
            src,
            err
        );
    }
}

#[test]
fn unit_lua_parse_reports_lines() {
    let err = compile_source("local ok = 1\nlocal bad = 2 ^ 3\n").unwrap_err();
    assert_eq!(err.line, 2);
}

#[test]
fn unit_lua_programs_arithmetic() {
    assert_both(
        "local a = 7\nlocal b = 3\nprint(a + b)\nprint(a - b)\nprint(a * b)\nprint(a / b)\nprint(a % b)\nprint(-a)\n",
        &["10", "4", "21", "2.3333333333333335", "1", "-7"],
    );
}

#[test]
fn unit_lua_programs_forloops() {
    // Constant positive step, constant negative step, and runtime step.
    assert_both(
        "local s = 0\nfor i = 1, 10 do s = s + i end\nprint(s)\nfor i = 10, 1, -2 do s = s + i end\nprint(s)\nlocal st = 3\nfor i = 1, 9, st do s = s + i end\nprint(s)\n",
        &["55", "85", "97"],
    );
    // Zero-iteration ranges in both directions.
    assert_both(
        "local n = 0\nfor i = 5, 1 do n = n + 1 end\nfor i = 1, 5, -1 do n = n + 1 end\nprint(n)\n",
        &["0"],
    );
}

#[test]
fn unit_lua_programs_while_repeat_break() {
    assert_both(
        "local i = 1\nlocal s = 0\nwhile i <= 5 do s = s + i i = i + 1 end\nprint(s)\nrepeat s = s + 10 i = i + 1 until i > 3\nprint(s)\nfor k = 1, 10 do if k == 4 then break end s = s + 100 end\nprint(s)\n",
        &["15", "25", "325"],
    );
}

#[test]
fn unit_lua_programs_if_chain_and_or_not() {
    assert_both(
        "local x = 7\nif x < 5 then print(1) elseif x < 10 then print(2) else print(3) end\nlocal a = false\nlocal b = 9\nprint(a and b or 42)\nprint(not a)\nprint(not 5)\nprint(0 and 1 or 2)\n",
        &["2", "42", "true", "false", "1"],
    );
}

#[test]
fn unit_lua_programs_tables_and_strings() {
    assert_both(
        "local t = {10, 20, 30}\nlocal s = 0\nfor i = 1, 3 do s = s + t[i] end\nprint(s)\nt.point = 5\nt[\"two\"] = 2\nprint(t.point * t.two)\n",
        &["60", "10"],
    );
}

#[test]
fn unit_lua_programs_globals_and_swap() {
    assert_both(
        "g = 0\ng = g + 5\nlocal a, b = 1, 2\na, b = b, a\nprint(g)\nprint(a)\nprint(b)\nlocal x, y = 3\nprint(x)\n",
        &["5", "2", "1", "3"],
    );
    // Missing initializers are nil.
    assert_both(
        "local a, b = 1\nprint(a)\nif b == nil then print(1) else print(0) end\n",
        &["1", "1"],
    );
}

#[test]
fn unit_lua_programs_nil_compare_truthiness() {
    // 0 is truthy in Lua; only nil and false are falsy.
    assert_both(
        "local z = 0\nif z == nil then print(1) else print(0) end\nif not z then print(1) else print(0) end\nlocal n\nprint(n == nil)\nprint(n ~= nil)\n",
        &["0", "0", "true", "false"],
    );
}

#[test]
fn unit_lua_programs_math_builtins() {
    // SSL math builtins are deterministic approximations; check structural facts.
    assert_both(
        "print(math.floor(3.7))\nprint(math.abs(-5))\nlocal s = math.sqrt(4.0)\nprint(s > 1.9 and s < 2.1)\nprint(math.sin(0.0) == 0.0)\n",
        &["3", "5", "true", "true"],
    );
}

#[test]
fn unit_lua_programs_float_widening() {
    // Integer overflow widens to double per the dual-number model.
    assert_both(
        "local big = 9223372036854775807\nprint(big + 1 > big)\nlocal f = 1 / 4\nprint(f)\nprint(10 / 2)\n",
        &["false", "0.25", "5"],
    );
}

#[test]
fn unit_lua_programs_nested_loops_mandel_lite() {
    assert_both(
        "local total = 0\nfor py = 0, 9 do\n  for px = 0, 9 do\n    local x = 0.0\n    local y = 0.0\n    local n = 0\n    while x * x + y * y <= 4.0 and n < 50 do\n      local xt = x * x - y * y + (px * 0.1 - 0.5)\n      y = 2.0 * x * y + (py * 0.1 - 0.5)\n      x = xt\n      n = n + 1\n    end\n    total = total + n\n  end\nend\nprint(total)\n",
        &["4602"],
    );
}

#[test]
fn unit_lua_programs_hot_loop_jit_compiles() {
    // Enough iterations to cross HOT_THRESHOLD; the JIT must compile a trace and
    // still produce the exact interpreter result.
    let src = "local s = 0\nfor i = 1, 500 do s = s + i end\nprint(s)\n";
    assert_both(src, &["125250"]);
}

#[test]
fn unit_lua_programs_table_traffic_jit() {
    // Table traffic through the JIT path: fill and sum a sized array.
    let src = "local t = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0}\nfor i = 1, 10 do t[i] = i * i end\nlocal s = 0\nfor r = 1, 200 do\n  for i = 1, 10 do s = s + t[i] end\nend\nprint(s)\n";
    assert_both(src, &["77000"]);
}

#[test]
fn unit_lua_programs_cond_or_and() {
    // Regression (reviewer R-B#1): or/and in condition contexts collapsed to
    // their last operand when the branch side was a fall-through.
    assert_both(
        "local a = 1\nlocal b = 0\nif a or b then print(1) else print(0) end\nif b or a then print(1) else print(0) end\nif b or 0 then print(1) else print(0) end\nlocal n = 0\nwhile a or b do n = n + 1 if n >= 3 then break end end\nprint(n)\nlocal k = 0\nrepeat k = k + 1 until a and b == 0 or k > 5\nprint(k)\n",
        &["1", "1", "1", "3", "1"],
    );
}

#[test]
fn unit_lua_programs_block_scope() {
    // Regression (reviewer R-B#2): names leaked past their blocks onto
    // recycled slots; shadowing destroyed the outer binding.
    assert_both(
        "local x = 1\ndo local x = 2 end\nprint(x)\nif true then local y = 5 end\nprint(y)\nfor i = 1, 3 do end\nprint(i)\nwhile false do local w = 1 end\nprint(w)\n",
        &["1", "nil", "nil", "nil"],
    );
}

#[test]
fn unit_lua_programs_table_ctor_fields() {
    // Regression (reviewer R-A#3/#7): named, keyed, and trailing-separator
    // constructor fields must parse and emit TSETK/TSETI correctly.
    assert_both(
        "local t = {1, 2, k = 3, [10] = 4,}\nprint(t[1] + t[2])\nprint(t.k)\nprint(t[10])\nlocal u = {a = 5; b = 6}\nprint(u.a + u.b)\n",
        &["3", "3", "4", "11"],
    );
}

#[test]
fn unit_lua_programs_mod_negative_operands() {
    // Lua floor-mod semantics on negatives.
    assert_both(
        "print(-7 % 3)\nprint(7 % -3)\nprint(5.5 % 2)\nprint(10 % 4)\n",
        &["2", "-2", "1.5", "2"],
    );
}

#[test]
fn unit_lua_programs_for_float_start_and_wide_step() {
    // Regression (reviewer R-B#3): float starts and steps beyond the ADDI
    // immediate must use the slot-based ADD path, never integer wrapping.
    assert_both(
        "local s = 0\nfor i = 1.0, 3.0 do s = s + i end\nprint(s)\nlocal c = 0\nfor i = 1, 10, 5000000000 do c = c + 1 end\nprint(c)\nlocal d = 0\nfor i = 10, 1, -5000000000 do d = d + 1 end\nprint(d)\n",
        &["6", "1", "1"],
    );
}

#[test]
fn unit_lua_programs_deep_prop_after_wide_array() {
    // Regression (reviewer R-B#7): the string-property area previously
    // overlapped array cells 7 and 8.
    assert_both(
        "local t = {1, 2, 3, 4, 5, 6, 7, 8}\nt.tag = 42\nprint(t[7] + t[8])\nprint(t.tag)\nprint(t[1])\n",
        &["15", "42", "1"],
    );
}

#[test]
fn unit_lua_rejects_string_compares() {
    // Ordering on strings is numeric garbage in the ISA; equality is only
    // sound between two literals (interned handles).
    for src in [
        "local a = 'x' < 'y'",
        "local a = 'x' <= 1",
        "local a = 'x' == 5",
        "local a = 1 ~= 'x'",
    ] {
        assert!(compile_source(src).is_err(), "expected rejection: {}", src);
    }
    assert_both("print('aa' == 'aa')\nprint('aa' ~= 'bb')\n", &["true", "true"]);
}

#[test]
fn unit_lua_programs_do_blocks_and_empty_statements() {
    assert_both(
        ";;local x = 1;;\ndo x = x + 1 ; end\nprint(x)\n",
        &["2"],
    );
}

#[test]
fn unit_lua_lexes_dot_five_and_escapes() {
    let tokens = ssl_cold::lua_lex::lex("local a = .5 + 1e-2").unwrap();
    assert!(matches!(tokens[3].kind, ssl_cold::lua_lex::TokKind::NumLit(v) if v == 0.5));
    let s = ssl_cold::lua_lex::lex("'a\\65b'").unwrap();
    assert_eq!(s[0].kind, ssl_cold::lua_lex::TokKind::StrLit("aAb".into()));
}

#[test]
fn unit_lua_lexes_long_bracket_comments() {
    let src = "--[==[ multi\nline ]==] local ok = 1\n";
    assert!(compile_source(src).is_ok());
    assert!(compile_source("--[=[ unterminated").is_err());
}

#[test]
fn unit_lua_parse_depth_budget() {
    let mut src = String::from("local x = ");
    for _ in 0..500 {
        src.push('(');
    }
    src.push('1');
    for _ in 0..500 {
        src.push(')');
    }
    let err = compile_source(&src).expect_err("depth budget must reject deep nesting");
    assert!(err.message.contains("nesting"), "got: {:?}", err);
    // Just under the budget still parses.
    let mut ok_src = String::from("local x = ");
    for _ in 0..80 {
        ok_src.push('(');
    }
    ok_src.push('1');
    for _ in 0..80 {
        ok_src.push(')');
    }
    assert!(compile_source(&ok_src).is_ok());
}

#[test]
fn unit_lua_rejects_budget_overruns() {
    // More than 256 live slots.
    let mut slots_src = String::new();
    for i in 0..300 {
        slots_src.push_str(&format!("local v{} = {}\n", i, i));
    }
    let err = compile_source(&slots_src).expect_err("slot budget");
    assert!(err.message.contains("slot"), "got: {:?}", err);
    // More than 256 globals.
    let mut globals_src = String::new();
    for i in 0..300 {
        globals_src.push_str(&format!("g{} = {}\n", i, i));
    }
    let err = compile_source(&globals_src).expect_err("global budget");
    assert!(err.message.contains("global"), "got: {:?}", err);
}

#[test]
fn unit_lua_programs_nested_break_and_goto_error() {
    assert_both(
        "local s = 0\nfor i = 1, 3 do\n  for j = 1, 3 do\n    if j == 2 then break end\n    s = s + 10\n  end\n  s = s + 1\nend\nprint(s)\n",
        &["33"],
    );
    let err = compile_source("goto done").expect_err("goto must error clearly");
    assert!(err.message.contains("goto"), "got: {:?}", err);
}

#[test]
fn unit_lua_programs_local_extras_dropped() {
    // Lua discards extra initializer values.
    assert_both(
        "local a = 1, 2, 3\nprint(a)\nlocal b, c = 7\nprint(b)\nprint(c == nil)\n",
        &["1", "7", "true"],
    );
}

#[test]
fn unit_lua_false_equals_nil_deviation() {
    // DOCUMENTED DEVIATION: the ISA has no bool/nil equality, so x == nil is
    // lowered to a truthiness test; false == nil reports true here where
    // real Lua reports false. nil == nil stays true, values stay correct.
    assert_both(
        "local f = false\nif f == nil then print(1) else print(0) end\nlocal n\nif n == nil then print(1) else print(0) end\n",
        &["1", "1"],
    );
}

#[test]
fn unit_lua_report_engagement() {
    // A hot loop must actually compile a trace, count interpreter steps, and
    // complete; the harness relies on all three signals.
    let src = "local s = 0\nfor i = 1, 200 do s = s + i end\nprint(s)\n";
    let mut driver = Driver::from_lua(src).expect("compile");
    let report = driver.run().expect("run");
    assert!(report.completed);
    assert!(report.traces_compiled >= 1, "jit must compile a trace");
    assert!(report.steps > 0, "interpreter steps must be counted");
    assert_eq!(report.out.len(), 1);
    let interp_src = Driver::from_lua(src).expect("compile");
    let mut interp = interp_src;
    interp.set_machine_exec(false);
    let report = interp.run().expect("run");
    assert!(report.completed);
    assert!(report.traces_compiled >= 1);
    assert_eq!(render(&report.out[0]), "20100");
}
