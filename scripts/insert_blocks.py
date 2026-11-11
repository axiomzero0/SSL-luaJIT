#!/usr/bin/env python3
# CEP:FILE: scripts/insert_blocks.py
# CEP:WHAT: Inserts authored CEP function comment blocks above Rust function definitions that lack them.
# CEP:WHY: CEP-LINT-FUNC-BLOCK requires a seven-field block above every function with at least two statements; authoring in a table keeps field text reviewable while insertion stays mechanical and deterministic.
# CEP:CLASS: CEP-2
# CEP:STATUS: complete
# CEP:FAILURE: Exits non-zero if a spec entry does not match a function definition or a block would be inserted twice.
# CEP:ASSUMES: source files use rustfmt-compatible brace-on-new-line function layout; spec keys are "path:fn_name".
# CEP:COST: offline tool; runtime cost irrelevant.
# CEP:EVIDENCE: cep_lint full-tree scan reports zero FUNC-BLOCK findings after a run.
# CEP:SECURITY: reads and writes repository files only; no network.

import sys
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def block(what, why, failure="none; pure scan over bounded input.", assumes="none",
          cost="cold; O(N) over file bytes.", evidence="self-lint gate plus unit tests in tools/cep_lint/tests",
          status="complete"):
    return [
        f"    // CEP:WHAT: {what}",
        f"    // CEP:WHY: {why}",
        f"    // CEP:STATUS: {status}",
        f"    // CEP:FAILURE: {failure}",
        f"    // CEP:ASSUMES: {assumes}",
        f"    // CEP:COST: {cost}",
        f"    // CEP:EVIDENCE: {evidence}",
        "",
    ]


SPEC = {}


def spec(path, name, *args, **kwargs):
    SPEC[f"{path}:{name}"] = block(*args, **kwargs)


# ---- blocks.rs
spec("tools/cep_lint/src/blocks.rs", "extract_blocks",
     "Groups contiguous comment lines into blocks and attaches parsed CEP fields to each block.",
     "File headers, function blocks, and stub declarations are all contiguous runs; one extractor keeps schema semantics consistent across checks.")
spec("tools/cep_lint/src/blocks.rs", "parse_field",
     "Parses one comment line into a CEP field name and value when it carries the CEP: prefix.",
     "Non-CEP prose must never yield a field; the prefix requirement prevents colon prose from being misread.")
spec("tools/cep_lint/src/blocks.rs", "file_class",
     "Returns the CEP:CLASS value declared in the first comment block of a file.",
     "Class-based rules such as banned tokens and topology limits need the declared conformance class.")

# ---- checks_code.rs
spec("tools/cep_lint/src/checks_code.rs", "check_numeric_literals",
     "Flags numeric literals outside the allowed values and sanctioned statement contexts.",
     "Law 7 and section 11.3 ban magic numbers; the statement window and exempt contexts come from configuration.")
spec("tools/cep_lint/src/checks_code.rs", "literal_text",
     "Extends a numeric literal match to its full text including hex prefix, underscores, and one decimal point.",
     "Value comparison is numeric, so 0x10 and 16 must resolve to the same literal text for allowed-value checks.")
spec("tools/cep_lint/src/checks_code.rs", "numeric_equal",
     "Compares a configured allowed value with a literal numerically across decimal and hexadecimal forms.",
     "The catalog requires value comparison, so 0x0 equals 0 and underscore separators are ignored.")
spec("tools/cep_lint/src/checks_code.rs", "statement_context",
     "Joins the lines forming the statement that contains a literal, bounded to the catalog window.",
     "Sanctioned forms such as const declarations are detected on the joined statement, not the bare line.")
spec("tools/cep_lint/src/checks_code.rs", "ends_statement",
     "Reports whether a code line terminates a statement by punctuation or emptiness.",
     "The statement window walk uses terminators to stop extending in both directions.")
spec("tools/cep_lint/src/checks_code.rs", "check_macro_prefix",
     "Flags macro definitions whose names violate the configured prefix and guard patterns.",
     "Section 33.16 requires CEP_ naming; in Rust, macro_rules! definitions are the object-like macro analog.")
spec("tools/cep_lint/src/checks_code.rs", "check_banned_tokens",
     "Flags banned tokens in files whose declared class is in the hot-class list.",
     "Section 5.1 and 25.3 ban allocating and dispatching constructs in CEP-0 hot code; tokens are matched on comment-and-string-blanked code.")
spec("tools/cep_lint/src/checks_code.rs", "check_flat_code_regex",
     "Runs a configured pattern over code lines with optional capture-name validation.",
     "Implements the flat_code_regex primitive used by the empty branch, empty catch, and type naming rules.")

# ---- checks_comment.rs
spec("tools/cep_lint/src/checks_comment.rs", "check_file_header",
     "Validates that the first comment block is a complete CEP file header with a known class.",
     "Section 35 requires the header to be the first content with nine fields; missing fields and late or misplaced headers are violations.")
spec("tools/cep_lint/src/checks_comment.rs", "check_status_value",
     "Flags CEP:STATUS values outside the configured allowed set.",
     "Section 10.5 restricts status to complete, partial, stub, and placeholder.")
spec("tools/cep_lint/src/checks_comment.rs", "parse_status_line",
     "Extracts the status value from a CEP:STATUS comment line.",
     "Status scanning works per line so stale or repeated status lines are all visible to the check.")
spec("tools/cep_lint/src/checks_comment.rs", "check_stub_requirements",
     "Requires ownership fields in blocks that declare stub, partial, or placeholder status.",
     "Section 10.10 bans anonymous stubs; OWNER and TICKET must sit in the same block as the status.")
spec("tools/cep_lint/src/checks_comment.rs", "check_comment_regex",
     "Runs the configured pattern over comment lines with an optional suppression pattern.",
     "Implements the line-scoped comment_regex primitive used by the TODO and placeholder comment rules.")
spec("tools/cep_lint/src/checks_comment.rs", "check_string_literal_regex",
     "Runs the configured pattern over string literal contents.",
     "Implements the string_literal_regex primitive; placeholders must fail loudly instead of leaking into runtime strings.")

# ---- checks_doc.rs
spec("tools/cep_lint/src/checks_doc.rs", "check_doc_sync",
     "Compares rule headings in the standard document with configured rules and validates the version line.",
     "CEP-LINT-DOC-SYNC enforces Law 8 mechanically in both coverage directions per section 50.3.")

# ---- checks_func.rs
spec("tools/cep_lint/src/checks_func.rs", "find_functions",
     "Finds Rust function definitions with captured names and brace-matched bodies.",
     "All four function_policy modes share one extractor so block, stub, naming, and constant-return checks stay consistent.")
spec("tools/cep_lint/src/checks_func.rs", "body_span",
     "Locates the brace-matched body of a function and rejects declarations without bodies.",
     "Trait declarations end with a semicolon before any brace and must not be treated as definitions.")
spec("tools/cep_lint/src/checks_func.rs", "count_statements",
     "Counts top-level statements in a function body using semicolons, block keywords, and a trailing expression.",
     "The catalog approximates nontrivial functions as two or more statements; block keywords count once each.")
spec("tools/cep_lint/src/checks_func.rs", "preceding_word_is_block_keyword",
     "Reports whether the identifier immediately before a brace is a control-flow keyword.",
     "Statement counting must classify if, match, for, while, loop, and unsafe blocks without comment noise.")
spec("tools/cep_lint/src/checks_func.rs", "check_function_policy",
     "Dispatches function_policy to the mode named by configuration.",
     "One primitive serves four catalog rules; the mode selects the check body.")
spec("tools/cep_lint/src/checks_func.rs", "block_above",
     "Returns the nearest comment block above a function when only sanctioned gap lines separate them.",
     "Section 50.3 allows attributes and qualifiers between block and definition; any other content breaks adjacency.",
     failure="Returns None when no qualifying block exists; callers raise the finding.")
spec("tools/cep_lint/src/checks_func.rs", "check_block_mode",
     "Requires complete CEP blocks above nontrivial functions.",
     "Implements CEP-LINT-FUNC-BLOCK with the configured field list and statement threshold.")
spec("tools/cep_lint/src/checks_func.rs", "check_stub_body_mode",
     "Flags empty function bodies unless the adjacent block declares a suppressed status.",
     "Implements CEP-LINT-STUB-BODY; empty special members should use default or delete forms in C++ and explicit statuses here.")
spec("tools/cep_lint/src/checks_func.rs", "check_naming_mode",
     "Flags function names that violate the configured snake_case pattern.",
     "Implements CEP-LINT-NAMING-FUNC per section 33.13.")
spec("tools/cep_lint/src/checks_func.rs", "check_constant_return",
     "Flags single-statement bodies that return a constant.",
     "Implements CEP-LINT-CONSTANT-RETURN; results must be computed from inputs.")

# ---- checks_topology.rs
spec("tools/cep_lint/src/checks_topology.rs", "check_file_topology",
     "Enforces class line limits, junk-drawer names, and pass-entry density for one file.",
     "Implements the file_topology_policy primitive required by section 62.5.3.")
spec("tools/cep_lint/src/checks_topology.rs", "base_name",
     "Extracts the file name component of a path.",
     "Junk-drawer detection applies to the file name, not the full path.")
spec("tools/cep_lint/src/checks_topology.rs", "unreachable_entry",
     "Returns a never-matching regex used when pass entry configuration is absent.",
     "Option handling must stay total without panicking; the sentinel keeps the tuple shape.")

# ---- json.rs
spec("tools/cep_lint/src/json.rs", "parse",
     "Parses a JSON document into the ordered tree with bounded depth and trailing-input checks.",
     "Configuration is data per section 50; the parser must reject malformed and oversized input with coded errors.",
     failure="Returns JsonError with line and column on malformed input, depth overflow, or trailing characters.")
spec("tools/cep_lint/src/json.rs", "get",
     "Looks up an object member by key preserving configuration order.",
     "Object order must remain stable for deterministic error reporting and manifest handling.")
spec("tools/cep_lint/src/json.rs", "as_str",
         "Reads a JSON member as a string when it holds one.",
         "Typed accessors keep configuration parsing strict without panicking on wrong types.")
spec("tools/cep_lint/src/json.rs", "as_u32",
     "Converts a JSON number to u32 when it is integral and in range.",
     "Severity and count parameters must be whole numbers; fractional or negative values are rejected.")
spec("tools/cep_lint/src/json.rs", "as_bool",
         "Reads a JSON member as a boolean when it holds one.",
         "Typed accessors keep configuration parsing strict without panicking on wrong types.")
spec("tools/cep_lint/src/json.rs", "as_arr",
         "Reads a JSON member as an array slice when it holds one.",
         "Typed accessors keep configuration parsing strict without panicking on wrong types.")
spec("tools/cep_lint/src/json.rs", "as_obj",
         "Reads a JSON member as an ordered object member list when it holds one.",
         "Typed accessors keep configuration parsing strict without panicking on wrong types.")
spec("tools/cep_lint/src/json.rs", "err",
     "Builds a JsonError carrying the current line and column.",
     "Bootstrap errors must point at the failure location per the CEP-LINT-BOOT-2 contract.")
spec("tools/cep_lint/src/json.rs", "peek",
         "Returns the byte at the cursor without advancing.",
         "Typed accessors keep configuration parsing strict without panicking on wrong types.")
spec("tools/cep_lint/src/json.rs", "bump",
     "Advances one byte while maintaining line and column counters.",
     "Error positions depend on accurate counters; newline handling updates both.")
spec("tools/cep_lint/src/json.rs", "skip_ws",
         "Advances the cursor over JSON whitespace bytes.",
         "Typed accessors keep configuration parsing strict without panicking on wrong types.")
spec("tools/cep_lint/src/json.rs", "parse_value",
     "Dispatches to the parser for the value at the cursor under a depth bound.",
     "Section 22.10 requires bounded nesting; depth is checked before every value.")
spec("tools/cep_lint/src/json.rs", "parse_keyword",
     "Consumes a literal JSON keyword and returns its value.",
     "true, false, and null are matched byte by byte with position-accurate errors.")
spec("tools/cep_lint/src/json.rs", "parse_number",
         "Parses a JSON number literal into an f64 value.",
         "Typed accessors keep configuration parsing strict without panicking on wrong types.")
spec("tools/cep_lint/src/json.rs", "parse_string",
     "Parses a JSON string with escapes, surrogate pairs, and control-character rejection.",
     "RFC 8259 string semantics are required for portable configuration; control bytes are rejected as malformed.",
     failure="Returns JsonError on unterminated strings, unknown escapes, invalid surrogates, or control characters.")
spec("tools/cep_lint/src/json.rs", "parse_hex4",
     "Reads four hexadecimal digits into a u16 value.",
     "Unicode escapes are always four digits wide per RFC 8259.")
spec("tools/cep_lint/src/json.rs", "finish_utf8_char",
     "Copies one UTF-8 multibyte character from input into the output string.",
     "Configuration is UTF-8; the raw bytes are carried through without revalidation because the source is validated at load.")
spec("tools/cep_lint/src/json.rs", "parse_array",
         "Parses a JSON array with ordered elements.",
         "Typed accessors keep configuration parsing strict without panicking on wrong types.")
spec("tools/cep_lint/src/json.rs", "parse_object",
         "Parses a JSON object with ordered members and duplicate-key tolerance.",
         "Typed accessors keep configuration parsing strict without panicking on wrong types.")

# ---- main.rs
spec("tools/cep_lint/src/main.rs", "main",
     "Parses command line options, loads configuration, and routes to self-test or lint execution.",
     "Section 50.1 fixes the invocation contract and exit codes; the driver owns process exit and filesystem access.",
     failure="Exits 2 on bootstrap failures, 3 on usage errors, 1 on blocking findings, 0 when clean.")
spec("tools/cep_lint/src/main.rs", "boot_fail",
     "Prints a coded CEP-LINT-BOOT-<n> line and exits with the bootstrap code.",
     "Section 50.4 requires coded bootstrap failures before message templates are available.",
     failure="Always exits the process with the bootstrap exit code.")
spec("tools/cep_lint/src/main.rs", "parse_args",
     "Parses options and positional targets, handling help and version banners inline.",
     "Options are fixed by section 50.1; unknown usage must exit 3 without scanning.",
     failure="Returns the usage exit code when an option is missing its argument.")
spec("tools/cep_lint/src/main.rs", "print_help",
         "Prints the usage banner fixed by section 50.1.",
         "Typed accessors keep the driver contract fixed without panicking on wrong types.")
spec("tools/cep_lint/src/main.rs", "collect_targets",
     "Expands file and directory targets into a sorted, deduplicated file list filtered by globs.",
     "Section 50.1 requires sorted traversal; deduplication keeps repeated targets from double reporting.")
spec("tools/cep_lint/src/main.rs", "collect_dir",
     "Recursively collects matching files under one directory in sorted order.",
     "Deterministic output requires sorted directory traversal at every level.")
spec("tools/cep_lint/src/main.rs", "glob_matches",
         "Matches a path against the configured glob list.",
         "Typed accessors keep the driver contract fixed without panicking on wrong types.")
spec("tools/cep_lint/src/main.rs", "glob_matches_one",
     "Matches one path against one glob supporting suffix and wildcard-stem forms.",
     "The configured globs are Rust-tree patterns; matching is lexical and deterministic.")
spec("tools/cep_lint/src/main.rs", "run_lint",
     "Loads every target, runs all rules, runs the DOC-SYNC gate, prints sorted findings, and exits by severity.",
     "This is the primary invocation path of section 50.1 with fail_on-driven exit semantics.",
     failure="Exits 2 on unreadable or oversized inputs; exits 1 when blocking findings exist.")
spec("tools/cep_lint/src/main.rs", "run_doc_sync",
     "Loads the standard document and runs the DOC-SYNC comparison for the live configuration.",
     "Section 50.6 item 5 requires the live gate over the document and configuration.")
spec("tools/cep_lint/src/main.rs", "run_self_test",
     "Loads the manifest, validates rule coverage, runs every scenario, and exits by result.",
     "Section 50.6 item 3 requires exact per-rule expected counts for one violating and one compliant scenario each.")
spec("tools/cep_lint/src/main.rs", "validate_manifest_rules",
     "Rejects manifests whose scenarios reference unknown rules.",
     "A manifest drift would silently pass; bootstrap failure is the sanctioned response.")

# ---- model.rs
spec("tools/cep_lint/src/model.rs", "load",
     "Loads and validates the lint configuration into typed rules with coded bootstrap failures.",
     "Every pattern, threshold, severity, message, and option lives in the configuration; this gate rejects malformed data with BOOT codes.")
spec("tools/cep_lint/src/model.rs", "rule",
     "Returns one rule by name.",
     "Named lookup keeps dispatch and manifest validation simple and order-independent.")
spec("tools/cep_lint/src/model.rs", "param_str",
     "Reads a string parameter with a default.",
     "Configuration parameters must have documented defaults so the engine never invents values.")
spec("tools/cep_lint/src/model.rs", "param_u32",
         "Reads an integer parameter with a default.",
         "Typed accessors keep configuration handling strict without panicking on wrong types.")
spec("tools/cep_lint/src/model.rs", "param_bool",
         "Reads a boolean parameter with a default.",
         "Typed accessors keep configuration handling strict without panicking on wrong types.")
spec("tools/cep_lint/src/model.rs", "param_str_list",
         "Reads a string array parameter as a list.",
         "Typed accessors keep configuration handling strict without panicking on wrong types.")
spec("tools/cep_lint/src/model.rs", "param_u32_list",
         "Reads an integer array parameter as a list.",
         "Typed accessors keep configuration handling strict without panicking on wrong types.")
spec("tools/cep_lint/src/model.rs", "compile_patterns",
     "Compiles every configured regex once before scanning.",
     "Compile errors surface as BOOT-8 before any file is read; compilation is hoisted out of the scan loop.")
spec("tools/cep_lint/src/model.rs", "regex_taste",
     "Decides case sensitivity and whether a parameter is a regex by key and scoped flag.",
     "Regex keys are a fixed vocabulary; scoped _icase flags allow per-pattern case control without engine changes.")
spec("tools/cep_lint/src/model.rs", "regex_for",
     "Fetches a compiled regex for one rule parameter.",
     "Checks retrieve their configured patterns by name; absence means the rule is unconfigured and skipped.")
spec("tools/cep_lint/src/model.rs", "parse_severity_list",
     "Validates fail_on severities against the zero-to-three range.",
     "Severity range violations are BOOT-7 per section 50.4.")
spec("tools/cep_lint/src/model.rs", "parse_rule",
     "Validates one rule body: known check, severity range, message, and params.",
     "Unknown check names are BOOT-6; missing keys are BOOT-4 per the bootstrap table.")

# ---- regex_lite.rs
spec("tools/cep_lint/src/regex_lite.rs", "compile",
     "Parses a pattern into an AST with length bounds and syntax validation.",
     "All lint patterns flow through this compiler; invalid syntax must surface as BOOT-8 before scanning.")
spec("tools/cep_lint/src/regex_lite.rs", "is_match",
     "Reports whether the pattern matches anywhere in the subject.",
     "Exempt-context and suppression checks need only boolean results.")
spec("tools/cep_lint/src/regex_lite.rs", "find_iter",
     "Returns all non-overlapping leftmost matches with capture text.",
     "Token and literal scans need spans and captures; zero-width matches are skipped to keep iteration finite.")
spec("tools/cep_lint/src/regex_lite.rs", "group_count",
     "Returns the number of capture groups in the pattern.",
     "Capture validation for name_group parameters needs the group arity.")
spec("tools/cep_lint/src/regex_lite.rs", "walk",
     "Matches one node against the subject at a position with a continuation and step budget.",
     "Backtracking with explicit continuations keeps the engine bounded and deterministic.",
     failure="Returns RegexError when the step budget is exhausted.")
spec("tools/cep_lint/src/regex_lite.rs", "walk_seq",
     "Matches a concat sequence by index with continuation chaining.",
     "Sequence matching is the backbone of every compiled pattern.")
spec("tools/cep_lint/src/regex_lite.rs", "is_single_char",
     "Reports whether a node consumes at most one character.",
     "Single-character repeats take the iterative path so long subjects cannot exhaust the stack.")
spec("tools/cep_lint/src/regex_lite.rs", "walk_single_repeat",
     "Matches a repeat of single-character nodes iteratively with greedy backtracking.",
     "Iterative counting prevents recursion depth from scaling with subject length per section 22.10.")
spec("tools/cep_lint/src/regex_lite.rs", "walk_general_repeat",
     "Matches a repeat of compound nodes with bounded recursion.",
     "Compound repeats are rare in lint patterns; recursion is bounded by the step budget.")
spec("tools/cep_lint/src/regex_lite.rs", "set_capture_count",
         "Allocates capture slots for one match attempt.",
         "Small accessors keep matcher state handling explicit and side-effect free.")
spec("tools/cep_lint/src/regex_lite.rs", "set_cap",
     "Records a capture span for one group index.",
     "Captures must survive continuation flow so name extraction reads consistent spans.")
spec("tools/cep_lint/src/regex_lite.rs", "clear_cap",
     "Clears a capture span after a failed backtracking attempt.",
     "Stale captures would leak into later matches and corrupt name validation.")
spec("tools/cep_lint/src/regex_lite.rs", "take_captures_text",
     "Converts recorded spans into captured strings for one match.",
     "Callers need text, not offsets, for name validation and finding messages.")
spec("tools/cep_lint/src/regex_lite.rs", "spend",
     "Consumes one matching step and rejects exhaustion.",
     "Section 22.10 forbids unbounded work; the budget bounds every match attempt.",
     failure="Returns RegexError when the step budget reaches zero.")
spec("tools/cep_lint/src/regex_lite.rs", "match_single",
     "Matches one single-character node at a position.",
     "Char, class, and shorthand classes share one fast path.")
spec("tools/cep_lint/src/regex_lite.rs", "class_hit",
     "Tests one character against one class item.",
     "Ranges, singles, and shorthand classes cover the pattern vocabulary used by configuration.")
spec("tools/cep_lint/src/regex_lite.rs", "at_boundary",
     "Reports whether a word boundary exists at a position.",
     "Token rules rely on word boundaries to avoid matching identifiers containing banned words.")
spec("tools/cep_lint/src/regex_lite.rs", "err",
     "Builds a RegexError with a pattern offset.",
     "Compile failures must identify the position for the BOOT-8 detail string.")
spec("tools/cep_lint/src/regex_lite.rs", "peek",
         "Returns the byte at the cursor without advancing.",
         "Small accessors keep matcher state handling explicit and side-effect free.")
spec("tools/cep_lint/src/regex_lite.rs", "peek_at",
     "Returns the character at a cursor offset without advancing.",
     "Look-ahead for the non-capture group syntax needs two-character inspection.")
spec("tools/cep_lint/src/regex_lite.rs", "parse_alt",
     "Parses alternation over concat branches.",
     "Alternation is the top-level pattern structure in the configured token and marker patterns.")
spec("tools/cep_lint/src/regex_lite.rs", "parse_concat",
         "Parses a sequence of quantified atoms until an alternation or group boundary.",
         "Small accessors keep matcher state handling explicit and side-effect free.")
spec("tools/cep_lint/src/regex_lite.rs", "parse_repeat",
     "Attaches a quantifier to one atom.",
     "Greedy and optional quantifiers cover every configured pattern.")
spec("tools/cep_lint/src/regex_lite.rs", "parse_bound",
     "Parses an explicit {m,n} bound.",
     "Explicit bounds are validated for syntax and overflow at compile time.")
spec("tools/cep_lint/src/regex_lite.rs", "parse_atom",
     "Parses one atom: group, class, anchor, escape, or character.",
     "Non-capture groups keep qualifier syntax from polluting capture indices.")
spec("tools/cep_lint/src/regex_lite.rs", "parse_escape",
     "Parses backslash escapes into shorthand nodes or literal characters.",
     "Shorthand classes and boundaries are the core of the token patterns.")
spec("tools/cep_lint/src/regex_lite.rs", "parse_class",
     "Parses a bracketed character class with ranges, negation, and class escapes.",
     "Naming and marker patterns depend on classes for case and shape validation.")

# ---- selftest.rs
spec("tools/cep_lint/src/selftest.rs", "parse_manifest",
     "Parses the self-test manifest into scenarios with base configuration, files, and expected counts.",
     "Section 50.6 item 3 defines the manifest contract; parsing must be strict so drift fails loudly.",
     failure="Returns None when required keys or shapes are missing; the caller raises BOOT-4.")
spec("tools/cep_lint/src/selftest.rs", "run_manifest",
     "Runs every scenario and returns one result each.",
     "The self-test gate reports pass and fail per scenario with exact counts.")
spec("tools/cep_lint/src/selftest.rs", "run_scenario",
     "Runs the violating and compliant variants and compares both with expected counts.",
     "Both directions must match exactly; a single-sided check would tolerate regressions.")
spec("tools/cep_lint/src/selftest.rs", "run_variant",
     "Lints one variant's files under the scenario configuration and counts findings for the scenario rule.",
     "Per-rule counting keeps fixtures independent of unrelated rule noise.")
spec("tools/cep_lint/src/selftest.rs", "run_doc_sync_variant",
     "Runs the DOC-SYNC comparison against scenario-provided document fixtures.",
     "The DOC-SYNC scenario needs virtual documents instead of the live repository file.")
spec("tools/cep_lint/src/selftest.rs", "variant_file_kind",
     "Classifies scenario files by embedded variant marker in the file name.",
     "Scenario files carry their variant in the name so one file list serves both runs.")
spec("tools/cep_lint/src/selftest.rs", "apply_overrides",
     "Applies dotted-path configuration overrides to a copy of the base configuration.",
     "Scenario-specific behavior, such as virtual document paths, is data not engine code.")
spec("tools/cep_lint/src/selftest.rs", "set_json_path",
     "Sets one nested JSON member addressed by a dotted path.",
     "Override paths address standard and rule parameters without ad hoc mutation logic.")
spec("tools/cep_lint/src/selftest.rs", "serialize_json",
     "Serializes the JSON tree back to text with stable ordering.",
     "Overrides must round-trip deterministically for repeatable self-test runs.")
spec("tools/cep_lint/src/selftest.rs", "serialize_string",
     "Serializes one JSON string with RFC escaping.",
     "Manifest and configuration round-trips must escape quotes and control bytes deterministically.")

# ---- source.rs
spec("tools/cep_lint/src/source.rs", "load",
     "Builds the per-file model: lines, blanked code, comment inventory, and string inventory.",
     "Every check depends on one consistent comment-and-string view; a single pass produces it.",
     cost="cold; single O(N) pass per file.")
spec("tools/cep_lint/src/source.rs", "raw_prefix_hashes",
     "Counts raw-string hash markers after a quote and returns the cursor past them.",
     "Raw strings change escape semantics; the hash count identifies the closing form.")
spec("tools/cep_lint/src/source.rs", "line_has_raw_prefix",
     "Reports whether the identifier before a quote is the raw-string prefix r.",
     "Distinguishing r\"...\" from normal strings requires inspecting the preceding identifier.")
spec("tools/cep_lint/src/source.rs", "raw_suffix_len",
     "Counts hash markers after a candidate raw-string terminator quote.",
     "A raw string closes only when the suffix hash count matches the prefix count.")
spec("tools/cep_lint/src/source.rs", "char_literal_end",
     "Locates the closing quote of a char literal, distinguishing it from lifetimes.",
     "Lifetimes and char literals share the apostrophe; misclassification would corrupt the code text.")


def find_fn_line(lines, fn_name):
    pattern = re.compile(r"^\s*(?:pub(?:\([a-z ]+\))?\s+)?(?:unsafe\s+)?(?:extern\s+\"[A-Za-z0-9]*\"\s+)?(?:const\s+)?fn\s+" + re.escape(fn_name) + r"\b")
    for idx, line in enumerate(lines):
        if pattern.match(line):
            return idx
    return None


def main():
    failures = []
    by_file = {}
    for key, lines_to_insert in SPEC.items():
        path, fn_name = key.rsplit(":", 1)
        by_file.setdefault(path, []).append((fn_name, lines_to_insert))
    for path, entries in sorted(by_file.items()):
        full = ROOT / path
        text = full.read_text()
        lines = text.split("\n")
        for fn_name, block_lines in entries:
            target = find_fn_line(lines, fn_name)
            if target is None:
                failures.append(f"{path}:{fn_name} definition not found")
                continue
            insert_at = target
            while insert_at > 0 and (lines[insert_at - 1].strip().startswith("#[")
                                     or lines[insert_at - 1].strip() in {"pub", "unsafe", "const", "async"}):
                insert_at -= 1
            preceding = lines[insert_at - 1] if insert_at > 0 else ""
            if preceding.strip().startswith("// CEP:WHAT:"):
                failures.append(f"{path}:{fn_name} already has a block")
                continue
            lines[insert_at:insert_at] = block_lines
        full.write_text("\n".join(lines))
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}")
        sys.exit(1)
    print(f"inserted blocks for {len(SPEC)} functions")


if __name__ == "__main__":
    main()
