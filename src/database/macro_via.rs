// SPDX-License-Identifier: MIT OR Apache-2.0
//! Query-time traversal through function-like macros: `via` hops and
//! macro-argument handovers over existing rows.
//!
//! Macro-body calls are already ordinary call edges on the macro row, so
//! this module adds no rows and changes no extraction. It answers two
//! questions at query time: which macro bodies a call passes through on its
//! way to a callee, and which invocation-site argument an invoked macro
//! parameter stands for. Every hop carries the file, line and guard it was
//! read from, and every scope decision is positional: a call site resolves
//! against the `#define`/`#undef` interval active at its own line.

use std::path::Path;

/// Whether a stored row is a function-like macro, read from the directive
/// text rather than the table it sits in.
///
/// The old binary-local test (empty return type, non-asm path) misfires:
/// `SYSCALL_DEFINE` functions also have an empty return type, `()` parses
/// to empty params exactly like an object-like macro, and object-like rows
/// sit in the functions table too. The `#define NAME(` text settles all
/// three: functions never start with it, object-like macros never carry
/// the paren. `#` may be followed by whitespace (`# define`, timer_list.c).
pub fn is_function_like_macro_body(body: &str) -> bool {
    let first = body.lines().find(|line| !line.trim().is_empty());
    let Some(line) = first else {
        return false;
    };
    let rest = match line.trim_start().strip_prefix('#') {
        Some(rest) => rest.trim_start(),
        None => return false,
    };
    let rest = match rest.strip_prefix("define") {
        Some(rest) => rest,
        None => return false,
    };
    // `define` must end at a word boundary: `#define_foo` is not one.
    match rest.chars().next() {
        Some(next) if next == '_' || next.is_alphanumeric() => return false,
        _ => {}
    }
    let rest = rest.trim_start();
    let name_len = rest
        .char_indices()
        .take_while(|(_, c)| *c == '_' || c.is_alphanumeric())
        .map(|(i, c)| i + c.len_utf8())
        .last()
        .unwrap_or(0);
    if name_len == 0 {
        return false;
    }
    // No trim: C reads `#define M (expr)` as object-like. The paren
    // must touch the name to take parameters.
    rest[name_len..].starts_with('(')
}

/// Whether a stored row is a function-like macro: no return type, not
/// assembly, and a `#define NAME(` directive. Hoisted into the library so
/// every frontend classifies the same rows.
pub fn is_macro_row(entity: &crate::types::FunctionInfo) -> bool {
    entity.return_type.is_empty()
        && !crate::asm::is_asm_path(Path::new(&entity.file_path))
        && is_function_like_macro_body(&entity.body)
}

/// A `#define NAME` with its line and guard path.
#[derive(Debug, Clone)]
pub struct RawDefine {
    pub name: String,
    pub line: u32,
    /// Set where the arm is definitely taken (file scope or every
    /// enclosing arm constant-true): the definition unconditionally
    /// shadows, so it terminates whatever its spelling. Under a merely
    /// live arm it may never execute — the overlap rules decide.
    pub certain: bool,
    /// Last physical line the definition covers: multi-line bodies join
    /// continuation lines, and a site on any of them sits inside the
    /// definition. Single-line defines end where they start.
    pub end: u32,
    pub has_params: bool,
    pub chain: u32,
    pub arm: u32,
    pub branch: Vec<(u32, u32)>,
    pub guard: String,
    /// The replacement text after the name (and parameter list), over the
    /// joined continuation lines. `None` where the parameter list does not
    /// balance: unknown content never proves stability.
    pub expansion: Option<String>,
    /// Outermost `#if` line of the live guard (the directive's own line
    /// where unguarded): where the guard terms were evaluated.
    pub guard_line: u32,
}

/// A `#undef NAME` with its guard path.
#[derive(Debug, Clone)]
pub struct RawUndef {
    pub name: String,
    pub line: u32,
    pub branch: Vec<(u32, u32)>,
    pub guard: String,
    /// Set where the arm is definitely taken (file scope or every
    /// enclosing arm constant-true): the `#undef` fires unconditionally,
    /// so it terminates whatever its spelling. Under a merely live arm
    /// it may never execute — the overlap rules decide.
    pub certain: bool,
}

/// The rescan of one file snapshot: every function-like `#define`, every
/// `#undef`, and every include line (any spelling: `#  include`,
/// `#include_next`, computed).
#[derive(Debug, Default, Clone)]
pub struct PreprocMap {
    pub defines: Vec<RawDefine>,
    pub undefs: Vec<RawUndef>,
    pub includes: Vec<u32>,
    /// Every `#if` frame, completed or still open at end of file: the arm
    /// conditions it cycled through, with its parent guard and `#if` line.
    /// Overlap checks read arm vocabularies back out of this table.
    pub frames: Vec<FrameInfo>,
    /// Dead line ranges (inclusive physical lines): arms under a
    /// constant-false condition (`#if 0`) and arms after a constant-true
    /// one (`#else` after `#if 1`). Directives there never reach the
    /// compiler, so they record nothing — and call sites there never run.
    pub dead: Vec<(u32, u32)>,
}

/// A constant `#if`/`#elif` condition: `Some` for integer literals in any
/// base (`0`, `00`, `0x0`, `0b0`, with `u`/`l` suffixes and `'` separators;
/// redundant parens aside). Anything symbolic is unknown, and unknown is
/// live.
fn const_bool(condition: &str) -> Option<bool> {
    // Digit separators first: `0'0` reads as `00`, or the paren scan
    // below mistakes the separator for a character constant (`(0'0)`
    // never unparenthesizes). Only between alphanumerics — the quotes
    // of a real character constant (`'a'`) never sit between two.
    let chars: Vec<char> = condition.chars().collect();
    let mut flat = String::with_capacity(condition.len());
    for (index, c) in chars.iter().enumerate() {
        if *c == '\''
            && index > 0
            && index + 1 < chars.len()
            && chars[index - 1].is_alphanumeric()
            && chars[index + 1].is_alphanumeric()
        {
            continue;
        }
        flat.push(*c);
    }
    let mut text = flat.trim();
    while crate::guard::wholly_parenthesized(text) {
        text = text[1..text.len() - 1].trim();
    }
    if text == "0" {
        return Some(false);
    }
    if text == "1" {
        return Some(true);
    }
    // An identifier is not a literal, whatever separators hide inside:
    // `_1` is symbolic (live), or the `#else` arm below a real
    // `#define _1 0` dies. Literals start with a digit, like in C.
    if !text.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return None;
    }
    // A C integer literal: base prefix, digits with separators, and an
    // optional unsigned/length suffix. A leading zero means octal, like
    // in C; anything else decimal. Nonzero is true.
    let (digits, base) = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .map_or_else(
            || {
                if let Some(octal) = text.strip_prefix("0o").or_else(|| text.strip_prefix("0O")) {
                    (octal, 8u32)
                } else if let Some(binary) =
                    text.strip_prefix("0b").or_else(|| text.strip_prefix("0B"))
                {
                    (binary, 2u32)
                } else if text.starts_with('0') {
                    (text, 8u32)
                } else {
                    (text, 10u32)
                }
            },
            |hex| (hex, 16u32),
        );
    let stripped: String = digits.chars().filter(|c| *c != '\'' && *c != '_').collect();
    let core = stripped.trim_end_matches(['u', 'U', 'l', 'L']);
    if core.is_empty() || !core.chars().all(|c| c.is_digit(base)) {
        return None;
    }
    u128::from_str_radix(core, base)
        .ok()
        .map(|value| value != 0)
}

/// A constant condition with rescan knowledge: a lone `defined(X)` (or
/// its negation) folds where the scan proved X undefined — `#undef X`
/// with no live `#define` above — or defined, where an unconditional
/// object value holds it. Anything else defers to `const_bool`, and
/// unknown is live: builtins and header defines are invisible
/// to a single-file scan.
fn const_bool_scoped(
    condition: &str,
    dead: &std::collections::HashSet<String>,
    values: &std::collections::HashMap<String, String>,
) -> Option<bool> {
    // Unconditional object defines expand in conditions exactly as the
    // compiler expands them (`#define _1 0` makes `#if _1` false).
    // Conditional-arm defines never enter the map, so a value here is
    // exact. Whole words only, bounded depth; cycles fall symbolic. The
    // operand of `defined` never expands: `defined(FLAG)` tests
    // definedness, so its parens copy through verbatim.
    let mut text_owned = condition.to_string();
    for _ in 0..8 {
        let mut out = String::with_capacity(text_owned.len());
        let mut changed = false;
        let mut rest = text_owned.as_str();
        while !rest.is_empty() {
            let cut = rest
                .find(|c: char| !(c == '_' || c.is_alphanumeric()))
                .unwrap_or(rest.len());
            let (word, tail) = rest.split_at(cut);
            if word == "defined" {
                // Copy `defined`, the gap, and one balanced group (or
                // nothing) without expanding: the name inside is quoted
                // by the operator.
                out.push_str(word);
                let mut tail_rest = tail;
                while let Some(blank) = tail_rest.chars().next().filter(|c| c.is_whitespace()) {
                    out.push(blank);
                    tail_rest = &tail_rest[blank.len_utf8()..];
                }
                if tail_rest.starts_with('(') {
                    let mut depth = 0u32;
                    let mut taken = 0usize;
                    for (index, c) in tail_rest.char_indices() {
                        match c {
                            '(' => depth += 1,
                            ')' => {
                                depth -= 1;
                                if depth == 0 {
                                    taken = index + c.len_utf8();
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    if taken > 0 {
                        out.push_str(&tail_rest[..taken]);
                        rest = &tail_rest[taken..];
                        continue;
                    }
                }
                rest = tail_rest;
                continue;
            }
            if let Some(value) = values.get(word) {
                out.push_str(value);
                changed = true;
            } else {
                out.push_str(word);
            }
            if tail.is_empty() {
                break;
            }
            out.push(tail.chars().next().unwrap_or(' '));
            rest = &tail[tail.chars().next().map_or(0, |c| c.len_utf8())..];
        }
        text_owned = out;
        if !changed {
            break;
        }
    }
    let text = text_owned.trim();
    let (negated, inner) = match text.strip_prefix('!') {
        Some(rest) => (true, rest.trim()),
        None => (false, text),
    };
    if let Some(paren) = inner.strip_prefix("defined") {
        let name = paren
            .trim_start()
            .strip_prefix('(')
            .and_then(|rest| rest.strip_suffix(')'))
            .map(str::trim)
            .unwrap_or("");
        if name.is_empty() || !name.chars().all(|c| c == '_' || c.is_alphanumeric()) {
            return const_bool(&text_owned);
        }
        if dead.contains(name) {
            return Some(negated);
        }
        // An unconditional object value proves definedness: the name
        // holds a value here, so `defined` holds with it.
        if values.contains_key(name) {
            return Some(!negated);
        }
    }
    const_bool(&text_owned)
}

/// One conditional frame: chain id, the guard above it, and every arm
/// condition in order.
#[derive(Debug, Clone)]
pub struct FrameInfo {
    pub chain: u32,
    pub parent: String,
    pub arms: Vec<String>,
}

/// Split a directive line into its keyword and the text after it. The `#`
/// may be indented and followed by whitespace; the keyword ends at the
/// first blank. `%:` is the `#` digraph and opens directives the same
/// way. Returns `None` for non-directive lines. Owned strings: `elifdef`
/// arms rewrite to `elif defined(..)` text no borrow can express.
fn directive_keyword(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim_start();
    let rest = trimmed
        .strip_prefix('#')
        .or_else(|| trimmed.strip_prefix("%:"))?;
    let rest = rest.trim_start();
    // `#if(` and `#elif(` glue the paren to the keyword (kernel style),
    // as does `#if!defined(` (no space, no paren); every other directive
    // ends its keyword at the first blank.
    for keyword in ["elif", "if"] {
        if let Some(text) = rest.strip_prefix(keyword) {
            if text.starts_with('(') || text.starts_with('!') {
                return Some((keyword.to_string(), text.to_string()));
            }
        }
    }
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    let (keyword, text) = (&rest[..end], rest[end..].trim_start());
    // C23 `elifdef`/`elifndef` are `elif` arms through `defined`: rewrite
    // to the `elif` form so arm tracking, dead ranges, and guards share
    // one path.
    if keyword == "elifdef" || keyword == "elifndef" {
        let name = text.split_whitespace().next().unwrap_or("");
        if !name.is_empty() && name.chars().all(|c| c == '_' || c.is_alphanumeric()) {
            let condition = if keyword == "elifdef" {
                format!("defined({name})")
            } else {
                format!("!defined({name})")
            };
            return Some(("elif".to_string(), condition));
        }
    }
    Some((keyword.to_string(), text.to_string()))
}

/// The guard text arm `text` contributes: `#ifdef X` and `#ifndef X` read
/// through `defined`, exactly as the stored guards do.
fn arm_condition_text(keyword: &str, text: &str) -> Option<String> {
    match keyword {
        "if" => Some(text.to_string()),
        "ifdef" => Some(format!("defined({})", text.split_whitespace().next()?)),
        "ifndef" => Some(format!("!defined({})", text.split_whitespace().next()?)),
        "elif" => Some(text.to_string()),
        _ => None,
    }
}

/// Identifiers a condition reads: bare words plus `defined()` operands.
/// Pure numeric tokens read nothing (no directive writes them).
fn condition_terms(condition: &str) -> std::collections::HashSet<String> {
    let mut terms = std::collections::HashSet::new();
    let mut rest = condition;
    while !rest.is_empty() {
        if rest.starts_with("defined") {
            let after = &rest["defined".len()..];
            let gap = after.len() - after.trim_start().len();
            let grouped = after[gap..].strip_prefix('(');
            let end = grouped.and_then(|rest| rest.find(')').map(|end| gap + 1 + end + 1));
            if let Some(take) = end {
                let name = after[gap + 1..take - 1].trim();
                if !name.is_empty()
                    && name.chars().all(|c| c == '_' || c.is_alphanumeric())
                    && !name.chars().all(|c| c.is_ascii_digit())
                {
                    terms.insert(name.to_string());
                }
                rest = &after[take..];
                continue;
            }
        }
        let cut = rest
            .find(|c: char| !(c == '_' || c.is_alphanumeric()))
            .unwrap_or(rest.len());
        let (word, tail) = rest.split_at(cut);
        if !word.is_empty() && !word.chars().all(|c| c.is_ascii_digit()) {
            terms.insert(word.to_string());
        }
        if tail.is_empty() {
            break;
        }
        rest = &tail[tail.chars().next().map_or(0, |c| c.len_utf8())..];
    }
    terms.remove("defined");
    terms
}

/// Whether every enclosing arm is definitely taken: file scope, or each
/// frame's current arm constant-true with every earlier arm constant-false
/// (`#elif B` after a true `#if A` never runs; `#else` holds exactly where
/// no earlier arm did). Folds with the knowledge live at this point, which
/// is what the compiler sees: directives below cannot conditionalize above.
/// Terms rewritten since the arm started void the take: the fold read the
/// new values, but the compiler took the arm on the old ones (a guard-line
/// stability the overlap engine keeps where certainty does not reach).
fn arms_definite(
    stack: &[(u32, Vec<String>, String, u32)],
    dead: &std::collections::HashSet<String>,
    values: &std::collections::HashMap<String, String>,
    writes: &[(u32, String)],
    now: u32,
) -> bool {
    stack.iter().all(|(_, arms, _, start)| {
        let Some((earlier, [cur])) = arms.split_at_checked(arms.len().saturating_sub(1)) else {
            return true;
        };
        let earlier_dead = earlier
            .iter()
            .filter(|condition| !condition.is_empty())
            .all(|condition| const_bool_scoped(condition, dead, values) == Some(false));
        let taken = if cur.is_empty() {
            earlier_dead
        } else {
            earlier_dead && const_bool_scoped(cur, dead, values) == Some(true)
        };
        if !taken {
            return false;
        }
        let terms: std::collections::HashSet<String> = arms
            .iter()
            .flat_map(|condition| condition_terms(condition))
            .collect();
        !writes
            .iter()
            .any(|(line, name)| *line > *start && *line < now && terms.contains(name))
    })
}

/// Rescan one file snapshot for preprocessor positions. Pure text: no
/// database, no revision. Guards are built with the same `as_conjunct` /
/// `negate_term` vocabulary the stored rows use, so text comparison meets.
/// Strip comments from one scan line: `//` to end of line and `/* ... */`,
/// which can span lines (the flag carries). A commented-out directive
/// (`/* #undef M */`) is not a directive. String and character literals
/// are opaque: the `/*` in `"/*"` opens no comment. Markers are ASCII, so
/// byte slicing at each match is always a character boundary.
fn strip_line_comment(line: &str, in_comment: &mut bool) -> String {
    let mut out = String::new();
    let mut rest = line;
    while !rest.is_empty() {
        if *in_comment {
            match rest.find("*/") {
                Some(end) => {
                    rest = &rest[end + 2..];
                    *in_comment = false;
                }
                // Unterminated to end of line: the comment still stood
                // where whitespace stands.
                None => {
                    out.push(' ');
                    break;
                }
            }
        } else if rest.starts_with("//") {
            break;
        } else if rest.starts_with("/*") {
            // A block comment is whitespace, not nothing: `#undef/**/RUN`
            // undefines RUN, and deleting the comment would fuse or drop
            // the tokens around it.
            out.push(' ');
            *in_comment = true;
            rest = &rest[2..];
        } else if rest.starts_with('"') || rest.starts_with('\'') {
            // A digit separator is not a quote: `0'0` keeps its tick, or
            // the scan below swallows the rest of the line as a character
            // constant and the trailing comment survives into the arm.
            // Only between alphanumerics — a real constant's quotes never
            // sit between two.
            let prev_alnum = out.chars().last().is_some_and(|c| c.is_alphanumeric());
            let next_alnum = rest[1..]
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric());
            if rest.starts_with('\'') && prev_alnum && next_alnum {
                out.push('\'');
                rest = &rest[1..];
                continue;
            }
            // A literal: skip to its unescaped close (or end of line for
            // an unterminated one, which still cannot comment).
            let quote = rest.as_bytes()[0];
            let mut index = 1usize;
            let bytes = rest.as_bytes();
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    index += 2;
                } else if bytes[index] == quote {
                    index += 1;
                    break;
                } else {
                    index += 1;
                }
            }
            let end = index.min(rest.len());
            out.push_str(&rest[..end]);
            rest = &rest[end..];
        } else {
            // Copy to the nearest marker, quote, or end.
            let next = [
                rest.find("/*"),
                rest.find("//"),
                rest.find('"'),
                rest.find('\''),
            ]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(rest.len());
            out.push_str(&rest[..next]);
            rest = &rest[next..];
        }
    }
    out
}

/// The replacement text after the name (and parameter list): `None` where
/// the parameter list does not balance. Function-pointer parameters nest,
/// so the close paren is balanced to, not searched for.
fn expansion_text(after_name: &str, has_params: bool) -> Option<String> {
    if !has_params {
        return Some(after_name.trim().to_string());
    }
    let mut depth = 0u32;
    for (index, cell) in after_name.char_indices() {
        match cell {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(after_name[index + cell.len_utf8()..].trim().to_string());
                }
            }
            _ => {}
        }
    }
    None
}

pub fn rescan_preprocessor(source: &str) -> PreprocMap {
    // Translation phases in C order: splice backslash-newline first (even
    // inside comments — a `//` comment ending in `\` continues onto the
    // next line), then strip comments. Each logical line keeps its first
    // physical line's number; indexes still align, and a commented-out
    // directive never parses as one.
    let mut spliced: Vec<(u32, String)> = Vec::new();
    let mut pending = String::new();
    let mut pending_line = 1u32;
    for (index, line) in source.lines().enumerate() {
        let line_no = (index + 1) as u32;
        if pending.is_empty() {
            pending_line = line_no;
        }
        match line.strip_suffix('\\') {
            Some(head) => pending.push_str(head),
            None => {
                pending.push_str(line);
                spliced.push((pending_line, std::mem::take(&mut pending)));
            }
        }
    }
    if !pending.is_empty() {
        spliced.push((pending_line, pending));
    }
    let mut in_comment = false;
    let lines: Vec<(u32, String)> = spliced
        .into_iter()
        .map(|(line_no, line)| (line_no, strip_line_comment(&line, &mut in_comment)))
        .collect();
    let mut map = PreprocMap::default();
    // Conditional stack: (chain id, arm conditions so far, parent guard,
    // innermost `#if` line). `#else` pushes an empty condition: its arm
    // holds where no earlier arm did.
    let mut stack: Vec<(u32, Vec<String>, String, u32)> = Vec::new();
    let mut next_chain: u32 = 1;

    // The guard live at this point: every frame's parent plus its current
    // arm, rebuilt from the arm lists. An `#elif` arm holds where the
    // earlier arms did not, which a "last condition wins" read gets
    // backwards (`#elif B` after `#if A` is `!A && B`, not `A && B`).
    let live_guard = |stack: &[(u32, Vec<String>, String, u32)]| -> String {
        let mut parts: Vec<String> = Vec::new();
        for (_, arms, parent, _) in stack {
            if arms.is_empty() {
                if !parent.is_empty() {
                    parts.push(parent.clone());
                }
                continue;
            }
            parts.push(chain_arm_guard(parent, arms, arms.len() - 1));
        }
        dedupe_conjuncts(
            &parts
                .into_iter()
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(" && "),
        )
    };

    let mut index = 0usize;
    // Dead-arm tracking alongside the conditional stack: an arm is dead
    // where its own condition is constant-false, where an earlier arm was
    // constant-true, or anywhere under a dead arm. Directives in dead arms
    // record nothing, and their line ranges land in `map.dead`. One entry
    // per frame: (chain id, an earlier arm was constant-true, some arm
    // lived, the current arm is dead, first line of the current arm).
    let mut dead_stack: Vec<(u32, bool, bool, bool, u32)> = Vec::new();
    // Names proved undefined: `#undef X` in a live arm ends X from there
    // on, even against `-D` (an `#undef` kills those too). A `#define`
    // re-arms. Anything else is symbolic — builtins and header
    // defines are unknown to a single-file scan.
    let mut dead_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Unconditional object-like values (`#define _1 0` at file scope):
    // exact expansions for condition folding. A merely-live write voids
    // them instead (a later definite write heals); conditional-arm
    // defines are left out — their values are build-dependent.
    let mut live_values: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    // Every recorded write (line, name): arm-taken certainty voids where
    // a guard term moved since the arm started.
    let mut writes: Vec<(u32, String)> = Vec::new();
    let total_physical = source.lines().count().max(1) as u32;
    while index < lines.len() {
        // Each entry already is one logical line: the pre-splice joined
        // every real backslash-newline above, so what ends in a backslash
        // here has trailing blanks after it — which C does not splice.
        let line_no = lines[index].0;
        // Physical span of this logical line: up to the next logical
        // line's start, or the file's last line.
        let end_no = lines
            .get(index + 1)
            .map(|(next, _)| next.saturating_sub(1).max(line_no))
            .unwrap_or(total_physical);
        let logical = lines[index].1.clone();
        let Some((keyword, text)) = directive_keyword(&logical) else {
            index += 1;
            continue;
        };
        let branch: Vec<(u32, u32)> = stack
            .iter()
            .map(|(chain, arms, _, _)| (*chain, arms.len().saturating_sub(1) as u32))
            .collect();
        let guard = live_guard(&stack);
        // Where the guard terms were evaluated: the outermost live `#if`,
        // or the directive itself where unguarded. Stability spans start
        // here — a write between the `#if` and the `#define` still moves
        // what the guard read.
        let guard_line = stack
            .iter()
            .map(|(_, _, _, line)| *line)
            .min()
            .unwrap_or(line_no);
        match keyword.as_str() {
            "if" | "ifdef" | "ifndef" => {
                if let Some(condition) = arm_condition_text(&keyword, &text) {
                    stack.push((next_chain, vec![condition.clone()], guard, line_no));
                    let parent_dead = dead_stack.iter().any(|entry| entry.3);
                    let fate =
                        const_bool_scoped(&condition, &dead_names, &live_values) == Some(false);
                    let cur_dead = parent_dead || fate;
                    dead_stack.push((
                        next_chain,
                        const_bool_scoped(&condition, &dead_names, &live_values) == Some(true),
                        !cur_dead,
                        cur_dead,
                        line_no + 1,
                    ));
                    next_chain += 1;
                }
            }
            "elif" => {
                if let Some(frame) = stack.last_mut() {
                    frame.1.push(text.to_string());
                }
                if dead_stack.last().is_some() {
                    let parent_dead = dead_stack[..dead_stack.len() - 1]
                        .iter()
                        .any(|entry| entry.3);
                    let last = dead_stack.len() - 1;
                    let entry = &mut dead_stack[last];
                    // The closing arm's lines never compile where it was dead.
                    let (_, any_true, any_live, cur_dead, arm_start) = *entry;
                    if cur_dead && arm_start < line_no {
                        map.dead.push((arm_start, line_no - 1));
                    }
                    let fate = any_true
                        || const_bool_scoped(&text, &dead_names, &live_values) == Some(false);
                    let cur_dead = parent_dead || fate;
                    *entry = (
                        entry.0,
                        any_true
                            || const_bool_scoped(&text, &dead_names, &live_values) == Some(true),
                        any_live || !cur_dead,
                        cur_dead,
                        line_no + 1,
                    );
                }
            }
            "else" => {
                if let Some(frame) = stack.last_mut() {
                    frame.1.push(String::new());
                }
                if dead_stack.last().is_some() {
                    let parent_dead = dead_stack[..dead_stack.len() - 1]
                        .iter()
                        .any(|entry| entry.3);
                    let last = dead_stack.len() - 1;
                    let entry = &mut dead_stack[last];
                    let (_, any_true, any_live, cur_dead, arm_start) = *entry;
                    if cur_dead && arm_start < line_no {
                        map.dead.push((arm_start, line_no - 1));
                    }
                    // The `#else` arm holds where no earlier arm did: dead
                    // exactly where an earlier arm was constant-true.
                    let cur_dead = parent_dead || any_true;
                    *entry = (
                        entry.0,
                        any_true,
                        any_live || !cur_dead,
                        cur_dead,
                        line_no + 1,
                    );
                }
            }
            "endif" => {
                if let Some(entry) = dead_stack.pop() {
                    if entry.3 && entry.4 < line_no {
                        map.dead.push((entry.4, line_no - 1));
                    }
                    if let Some((chain, arms, parent, _)) = stack.pop() {
                        // All-dead frames guarded nothing live: their terms
                        // stay out of every vocabulary.
                        if entry.2 {
                            map.frames.push(FrameInfo {
                                chain,
                                parent,
                                arms,
                            });
                        }
                    }
                } else {
                    stack.pop();
                }
            }
            "define" => {
                // Directives in dead arms never reach the compiler: they
                // record nothing.
                if dead_stack.iter().all(|entry| !entry.3) {
                    let name_len = text
                        .char_indices()
                        .take_while(|(_, c)| *c == '_' || c.is_alphanumeric())
                        .map(|(i, c)| i + c.len_utf8())
                        .last()
                        .unwrap_or(0);
                    if name_len > 0 {
                        let name = text[..name_len].to_string();
                        // Decided before the unfold below: defining the
                        // arm's own flag does not untake the arm.
                        let certain =
                            arms_definite(&stack, &dead_names, &live_values, &writes, line_no);
                        dead_names.remove(name.as_str());
                        writes.push((line_no, name.clone()));
                        let after_name = &text[name_len..];
                        // No trim: `#define M (expr)` is object-like. The
                        // paren must touch the name to take parameters.
                        let has_params = after_name.starts_with('(');
                        let expansion = expansion_text(after_name, has_params);
                        if !has_params && certain {
                            // A definite write heals: the value holds in
                            // every build past here, whatever stood before.
                            match expansion.as_deref().map(str::trim) {
                                Some(value) if !value.is_empty() => {
                                    live_values.insert(name.clone(), value.to_string());
                                }
                                _ => {
                                    live_values.remove(name.as_str());
                                }
                            }
                        } else if !has_params {
                            // A merely-live write may never execute: prior
                            // unconditional knowledge ends here, healed by
                            // a later definite write.
                            live_values.remove(name.as_str());
                        }
                        let (chain, arm) = branch.last().copied().unwrap_or((0, 0));
                        map.defines.push(RawDefine {
                            name,
                            line: line_no,
                            certain,
                            end: end_no,
                            has_params,
                            chain,
                            arm,
                            branch: branch.clone(),
                            guard,
                            expansion,
                            guard_line,
                        });
                    }
                }
            }
            "undef" => {
                if dead_stack.iter().all(|entry| !entry.3) {
                    let name = text
                        .split(|c: char| !(c == '_' || c.is_alphanumeric()))
                        .next()
                        .unwrap_or("")
                        .to_string();
                    if !name.is_empty() {
                        // Fold-direction writes need a definitely-taken arm:
                        // an `#undef` under an unknown condition may never
                        // execute, and recording it silences live code below.
                        // Decided before the insert: undefining the arm's own
                        // flag does not untake the arm. The value is void
                        // either way: taken or not, nothing unconditional
                        // stands past a live `#undef`.
                        let certain =
                            arms_definite(&stack, &dead_names, &live_values, &writes, line_no);
                        live_values.remove(name.as_str());
                        writes.push((line_no, name.clone()));
                        if certain {
                            dead_names.insert(name.clone());
                        }
                        map.undefs.push(RawUndef {
                            name,
                            line: line_no,
                            branch: branch.clone(),
                            guard,
                            certain,
                        });
                    }
                }
            }
            "include" | "include_next" if dead_stack.iter().all(|entry| !entry.3) => {
                map.includes.push(line_no);
                // A header may define anything: earlier `#undef`s and
                // object values stop proving past it.
                dead_names.clear();
                live_values.clear();
            }
            _ => {}
        }
        index += 1;
    }
    // Frames still open at end of file count too: their arms guarded
    // what they guarded, `#endif` or no. Dead arms close at end of file.
    let last_line = lines.last().map(|(line_no, _)| *line_no).unwrap_or(1);
    for ((chain, arms, parent, _), (_, _, any_live, cur_dead, arm_start)) in
        stack.into_iter().zip(dead_stack)
    {
        if cur_dead && arm_start <= last_line {
            map.dead.push((arm_start, last_line));
        }
        if any_live {
            map.frames.push(FrameInfo {
                chain,
                parent,
                arms,
            });
        }
    }
    // An `#endif` with no `#if` pops nothing above: unmatched closes leave
    // the stacks uneven, so only zipped pairs report.
    map
}

/// Join guard conjuncts without exact repeats: nested restatements of one
/// condition (`#ifndef T_H` inside `#ifndef T_H`) read once. Exact strings
/// only — no canonicalization, so every text comparison downstream meets
/// the same vocabulary it always did.
fn dedupe_conjuncts(guard: &str) -> String {
    let mut seen = std::collections::HashSet::new();
    crate::guard::terms(guard)
        .into_iter()
        .filter(|term| seen.insert(term.to_string()))
        .collect::<Vec<_>>()
        .join(" && ")
}

/// Rebuild one chain arm's guard from its arm conditions: arm k holds where
/// the parent holds, earlier arms did not, and its own condition holds. An
/// empty condition marks the `#else` arm.
fn chain_arm_guard(parent: &str, arms: &[String], arm: usize) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !parent.is_empty() {
        parts.push(parent.to_string());
    }
    for previous in &arms[..arm.min(arms.len())] {
        if previous.is_empty() {
            continue;
        }
        parts.push(crate::guard::negate_term(previous));
    }
    match arms.get(arm) {
        Some(condition) if !condition.is_empty() => {
            parts.push(crate::guard::as_conjunct(condition));
        }
        _ => {}
    }
    dedupe_conjuncts(&parts.join(" && "))
}

/// A live interval for one name: the lines where one definition (or one
/// joined sibling-arm group) answers, and the guard it answers under.
#[derive(Debug, Clone)]
pub struct ScopeInterval {
    pub define_lines: Vec<u32>,
    pub start: u32,
    pub end: u32,
    pub guard: String,
}

/// The scope a call site at `line` resolves to: every interval covering it,
/// guards joined. `None` where no definition is live there — between an
/// `#undef` and the next definition, or past the last end.
#[derive(Debug, Clone)]
pub struct ActiveScope {
    /// Live definitions as (file, line): line numbers alone collide
    /// across files (a live `RUN` at live.h:1 beside a dead one at
    /// dead.h:1), so every membership check carries the file.
    pub defines: Vec<(String, u32)>,
    pub guard: String,
}

impl ActiveScope {
    /// Whether the definition at (file, line) is live in this scope.
    pub fn defines_at(&self, file: &str, line: u32) -> bool {
        self.defines
            .iter()
            .any(|(path, define)| path == file && *define == line)
    }
}

/// Normalize a guard for overlap comparison: flatten groups that are pure
/// conjunctions (group-flattening only — never `config_facts`
/// term-dropping, which would count `DEBUG && CONFIG_A` as a subset of
/// `CONFIG_A`), and spell `defined M` as `defined(M)`.
fn normalize_terms(guard: &str) -> Vec<String> {
    fn flatten(term: &str, out: &mut Vec<String>) {
        let term = term.trim();
        if crate::guard::wholly_parenthesized(term) {
            let inner = &term[1..term.len() - 1];
            if !inner.contains("||") && !inner.contains('?') {
                for part in crate::guard::terms(inner) {
                    flatten(part, out);
                }
                return;
            }
        }
        // `defined M` and `defined(M)` are the same predicate, under any
        // redundant parens: `(!(defined(X)))` is `!defined(X)`. Negation
        // parity is counted out before the parens come off, and anything
        // that is not a defined-predicate afterwards stays whole: De
        // Morgan over a conjunction would be a disjunction.
        let mut core = term;
        let mut negated = false;
        loop {
            if let Some(rest) = core.strip_prefix('!') {
                negated = !negated;
                core = rest.trim();
                continue;
            }
            if crate::guard::wholly_parenthesized(core) {
                core = core[1..core.len() - 1].trim();
                continue;
            }
            break;
        }
        // `defined M` and `defined(M)` are the same predicate. The loop
        // above already counted out leading negations and redundant
        // parens, so only the positive spellings remain.
        // `defined X`, `defined(X)`, and `defined (X)`: GCC accepts a
        // space between the operator and the paren. A bare `defined`
        // prefix of a longer identifier is not the operator.
        if let Some(rest) = core.strip_prefix("defined") {
            if rest.starts_with('(') || rest.starts_with(char::is_whitespace) {
                let rest = rest.trim_start();
                if let Some(inner) = rest
                    .strip_prefix('(')
                    .and_then(|inner| inner.strip_suffix(')'))
                {
                    let name = inner.trim();
                    if !name.is_empty() && name.chars().all(|c| c == '_' || c.is_alphanumeric()) {
                        out.push(if negated {
                            format!("!defined({name})")
                        } else {
                            format!("defined({name})")
                        });
                        return;
                    }
                } else {
                    let name: String = rest
                        .chars()
                        .take_while(|c| *c == '_' || c.is_alphanumeric())
                        .collect();
                    if !name.is_empty() && rest[name.len()..].trim().is_empty() {
                        out.push(if negated {
                            format!("!defined({name})")
                        } else {
                            format!("defined({name})")
                        });
                        return;
                    }
                }
            }
        }
        out.push(term.to_string());
    }
    let mut out = Vec::new();
    for term in crate::guard::terms(guard) {
        flatten(term, &mut out);
    }
    out
}

/// The identifiers a guard term depends on: the term itself less `defined`
/// wrapping and negation, plus one expansion level. `IS_ENABLED(X)` reads
/// `X` and `X_MODULE` through token pasting, so it is never stable.
fn term_dependencies(term: &str, map: &PreprocMap) -> Option<Vec<String>> {
    let term = term.trim();
    let positive = term.strip_prefix('!').unwrap_or(term).trim();
    if positive.starts_with("IS_ENABLED(") {
        return None;
    }
    let (name, bare): (String, bool) = if let Some(inner) = positive
        .strip_prefix("defined(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        // `defined(X)` consumes the whole term: X is the dependency.
        (inner.trim().to_string(), false)
    } else if positive.starts_with("defined") {
        return None;
    } else {
        let name: String = positive
            .chars()
            .take_while(|c| *c == '_' || c.is_alphanumeric())
            .collect();
        (name, true)
    };
    if name.is_empty() || (bare && !positive[name.len()..].trim().is_empty()) {
        // A compound term (`A || B`, a comparison): no single dependency,
        // and no proven stability. The safe direction keeps the leg.
        return None;
    }
    let mut deps = vec![name.clone()];
    // One expansion level: what the name itself is defined as.
    for define in &map.defines {
        if define.name == name {
            deps.push(format!("expansion-of-{name}-at-{}", define.line));
        }
    }
    Some(deps)
}

/// Whether one guard term is proven stable between two positions: no write
/// to it or its one-level expansion dependencies in the span, and no
/// `#include` (any spelling: `#  include`, `#include_next`, computed) in
/// the span. The span starts at the guard's evaluation (the outermost
/// `#if`), not at the `#define`: a write between the two still moves what
/// the guard read. `defined(X)` terms skip expansion resolution — they only
/// test whether X is defined — but writes and includes still count. Being a
/// Kconfig symbol proves nothing: headers `#undef` those too. A
/// redefinition with identical replacement text is not a write.
fn term_stable(term: &str, from_line: u32, to_line: u32, map: &PreprocMap) -> bool {
    let (low, high) = if from_line <= to_line {
        (from_line, to_line)
    } else {
        (to_line, from_line)
    };
    // The span starts at the term's own guard-evaluation site, not at the
    // directive: an arm can `#undef` the term before defining M, and
    // scanning only between the two M directives misses the change.
    let Some(deps) = term_dependencies(term, map) else {
        return false;
    };
    for include in &map.includes {
        if *include >= low && *include <= high {
            return false;
        }
    }
    // A redefinition vetoes unless it restates a value that is
    // unconditionally live there: an identical `#define` over an
    // unconditional prior changes nothing in any configuration, but a
    // conditional prior (`#ifdef A / #define FLAG 1`) leaves worlds where
    // the restatement newly establishes the name. An intervening `#undef`
    // likewise always counts as a change — in any arm, not just inside
    // the span: an `#undef` under `#ifdef A` after the unconditional
    // prior means the restatement re-establishes the name under A.
    // Establishing the name (or an unparseable replacement) always counts
    // as a change.
    let name = deps.first().cloned().unwrap_or_default();
    for define in &map.defines {
        if define.name == name && define.line >= low && define.line <= high {
            if map
                .undefs
                .iter()
                .any(|undef| undef.name == name && undef.line >= low && undef.line < define.line)
            {
                return false;
            }
            let Some(current) = &define.expansion else {
                return false;
            };
            // The latest unconditional prior with the identical expansion:
            // anything after it that could move the value vetoes.
            let mut prior_line = 0u32;
            for prior in &map.defines {
                if prior.name == name
                    && prior.line < define.line
                    && normalize_terms(&prior.guard).is_empty()
                    && prior.expansion.as_deref() == Some(current.as_str())
                {
                    prior_line = prior_line.max(prior.line);
                }
            }
            if prior_line == 0 {
                return false;
            }
            let moved = map.undefs.iter().any(|undef| {
                undef.name == name && undef.line > prior_line && undef.line < define.line
            }) || map.defines.iter().any(|later| {
                later.name == name
                    && later.line > prior_line
                    && later.line < define.line
                    && later.expansion.as_deref() != Some(current.as_str())
            });
            if moved {
                return false;
            }
        }
    }
    for undef in &map.undefs {
        if undef.line >= low && undef.line <= high && deps.contains(&undef.name) {
            return false;
        }
    }
    true
}

/// Whether two branch paths share branch identity: the terminator's full
/// `#if` path is a prefix of the interval's path. A common element is not
/// enough: an `#undef` under the same include guard but a different live
/// `#if` re-reads its conditions fresh, so a write between the two guards
/// still moves what the terminator read — only stability decides those.
/// Same nest (equal paths, or the terminator strictly outside) shares.
fn shared_branch(a: &[(u32, u32)], b: &[(u32, u32)]) -> bool {
    b.len() <= a.len() && b.iter().zip(a.iter()).all(|(x, y)| x == y)
}

/// The guard terms one branch-path element contributes: the arm's own
/// condition plus the negated earlier arms, under its parent guard.
/// Normalized like every other term set: a raw `#if defined A` must match
/// the normalized `defined(A)` it is compared against.
fn frame_arm_terms(map: &PreprocMap, chain: u32, arm: u32) -> Vec<String> {
    map.frames
        .iter()
        .find(|frame| frame.chain == chain)
        .map(|frame| {
            let arm_guard = chain_arm_guard(&frame.parent, &frame.arms, arm as usize);
            crate::guard::terms(&arm_guard)
                .iter()
                .flat_map(|term| normalize_terms(term))
                .collect::<Vec<String>>()
        })
        .unwrap_or_default()
}

/// Whether the `#undef` (or out-of-chain redefinition) with guard U fully
/// ends an interval with guard D: U's terms are a subset of D's, and either
/// the two share branch identity or every U term is proven stable. An empty
/// U (after stripping `defined(M)`) is always full.
fn full_overlap(
    interval: &ScopeInterval,
    undef_guard: &str,
    undef_branch: &[(u32, u32)],
    undef_line: u32,
    def_name: &str,
    map: &PreprocMap,
) -> bool {
    let mut u_terms = normalize_terms(undef_guard);
    // Positive self-terms name the live definition's own default shape
    // (`#ifdef M` ... `#define M`): the terminator fires where the name
    // holds, so it ends the interval. A negated self-term (`!defined(M)`,
    // the `#else` arm) fires only where the name is absent — it can never
    // meet the live definition, so it stays and fails the subset below
    // instead of emptying the set into a false full end.
    let self_term = format!("defined({def_name})");
    u_terms.retain(|term| term.as_str() != self_term && term.as_str() != def_name);
    if u_terms.is_empty() {
        return true;
    }
    let d_terms = normalize_terms(&interval.guard);
    // Terms from frames both paths share were evaluated exactly once, at
    // the shared `#if`: no later write can move what that one evaluation
    // read, so they are free — unless an unshared inner frame re-reads
    // them, which starts a fresh evaluation that stability must cover.
    // (`#ifndef H_H` ... `#define H_H` ... `#undef M`: the define sits
    // between the shared evaluation and the undef but cannot touch it.)
    let interval_path = interval_branch(interval, map);
    let shared_len = interval_path
        .iter()
        .zip(undef_branch.iter())
        .take_while(|(x, y)| x == y)
        .count();
    let mut shared_terms: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (chain, arm) in &interval_path[..shared_len] {
        shared_terms.extend(frame_arm_terms(map, *chain, *arm));
    }
    let mut reread: std::collections::HashSet<String> = std::collections::HashSet::new();
    for frame in &map.frames {
        if undef_branch[shared_len..]
            .iter()
            .any(|(chain, _)| *chain == frame.chain)
        {
            // Own arm vocabulary only, not the inherited parent: parent
            // terms come from shared frames above, whose single evaluation
            // both sides already agree on. Normalized, like the shared set.
            for arm in 0..frame.arms.len() {
                reread.extend(
                    crate::guard::terms(&chain_arm_guard("", &frame.arms, arm))
                        .iter()
                        .flat_map(|term| normalize_terms(term)),
                );
            }
        }
    }
    let rest: Vec<&String> = u_terms
        .iter()
        .filter(|term| !(shared_terms.contains(*term) && !reread.contains(*term)))
        .collect();
    if !rest.iter().all(|term| d_terms.contains(term)) {
        return false;
    }
    if shared_branch(&interval_path, undef_branch) {
        return true;
    }
    rest.iter()
        .all(|term| term_stable(term, interval_guard_site(interval, map), undef_line, map))
}

/// Where the interval's guard was evaluated: the outermost `#if` over its
/// defines. Stability spans start here — a write between the guard and the
/// `#define` still moves what the guard read, and only writes between the
/// two guards' evaluations can break their agreement.
fn interval_guard_site(interval: &ScopeInterval, map: &PreprocMap) -> u32 {
    let mut site = interval.start;
    for define in &map.defines {
        if interval.define_lines.contains(&define.line) && define.guard_line < site {
            site = define.guard_line;
        }
    }
    site
}

/// The branch path of an interval: the shared elements of its defines.
/// Sibling arms of one chain share the chain's outer path.
fn interval_branch(interval: &ScopeInterval, map: &PreprocMap) -> Vec<(u32, u32)> {
    let mut branches: Vec<Vec<(u32, u32)>> = Vec::new();
    for define in &map.defines {
        if interval.define_lines.contains(&define.line) {
            branches.push(define.branch.clone());
        }
    }
    let Some(first) = branches.first().cloned() else {
        return Vec::new();
    };
    first
        .into_iter()
        .filter(|element| branches.iter().all(|branch| branch.contains(element)))
        .collect()
}

/// A scope terminator event: line, guard vocabulary, branch identity.
/// A terminator event: its line, its guard, its branch path.
type ScopeEvent = (u32, String, Vec<(u32, u32)>, bool);

/// Compute every live interval for one function-like macro name: sibling
/// arms of one chain join with unioned guards; `#undef`s and out-of-chain
/// redefinitions end, restrict, or leave intervals per the overlap rules.
/// Back-to-back redefinitions in one arm are sequential, never arms.
pub fn scope_intervals(map: &PreprocMap, name: &str) -> Vec<ScopeInterval> {
    // Function-like and object-like defines share intervals: an alias hop
    // (`ALIAS` for `DROP`) is live exactly where its `#define` is, and
    // `#undef` terminates either kind the same way.
    let mut defines: Vec<&RawDefine> = map
        .defines
        .iter()
        .filter(|define| define.name == name)
        .collect();
    defines.sort_by_key(|define| define.line);
    if defines.is_empty() {
        return Vec::new();
    }
    // Sibling arms of one chain join: one interval spanning the group.
    // Same arm twice does not join: two `#define`s in one arm are a
    // sequential redefinition, and the earlier one ends there.
    let mut groups: Vec<Vec<&RawDefine>> = Vec::new();
    for define in defines {
        let join = groups.iter_mut().find(|group| {
            group.iter().any(|member| {
                member.chain != 0 && member.chain == define.chain && member.arm != define.arm
            })
        });
        if let Some(group) = join {
            group.push(define);
        } else {
            groups.push(vec![define]);
        }
    }
    let mut intervals: Vec<ScopeInterval> = groups
        .into_iter()
        .map(|group| {
            let start = group.iter().map(|define| define.line).min().unwrap_or(0);
            let mut guards: Vec<String> = group
                .iter()
                .map(|define| define.guard.clone())
                .filter(|guard| !guard.is_empty())
                .collect();
            guards.sort();
            guards.dedup();
            ScopeInterval {
                define_lines: group.iter().map(|define| define.line).collect(),
                start,
                end: u32::MAX,
                guard: guards.join(" || "),
            }
        })
        .collect();
    intervals.sort_by_key(|interval| interval.start);

    // Terminators in line order: `#undef`s and redefinitions outside the
    // interval's own group. Same-group later defines already joined, so a
    // sequential redefinition (two `.c` groups, or two file-scope defines)
    // always terminates the earlier interval.
    let mut undefs: Vec<&RawUndef> = map
        .undefs
        .iter()
        .filter(|undef| undef.name == name)
        .collect();
    undefs.sort_by_key(|undef| undef.line);
    let mut redefines: Vec<&RawDefine> = map
        .defines
        .iter()
        .filter(|define| define.name == name && define.has_params)
        .collect();
    redefines.sort_by_key(|define| define.line);
    // An object-like redefinition ends the function-like meaning too: GCC
    // warns and keeps the last shape, so `#define M (0)` after
    // `#define M(cb) cb()` leaves no function-like `M` behind.
    let mut shape_ends: Vec<&RawDefine> = map
        .defines
        .iter()
        .filter(|define| define.name == name && !define.has_params)
        .collect();
    shape_ends.sort_by_key(|define| define.line);

    for interval in &mut intervals {
        // Every terminator after the interval's start: `#undef`s anywhere,
        // plus every same-name definition outside this interval's group.
        // (line, guard vocabulary, branch identity).
        let mut events: Vec<ScopeEvent> = Vec::new();
        for undef in &undefs {
            events.push((
                undef.line,
                undef.guard.clone(),
                undef.branch.clone(),
                undef.certain,
            ));
        }
        for define in &redefines {
            if interval.define_lines.contains(&define.line) {
                continue;
            }
            events.push((
                define.line,
                define.guard.clone(),
                define.branch.clone(),
                define.certain,
            ));
        }
        for define in &shape_ends {
            events.push((
                define.line,
                define.guard.clone(),
                define.branch.clone(),
                define.certain,
            ));
        }
        events.sort_by_key(|event| event.0);
        for (line, guard, branch, certain) in &events {
            if *line <= interval.start || *line >= interval.end {
                continue;
            }
            // Constant-fold the event's arm: a terminator in a dead arm
            // (`#if 0`) never executes, so it ends nothing; one in a
            // definitely-taken arm (`%:if 1`, or `#ifndef` over an
            // explicitly undefined flag) fires unconditionally, so it ends
            // the interval whatever its spelling. Without this a taken-arm
            // `#undef` falls into partial-overlap survival and the old
            // definition leaks past it.
            if const_bool(guard) == Some(false) {
                continue;
            }
            if *certain || const_bool(guard) == Some(true) {
                interval.end = *line;
                break;
            }
            if full_overlap(&*interval, guard, branch, *line, name, map) {
                interval.end = *line;
                break;
            }
            // `U ⊆ D` keeps D directly: routing it through `excludes`
            // cannot prove `A && B && !(A && B)` empty for unstable terms,
            // and a live leg labeled impossible is worse than a survivor.
            let u_terms = normalize_terms(guard);
            let d_terms = normalize_terms(&interval.guard);
            if !u_terms.is_empty() && u_terms.iter().all(|term| d_terms.contains(term)) {
                continue;
            }
            // Disjoint first, but only where `excludes` is gated: the
            // conflicting terms must share a branch decision or be proven
            // stable, else `#if A` … `#if !A` both run when A is undefined
            // between them.
            if crate::guard::excludes(&interval.guard, guard)
                && shared_branch(&interval_branch(&*interval, map), branch)
            {
                continue;
            }
            // Partial overlap survives on the complement. The complement is
            // kept: proving it empty is what `excludes` cannot do for a
            // genuine partial overlap, and the safe direction keeps the leg
            // with its guard, never silently drops it.
            interval.guard = if interval.guard.is_empty() {
                format!("!({guard})")
            } else {
                format!("{} && !({guard})", interval.guard)
            };
        }
    }
    intervals
        .into_iter()
        .filter(|interval| interval.start < interval.end)
        .collect()
}

/// The scope live for `name` at `line`: every covering interval, guards
/// joined, definitions listed. `None` where nothing is live — between an
/// `#undef` and the next definition, or past the last end.
/// The live scope with the defining file attached: every membership check
/// below carries (file, line), so same-numbered definitions in different
/// files never validate each other.
pub fn scope_at_file(map: &PreprocMap, file: &str, name: &str, line: u32) -> Option<ActiveScope> {
    let mut covering: Vec<ScopeInterval> = scope_intervals(map, name)
        .into_iter()
        .filter(|interval| interval.start <= line && line < interval.end)
        .collect();
    if covering.is_empty() {
        return None;
    }
    covering.sort_by_key(|interval| interval.start);
    // Only definitions reached by this line: a joined sibling arm below
    // the query has not run yet (its line sorts after).
    let mut defines: Vec<(String, u32)> = covering
        .iter()
        .flat_map(|interval| interval.define_lines.clone())
        .filter(|define| *define <= line)
        .map(|define| (file.to_string(), define))
        .collect();
    defines.sort();
    defines.dedup();
    let mut guards: Vec<String> = covering
        .iter()
        .map(|interval| interval.guard.clone())
        .filter(|guard| !guard.is_empty())
        .collect();
    guards.sort();
    guards.dedup();
    Some(ActiveScope {
        defines,
        guard: guards.join(" || "),
    })
}

#[cfg(test)]
mod scope_tests {
    use super::*;

    #[test]
    fn work_budget_trips_at_limit() {
        let snapshot = ViaSnapshot::default();
        for _ in 0..WORK_LIMIT_CLASSIFIED - 1 {
            assert!(!snapshot.charge_work());
        }
        assert!(!snapshot.exhausted());
        assert!(snapshot.charge_work());
        assert!(snapshot.exhausted());
        assert!(snapshot.tripped_since(WORK_LIMIT_CLASSIFIED - 1));
        assert!(!snapshot.tripped_since(WORK_LIMIT_CLASSIFIED));
    }

    fn husk(name: &str) -> ViaNode {
        ViaNode {
            hop: ViaHop {
                macro_name: name.to_string(),
                file_path: "h.h".to_string(),
                line: 1,
                guard: None,
            },
            callers: Vec::new(),
            deeper: Vec::new(),
            truncated: false,
            depth_cut: false,
        }
    }

    #[test]
    fn husk_nodes_prune_but_truncated_survive() {
        let mut productive = husk("KEEP");
        productive
            .callers
            .push(("caller".to_string(), "u.c".to_string()));
        let mut nested = husk("OUTER");
        nested.deeper.push(productive);
        let mut truncated = husk("CUT");
        truncated.truncated = true;
        let mut nodes = vec![husk("EMPTY"), nested, truncated];
        prune_husk_nodes(&mut nodes);
        let names: Vec<&str> = nodes.iter().map(|n| n.hop.macro_name.as_str()).collect();
        assert_eq!(names, vec!["OUTER", "CUT"]);
        assert_eq!(nodes[0].deeper.len(), 1);
    }

    #[test]
    fn classifies_from_directive_text() {
        assert!(is_function_like_macro_body("#define P(x) (x)\n"));
        assert!(is_function_like_macro_body("# define P(x) (x)\n"));
        assert!(is_function_like_macro_body("#define P() 0\n"));
        assert!(!is_function_like_macro_body("#define P 0\n"));
        assert!(!is_function_like_macro_body("int f(void)\n{\n}\n"));
        assert!(!is_function_like_macro_body("#define_foo(x) (x)\n"));
        assert!(!is_function_like_macro_body(""));
    }

    #[test]
    fn rescan_finds_positions_and_guards() {
        let source = "#define A(x) (x)\n#ifdef X\n#define B 1\n#undef A\n#endif\n";
        let map = rescan_preprocessor(source);
        assert_eq!(map.defines.len(), 2);
        assert_eq!(map.defines[0].name, "A");
        assert_eq!(map.defines[0].line, 1);
        assert!(map.defines[0].has_params);
        assert_eq!(map.defines[0].guard, "");
        assert_eq!(map.defines[1].name, "B");
        assert_eq!(map.defines[1].guard, "defined(X)");
        assert_eq!(map.undefs.len(), 1);
        assert_eq!(map.undefs[0].name, "A");
        assert_eq!(map.undefs[0].guard, "defined(X)");
    }

    #[test]
    fn rescan_records_includes_and_elif() {
        let source = "#include <a.h>\n#  include_next <b.h>\n#if A\n#define X 1\n#elif B\n#define X 2\n#else\n#define X 3\n#endif\n";
        let map = rescan_preprocessor(source);
        assert_eq!(map.includes, vec![1, 2]);
        assert_eq!(map.defines.len(), 3);
        // `#elif B` after `#if A` holds where A did not and B does.
        assert_eq!(map.defines[0].guard, "A");
        assert_eq!(map.defines[1].guard, "!A && B");
        assert_eq!(map.defines[2].guard, "!A && !B");
    }

    #[test]
    fn evidence_parses() {
        assert_eq!(
            parse_parameter_evidence("_p_func (parameter 0)"),
            Some(("_p_func".to_string(), 0))
        );
        assert_eq!(
            parse_parameter_evidence("cb (parameter 2)"),
            Some(("cb".to_string(), 2))
        );
        assert_eq!(parse_parameter_evidence("nope"), None);
    }

    #[test]
    fn body_invocations_parse_calls_and_actuals() {
        let flat = |definition: &str| {
            body_call_tree(definition)
                .into_iter()
                .map(|call| (call.callee, call.actuals))
                .collect::<Vec<_>>()
        };
        let invs = flat("#define LOG_MSG(s) EMIT_WRAP(other_fn, s)");
        assert_eq!(
            invs,
            vec![(
                "EMIT_WRAP".to_string(),
                vec![Some("other_fn".to_string()), Some("s".to_string())]
            )]
        );
        // Pasted bodies yield nothing.
        assert!(flat("#define M(f) __##f(x)").is_empty());
        // Not a define.
        assert!(flat("int f(void) { }").is_empty());
    }

    #[test]
    fn body_call_tree_links_nested_calls_to_their_slot() {
        // `cb()` runs only when DROP evaluates slot 0; the tree records
        // where it sits so the executability proof can decide.
        let tree = body_call_tree("#define OUT(cb) DROP(cb())");
        assert_eq!(tree.len(), 2);
        assert_eq!(tree[0].callee, "DROP");
        assert_eq!(tree[0].parent, None);
        assert_eq!(tree[1].callee, "cb");
        assert_eq!(tree[1].parent, Some((0, 0)));
    }

    #[test]
    fn sequential_redefinitions_are_scoped() {
        // debug.c `P(` style: back-to-back definitions are sequential,
        // never arms. A call between them binds the earlier one.
        // Object-like defines scope too: an alias hop is live exactly
        // where its `#define` is, and `#undef` ends it the same way.
        let source =
            "#define P(x) f(x)\nint a = P(1);\n#define P(x) g(x)\nint b = P(2);\n#define Q 0\n";
        let map = rescan_preprocessor(source);
        let first = scope_at_file(&map, "t.h", "P", 2).expect("call after first define");
        assert_eq!(first.defines, vec![("t.h".to_string(), 1)]);
        let second = scope_at_file(&map, "t.h", "P", 4).expect("call after second define");
        assert_eq!(second.defines, vec![("t.h".to_string(), 3)]);
        let object = scope_at_file(&map, "t.h", "Q", 5).expect("object-like scopes");
        assert_eq!(object.defines, vec![("t.h".to_string(), 5)]);
    }

    #[test]
    fn space_before_paren_is_object_like() {
        // C reads `#define M (expr)` as object-like: the paren must touch
        // the name to take parameters. Object-like still scopes: an alias
        // hop is live exactly where its `#define` is.
        let map = rescan_preprocessor("#define M (x)\nint a = M;\n");
        assert!(map.defines.iter().all(|define| !define.has_params));
        let live = scope_at_file(&map, "t.h", "M", 2).expect("object-like scopes");
        assert_eq!(live.defines, vec![("t.h".to_string(), 1)]);
        assert!(!is_function_like_macro_body("#define M (x)"));
        assert!(is_function_like_macro_body("#define M(x) x"));
    }

    #[test]
    fn block_comment_is_whitespace_not_nothing() {
        // C replaces comments with a single space: `#undef/**/RUN`
        // undefines RUN. Deleting the comment fuses the tokens.
        let map = rescan_preprocessor("#define RUN(cb) cb()\n#undef/**/RUN\n");
        assert!(
            map.undefs.iter().any(|undef| undef.name == "RUN"),
            "comment-glued undef parses: {:?}",
            map.undefs
        );
    }

    #[test]
    fn line_comment_continuation_swallows_the_next_line() {
        let source = "// note \\\n#define HIDDEN 1\n#define M(x) f(x)\n";
        let map = rescan_preprocessor(source);
        assert!(map.defines.iter().all(|define| define.name != "HIDDEN"));
    }

    #[test]
    fn nested_restatement_reads_once() {
        let source = "#ifndef T_H\n#ifndef T_H\n#define M(x) f(x)\n#endif\n#endif\n";
        let map = rescan_preprocessor(source);
        let scope = scope_at_file(&map, "t.h", "M", 3).expect("nested define scopes");
        assert_eq!(scope.guard, "!defined(T_H)", "{}", scope.guard);
        assert_eq!(
            dedupe_conjuncts("defined(A) && defined(A) && B"),
            "defined(A) && B"
        );
    }

    #[test]
    fn glued_if_bang_keeps_its_frame() {
        let map = rescan_preprocessor("#if!defined(FOO)\n#define M(x) f(x)\n#endif\n");
        let scope = scope_at_file(&map, "t.h", "M", 2).expect("guarded define scopes");
        assert!(scope.guard.contains("defined(FOO)"), "{}", scope.guard);
    }

    #[test]
    fn glued_if_paren_pushes_a_frame() {
        let map = rescan_preprocessor("#if(FOO)\n#define M(x) f(x)\n#endif\n");
        let scope = scope_at_file(&map, "t.h", "M", 2).expect("guarded define scopes");
        assert!(scope.guard.contains("FOO"), "{}", scope.guard);
    }

    #[test]
    fn restatement_after_conditional_undef_is_a_change() {
        // Under A the `#undef FLAG` fires, so the later `#define FLAG 1`
        // re-establishes it: HIDDEN (defined while FLAG is down) stays
        // live under A past the `#undef HIDDEN` that only fires where
        // FLAG is up.
        let src = "#define FLAG 1\n#ifdef A\n#undef FLAG\n#endif\n#ifndef FLAG\n#define HIDDEN(cb) cb()\n#endif\n#define FLAG 1\n#ifndef FLAG\n#undef HIDDEN\n#endif\nint k = HIDDEN(1);\n";
        let map = rescan_preprocessor(src);
        assert!(scope_at_file(&map, "m.h", "HIDDEN", 12).is_some());
    }

    #[test]
    fn control_plain_restatement_is_no_change() {
        let src = "#define FLAG 1\n#ifndef FLAG\n#define HIDDEN(cb) cb()\n#endif\n#define FLAG 1\n#ifndef FLAG\n#undef HIDDEN\n#endif\nint k = HIDDEN(1);\n";
        let map = rescan_preprocessor(src);
        assert!(scope_at_file(&map, "m.h", "HIDDEN", 9).is_none());
    }

    #[test]
    fn reread_spelling_is_normalized() {
        // Under A: M defined, A undefined, the inner `#if defined A` is
        // false, the `#undef M` never fires. The re-read vocabulary must
        // normalize like the terms it is compared against.
        let src = "#ifdef A\n#define M(x) x()\n#undef A\n#if defined A\n#undef M\n#endif\n#endif\nint k = M(1);\n";
        let map = rescan_preprocessor(src);
        assert!(scope_at_file(&map, "m.h", "M", 8).is_some());
    }

    #[test]
    fn dead_if0_arm_records_nothing() {
        let src = "#define RUN(cb) cb()\n#if 0\n#undef RUN\n#endif\nint k = RUN(1);\n";
        let map = rescan_preprocessor(src);
        assert!(map.undefs.is_empty(), "{:?}", map.undefs);
        assert_eq!(map.dead, vec![(3u32, 3u32)]);
        assert!(scope_at_file(&map, "m.h", "RUN", 5).is_some());
        assert_eq!(map.dead, vec![(3u32, 3u32)]);
    }

    #[test]
    fn reread_control_paren_spelling() {
        let src = "#ifdef A\n#define M(x) x()\n#undef A\n#if defined(A)\n#undef M\n#endif\n#endif\nint k = M(1);\n";
        let map = rescan_preprocessor(src);
        assert!(scope_at_file(&map, "m.h", "M", 8).is_some());
    }

    #[test]
    fn block_comments_hide_directives() {
        let source = "#define M(x) f(x)\n/* #undef M */\nint a = M(1);\n";
        let map = rescan_preprocessor(source);
        assert!(map.undefs.is_empty(), "{:?}", map.undefs);
        assert!(scope_at_file(&map, "t.h", "M", 3).is_some());
        // A comment spanning lines hides every directive inside it; a
        // trailing-comment `#endif` still pops its frame.
        let source = "/*\n#undef M\n*/\n#if A\n#define N(x) g(x)\n#endif /* A */\n";
        let map = rescan_preprocessor(source);
        assert!(map.undefs.is_empty(), "{:?}", map.undefs);
        assert!(scope_at_file(&map, "t.h", "N", 5).is_some());
        // String and character literals are opaque: the `/*` inside one
        // opens no comment, so the `#undef` below still counts.
        let source = "static const char text[] = \"/*\";\n#define M(x) f(x)\n#undef M\n";
        let map = rescan_preprocessor(source);
        assert_eq!(map.undefs.len(), 1, "{:?}", map.undefs);
        assert_eq!(map.undefs[0].line, 3);
        assert!(scope_at_file(&map, "t.h", "M", 4).is_none());
    }

    #[test]
    fn multiline_conditions_join() {
        let source = "#if A && \\\n B\n#define M(x) f(x)\n#endif\n";
        let map = rescan_preprocessor(source);
        let scope = scope_at_file(&map, "t.h", "M", 3).expect("define under split guard");
        let terms = normalize_terms(&scope.guard);
        assert!(terms.contains(&"A".to_string()), "{terms:?}");
        assert!(terms.contains(&"B".to_string()), "{terms:?}");
    }

    #[test]
    fn else_arm_undef_does_not_end_the_interval() {
        // The `#else` of `#ifdef M` fires only where M is absent: it can
        // never meet the live definition, so the interval survives past
        // the `#endif` instead of ending at the `#undef`.
        let source = "#define M(x) f(x)\n#ifdef M\n#else\n#undef M\n#endif\nint a = M(1);\n";
        let map = rescan_preprocessor(source);
        assert!(
            scope_at_file(&map, "t.h", "M", 6).is_some(),
            "survives the dead undef"
        );
    }

    #[test]
    fn identical_redefinition_keeps_stability() {
        // Restating `#define A 1` changes nothing the guard read: the
        // `#undef M` still fully ends the interval.
        let source =
            "#define A 1\n#if A\n#define M(x) f(x)\n#endif\n#if A\n#define A 1\n#undef M\n#endif\n";
        let map = rescan_preprocessor(source);
        let intervals = scope_intervals(&map, "M");
        assert_eq!(intervals.len(), 1);
        assert_eq!(intervals[0].end, 7, "{intervals:?}");
    }

    #[test]
    fn changed_redefinition_breaks_stability() {
        // `#define A 2` over `#define A 1` moves what the guard read: the
        // `#undef M` can no longer fully end the interval.
        let source =
            "#define A 1\n#if A\n#define M(x) f(x)\n#endif\n#if A\n#define A 2\n#undef M\n#endif\n";
        let map = rescan_preprocessor(source);
        let intervals = scope_intervals(&map, "M");
        assert_eq!(intervals.len(), 1);
        assert_eq!(intervals[0].end, u32::MAX, "{intervals:?}");
    }

    #[test]
    fn write_before_guard_evaluation_breaks_stability() {
        // `#undef A` at line 2 runs before the second `#if A` is
        // evaluated: the `#undef M` under it never fires, so the interval
        // must survive.
        let source = "#if A\n#undef A\n#define M(x) f(x)\n#endif\n#if A\n#undef M\n#endif\n";
        let map = rescan_preprocessor(source);
        let intervals = scope_intervals(&map, "M");
        assert_eq!(intervals.len(), 1);
        assert_eq!(intervals[0].end, u32::MAX, "{intervals:?}");
    }

    #[test]
    fn unguarded_undef_ends_the_interval() {
        // An unguarded `#undef` fires in every build: it genuinely ends
        // the interval (the empty guard is the full overlap, not a gap in
        // the reasoning).
        let map = rescan_preprocessor("#define M(x) f(x)\n#undef M\nint a = M(1);\n");
        assert!(scope_at_file(&map, "t.h", "M", 3).is_none());
    }

    #[test]
    fn parenthesized_negations_normalize() {
        assert_eq!(
            normalize_terms("(!(defined(X)))"),
            vec!["!defined(X)".to_string()]
        );
        // Not a defined-predicate: De Morgan stays out, but the redundant
        // group still distributes to the bare negation.
        assert_eq!(normalize_terms("(!(X))"), vec!["!(X)".to_string()]);
    }

    #[test]
    fn stringized_params_prove_nothing() {
        // `#f` is not a call: the body proves no invocation.
        assert!(body_call_tree("#define S(f) g(#f)").is_empty());
    }

    #[test]
    fn va_elision_reads_as_the_bundle_marker() {
        assert_eq!(
            scrub_va_elision("emit2(fmt, ##__VA_ARGS__)"),
            "emit2(fmt, __VA_ARGS__)".to_string()
        );
        // Other pastes are untouched: still silent downstream.
        assert!(scrub_va_elision("x##y").contains("##"));
        let tree = body_call_tree("#define LOG2(fmt, ...) emit2(fmt, ##__VA_ARGS__)");
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].callee, "emit2");
        assert_eq!(
            tree[0].actuals,
            vec![Some("fmt".to_string()), Some(BUNDLE_MARKER.to_string())]
        );
    }

    #[test]
    fn pasted_callee_severs_its_subtree() {
        // A paste never parses as a callee: the error poisons the whole
        // tree, which parses to nothing.
        assert!(body_call_tree("#define M(f) g(__##h(f))").is_empty());
        // A call through a pointer parses but names no callee: whatever
        // nests under it threads through an anonymous node, never promoted
        // to top level. Its arguments still evaluate, so the nested call
        // stands under the anonymous call's slot.
        let tree = body_call_tree("#define M(cb) g((*fp)(cb()))");
        assert_eq!(tree.len(), 3);
        assert_eq!(tree[0].callee, "g");
        assert_eq!(tree[0].actuals, vec![None]);
        assert_eq!(tree[0].parent, None);
        assert_eq!(tree[1].callee, "");
        assert_eq!(tree[1].parent, Some((0, 0)));
        assert_eq!(tree[2].callee, "cb");
        assert_eq!(tree[2].parent, Some((1, 0)));
    }

    #[test]
    fn undef_gap_has_no_scope() {
        let source = "#define M(x) f(x)\nint a = M(1);\n#undef M\nint b = 0;\n#define M(x) g(x)\nint c = M(2);\n";
        let map = rescan_preprocessor(source);
        assert_eq!(
            scope_at_file(&map, "t.h", "M", 2).unwrap().defines,
            vec![("t.h".to_string(), 1)]
        );
        assert!(
            scope_at_file(&map, "t.h", "M", 4).is_none(),
            "call between undef and redefine"
        );
        assert_eq!(
            scope_at_file(&map, "t.h", "M", 6).unwrap().defines,
            vec![("t.h".to_string(), 5)]
        );
    }

    #[test]
    fn sibling_arms_join_after_endif() {
        // refcount.c style: `#if`/`#else` arms join with unioned guards.
        let source =
            "#if C\n#define R(x) pr_err(x)\n#else\n#define R(x) 0\n#endif\nint k = R(1);\n";
        let map = rescan_preprocessor(source);
        let scope = scope_at_file(&map, "t.h", "R", 6).expect("post-endif call");
        assert_eq!(
            scope.defines,
            vec![("t.h".to_string(), 2), ("t.h".to_string(), 4)]
        );
        assert!(
            scope.guard.contains("C"),
            "guard shows the arm: {}",
            scope.guard
        );
        // Joined arms union their guards exactly: no `C && !(!C)`
        // fragment from treating the `#else` arm as a redefinition.
        let mut arms: Vec<&str> = scope.guard.split(" || ").collect();
        arms.sort();
        assert_eq!(arms, vec!["!C", "C"], "union guard: {}", scope.guard);
    }

    #[test]
    fn same_block_undef_ends_the_interval() {
        // debug.c :887/:925 style: define and undef in one `#ifdef` block.
        let source =
            "#ifdef X\n#define M(x) f(x)\nint a = M(1);\n#undef M\n#endif\nint b = M(2);\n";
        let map = rescan_preprocessor(source);
        assert_eq!(
            scope_at_file(&map, "t.h", "M", 3).unwrap().defines,
            vec![("t.h".to_string(), 2)]
        );
        assert!(
            scope_at_file(&map, "t.h", "M", 6).is_none(),
            "post-endif call is past the undef"
        );
    }

    #[test]
    fn partial_overlap_survives_on_the_complement() {
        // 7990.c style: unguarded define, guarded undef. The leg survives
        // for builds without the guard, carrying the leftover guard text.
        let source =
            "#define W(x) out(x)\nint a = W(1);\n#ifdef H\n#undef W\n#endif\nint b = W(2);\n";
        let map = rescan_preprocessor(source);
        let before = scope_at_file(&map, "t.h", "W", 2).unwrap();
        assert_eq!(before.defines, vec![("t.h".to_string(), 1)]);
        let after = scope_at_file(&map, "t.h", "W", 6).expect("complement survives");
        assert_eq!(after.defines, vec![("t.h".to_string(), 1)]);
        assert!(
            after.guard.contains("!defined(H)") || after.guard.contains("!(defined(H))"),
            "leftover guard kept: {}",
            after.guard
        );
    }

    #[test]
    fn nested_chain_keeps_inner_and_stub() {
        // rwsem.c style: an inner chain inside `#ifndef OUTER`, plus the
        // outer `#else` stub. Post-`#endif` callers see both, guarded.
        let source = "#ifndef OUTER\n#if A\n#define M(x) f(x)\n#else\n#define M(x) g(x)\n#endif\n#else\n#define M(x) 0\n#endif\nint k = M(1);\n";
        let map = rescan_preprocessor(source);
        let scope = scope_at_file(&map, "t.h", "M", 9).expect("post-endif call");
        assert_eq!(scope.defines.len(), 3);
        assert!(
            scope.guard.contains("OUTER"),
            "guards shown: {}",
            scope.guard
        );
    }
}

// ---------------------------------------------------------------------------
// Query-time traversal: snapshot, content, classification, both directions.
// ---------------------------------------------------------------------------

use crate::database::connection::DatabaseManager;
use anyhow::Result;

/// Budgets. The work limit counts classified rows; the named-hop cap bounds
/// macro layers; the group cap bounds rendered output.
pub const WORK_LIMIT_CLASSIFIED: usize = 8192;
pub const MAX_NAMED_HOPS: usize = 8;
pub const MAX_FORWARD_LEGS: usize = 64;
pub const TOP_VIA_GROUPS: usize = 25;
pub const TRUNCATED_GROUPS_MARKER: &str = "(truncated: showing top 25 of";
pub const TRUNCATED_WORK_MARKER: &str = "(truncated: work limit reached; counts are lower bounds)";
pub const TRUNCATED_DEPTH_MARKER: &str =
    "(truncated: nesting limit reached; chains below are lower bounds)";

/// One immutable revision/overlay snapshot per query: resolved once at the
/// entry, never re-resolved mid-walk, so a warm overlay or a manifest swap
/// cannot change what the hops below see. Cache identity comes from the
/// manifest revision plus the workdir command generation inside the
/// memoized lookups; the snapshot's own guarantee is single resolution.
#[derive(Default)]
pub struct ViaSnapshot {
    pub git_sha: String,
    pub manifest: std::sync::Arc<crate::database::resolution::RevisionPaths>,
    /// Workdir-dirty files at this snapshot: their committed rows and blob
    /// text are stale, so only overlay rows answer for them. Read once per
    /// snapshot so every leg in the query agrees on the workdir state.
    pub dirty: std::collections::HashSet<String>,
    /// Committed blob rescans by file: one parse per file per query, not
    /// one per call site. Dirty files never enter (their blob is stale).
    pub rescans: std::cell::RefCell<std::collections::HashMap<String, Option<PreprocMap>>>,
    /// Workdir call inventory by dirty file: overlay handover sites.
    pub dirty_calls: std::cell::RefCell<std::collections::HashMap<String, Vec<OverlayCallSite>>>,
    /// Workdir text by dirty file, split into lines: the stale-site gate
    /// below reads one line per site without re-reading the file.
    pub dirty_lines: std::cell::RefCell<std::collections::HashMap<String, Vec<String>>>,
    /// One executability summary per macro definition per query, keyed
    /// (name, file, line, pin): every site and every hop shares one proof
    /// per definition instead of re-proving it per site per hop. The pin
    /// joins the key because admission narrows by it mid-query: one
    /// definition proves differently under different pins.
    pub summaries:
        std::cell::RefCell<std::collections::HashMap<(String, String, u32, String), MacroSummary>>,
    /// Macro rows by name per query: admission and scope checks reuse one
    /// lookup per name instead of one per site per hop.
    pub macro_rows:
        std::cell::RefCell<std::collections::HashMap<String, Vec<crate::types::FunctionInfo>>>,
    /// Definitions currently under summary proof: cycle guard for the
    /// summary cache (a cycle summarizes empty, never recurses).
    pub summary_active:
        std::cell::RefCell<std::collections::HashSet<(String, String, u32, String)>>,
    /// Call arities per file per query: how many actuals each
    /// `(callee, line)` call carries, parsed once from workdir text where
    /// dirty and the committed blob otherwise. Pack widths (and therefore
    /// every post-splice slot) derive from these.
    pub arities: std::cell::RefCell<std::collections::HashMap<String, Vec<CallArity>>>,
    /// Dead preprocessor line ranges per file per query: arms under a
    /// constant-false condition never compile, so call sites there never
    /// run. Parsed once from workdir text where dirty and the committed
    /// blob otherwise.
    pub deadlines: std::cell::RefCell<std::collections::HashMap<String, Vec<(u32, u32)>>>,
    /// The git repo, opened once per query on first blob need: every
    /// committed-text read shares it instead of discovering per file.
    /// Plain (not thread-safe) handle: blob reads are synchronous, so
    /// it never crosses an await while borrowed. Boxed: a Repository
    /// is large, and `ViaSnapshot` lives by value in every deep
    /// recursion level, so the handle stays on the heap.
    pub repo: std::cell::RefCell<Option<Box<gix::Repository>>>,
    /// The proof budget for this query: charged by every proof path
    /// through the methods below, tripped at the shared limit. Past
    /// the limit proofs end and drop their legs; the aggregation
    /// points mark the results truncated.
    pub budget: std::cell::RefCell<ViaBudget>,
}

impl ViaSnapshot {
    /// Charge one unit of proof work: true when the shared limit
    /// trips. Loops break on true; aggregation points OR exhaustion
    /// into their truncated flags, so counts stay lower bounds.
    pub fn charge_work(&self) -> bool {
        let mut budget = self.budget.borrow_mut();
        budget.classified += 1;
        budget.classified >= WORK_LIMIT_CLASSIFIED
    }

    /// Charge bulk-admitted work (a classified chunk and its rows):
    /// true when the shared limit trips.
    pub fn charge_many(&self, n: usize) -> bool {
        let mut budget = self.budget.borrow_mut();
        budget.classified += n;
        budget.classified >= WORK_LIMIT_CLASSIFIED
    }

    /// Whether the shared limit already tripped: aggregation points
    /// OR this into their truncated flags even where the trip fired
    /// in an earlier phase, since later phases then run partial.
    pub fn exhausted(&self) -> bool {
        self.budget.borrow().classified >= WORK_LIMIT_CLASSIFIED
    }

    /// Whether this call tripped the limit: true when exhausted now
    /// but the budget still had room on entry. Third-level displays
    /// render the work marker exactly once through it, however many
    /// edges follow.
    pub fn tripped_since(&self, was: usize) -> bool {
        self.exhausted() && was < WORK_LIMIT_CLASSIFIED
    }

    /// One dispatch-site read, for sizing: no trip semantics.
    pub fn note_dispatch(&self) {
        self.budget.borrow_mut().dispatch_calls += 1;
    }

    /// One committed-blob open, for sizing: no trip semantics.
    pub fn note_blob(&self) {
        self.budget.borrow_mut().blob_opens += 1;
    }

    /// One named-hop descent, for sizing: no trip semantics. Paired
    /// with `leave_hop` below: the hop cap bounds depth, not work.
    pub fn note_hop(&self) {
        self.budget.borrow_mut().named_hops += 1;
    }

    /// Ascend one named hop on the way out: no trip semantics.
    pub fn leave_hop(&self) {
        self.budget.borrow_mut().named_hops -= 1;
    }

    /// Current named-hop depth, for the nesting backstop.
    pub fn hop_depth(&self) -> usize {
        self.budget.borrow().named_hops
    }

    /// Work charged so far, for trip-transition checks.
    pub fn classified(&self) -> usize {
        self.budget.borrow().classified
    }

    /// Counter readout for sizing work: prints to stderr when
    /// SEMCODE_VIA_STATS is set, silent otherwise. `rescans` is the
    /// snapshot's rescan-cache size (no increments needed — the map
    /// only grows on misses).
    pub fn dump_stats(&self, label: &str, rescans: usize) {
        if std::env::var("SEMCODE_VIA_STATS").is_ok() {
            let budget = self.budget.borrow();
            eprintln!(
                "via-stats {label}: classified={} named_hops={} dispatch_calls={} blob_opens={} rescans={}",
                budget.classified, budget.named_hops, budget.dispatch_calls, budget.blob_opens, rescans,
            );
        }
    }
}

/// One call's arity: the callee, its 1-based line, how many actuals it
/// passes (comments excluded, like every other slot count), and the
/// enclosing function (empty at file scope).
#[derive(Debug, Clone)]
pub struct CallArity {
    pub callee: String,
    pub line: u32,
    pub arity: u32,
    pub enclosing: String,
}

/// Where the value a proof tracks sits relative to the current macro's
/// pack: its position within the pack (pack-relative, never the top
/// site's absolute index — repacking reshapes every absolute slot), and
/// the pack's width (how many elements a splice of this pack expands to).
/// `None` position is a named value; `None` width is unknown, and unknown
/// keeps the site: slots read unadjusted.
#[derive(Debug, Clone, Copy)]
pub struct PackState {
    pub pos: Option<u32>,
    pub width: Option<u32>,
}

/// Where one handover hop lands: a fixed slot, or a pack position.
#[derive(Debug, Clone, Copy)]
enum Landing {
    Fixed(usize),
    Pack(u32),
}

/// Pack-relative landing through one handover hop: the handing call's
/// actual at `slot` (a `marker` splice of the current pack, or the named
/// value the proof tracks) into `row`. Absolute site slots are meaningless
/// past a repack, so every hop re-grounds in the current pack: a pack
/// spliced into the next macro passes through unchanged; spliced into fixed
/// slots it lands by offset from its pack position; a named value landing
/// past the fixed parameters joins the next pack at its offset there. Each
/// landing records the next level's pack state: the pack's own width where
/// it passes through, the reshaped width where trailing actuals repack it.
/// `slot` is syntactic (an index into `actuals`); a `__VA_ARGS__` splice
/// before it widens the call by the pack width, so fixed landings use the
/// semantic slot. Only a direct splice actual widens — argument
/// pre-expansion splits arguments before expanding them, so a splice
/// nested inside another actual never shifts slots. Unknown width keeps
/// the syntactic slot.
fn pack_landings(
    actuals: &[Option<String>],
    slot: usize,
    marker: bool,
    cur: PackState,
    row: &crate::types::FunctionInfo,
) -> Vec<(Landing, PackState)> {
    let child_width = variadic_slot(row).and_then(|vslot| {
        let mut width = 0u32;
        for actual in actuals.iter().skip(vslot) {
            if actual.as_deref() == Some(BUNDLE_MARKER) {
                width = width.checked_add(cur.width?)?;
            } else {
                width = width.checked_add(1)?;
            }
        }
        Some(width)
    });
    let child_pack = PackState {
        pos: None,
        width: child_width,
    };
    let semantic = match cur.width {
        Some(width) => {
            let splices = actuals
                .iter()
                .take(slot)
                .filter(|actual| actual.as_deref() == Some(BUNDLE_MARKER))
                .count();
            (slot as i64 - splices as i64 + splices as i64 * width as i64).max(0) as usize
        }
        // Unknown width: a slot at or past a splice shifts by it, so no
        // landing there is provable — falling back to the syntactic slot
        // invents landings twin calls disprove (`W(t,f)` beside `W(f,..)`
        // lands `f` in the pack, never at slot 1). Slots before any
        // splice are width-independent and land syntactically.
        None => {
            if actuals
                .iter()
                .take(slot)
                .any(|actual| actual.as_deref() == Some(BUNDLE_MARKER))
            {
                return Vec::new();
            }
            slot
        }
    };
    if marker {
        let slot = semantic + cur.pos.unwrap_or(0) as usize;
        // A bundle's head fills the callee's fixed slots first
        // (`SEL(__VA_ARGS__, f)` with two trailing actuals lands the
        // first two in `a` and `b`): only the extra actuals past them join
        // the callee's own bundle.
        if let Some(param) = row.parameters.get(slot) {
            if param.name != "..." {
                return vec![(Landing::Fixed(slot), child_pack)];
            }
        }
        if variadic_slot(row).is_some() {
            return vec![(Landing::Pack(cur.pos.unwrap_or(0)), cur)];
        }
        return row
            .parameters
            .get(slot)
            .map(|_| (Landing::Fixed(slot), child_pack))
            .into_iter()
            .collect();
    }
    if row.parameters.get(semantic).is_some() {
        return vec![(Landing::Fixed(semantic), child_pack)];
    }
    if let Some(vslot) = variadic_slot(row) {
        if semantic >= vslot {
            let pos = semantic as u32 - vslot as u32;
            return vec![(
                Landing::Pack(pos),
                PackState {
                    pos: Some(pos),
                    width: child_width,
                },
            )];
        }
    }
    Vec::new()
}

/// Resolve the snapshot once per query.
pub async fn snapshot_for(db: &DatabaseManager, git_sha: &str) -> Result<ViaSnapshot> {
    let manifest = db.git_manifest_cached(git_sha).await?;
    let dirty = db.overlay_dirty_files(git_sha).into_iter().collect();
    Ok(ViaSnapshot {
        git_sha: git_sha.to_string(),
        manifest,
        dirty,
        rescans: std::cell::RefCell::new(std::collections::HashMap::new()),
        dirty_calls: std::cell::RefCell::new(std::collections::HashMap::new()),
        dirty_lines: std::cell::RefCell::new(std::collections::HashMap::new()),
        summaries: std::cell::RefCell::new(std::collections::HashMap::new()),
        macro_rows: std::cell::RefCell::new(std::collections::HashMap::new()),
        summary_active: std::cell::RefCell::new(std::collections::HashSet::new()),
        arities: std::cell::RefCell::new(std::collections::HashMap::new()),
        deadlines: std::cell::RefCell::new(std::collections::HashMap::new()),
        repo: std::cell::RefCell::new(None),
        budget: std::cell::RefCell::new(ViaBudget::default()),
    })
}

/// Whether a committed argument row belongs to the snapshot: same rule as
/// macro rows — a dirty file's committed rows are stale. The callers
/// display filters its handed list through this.
pub fn row_belongs(snapshot: &ViaSnapshot, file_path: &str, git_file_hash: &str) -> bool {
    row_in_snapshot(snapshot, file_path, git_file_hash, false)
}

/// Whether a stored row belongs to this snapshot: committed rows match the
/// manifest hash, except in dirty files (the workdir text supersedes them
/// there); overlay rows are workdir state and always belong.
fn row_in_snapshot(
    snapshot: &ViaSnapshot,
    file_path: &str,
    git_file_hash: &str,
    from_overlay: bool,
) -> bool {
    if from_overlay {
        return true;
    }
    if snapshot.dirty.contains(file_path) {
        return false;
    }
    snapshot
        .manifest
        .hash_of(file_path)
        .is_some_and(|hash| hash == git_file_hash)
}

/// Blob text at the snapshot revision. `None` where the file is absent or
/// unreadable there; the caller falls back to overlay rows.
fn blob_text_at(
    repo_path: &str,
    commit_sha: &str,
    file_path: &str,
    repo_cache: &std::cell::RefCell<Option<Box<gix::Repository>>>,
) -> Result<Option<String>> {
    if repo_cache.borrow().is_none() {
        *repo_cache.borrow_mut() = Some(Box::new(gix::discover(repo_path)?));
    }
    let repo = repo_cache.borrow();
    let repo = repo.as_ref().expect("cached above");
    let commit = crate::git::resolve_to_commit(repo, commit_sha)?;
    let tree = commit
        .tree()
        .map_err(|e| anyhow::anyhow!("tree for '{commit_sha}': {e}"))?;
    let entry = tree
        .lookup_entry_by_path(std::path::Path::new(file_path))
        .map_err(|e| anyhow::anyhow!("lookup '{file_path}': {e}"))?;
    let Some(entry) = entry else {
        return Ok(None);
    };
    if !entry.mode().is_blob() {
        return Ok(None);
    }
    let object = repo.find_object(entry.object_id())?;
    Ok(Some(String::from_utf8_lossy(&object.data).into_owned()))
}

/// The scope sources for one file: a rescanned committed snapshot, plus
/// overlay macro rows standing as single-interval scopes where dirty.
pub struct FileScopes {
    pub map: Option<PreprocMap>,
    pub overlay_macros: Vec<crate::types::FunctionInfo>,
}

pub async fn file_scopes(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    file_path: &str,
) -> Result<FileScopes> {
    let overlay_macros = db.overlay_macros_in_file(file_path, &snapshot.git_sha);
    // A dirty file answers from its workdir text: the committed blob is
    // the text before the edit, so its intervals are stale — including the
    // delete case, where the workdir holds no macro at all. The rescan
    // parses the current text directly, so sequential redefinitions and
    // `#undef`s the row extractor dedups away still end intervals. (The
    // extractor stores one row per name per file; the rescan stores
    // every directive.)
    // The borrow ends with the statement: holding it across the insert
    // below panics the RefCell at runtime.
    let cached = snapshot.rescans.borrow().get(file_path).cloned();
    let map = if let Some(map) = cached {
        map
    } else if snapshot.dirty.contains(file_path) {
        let map = std::fs::read_to_string(std::path::Path::new(db.repo_path()).join(file_path))
            .ok()
            .map(|text| rescan_preprocessor(&text));
        snapshot
            .rescans
            .borrow_mut()
            .insert(file_path.to_string(), map.clone());
        map
    } else if overlay_macros.is_empty() {
        snapshot.note_blob();
        let map = blob_text_at(db.repo_path(), &snapshot.git_sha, file_path, &snapshot.repo)?
            .map(|text| rescan_preprocessor(&text));
        snapshot
            .rescans
            .borrow_mut()
            .insert(file_path.to_string(), map.clone());
        map
    } else {
        None
    };
    Ok(FileScopes {
        map,
        overlay_macros,
    })
}

/// The live scope for `name` at `line` in `file_path`: committed intervals
/// from the rescan, or the overlay row's own span where dirty. Where the
/// site file never defines the name (a `.c` file calling a header macro),
/// the defining file decides: live iff one of the snapshot definitions
/// sits in an interval still open at its own end of file — a macro closed
/// before its file's end is visible to no includer. Include order inside
/// the site file is not modeled: a call above its own `#include` reads as
/// live. That over-approximates only where the source cannot compile.
pub async fn scope_at_site(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    file_path: &str,
    name: &str,
    line: u32,
) -> Result<Option<ActiveScope>> {
    // Budget spent: no scope to admit the callers with, so the edge
    // drops and the aggregation points mark it.
    if snapshot.charge_work() {
        return Ok(None);
    }
    let scopes = file_scopes(db, snapshot, file_path).await?;
    if let Some(map) = scopes.map.as_ref() {
        if let Some(scope) = scope_at_file(map, file_path, name, line) {
            return Ok(Some(scope));
        }
        // Defined in this file but not live here (use before define, or
        // past an `#undef`): the file's own rules already spoke. Only a
        // name the site file never defines — at or before this line —
        // falls through to its headers: a later redefinition must not
        // shadow what the headers answered here.
        if map
            .defines
            .iter()
            .any(|define| define.name == name && define.line <= line)
            || map
                .undefs
                .iter()
                .any(|undef| undef.name == name && undef.line <= line)
        {
            return Ok(None);
        }
    } else {
        // Dirty file: each overlay macro row is its own single-interval scope,
        // live from its definition line on. The latest definition at or
        // before the line wins (a sequential redefinition shadows the
        // earlier one); the first would keep a dead version live past its
        // replacement. The overlay keeps rows, not text, so later `#undef`s
        // in the dirty file are invisible: the sound direction keeps the
        // leg with the row's guard rather than dropping what the rescan
        // cannot see.
        let mut best: Option<&crate::types::FunctionInfo> = None;
        for row in &scopes.overlay_macros {
            if row.name == name
                && is_macro_row(row)
                && row.line_start <= line
                && best.is_none_or(|prior| prior.line_start <= row.line_start)
            {
                best = Some(row);
            }
        }
        if let Some(row) = best {
            return Ok(Some(ActiveScope {
                defines: vec![(file_path.to_string(), row.line_start)],
                guard: row.guard.clone().unwrap_or_default(),
            }));
        }
    }
    // Cross-file: union the open intervals of every snapshot definition.
    // A first-match return would let one file's live line validate a
    // same-numbered dead definition in another file; the caller's
    // file-aware check then selects its own arm from the union.
    let mut defines: Vec<(String, u32)> = Vec::new();
    let mut guards: Vec<String> = Vec::new();
    for row in macro_rows_for(db, snapshot, name).await? {
        if !is_macro_row(&row) {
            continue;
        }
        let defining = file_scopes(db, snapshot, &row.file_path).await?;
        if let Some(dmap) = defining.map.as_ref() {
            for interval in scope_intervals(dmap, name) {
                if interval.define_lines.contains(&row.line_start) && interval.end == u32::MAX {
                    defines.extend(
                        interval
                            .define_lines
                            .iter()
                            .map(|line| (row.file_path.clone(), *line)),
                    );
                    if !interval.guard.is_empty() {
                        guards.push(interval.guard.clone());
                    }
                }
            }
        } else {
            for orow in &defining.overlay_macros {
                if orow.name == name && is_macro_row(orow) {
                    defines.push((orow.file_path.clone(), orow.line_start));
                    if let Some(guard) = orow.guard.clone() {
                        if !guard.is_empty() {
                            guards.push(guard);
                        }
                    }
                }
            }
        }
    }
    if defines.is_empty() {
        return Ok(None);
    }
    defines.sort();
    defines.dedup();
    guards.sort();
    guards.dedup();
    Ok(Some(ActiveScope {
        defines,
        guard: guards.join(" || "),
    }))
}

/// One ordered `via` hop for evidence: the macro passed through, and where.
#[derive(Debug, Clone)]
pub struct ViaHop {
    pub macro_name: String,
    pub file_path: String,
    pub line: u32,
    pub guard: Option<String>,
}

impl ViaHop {
    pub fn render(&self) -> String {
        let mut text = format!("via {} ({}:{})", self.macro_name, self.file_path, self.line);
        if let Some(guard) = self.guard.as_ref() {
            if !guard.is_empty() {
                text.push_str(&format!(" [{guard}]"));
            }
        }
        text
    }
}

/// A macro layer in reverse: macro M whose body calls the target, with M's
/// admitted callers. `deeper` holds macro callers expanded one more layer;
/// function callers stop their branch.
#[derive(Debug, Clone)]
pub struct ViaNode {
    pub hop: ViaHop,
    pub callers: Vec<(String, String)>,
    pub deeper: Vec<ViaNode>,
    pub truncated: bool,
    /// A nesting cut stopped below this node: lower bounds, never
    /// completeness. Prints its own marker, never the work-limit text.
    pub depth_cut: bool,
}

/// Drop husk nodes: no callers and no deeper chains. A walk that passed
/// through a macro but found nothing beyond it drops too — unless a
/// budget cut it, which the truncation flag marks.
pub fn prune_husk_nodes(nodes: &mut Vec<ViaNode>) {
    for node in nodes.iter_mut() {
        prune_husk_nodes(&mut node.deeper);
    }
    nodes.retain(|node| {
        !node.callers.is_empty() || !node.deeper.is_empty() || node.truncated || node.depth_cut
    });
}

/// Shared walk budgets, counted across one closure.
#[derive(Debug, Default)]
pub struct ViaBudget {
    pub classified: usize,
    pub named_hops: usize,
    /// Observability counters (no trip semantics): per-op volumes that
    /// size future batching work. Read by tests and the stats dump;
    /// only `classified` trips.
    pub dispatch_calls: usize,
    pub blob_opens: usize,
}

/// Query-scoped proof accounting: every proof path holds the snapshot,
/// which holds the budget, so no signature takes a budget parameter.
/// Classify one frontier in a single batched read: metadata for every name,
/// bodies bulk-fetched only for empty-return-type rows. Returns the macro
/// rows (manifest- or overlay-filtered) keyed by name, and whether the work
/// limit cut the frontier.
pub async fn classify_frontier(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    names: &[String],
) -> Result<(
    std::collections::HashMap<String, Vec<crate::types::FunctionInfo>>,
    bool,
)> {
    let mut macros: std::collections::HashMap<String, Vec<crate::types::FunctionInfo>> =
        std::collections::HashMap::new();
    if names.is_empty() {
        return Ok((macros, false));
    }
    let mut sorted: Vec<String> = names.to_vec();
    sorted.sort();
    sorted.dedup();
    let mut truncated = false;
    let mut todo: Vec<String> = Vec::new();
    for chunk in sorted.chunks(100) {
        if snapshot.exhausted() {
            truncated = true;
            break;
        }
        snapshot.charge_many(chunk.len());
        todo.extend(chunk.iter().cloned());
    }
    for chunk in todo.chunks(100) {
        let rows = db.macro_candidates(chunk).await?;
        // Fetched rows charge too: the name count above admits the chunks,
        // the row count pays for what they return.
        if snapshot.charge_many(rows.len()) {
            truncated = true;
            break;
        }
        for row in rows {
            if !row_in_snapshot(snapshot, &row.file_path, &row.git_file_hash, false) {
                continue;
            }
            if is_macro_row(&row) {
                macros.entry(row.name.clone()).or_default().push(row);
            }
        }
    }
    // Overlay rows join the committed ones: dirty macros classify too.
    for name in &sorted {
        for row in db.overlay_rows_named(name, &snapshot.git_sha) {
            if is_macro_row(&row) {
                macros.entry(row.name.clone()).or_default().push(row);
            }
        }
    }
    Ok((macros, truncated))
}

/// The definitions of M one build reaches: same program; arch definitions
/// shadow generic ones under a pinned arch; generic builds see arch-less
/// definitions only. Union within, never across: two arms in one file are
/// different configurations of one macro, while an arch file is another
/// build's macro that happens to share a spelling (the sparc-leaves rule).
fn defs_for_build(
    rows: &[crate::types::FunctionInfo],
    eff: crate::domain::Domain,
) -> Vec<&crate::types::FunctionInfo> {
    let same_program: Vec<&crate::types::FunctionInfo> = rows
        .iter()
        .filter(|row| crate::domain::domain_of(&row.file_path).program == eff.program)
        .collect();
    match eff.arch {
        Some(arch) => {
            let arch_rows: Vec<&crate::types::FunctionInfo> = same_program
                .iter()
                .filter(|row| crate::domain::domain_of(&row.file_path).arch == Some(arch))
                .copied()
                .collect();
            if !arch_rows.is_empty() {
                return arch_rows;
            }
            same_program
                .into_iter()
                .filter(|row| crate::domain::domain_of(&row.file_path).arch.is_none())
                .collect()
        }
        None => same_program
            .into_iter()
            .filter(|row| crate::domain::domain_of(&row.file_path).arch.is_none())
            .collect(),
    }
}

/// Whether macro row `m` calls `target` in its stored body edges: the
/// row's own invocation proof, independent of name matching. Shared by the
/// body layer and the reverse nesting below so the two cannot diverge.
fn row_calls_target(m: &crate::types::FunctionInfo, target: &str) -> bool {
    m.calls.as_deref().unwrap_or_default().iter().any(|edge| {
        let callee = edge.callee();
        callee == target || crate::types::split_callee_edge(callee).0 == target
    })
}

/// Admit macro definition `m` for a caller in `caller_file`: `m` must be
/// among the definitions the caller's build reaches. The guard follows
/// the evidence — an unasserted configuration never rejects, which is why
/// this does not go through the choosing resolver (it returns no choice
/// between unasserted arms at all).
fn admit_definition(
    m: &crate::types::FunctionInfo,
    all_rows: &[crate::types::FunctionInfo],
    caller_file: &str,
    walk_context: crate::domain::Context,
) -> bool {
    let eff = match walk_context {
        crate::domain::Context::Any => crate::domain::domain_of(caller_file),
        crate::domain::Context::In(domain) => domain,
    };
    defs_for_build(all_rows, eff)
        .iter()
        .any(|row| row.file_path == m.file_path && row.line_start == m.line_start)
}

/// One reverse body layer: the macros whose body calls `target`, each with
/// the macro's OWN admitted callers. Callers come from the indexed reverse
/// lookup plus the overlay, resolved once per (macro, domain); admission
/// (domain) applies before anything renders. Classification is one batched
/// read per frontier.
pub async fn reverse_body_layer(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    target: &str,
    walk_context: crate::domain::Context,
) -> Result<Vec<ViaNode>> {
    let mut pairs: Vec<(String, String)> = db
        .get_function_callers_with_manifest(target, &snapshot.manifest)
        .await?;
    for row in db.overlay_callers_of(target, &snapshot.git_sha) {
        pairs.push((row.name.clone(), row.file_path.clone()));
    }
    pairs.sort();
    pairs.dedup();
    if pairs.is_empty() {
        return Ok(Vec::new());
    }
    let names: Vec<String> = pairs.iter().map(|(name, _)| name.clone()).collect();
    let (macros, truncated) = classify_frontier(db, snapshot, &names).await?;
    let mut nodes: Vec<ViaNode> = Vec::new();
    'outer: for (macro_name, rows) in &macros {
        // One node per file: same-file arms merge with unioned guards
        // (different configurations of one macro); different files stay
        // separate builds (another arch's macro sharing a spelling).
        let mut files: Vec<String> = rows.iter().map(|row| row.file_path.clone()).collect();
        files.sort();
        files.dedup();
        for file in files {
            let frows: Vec<&crate::types::FunctionInfo> =
                rows.iter().filter(|row| row.file_path == *file).collect();
            // At least one definition in this file must call the target
            // itself: callers of a same-name definition from another
            // build (the x86 `BUG` beside the asm-generic one) stay out.
            let mut calling: Vec<&crate::types::FunctionInfo> = frows
                .into_iter()
                .filter(|m| row_calls_target(m, target))
                .collect();
            if calling.is_empty() {
                continue;
            }
            calling.sort_by_key(|m| m.line_start);
            // The macro's own callers — not the target's — admitted for
            // any calling definition in this file. The guard follows
            // the evidence: an unasserted configuration never rejects.
            let mut own: Vec<(String, String)> = db
                .get_function_callers_with_manifest(macro_name, &snapshot.manifest)
                .await?;
            for row in db.overlay_callers_of(macro_name, &snapshot.git_sha) {
                own.push((row.name.clone(), row.file_path.clone()));
            }
            own.sort();
            own.dedup();
            let mut callers: Vec<(String, String)> = Vec::new();
            for (caller, caller_file) in &own {
                // Each caller costs two proofs below; a trip drops the
                // rest of this macro's callers, and reverse_closure
                // marks through the shared budget below.
                if snapshot.charge_work() {
                    break 'outer;
                }
                // A caller whose own file defines the name binds that
                // definition, never this file's: it belongs under its own
                // file's node, if any.
                if caller_file.as_str() != file
                    && file_defines_macro(db, snapshot, caller_file, macro_name).await?
                {
                    continue;
                }
                let admitted = calling
                    .iter()
                    .any(|m| admit_definition(m, rows, caller_file, walk_context));
                if !admitted {
                    continue;
                }
                // The caller's call must expand where it stands: a macro
                // that drops the slot (`DN(NM())` with `DN(x) 0`) never
                // runs its argument, however live the scope.
                if named_edge_expands(db, snapshot, walk_context, caller_file, caller, macro_name)
                    .await?
                {
                    callers.push((caller.clone(), caller_file.clone()));
                }
            }
            if callers.is_empty() {
                continue;
            }
            callers.sort();
            callers.dedup();
            let mut guards: Vec<String> = calling
                .iter()
                .filter_map(|m| m.guard.clone())
                .filter(|guard| !guard.is_empty())
                .collect();
            guards.sort();
            guards.dedup();
            let first = calling[0];
            nodes.push(ViaNode {
                hop: ViaHop {
                    macro_name: macro_name.clone(),
                    file_path: first.file_path.clone(),
                    line: first.line_start,
                    guard: if guards.is_empty() {
                        None
                    } else {
                        Some(guards.join(" || "))
                    },
                },
                callers,
                deeper: Vec::new(),
                truncated,
                depth_cut: false,
            });
        }
    }
    nodes.sort_by(|a, b| {
        b.callers
            .len()
            .cmp(&a.callers.len())
            .then(a.hop.macro_name.cmp(&b.hop.macro_name))
    });
    Ok(nodes)
}

/// One displayed caller edge for the two-level displays: the caller, its
/// file, and the macro chain from the target outward (`via M`, `via M2
/// via M`).
#[derive(Debug, Clone)]
pub struct CallerEdge {
    pub name: String,
    pub file: String,
    pub via: Vec<String>,
    pub guard: Option<String>,
}

impl CallerEdge {
    pub fn via_suffix(&self) -> String {
        if self.via.is_empty() {
            return String::new();
        }
        let chain: Vec<String> = self.via.iter().map(|m| format!("via {m}")).collect();
        format!(" [{}]", chain.join(" "))
    }
}

/// Whether the file defines the macro itself: committed rows where the
/// file is clean, overlay rows where it is dirty. A caller in such a file
/// binds its own definition, never another file's same-named macro — no
/// line info needed.
async fn file_defines_macro(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    file: &str,
    name: &str,
) -> Result<bool> {
    if snapshot.dirty.contains(file) {
        return Ok(db
            .overlay_macros_in_file(file, &snapshot.git_sha)
            .iter()
            .any(|row| row.name == name && is_macro_row(row)));
    }
    Ok(macro_rows_for(db, snapshot, name)
        .await?
        .iter()
        .any(|row| row.file_path == file))
}

/// The admitted, live rows a body call resolves to at one scope point,
/// sorted and deduped for comparison. Ordinary and unknown callees resolve
/// to nothing everywhere.
async fn resolved_live_rows(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    pin: crate::domain::Context,
    file: &str,
    line: u32,
    callee: &str,
) -> Result<(Vec<crate::types::FunctionInfo>, bool)> {
    let was = snapshot.classified();
    let (rows, scope_name, cut) = alias_macro_rows(db, snapshot, pin, file, line, callee).await?;
    let mut out = Vec::new();
    if let Some(scope) = scope_at_site(db, snapshot, file, &scope_name, line).await? {
        for row in &rows {
            if admit_definition(row, &rows, file, pin)
                && scope.defines_at(&row.file_path, row.line_start)
            {
                out.push(row.clone());
            }
        }
    }
    out.sort_by(|a, b| (&a.file_path, a.line_start).cmp(&(&b.file_path, b.line_start)));
    out.dedup_by(|a, b| a.file_path == b.file_path && a.line_start == b.line_start);
    // A cut in the scope lookup empties the same way: report it, or two
    // empties read as agreement below.
    Ok((out, cut || snapshot.tripped_since(was)))
}

fn row_key(row: &crate::types::FunctionInfo) -> (String, u32) {
    (row.file_path.clone(), row.line_start)
}

/// Whether the macro row's expansion transfers to the use site: every body
/// call must resolve to the same admitted, live rows where it is defined
/// and where it is used, recursed boundedly. A rebound between the two
/// (`WRAP` → 0) ends the edge even though the outer row is still live
/// at both ends; the site proof below ran in definition scope and
/// does not transfer. Identical resolutions keep the edge.
#[allow(clippy::too_many_arguments)]
async fn macro_expands_at_site(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    pin: crate::domain::Context,
    row: &crate::types::FunctionInfo,
    site_file: &str,
    site_line: u32,
    depth: u32,
    visited: &mut std::collections::HashSet<(String, u32)>,
) -> Result<bool> {
    // Budget spent: this leg claims nothing; aggregation points
    // mark the truncation.
    if snapshot.exhausted() {
        return Ok(false);
    }
    if depth == 0 {
        return Ok(true);
    }
    let key = (row.name.clone(), row.line_start);
    if !visited.insert(key.clone()) {
        return Ok(true);
    }
    let mut transfers = true;
    let calls = executing_calls(db, snapshot, row, pin).await?;
    if snapshot.exhausted() {
        // Partial inventory: the omitted nested calls may disprove
        // transfer, so the check below would agree on survivors only.
        // Budget spent: this leg claims nothing; aggregation points
        // mark the truncation.
        visited.remove(&key);
        return Ok(false);
    }
    for (_, callee, _) in calls {
        if callee == row.name {
            continue;
        }
        let (defined, defined_cut) =
            resolved_live_rows(db, snapshot, pin, &row.file_path, row.line_start, &callee).await?;
        let (used, used_cut) =
            resolved_live_rows(db, snapshot, pin, site_file, site_line, &callee).await?;
        // A trip on either side breaks the agreement: the child drops.
        if defined_cut || used_cut {
            transfers = false;
            break;
        }
        let defined_keys: Vec<(String, u32)> = defined.iter().map(row_key).collect();
        let used_keys: Vec<(String, u32)> = used.iter().map(row_key).collect();
        if defined_keys != used_keys {
            transfers = false;
            break;
        }
        if defined_keys.is_empty() {
            // No resolution on either side: an ordinary callee (no
            // macro rows anywhere) transfers vacuously, but a macro
            // callee that resolves nowhere proves nothing — cut, or
            // dead at both ends — so the child drops and the
            // aggregation points mark it.
            let has_rows = !macro_rows_for(db, snapshot, &callee).await?.is_empty();
            if has_rows {
                transfers = false;
                break;
            }
        }
        for nested in &defined {
            if !Box::pin(macro_expands_at_site(
                db,
                snapshot,
                pin,
                nested,
                site_file,
                site_line,
                depth - 1,
                visited,
            ))
            .await?
            {
                transfers = false;
                break;
            }
        }
        if !transfers {
            break;
        }
    }
    visited.remove(&key);
    Ok(transfers)
}

/// Whether a stored body-call child of a macro still expands: the child's
/// name resolves, at some live use site of the parent row, to an admitted
/// definition whose body makes calls. A rebound callee (`INV` redefined to
/// `0` at every site) ends the whole subtree there; a callee invoking at
/// any live site keeps it. No live sites means no evidence either way —
/// unknown keeps. One site is enough even where the branch arrives through
/// another: the tree does not carry per-branch sites, so mixed-resolution
/// wrappers can over-keep in the rebound branch (rare outside X-macro
/// rebinding; the reverse direction gates per site).
pub async fn stored_child_expands(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    pin: crate::domain::Context,
    parent: &crate::types::FunctionInfo,
    child_name: &str,
) -> Result<bool> {
    let sites = macro_use_sites(db, snapshot, parent).await?;
    if sites.is_empty() {
        // No sites is no evidence, so the child stands — unless the
        // budget is exhausted, when the emptiness is never trustworthy
        // (some collection loop broke). Budget spent: the child drops
        // instead, and aggregation points mark the truncation.
        return Ok(!snapshot.exhausted());
    }
    for (site_file, site_line) in &sites {
        let (rows, _, _cut) =
            alias_macro_rows(db, snapshot, pin, site_file, *site_line, child_name).await?;
        for row in &rows {
            if !admit_definition(row, &rows, site_file, pin) {
                continue;
            }
            let live = scope_at_site(db, snapshot, site_file, child_name, *site_line)
                .await?
                .is_some_and(|scope| scope.defines_at(&row.file_path, row.line_start));
            if !live {
                continue;
            }
            if !executing_calls(db, snapshot, row, pin).await?.is_empty() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Live invocation sites of one macro row: files and lines calling it,
/// committed or overlay, where this definition is live and the site itself
/// runs. No actuals — for gating stored body-call children at use sites.
pub async fn macro_use_sites(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    m: &crate::types::FunctionInfo,
) -> Result<Vec<(String, u32)>> {
    let mut seen = std::collections::HashSet::new();
    let mut sites = Vec::new();
    let push_site = |sites: &mut Vec<(String, u32)>,
                     seen: &mut std::collections::HashSet<(String, u32)>,
                     file: String,
                     line: u32| {
        if !seen.insert((file.clone(), line)) {
            return;
        }
        sites.push((file, line));
    };
    for site in db.argument_rows_for_callee(&m.name).await? {
        if !row_in_snapshot(snapshot, &site.file_path, &site.git_file_hash, false) {
            continue;
        }
        push_site(&mut sites, &mut seen, site.file_path.clone(), site.line);
    }
    // Argument rows miss nullary calls (`USEIT()` hands nothing), so the
    // caller inventory fills those in: dispatch sites where indexed, call
    // arities elsewhere. Both name the callee with a line.
    let mut pairs: Vec<(String, String)> = db
        .get_function_callers_with_manifest(&m.name, &snapshot.manifest)
        .await?;
    for row in db.overlay_callers_of(&m.name, &snapshot.git_sha) {
        pairs.push((row.name.clone(), row.file_path.clone()));
    }
    pairs.sort();
    pairs.dedup();
    for (caller, file) in &pairs {
        if snapshot.charge_work() {
            break;
        }
        snapshot.note_dispatch();
        for site in db.dispatch_sites_for_caller(caller).await? {
            // Each scanned row costs a snapshot check below: a cut
            // stops the scan, and the live pass runs on the prefix.
            if snapshot.charge_work() {
                break;
            }
            if site.caller_name != *caller || site.file_path != *file {
                continue;
            }
            if site.target.as_deref() != Some(m.name.as_str()) {
                continue;
            }
            if !row_in_snapshot(snapshot, &site.file_path, &site.git_file_hash, false) {
                continue;
            }
            push_site(&mut sites, &mut seen, site.file_path.clone(), site.line);
        }
        if let Ok(arities) = call_arities(db, snapshot, file) {
            for arity in &arities {
                if arity.callee == m.name && arity.enclosing == *caller {
                    push_site(&mut sites, &mut seen, file.clone(), arity.line);
                }
            }
        }
    }
    // One scope-and-liveness pass over every candidate: this definition
    // live at the site, and the site itself running.
    let mut live_sites = Vec::new();
    for (file, line) in sites {
        if snapshot.charge_work() {
            break;
        }
        let live = scope_at_site(db, snapshot, &file, &m.name, line)
            .await?
            .is_some_and(|scope| scope.defines_at(&m.file_path, m.line_start));
        if !live {
            continue;
        }
        if !site_is_live(db, snapshot, &file, line) {
            continue;
        }
        live_sites.push((file, line));
    }
    // No overlay walk: a macro called only from dirty text has no
    // committed sites, and no sites means unknown — the caller keeps
    // every child below.
    live_sites.sort();
    Ok(live_sites)
}

/// Whether a caller's textual call of a macro expands at its site: every
/// enclosing macro call must evaluate the slot the call sits in, proved at
/// the site through the shared hop proof (a redefinition between the
/// wrapper and the site can drop the slot, exactly like the handover
/// gate). Ordinary calls always expand their arguments; a direct call
/// expands where its function runs. Candidate lines come from dispatch
/// sites where they exist and the file's call inventory elsewhere (plain
/// edges record no dispatch sites). No candidate — or a body that will not
/// parse — is no evidence of death, so the caller stands.
/// Whether one macro call chain grounds its caller here: every enclosing
/// slot evaluates at the site, the call resolves to an admitted live macro
/// row, and that row's expansion transfers to the site. Shared by the
/// first-match recorded lines and the any-match macro-caller fallback.
#[allow(clippy::too_many_arguments)]
async fn named_chain_expands(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    pin: crate::domain::Context,
    site_file: &str,
    site_line: u32,
    macro_name: &str,
    chain: &[EnclosingHop],
) -> Result<bool> {
    // Budget spent: this leg claims nothing; aggregation points
    // mark the truncation.
    if snapshot.exhausted() {
        return Ok(false);
    }
    let mut visited = std::collections::HashSet::new();
    for (outer, slot, actuals) in chain {
        if outer.is_empty() {
            // Ordinary functions evaluate every argument they receive.
            continue;
        }
        let (rows, scope_name, _cut) =
            alias_macro_rows(db, snapshot, pin, site_file, site_line, outer).await?;
        if rows.is_empty() {
            continue;
        }
        let mut flows = false;
        for row in &rows {
            if !admit_definition(row, &rows, site_file, pin) {
                continue;
            }
            let live = scope_at_site(db, snapshot, site_file, &scope_name, site_line)
                .await?
                .is_some_and(|scope| scope.defines_at(&row.file_path, row.line_start));
            if !live {
                continue;
            }
            if macro_slot_flows_at_site(
                db,
                snapshot,
                pin,
                actuals,
                *slot,
                row,
                outer,
                &SubstMap::new(),
                site_file,
                site_line,
                // No handover index here: the stored-edge fallback must
                // not match a fabricated one.
                u32::MAX,
                None,
                &mut visited,
            )
            .await?
            {
                flows = true;
                break;
            }
        }
        if !flows {
            return Ok(false);
        }
    }
    // The call must also resolve to a live macro definition here, not an
    // ordinary function that replaced it: after `#undef M`, `M()` is an
    // ordinary call however macro-like it reads. The scope's definers must
    // include an admitted macro row; a name the scope does not define
    // drops the caller.
    let rows = macro_rows_for(db, snapshot, macro_name).await?;
    let mut resolved: Vec<crate::types::FunctionInfo> = Vec::new();
    if let Some(scope) = scope_at_site(db, snapshot, site_file, macro_name, site_line).await? {
        for row in &rows {
            if is_macro_row(row)
                && admit_definition(row, &rows, site_file, pin)
                && scope.defines_at(&row.file_path, row.line_start)
            {
                resolved.push(row.clone());
            }
        }
    }
    // The definition must also expand here: nested macro calls resolve at
    // the use site, so a rebound wrapper ends the edge even though the
    // outer row is still live.
    for row in &resolved {
        let mut exp_visited = std::collections::HashSet::new();
        if Box::pin(macro_expands_at_site(
            db,
            snapshot,
            pin,
            row,
            site_file,
            site_line,
            8,
            &mut exp_visited,
        ))
        .await?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub async fn named_edge_expands(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    pin: crate::domain::Context,
    site_file: &str,
    caller_fn: &str,
    macro_name: &str,
) -> Result<bool> {
    let mut lines: Vec<u32> = Vec::new();
    snapshot.note_dispatch();
    // One charge for the dispatch read above: a trip before any proof
    // claims nothing.
    if snapshot.charge_work() {
        return Ok(false);
    }
    for site in db.dispatch_sites_for_caller(caller_fn).await? {
        if site.caller_name != caller_fn || site.file_path != site_file {
            continue;
        }
        if site.target.as_deref() != Some(macro_name) {
            continue;
        }
        if !row_in_snapshot(snapshot, &site.file_path, &site.git_file_hash, false) {
            continue;
        }
        lines.push(site.line);
    }
    if let Ok(arities) = call_arities(db, snapshot, site_file) {
        for arity in &arities {
            if arity.callee == macro_name && arity.enclosing == caller_fn {
                lines.push(arity.line);
            }
        }
    }
    lines.sort();
    lines.dedup();
    // Lines the macro-caller fallback adds below (never parsed-C lines):
    // only those get any-call semantics, so recorded lines keep their
    // longstanding first-match proof.
    let mut fallback_lines = std::collections::HashSet::new();
    if lines.is_empty() {
        // Calls by name inside a macro body never reach the parsed-C
        // indexes: where the caller is itself a macro, ground the proof
        // on every physical line the definition covers — the call may sit
        // on a continuation line — and let the enclosing-body walk lend
        // the cut text. Function callers with no recorded call keep the
        // early-out — unknown keeps.
        for row in macro_rows_for(db, snapshot, caller_fn).await? {
            if row.file_path == site_file {
                let (start, end) = macro_extent(&row);
                fallback_lines.extend(start..=end);
            }
        }
        lines.extend(fallback_lines.iter().copied());
        lines.sort();
        lines.dedup();
        if lines.is_empty() {
            return Ok(true);
        }
    }
    for site_line in lines {
        // Each line's proofs (body walk, slot chains) cost real work:
        // a spent budget ends the lines left.
        if snapshot.charge_work() {
            return Ok(false);
        }
        if !site_is_live(db, snapshot, site_file, site_line) {
            continue;
        }
        let bodies = enclosing_body_for(db, snapshot, site_file, site_line, caller_fn).await?;
        for (body, body_start) in bodies {
            if fallback_lines.contains(&site_line) {
                // Macro-caller fallback: several calls may share the
                // definition, so every match grounds the proof and any
                // proving call keeps the caller.
                for chain in enclosing_chains(&body, body_start, site_line, macro_name) {
                    if named_chain_expands(
                        db, snapshot, pin, site_file, site_line, macro_name, &chain,
                    )
                    .await?
                    {
                        return Ok(true);
                    }
                }
            } else if let Some(chain) =
                enclosing_calls(&body, body_start, site_line, macro_name, None, None)
            {
                // Recorded lines keep their longstanding first-match proof:
                // twins share the line, and an unprovable twin keeps the
                // caller.
                if named_chain_expands(db, snapshot, pin, site_file, site_line, macro_name, &chain)
                    .await?
                {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Whether a caller's textual call of a macro is live: any dispatch site
/// naming the macro in the caller's file sits inside the macro's scope.
/// No sites means no evidence either way — the sound direction keeps the
/// caller. Sites that all fall outside a live scope drop it.
async fn caller_call_live(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    caller_name: &str,
    caller_file: &str,
    macro_name: &str,
) -> Result<bool> {
    let mut sites = 0u32;
    snapshot.note_dispatch();
    for site in db.dispatch_sites_for_caller(caller_name).await? {
        // Budget spent: the caller drops, and aggregation points mark
        // the truncation.
        if snapshot.charge_work() {
            return Ok(false);
        }
        if site.caller_name != caller_name {
            continue;
        }
        // Dispatch targets name the callee; macro body calls land here too.
        let names_macro = site.target.as_deref() == Some(macro_name);
        if !names_macro {
            continue;
        }
        if site.file_path != caller_file {
            continue;
        }
        if !row_in_snapshot(snapshot, &site.file_path, &site.git_file_hash, false) {
            continue;
        }
        sites += 1;
        let live = scope_at_site(db, snapshot, &site.file_path, macro_name, site.line)
            .await?
            .is_some();
        if live {
            return Ok(true);
        }
    }
    // Callers express calls through the calls index rather than dispatch
    // sites for plain edges; no site is no evidence, not a negative. But
    // sites that all fall outside a live scope drop the caller: every
    // known call is dead.
    Ok(sites == 0)
}

/// Second-level edges under one level-1 macro caller: M's admitted callers,
/// each carrying the extended via chain. Admission (domain) and depth apply
/// before anything renders; scope drops only callers whose every site is
/// provably outside a live scope.
pub async fn second_level_edges(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    macro_name: &str,
    macro_file: &str,
    chain: &[String],
    walk_context: crate::domain::Context,
) -> Result<Vec<CallerEdge>> {
    let mut pairs: Vec<(String, String)> = db
        .get_function_callers_with_manifest(macro_name, &snapshot.manifest)
        .await?;
    for row in db.overlay_callers_of(macro_name, &snapshot.git_sha) {
        pairs.push((row.name.clone(), row.file_path.clone()));
    }
    pairs.sort();
    pairs.dedup();
    // Admit against the macro's definitions in this file: a caller lands
    // here only where its build reaches one of them. Same-file arms merge
    // (union); the guard follows the evidence.
    let rows = macro_rows_for(db, snapshot, macro_name).await?;
    let file_rows: Vec<&crate::types::FunctionInfo> = rows
        .iter()
        .filter(|row| row.file_path == macro_file)
        .collect();
    if file_rows.is_empty() {
        return Ok(Vec::new());
    }
    let mut edges: Vec<CallerEdge> = Vec::new();
    for (caller, file) in &pairs {
        // Each caller costs up to three proofs below; a trip drops the
        // rest, and the aggregation points mark it.
        if snapshot.charge_work() {
            break;
        }
        // A caller whose own file defines the name binds that definition,
        // never this file's.
        if file != macro_file && file_defines_macro(db, snapshot, file, macro_name).await? {
            continue;
        }
        let admitted = file_rows
            .iter()
            .any(|m| admit_definition(m, &rows, file, walk_context));
        if !admitted {
            continue;
        }
        if !caller_call_live(db, snapshot, caller, file, macro_name).await? {
            continue;
        }
        // The caller's call must expand where it stands, like the tree.
        if !named_edge_expands(db, snapshot, walk_context, file, caller, macro_name).await? {
            continue;
        }
        let mut via: Vec<String> = chain.to_vec();
        via.push(macro_name.to_string());
        edges.push(CallerEdge {
            name: caller.clone(),
            file: file.clone(),
            via,
            guard: None,
        });
    }
    edges.sort_by(|a, b| a.name.cmp(&b.name).then(a.file.cmp(&b.file)));
    edges.dedup_by(|a, b| a.name == b.name && a.file == b.file);
    Ok(edges)
}

/// A proved handover through a macro: `target` handed to C's parameter
/// position at a call site, and C invokes that parameter. Reverse leg.
#[derive(Debug, Clone)]
pub struct HandoverLeg {
    pub macro_name: String,
    pub macro_file: String,
    pub macro_line: u32,
    pub macro_guard: Option<String>,
    pub param: String,
    pub position: u32,
    pub site_file: String,
    pub site_line: u32,
    pub enclosing: String,
    /// Pass-through macros between the site and the invoking definition,
    /// outermost first: empty for a direct handover. The site handed its
    /// actual to `outer[0]`, which handed it on down to `macro_name`.
    pub outer: Vec<OuterHop>,
}

/// One pass-through hop of a nested reverse handover: the macro that
/// handed the value on, and the slot it used.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OuterHop {
    pub macro_name: String,
    pub macro_file: String,
    pub macro_line: u32,
    pub param: String,
    pub position: u32,
}

impl HandoverLeg {
    /// The site this leg proves reached: the call-site file and line with
    /// the site-facing macro and slot, not the innermost invoker. A nested
    /// leg proves its top site, so the reached/unreached split keys on
    /// this, never the bare pair: one proved slot's proof never covers
    /// an unproved slot — or another site — of the same macro.
    pub fn site_key(&self) -> (String, u32, String, u32) {
        match self.outer.first() {
            Some(first) => (
                self.site_file.clone(),
                self.site_line,
                first.macro_name.clone(),
                first.position,
            ),
            None => (
                self.site_file.clone(),
                self.site_line,
                self.macro_name.clone(),
                self.position,
            ),
        }
    }
}

/// One handover site: a call handing the target (or a value carrying it)
/// to a macro's parameter slot. Committed sites come from argument rows;
/// dirty sites are re-derived from overlay macro bodies, at the overlay
/// row's own line.
struct HandoverSite {
    callee: String,
    index: u32,
    file: String,
    line: u32,
    enclosing: String,
}

/// A forward handover leg: macro M invokes its parameter, and this call
/// site handed `actual` for it. `outer` holds the macro body the handover
/// passed through first: nested legs read `via OUT → INNER`, each with its
/// own definition site.
#[derive(Debug, Clone)]
pub struct ForwardLeg {
    pub macro_name: String,
    pub macro_file: String,
    pub macro_line: u32,
    pub macro_guard: Option<String>,
    pub param: String,
    pub position: u32,
    pub actual: String,
    pub site_file: String,
    pub site_line: u32,
    pub site_guard: String,
    pub outer: Option<(String, String, u32)>,
}

impl ForwardLeg {
    /// The evidence line: which definition handed what where, with both
    /// guards. Every field rides along so no hop is anonymous.
    /// The handover chain as bare text, without a `via` prefix: print
    /// sites add their own (`[via {chain}]`, `└─ ... via {chain}`).
    pub fn chain_text(&self) -> String {
        let inner = format!(
            "{} ({}:{}, handed argument {} ({}))",
            self.macro_name, self.macro_file, self.macro_line, self.position, self.param
        );
        let mut text = match &self.outer {
            Some((name, file, line)) => format!("{name} ({file}:{line}) → {inner}"),
            None => inner,
        };
        if let Some(guard) = self.macro_guard.as_deref() {
            if !guard.is_empty() {
                text.push_str(&format!(" [{guard}]"));
            }
        }
        text
    }
}

/// An actual resolved through nesting levels: the function handed for a
/// parameter, with the top-level site that handed it.
#[derive(Debug, Clone)]
pub struct ResolvedActual {
    pub actual: String,
    pub site_file: String,
    pub site_line: u32,
    pub site_guard: String,
    /// The site's absolute argument slot: bundle-offset threading needs
    /// the trailing index, which only the site level knows.
    pub site_index: u32,
    /// Where the value sits inside the site's pack, where the site hands a
    /// pack element: a spliced element lands by offset from its pack
    /// position, never at the splice's own slot. `None` is a named value.
    pub pack_pos: Option<u32>,
    /// The call handing the value at the site, and its enclosing function:
    /// the leg stands only where that call expands.
    pub site_callee: String,
    pub site_enclosing: String,
}

/// Parse `{param} (parameter {N})` evidence from a
/// `c:macro_parameter_call` edge.
fn parse_parameter_evidence(evidence: &str) -> Option<(String, u32)> {
    let (param, position) = evidence.rsplit_once("(parameter ")?;
    let position = position.strip_suffix(')')?.trim();
    Some((param.trim().to_string(), position.parse().ok()?))
}

/// Macro definition rows for one name at this snapshot: committed rows
/// matching the manifest plus overlay rows.
pub async fn macro_rows_for(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    name: &str,
) -> Result<Vec<crate::types::FunctionInfo>> {
    if let Some(cached) = snapshot.macro_rows.borrow().get(name) {
        return Ok(cached.clone());
    }
    let mut rows: Vec<crate::types::FunctionInfo> = Vec::new();
    // Boxed: the LanceDB planning subtree would otherwise live
    // inline in every ancestor future on the query thread's stack.
    for row in Box::pin(db.find_all_functions_git_aware(name, &snapshot.git_sha)).await? {
        if !row_in_snapshot(snapshot, &row.file_path, &row.git_file_hash, false) {
            continue;
        }
        if is_macro_row(&row) {
            rows.push(row);
        }
    }
    for row in db.overlay_rows_named(name, &snapshot.git_sha) {
        if is_macro_row(&row) {
            rows.push(row);
        }
    }
    snapshot
        .macro_rows
        .borrow_mut()
        .insert(name.to_string(), rows.clone());
    Ok(rows)
}

/// Whether a row is an object-like macro definition (`#define NAME
/// replacement` with no parameter list): function-like rows answer
/// elsewhere, ordinary functions never start their body with `#`.
fn is_object_row(row: &crate::types::FunctionInfo) -> bool {
    if is_macro_row(row) {
        return false;
    }
    let Some(first) = row.body.lines().find(|line| !line.trim().is_empty()) else {
        return false;
    };
    let trimmed = first.trim_start();
    let rest = trimmed.strip_prefix('#').unwrap_or(trimmed);
    let rest = rest.trim_start();
    if rest == "define" || rest.starts_with("define ") || rest.starts_with("define\t") {
        return true;
    }
    rest.strip_prefix("define")
        .is_some_and(|after| after.starts_with('('))
}

/// Function-like rows for a call callee, following object-like aliases:
/// `#define ALIAS DROP` expands where written, so a call through ALIAS
/// proves against DROP's rows, with each alias hop scope-checked at the
/// site like every other hop. Returns the rows with the name to scope
/// them under (the alias target where a hop was taken, else the name
/// itself). Empty rows where the name is ordinary, unknown, cyclically
/// aliased, or expands to anything but a bare macro name.
#[allow(clippy::too_many_arguments)]
async fn alias_macro_rows(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    pin: crate::domain::Context,
    site_file: &str,
    site_line: u32,
    name: &str,
) -> Result<(Vec<crate::types::FunctionInfo>, String, bool)> {
    let was = snapshot.classified();
    let mut seen = vec![name.to_string()];
    let mut current = name.to_string();
    // The boolean is a cut flag, not a third row state: a trip empties
    // resolutions, and empty must not pass as ordinary below. Callers
    // drop on a trip; genuine emptiness retains its longstanding
    // meaning.
    loop {
        // Each hop fires its own queries: a trip resolves nothing
        // further, and the empty rows read as not-a-macro below.
        if snapshot.charge_work() {
            return Ok((Vec::new(), current, true));
        }
        let rows = macro_rows_for(db, snapshot, &current).await?;
        if !rows.is_empty() {
            return Ok((rows, current, snapshot.tripped_since(was)));
        }
        if seen.len() > 8 {
            return Ok((Vec::new(), current, snapshot.tripped_since(was)));
        }
        // Object-like rows for this name, committed and overlay alike.
        // Boxed with the leaf above: the planning subtree would
        // otherwise live inline in the ancestor futures.
        let mut objects: Vec<crate::types::FunctionInfo> = Vec::new();
        if let Ok(candidates) =
            Box::pin(db.find_all_functions_git_aware(&current, &snapshot.git_sha)).await
        {
            objects.extend(candidates.into_iter().filter(|row| {
                row_in_snapshot(snapshot, &row.file_path, &row.git_file_hash, false)
                    && is_object_row(row)
            }));
        }
        objects.extend(
            db.overlay_rows_named(&current, &snapshot.git_sha)
                .into_iter()
                .filter(is_object_row),
        );
        let mut advanced = false;
        for row in &objects {
            let admitted = admit_definition(row, &objects, site_file, pin);
            let live = scope_at_site(db, snapshot, site_file, &current, site_line)
                .await?
                .is_some_and(|scope| scope.defines_at(&row.file_path, row.line_start));
            if !admitted {
                continue;
            }
            if !live {
                continue;
            }
            let Some(cut) = cut_macro_header(&row.body) else {
                continue;
            };
            let mut expansion = cut.trim();
            if expansion.starts_with('(') && expansion.ends_with(')') {
                // A parenthesized hop never expands a function-like
                // target (`(A)(x)` does not invoke macro `A`): strip to
                // the name only where no function-like rows hide behind
                // it, so the walk below cannot route a call to a macro
                // the parens block.
                let inner = expansion[1..expansion.len() - 1].trim();
                if macro_rows_for(db, snapshot, inner).await?.is_empty() {
                    expansion = inner;
                }
            }
            if expansion.is_empty()
                || !expansion.chars().all(|c| c == '_' || c.is_alphanumeric())
                || seen.iter().any(|seen| seen == expansion)
            {
                continue;
            }
            seen.push(current.clone());
            current = expansion.to_string();
            advanced = true;
            break;
        }
        // Sequential object redefinitions dedup away in the index (one row
        // per name per file): where the surviving row is dead at the site,
        // the rescan still holds every directive, so the live rebound
        // resolves through it. Same-file defines share the site's build,
        // so liveness alone admits them.
        if !advanced {
            if let Ok(scopes) = file_scopes(db, snapshot, site_file).await {
                if let Some(map) = scopes.map.as_ref() {
                    let scope = scope_at_site(db, snapshot, site_file, &current, site_line).await?;
                    for define in map
                        .defines
                        .iter()
                        .filter(|define| define.name == current && !define.has_params)
                    {
                        let live = scope
                            .as_ref()
                            .is_some_and(|scope| scope.defines_at(site_file, define.line));
                        if !live {
                            continue;
                        }
                        let Some(text) = define.expansion.as_deref() else {
                            continue;
                        };
                        let mut expansion = text.trim();
                        if expansion.starts_with('(') && expansion.ends_with(')') {
                            let inner = expansion[1..expansion.len() - 1].trim();
                            if macro_rows_for(db, snapshot, inner).await?.is_empty() {
                                expansion = inner;
                            }
                        }
                        if expansion.is_empty()
                            || !expansion.chars().all(|c| c == '_' || c.is_alphanumeric())
                            || seen.iter().any(|seen| seen == expansion)
                        {
                            continue;
                        }
                        seen.push(current.clone());
                        current = expansion.to_string();
                        advanced = true;
                        break;
                    }
                }
            }
        }
        if !advanced {
            return Ok((Vec::new(), current, snapshot.tripped_since(was)));
        }
    }
}

/// The raw directive span of one macro row: line_start plus body lines.
/// Bodies store the whole definition, so this is the `#define` through its
/// last continuation line.
fn macro_extent(row: &crate::types::FunctionInfo) -> (u32, u32) {
    (
        row.line_start,
        row.line_start + row.body.lines().count().max(1) as u32,
    )
}

/// Invoked parameters read straight from a macro body: a body call whose
/// callee is one of the macro's own parameters invokes it at that slot.
/// This is what proves invocation for overlay rows (the overlay stores no
/// unresolved edges) and where the committed row is shadowed by a dirty
/// Whether a macro body parses cleanly: the header cuts and the
/// replacement list holds no token pasting. Only a clean parse refutes a
/// stored invocation edge; anything else leaves the edge standing.
fn body_parse_ok(definition: &str) -> bool {
    let Some(body) = cut_macro_header(definition) else {
        return false;
    };
    if body.contains("##") {
        return false;
    }
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .is_err()
    {
        return false;
    }
    let wrapped = format!("void __macro_via_body(void) {{ {body}; }}");
    let Some(tree) = parser.parse(&wrapped, None) else {
        return false;
    };
    !tree.root_node().has_error()
}

/// Where the executability proof marks an invoked parameter for one
/// executing call: calling a parameter invokes it, and handing one as an
/// actual evaluates it — always for ordinary functions (C evaluates
/// arguments before the call), only for an invoked slot of a macro, only
/// once invoked for a parameter callee. The bundle marker flags the `...`
/// under the same rules, which is what keeps a dropped bundle silent: the
/// marker evaluates only where the inner macro invokes its slot.
/// Returns whether the invoked set grew.
/// What one macro definition does with its parameters: which it provably
/// calls (gates legs) and which it merely evaluates (ordinary-function
/// arguments, bare uses, dropped-then-read values — never legs on their
/// own). Called implies evaluated. Cached per definition per query: every
/// site and every hop in the query shares one proof per definition.
#[derive(Debug, Clone, Default)]
pub struct MacroSummary {
    pub called: Vec<(String, u32)>,
    pub evaluated: Vec<(String, u32)>,
    /// The parsed body both sets above were proved over: execution gates
    /// walk parents without re-parsing per site per hop.
    pub tree: Vec<BodyCall>,
    /// Which tree entries execute (body-level proof).
    pub executing: Vec<bool>,
}

async fn mark_executing_call(
    ctx: ProofCtx<'_>,
    m: &crate::types::FunctionInfo,
    call: &BodyCall,
    called: &mut std::collections::HashSet<String>,
    evaluated: &mut std::collections::HashSet<String>,
    proof_visited: &mut std::collections::HashSet<String>,
) -> Result<bool> {
    // Budget spent: this leg claims nothing; aggregation points
    // mark the truncation.
    if ctx.snapshot.exhausted() {
        return Ok(false);
    }
    let mut grown = false;
    // A parameter in callee position of a running call is invoked: the
    // call runs, so the value runs.
    if call.callee != m.name && m.parameters.iter().any(|p| p.name == call.callee) {
        grown |= called.insert(call.callee.clone());
        grown |= evaluated.insert(call.callee.clone());
    }
    let variadic = variadic_slot(m).is_some();
    for (index, actual) in call.actuals.iter().enumerate() {
        let Some(name) = actual.as_deref() else {
            continue;
        };
        let target = if m.parameters.iter().any(|p| p.name == name) {
            name.to_string()
        } else if variadic && name == BUNDLE_MARKER {
            "...".to_string()
        } else {
            continue;
        };
        // The actual evaluates where the slot evaluates; it is invoked
        // only where the callee invokes that slot. An ordinary function
        // never invokes (handing `cb` to `register_cb(cb)` evaluates it),
        // and a parameter callee names an unknown function, so only a
        // macro callee with a proved slot invokes.
        let evaluates = slot_evaluates(ctx, m, &call.callee, index, called, proof_visited).await?;
        if evaluates {
            grown |= evaluated.insert(target.clone());
        }
        // A pointer call evaluates its arguments and invokes none of them
        // by name; a parameter callee names an unknown function, so it
        // invokes nothing either; an ordinary function evaluates without
        // invoking. Only a macro callee with a proved slot invokes — and
        // a `...` pack invokes where it splices into one: some fixed slot
        // at or past its position the inner macro calls, or a repack into
        // the inner `...` that evaluates onward. The site level still does
        // the exact landing; this only opens the threading.
        let invokes = if target == "..." {
            bundle_invokes(ctx, m, &call.callee, index, proof_visited).await?
        } else if call.callee.is_empty()
            || m.parameters.iter().any(|p| p.name == call.callee)
            || macro_rows_for(ctx.db, ctx.snapshot, &call.callee)
                .await?
                .is_empty()
        {
            false
        } else {
            macro_slot_invoked(ctx, m, &call.callee, index, proof_visited).await?
        };
        if target == "..." {
            // A pack opens threading where it splices into an invoking
            // slot; elsewhere it rides only as far as it evaluates.
            if invokes {
                grown |= evaluated.insert(target.clone());
                grown |= called.insert(target);
            } else if evaluates {
                grown |= evaluated.insert(target);
            }
            continue;
        }
        if evaluates && invokes {
            grown |= evaluated.insert(target.clone());
            grown |= called.insert(target);
        }
    }
    Ok(grown)
}

/// Bare parameter uses — identifiers that are neither a call's callee nor
/// one of its actuals (`(x)`, `x + 1`): the call tree never records them,
/// but a running use evaluates the parameter all the same. Evaluating is
/// not invoking (`ID(x) (x)` never calls `x`), so bare uses feed only the
/// evaluated set. A use runs where every enclosing call runs (the fixpoint
/// already decided each one); unpushed enclosers are pointer calls, whose
/// arguments evaluate.
/// Short-circuit arms (`&&`, `?:`) read as executing: the safe direction
/// keeps the leg.
/// Parameter identifier uses in a parsed body: every `name` with its span,
/// plus the spans covered as some call's function or actual (the calls'
/// own business — invocation rules handle those, never the use scans).
type ParamUses = (
    std::collections::HashSet<(usize, usize)>,
    Vec<(String, (usize, usize))>,
);

fn collect_param_uses(
    root: tree_sitter::Node,
    bytes: &[u8],
    is_param: &impl Fn(&str) -> bool,
) -> ParamUses {
    fn walk(
        node: tree_sitter::Node,
        bytes: &[u8],
        covered: &mut std::collections::HashSet<(usize, usize)>,
        uses: &mut Vec<(String, (usize, usize))>,
        is_param: &impl Fn(&str) -> bool,
    ) {
        if node.kind() == "identifier" {
            if let Ok(text) = node.utf8_text(bytes) {
                if is_param(text) {
                    uses.push((text.to_string(), (node.start_byte(), node.end_byte())));
                }
            }
        }
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                covered.insert((function.start_byte(), function.end_byte()));
            }
            if let Some(arguments) = node.child_by_field_name("arguments") {
                let mut cursor = arguments.walk();
                for child in arguments.named_children(&mut cursor) {
                    covered.insert((child.start_byte(), child.end_byte()));
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            walk(child, bytes, covered, uses, is_param);
        }
    }
    let mut covered = std::collections::HashSet::new();
    let mut uses = Vec::new();
    walk(root, bytes, &mut covered, &mut uses, is_param);
    (covered, uses)
}

/// The identifier node at `span`: descend to the smallest node covering
/// it. `None` where the tree shifted under the scan (never on a fresh
/// parse of the same text).
fn find_use_node<'a>(
    root: tree_sitter::Node<'a>,
    span: (usize, usize),
) -> Option<tree_sitter::Node<'a>> {
    let mut stack = vec![root];
    while let Some(candidate) = stack.pop() {
        if candidate.start_byte() <= span.0 && span.1 <= candidate.end_byte() {
            if candidate.kind() == "identifier"
                && (candidate.start_byte(), candidate.end_byte()) == span
            {
                return Some(candidate);
            }
            let mut cursor = candidate.walk();
            for child in candidate.children(&mut cursor) {
                stack.push(child);
            }
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
async fn mark_bare_uses(
    ctx: ProofCtx<'_>,
    tree: &[BodyCall],
    executing: &[bool],
    m: &crate::types::FunctionInfo,
    source: &str,
    called: &std::collections::HashSet<String>,
    proof_visited: &mut std::collections::HashSet<String>,
    evaluated: &mut std::collections::HashSet<String>,
) -> Result<()> {
    let is_param = |name: &str| m.parameters.iter().any(|p| p.name == name);
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .is_err()
    {
        return Ok(());
    }
    let wrapped = format!("void __macro_via_body(void) {{ {source}; }}");
    let bytes = wrapped.as_bytes();
    let Some(parsed) = parser.parse(&wrapped, None) else {
        return Ok(());
    };
    if parsed.root_node().has_error() {
        return Ok(());
    }
    let index_of: std::collections::HashMap<(usize, usize), usize> = tree
        .iter()
        .enumerate()
        .map(|(index, call)| (call.span, index))
        .collect();
    let (covered, uses) = collect_param_uses(parsed.root_node(), bytes, &is_param);
    for (param, span) in uses {
        if covered.contains(&span) {
            continue;
        }
        let Some(node) = find_use_node(parsed.root_node(), span) else {
            continue;
        };
        // The use evaluates only where every enclosing call both runs and
        // evaluates the slot the use sits in: an enclosing macro that
        // drops the slot (`EVAL(x) DROP((x))`) never evaluates it, however
        // live the call itself looks. A use as a call's callee belongs to
        // the call tree, not to this scan.
        let mut child = node;
        let mut runs = true;
        while let Some(parent) = child.parent() {
            if parent.kind() != "call_expression" {
                child = parent;
                continue;
            }
            let is_function = parent
                .child_by_field_name("function")
                .is_some_and(|function| function.id() == child.id());
            if is_function {
                runs = false;
                break;
            }
            let Some(arguments) = parent.child_by_field_name("arguments") else {
                child = parent;
                continue;
            };
            let Some(arg) = call_actuals(arguments)
                .into_iter()
                .enumerate()
                .find(|(_, named)| named.start_byte() <= span.0 && span.1 <= named.end_byte())
                .map(|(index, _)| index)
            else {
                child = parent;
                continue;
            };
            let key = (parent.start_byte(), parent.end_byte());
            let Some(index) = index_of.get(&key) else {
                child = parent;
                continue;
            };
            if !executing.get(*index).copied().unwrap_or(false) {
                runs = false;
                break;
            }
            let callee = tree
                .get(*index)
                .map(|call| call.callee.as_str())
                .unwrap_or_default();
            if !slot_evaluates(ctx, m, callee, arg, called, proof_visited).await? {
                runs = false;
                break;
            }
            child = parent;
        }
        if runs {
            evaluated.insert(param);
        }
    }
    Ok(())
}
/// The database handles one executability proof needs: the snapshot to
/// resolve against and the pinned build for admission.
#[derive(Clone, Copy)]
struct ProofCtx<'a> {
    db: &'a DatabaseManager,
    snapshot: &'a ViaSnapshot,
    pin: crate::domain::Context,
}

/// The executability fixpoint for one macro body: which calls execute,
// which parameters that calls, and which it evaluates. A top-level call
// executes; a call nested in another call's arguments executes only when
// the outer call evaluates that slot — ordinary functions always do,
// macros only when the slot's value flows into an evaluating position,
// parameters only once called themselves. Monotone over finite call and
// parameter sets, so the loop terminates; cross-macro recursion carries a
// visited set, and a cycle proves nothing (silence, never an edge).
/// Cycle-poison marker for the shared proof set: any skip of an already-
/// visited row, or any re-entrant (still-active) summary, inserts this into
/// the shared `proof_visited` set. A summary computed while it is present
/// excluded something, so it must not be cached; a summary computed without
/// it saw the whole reachable subgraph and is complete under its key. The
/// marker outlives the exiting frame on purpose — whatever it poisoned
/// above stays uncached too — and top-level callers always start from a
/// fresh set, so it never leaks across queries. It cannot collide with a
/// macro name: NUL never appears in one.
const CYCLE_POISON: &str = "\0cycle-poison";

async fn proof_fixpoint(
    ctx: ProofCtx<'_>,
    m: &crate::types::FunctionInfo,
    proof_visited: &mut std::collections::HashSet<String>,
) -> Result<(
    Vec<bool>,
    std::collections::HashSet<String>,
    std::collections::HashSet<String>,
)> {
    let tree = body_call_tree(&m.body);
    let mut executing = vec![false; tree.len()];
    let mut called: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut evaluated: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Top-level calls execute; per-actual marking runs to closure below.
    for index in 0..tree.len() {
        if tree[index].parent.is_none() {
            executing[index] = true;
            mark_executing_call(
                ctx,
                m,
                &tree[index].clone(),
                &mut called,
                &mut evaluated,
                proof_visited,
            )
            .await?;
        }
    }
    loop {
        let mut changed = false;
        for index in 0..tree.len() {
            if executing[index] {
                continue;
            }
            let Some((parent, arg)) = tree[index].parent else {
                continue;
            };
            if parent >= tree.len() || !executing[parent] {
                continue;
            }
            if slot_evaluates(ctx, m, &tree[parent].callee, arg, &called, proof_visited).await? {
                executing[index] = true;
                changed |= mark_executing_call(
                    ctx,
                    m,
                    &tree[index].clone(),
                    &mut called,
                    &mut evaluated,
                    proof_visited,
                )
                .await?;
            }
        }
        if !changed {
            break;
        }
    }
    // Bare uses (`(x)`, `x + 1`) never enter the call tree: with the final
    // executability decided, any use where every enclosing call runs and
    // evaluates its slot evaluates the parameter.
    if let Some(body) = cut_macro_header(&m.body) {
        mark_bare_uses(
            ctx,
            &tree,
            &executing,
            m,
            &scrub_va_elision(body),
            &called,
            proof_visited,
            &mut evaluated,
        )
        .await?;
    }
    Ok((executing, called, evaluated))
}

/// Whether the outer call `callee` evaluates its argument `arg` (the
/// value is computed, not necessarily invoked): ordinary functions always
/// do; a parameter does only once called; a macro does only when the
/// value flows into an evaluating position of an admitted, live
/// definition. Threading execution through a body uses this; claiming an
/// invocation uses `macro_slot_invoked`.
async fn slot_evaluates(
    ctx: ProofCtx<'_>,
    m: &crate::types::FunctionInfo,
    callee: &str,
    arg: usize,
    called: &std::collections::HashSet<String>,
    proof_visited: &mut std::collections::HashSet<String>,
) -> Result<bool> {
    // Budget spent: this leg claims nothing; aggregation points
    // mark the truncation.
    if ctx.snapshot.exhausted() {
        return Ok(false);
    }
    if m.parameters.iter().any(|p| p.name == callee) {
        return Ok(called.contains(callee));
    }
    let (rows, scope_name, cut) = alias_macro_rows(
        ctx.db,
        ctx.snapshot,
        ctx.pin,
        &m.file_path,
        m.line_start,
        callee,
    )
    .await?;
    if rows.is_empty() {
        // An ordinary function (or an unknown name): C evaluates every
        // argument before the call. A pointer call (`callee == ""`) lands
        // here too: its arguments evaluate when it runs. But where a
        // trip produced the emptiness, the slot drops.
        if cut {
            return Ok(false);
        }
        return Ok(true);
    }
    for row in &rows {
        if !admit_definition(row, &rows, &m.file_path, ctx.pin) {
            continue;
        }
        let live = scope_at_site(
            ctx.db,
            ctx.snapshot,
            &m.file_path,
            &scope_name,
            m.line_start,
        )
        .await?
        .is_some_and(|scope| scope.defines_at(&row.file_path, row.line_start));
        if !live {
            continue;
        }
        if !proof_visited.insert(row.name.clone()) {
            // A back-edge proves nothing here, and whatever summary this
            // feeds is partial: poison it against the cache.
            proof_visited.insert(CYCLE_POISON.to_string());
            continue;
        }
        let inner = Box::pin(evaluated_params_inner(
            ctx.db,
            ctx.snapshot,
            row,
            ctx.pin,
            proof_visited,
        ))
        .await?;
        proof_visited.remove(&row.name);
        if evaluated_covers(&inner, row, arg) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether the value handed to slot `arg` reaches an evaluating position
/// of `row`: an exact-slot evaluation, or the `...` bundle covering every
/// trailing index. (A bundle handed where fixed parameters start packs
/// again only through a `...` slot; splicing a pack into fixed slots is a
/// site-indexed question the body level cannot answer.)
fn evaluated_covers(inner: &[(String, u32)], row: &crate::types::FunctionInfo, arg: usize) -> bool {
    if inner.iter().any(|(_, position)| *position == arg as u32) {
        return true;
    }
    let Some(slot) = variadic_slot(row) else {
        return false;
    };
    arg >= slot && inner.iter().any(|(param, _)| param == "...")
}

/// Whether a `...` pack handed to slot `arg` of `callee` can be invoked
/// downstream: an admitted, live definition calls some fixed slot at or
/// past the splice, or repacks into its own evaluating `...`. Ordinary
/// functions and unknown callees evaluate packs without invoking them.
async fn bundle_invokes(
    ctx: ProofCtx<'_>,
    m: &crate::types::FunctionInfo,
    callee: &str,
    arg: usize,
    proof_visited: &mut std::collections::HashSet<String>,
) -> Result<bool> {
    // Budget spent: this leg claims nothing; aggregation points
    // mark the truncation.
    if ctx.snapshot.exhausted() {
        return Ok(false);
    }
    if callee.is_empty() || m.parameters.iter().any(|p| p.name == callee) {
        return Ok(false);
    }
    let (rows, scope_name, _cut) = alias_macro_rows(
        ctx.db,
        ctx.snapshot,
        ctx.pin,
        &m.file_path,
        m.line_start,
        callee,
    )
    .await?;
    if rows.is_empty() {
        return Ok(false);
    }
    for row in &rows {
        if !admit_definition(row, &rows, &m.file_path, ctx.pin) {
            continue;
        }
        let live = scope_at_site(
            ctx.db,
            ctx.snapshot,
            &m.file_path,
            &scope_name,
            m.line_start,
        )
        .await?
        .is_some_and(|scope| scope.defines_at(&row.file_path, row.line_start));
        if !live {
            continue;
        }
        if !proof_visited.insert(row.name.clone()) {
            // A back-edge proves nothing here, and whatever summary this
            // feeds is partial: poison it against the cache.
            proof_visited.insert(CYCLE_POISON.to_string());
            continue;
        }
        let inner_called = Box::pin(invoked_params_inner(
            ctx.db,
            ctx.snapshot,
            row,
            ctx.pin,
            proof_visited,
        ))
        .await?;
        let inner_evaluated = Box::pin(evaluated_params_inner(
            ctx.db,
            ctx.snapshot,
            row,
            ctx.pin,
            proof_visited,
        ))
        .await?;
        proof_visited.remove(&row.name);
        if inner_called
            .iter()
            .any(|(_, position)| *position as usize >= arg)
        {
            return Ok(true);
        }
        if variadic_slot(row).is_some() && inner_evaluated.iter().any(|(param, _)| param == "...") {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether macro `callee` invokes its argument `arg`: an admitted, live
/// definition provably calls that slot. Ordinary functions never do
/// (evaluation is not invocation), and neither do parameter callees (their
/// target is unknown at the body level).
async fn macro_slot_invoked(
    ctx: ProofCtx<'_>,
    m: &crate::types::FunctionInfo,
    callee: &str,
    arg: usize,
    proof_visited: &mut std::collections::HashSet<String>,
) -> Result<bool> {
    // Budget spent: this leg claims nothing; aggregation points
    // mark the truncation.
    if ctx.snapshot.exhausted() {
        return Ok(false);
    }
    let (rows, scope_name, _cut) = alias_macro_rows(
        ctx.db,
        ctx.snapshot,
        ctx.pin,
        &m.file_path,
        m.line_start,
        callee,
    )
    .await?;
    for row in &rows {
        if !admit_definition(row, &rows, &m.file_path, ctx.pin) {
            continue;
        }
        let live = scope_at_site(
            ctx.db,
            ctx.snapshot,
            &m.file_path,
            &scope_name,
            m.line_start,
        )
        .await?
        .is_some_and(|scope| scope.defines_at(&row.file_path, row.line_start));
        if !live {
            continue;
        }
        if !proof_visited.insert(row.name.clone()) {
            // A back-edge proves nothing here, and whatever summary this
            // feeds is partial: poison it against the cache.
            proof_visited.insert(CYCLE_POISON.to_string());
            continue;
        }
        let inner = Box::pin(invoked_params_inner(
            ctx.db,
            ctx.snapshot,
            row,
            ctx.pin,
            proof_visited,
        ))
        .await?;
        proof_visited.remove(&row.name);
        if inner.iter().any(|(_, position)| *position == arg as u32) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The body calls that execute, with their tree index and actuals: the
/// threading and site-deriving loops walk this, never the flat parse. A
/// call that sits in a discarded macro slot never expands, so it hands
/// nothing on.
pub async fn executing_calls(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    m: &crate::types::FunctionInfo,
    pin: crate::domain::Context,
) -> Result<Vec<(usize, String, Vec<Option<String>>)>> {
    let mut proof_visited = std::collections::HashSet::new();
    let summary = summarize_macro(db, snapshot, m, pin, &mut proof_visited).await?;
    let mut out: Vec<(usize, String, Vec<Option<String>>)> = Vec::new();
    for (index, call) in summary.tree.iter().enumerate() {
        if summary.executing.get(index).copied().unwrap_or(false) {
            out.push((index, call.callee.clone(), call.actuals.clone()));
        }
    }
    Ok(out)
}

/// The bound actual per `m` call spanning `site_line`: the actual at
/// `param_idx` where it is a bare identifier, `None` where the slot
/// holds anything else. Shared by the raw file scan and the lent
/// macro-body scans in the site binding proof.
fn collect_spanning_bounds(
    root: tree_sitter::Node,
    bytes: &[u8],
    m_name: &str,
    param_idx: usize,
    site_line: u32,
    out: &mut Vec<Option<String>>,
) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression" {
            let name = node
                .child_by_field_name("function")
                .filter(|function| function.kind() == "identifier")
                .and_then(|function| function.utf8_text(bytes).ok());
            if name == Some(m_name)
                && (node.start_position().row as u32) < site_line
                && site_line <= node.end_position().row as u32 + 1
            {
                let actuals: Vec<Option<String>> = node
                    .child_by_field_name("arguments")
                    .map(|arguments| {
                        call_actuals(arguments)
                            .into_iter()
                            .map(|child| {
                                (child.kind() == "identifier")
                                    .then(|| child.utf8_text(bytes).ok().map(str::to_string))
                                    .flatten()
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                out.push(
                    actuals
                        .get(param_idx)
                        .and_then(|a| a.as_deref())
                        .map(str::to_string),
                );
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
}

/// Whether the parameter-called ancestor expands at the site: what the
/// site's call binds the parameter to must evaluate the slot the inner
/// call sits in. Every spanning call must bind the same actual, or the
/// site proves nothing — except where each distinct bound is an ordinary
/// function (a concrete non-parameter name with no macro rows): a
/// function call evaluates every argument, so either twin discharges the
/// same evaluation. A lone parameter binding stays unknown and keeps the
/// call, as does no site call found at all — a nested site's
/// substitutions live outside this proof.
#[allow(clippy::too_many_arguments)]
async fn site_binding_evaluates(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    pin: crate::domain::Context,
    m: &crate::types::FunctionInfo,
    param: &str,
    inner_actuals: &[Option<String>],
    inner_slot: usize,
    site_file: &str,
    site_line: u32,
    site_index: u32,
    pack_width: Option<u32>,
    subst: &SubstMap,
    visited: &mut std::collections::HashSet<(String, String)>,
) -> Result<bool> {
    let Some(param_idx) = m.parameters.iter().position(|p| p.name == param) else {
        return Ok(true);
    };
    let text = if snapshot.dirty.contains(site_file) {
        std::path::Path::new(db.repo_path())
            .join(site_file)
            .to_str()
            .and_then(|path| std::fs::read_to_string(path).ok())
    } else {
        snapshot.note_blob();
        blob_text_at(db.repo_path(), &snapshot.git_sha, site_file, &snapshot.repo)?
    };
    let Some(text) = text else {
        return Ok(true);
    };
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .is_err()
    {
        return Ok(true);
    }
    let Some(tree) = parser.parse(&text, None) else {
        return Ok(true);
    };
    let bytes = text.as_bytes();
    // Twin calls share the line: every spanning `m` call must bind the
    // same actual, or the site proves nothing — a sibling evaluating a
    // different callback must not discharge this site's proof. Raw file
    // text first, then every macro body covering the site line: a site
    // written inside a `#define` never parses as C where it stands.
    let mut bounds: Vec<Option<String>> = Vec::new();
    collect_spanning_bounds(
        tree.root_node(),
        bytes,
        &m.name,
        param_idx,
        site_line,
        &mut bounds,
    );
    if let Ok(scopes) = file_scopes(db, snapshot, site_file).await {
        if let Some(map) = scopes.map.as_ref() {
            for define in &map.defines {
                if define.line > site_line || site_line > define.end {
                    continue;
                }
                let Some(expansion) = define.expansion.as_deref() else {
                    continue;
                };
                let wrapped = format!(
                    "void __macro_via_lent(void) {{ {}; }}",
                    scrub_gnu_elision(expansion)
                );
                let mut lent = tree_sitter::Parser::new();
                if lent.set_language(&tree_sitter_c::LANGUAGE.into()).is_err() {
                    continue;
                }
                let Some(parsed) = lent.parse(&wrapped, None) else {
                    continue;
                };
                if parsed.root_node().has_error() {
                    continue;
                }
                // Body-relative rows sit on the site line: the wrapper
                // puts the whole expansion on physical row 0, which the
                // 1-based check reads as line 1.
                collect_spanning_bounds(
                    parsed.root_node(),
                    wrapped.as_bytes(),
                    &m.name,
                    param_idx,
                    1,
                    &mut bounds,
                );
            }
        }
    }
    let mut bound_seen: Option<Option<String>> = None;
    let no_bounds = bounds.is_empty();
    let mut distinct: Vec<Option<String>> = Vec::new();
    for bound in bounds {
        if !distinct.contains(&bound) {
            distinct.push(bound.clone());
        }
        match &bound_seen {
            None => bound_seen = Some(bound),
            Some(first) if first == &bound => {}
            Some(_) => {
                // Sibling calls binding different actuals leave no single
                // proof — unless every twin binds an ordinary function:
                // a function call evaluates every argument it receives,
                // so discharging with either twin proves the same
                // evaluation. A macro twin may drop the slot (and a
                // parameter or complex actual is unknowable), so any of
                // those keeps the silence.
                let mut all_ordinary = true;
                for distinct_bound in &distinct {
                    let Some(name) = distinct_bound.as_deref() else {
                        all_ordinary = false;
                        break;
                    };
                    if m.parameters.iter().any(|p| p.name == name) {
                        all_ordinary = false;
                        break;
                    }
                    if !macro_rows_for(db, snapshot, name).await?.is_empty() {
                        all_ordinary = false;
                        break;
                    }
                }
                if all_ordinary {
                    return Ok(true);
                }
                return Ok(false);
            }
        }
    }
    if let Some(Some(bound)) = bound_seen {
        // A parameter threaded through stays unknown; an ordinary
        // binding evaluates everything.
        if m.parameters.iter().any(|p| p.name == bound) {
            return Ok(true);
        }
        let (rows, scope_name, cut) =
            alias_macro_rows(db, snapshot, pin, site_file, site_line, &bound).await?;
        if rows.is_empty() {
            // An ordinary binding evaluates everything — unless a cut
            // produced the emptiness, which proves no evaluation.
            if cut {
                return Ok(false);
            }
            return Ok(true);
        }
        for row in &rows {
            if !admit_definition(row, &rows, site_file, pin) {
                continue;
            }
            let live = scope_at_site(db, snapshot, site_file, &scope_name, site_line)
                .await?
                .is_some_and(|scope| scope.defines_at(&row.file_path, row.line_start));
            if !live {
                continue;
            }
            if macro_slot_flows_at_site(
                db,
                snapshot,
                pin,
                inner_actuals,
                inner_slot,
                row,
                &m.name,
                subst,
                site_file,
                site_line,
                site_index,
                pack_width,
                visited,
            )
            .await?
            {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    // No bound identifier (a complex actual), or no spanning call at all:
    // a nested site binds through the outer actuals instead: resolve the
    // parameter through the path map and re-prove for a concrete bound
    // (`w <- DROP` kills the slot; unresolvable keeps).
    if no_bounds {
        if let Some(bound) = resolve_subst(db, snapshot, subst, &m.name, param).await? {
            let (rows, scope_name, cut) =
                alias_macro_rows(db, snapshot, pin, site_file, site_line, &bound).await?;
            if rows.is_empty() {
                // As above: unresolvable keeps, a trip drops.
                if cut {
                    return Ok(false);
                }
                return Ok(true);
            }
            for row in &rows {
                if !admit_definition(row, &rows, site_file, pin) {
                    continue;
                }
                let live = scope_at_site(db, snapshot, site_file, &scope_name, site_line)
                    .await?
                    .is_some_and(|scope| scope.defines_at(&row.file_path, row.line_start));
                if !live {
                    continue;
                }
                if macro_slot_flows_at_site(
                    db,
                    snapshot,
                    pin,
                    inner_actuals,
                    inner_slot,
                    row,
                    &m.name,
                    subst,
                    site_file,
                    site_line,
                    site_index,
                    pack_width,
                    visited,
                )
                .await?
                {
                    return Ok(true);
                }
            }
            return Ok(false);
        }
    }
    Ok(true)
}

/// One proof path's parameter bindings: (macro, param) -> (binder, bound).
/// Built at each descent into a macro row from the caller's body actuals, so
/// a parameter callee (`w(cb())`) resolves through the outer binding
/// (`w <- DROP` above a nested site) instead of keeping unknown. A bound
/// naming the binder's own parameter resolves transitively; conflicting
/// bindings drop the key (ambiguity proves nothing, like the twin rule); a
/// missing key is unknown, never negative.
type SubstMap = std::collections::HashMap<(String, String), (String, String)>;

/// Extend the map descending caller -> row through actuals (positional,
/// fixed-arity prefix only: any bundle marker voids the alignment, and the
/// descent keeps the map it arrived with).
fn extend_subst(
    map: &SubstMap,
    caller: &str,
    actuals: &[Option<String>],
    row: &crate::types::FunctionInfo,
) -> SubstMap {
    let mut out = map.clone();
    if actuals
        .iter()
        .any(|actual| actual.as_deref() == Some(BUNDLE_MARKER))
    {
        return out;
    }
    // A pack on the row's side reshapes every slot past it: positional
    // mapping cannot land, so the descent keeps the map it arrived with.
    if row.parameters.iter().any(|p| p.name == "...") {
        return out;
    }
    for (index, param) in row.parameters.iter().enumerate() {
        let Some(Some(name)) = actuals.get(index) else {
            continue;
        };
        let key = (row.name.clone(), param.name.clone());
        let val = (caller.to_string(), name.clone());
        match out.get(&key) {
            Some(existing) if *existing != val => {
                out.remove(&key);
            }
            Some(_) => {}
            None => {
                out.insert(key, val);
            }
        }
    }
    out
}

/// Resolve (macro, param) through the map to a concrete name: follows
/// binder-parameter links, cycle-guarded. None where unknown, cyclic, or
/// landing on another parameter — only a provably concrete bound proves.
async fn resolve_subst(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    map: &SubstMap,
    macro_name: &str,
    param: &str,
) -> Result<Option<String>> {
    let mut seen = std::collections::HashSet::new();
    let (mut cur_macro, mut cur_param) = (macro_name.to_string(), param.to_string());
    loop {
        if !seen.insert((cur_macro.clone(), cur_param.clone())) {
            return Ok(None);
        }
        let Some((binder, name)) = map.get(&(cur_macro, cur_param)).cloned() else {
            return Ok(None);
        };
        let binder_rows = macro_rows_for(db, snapshot, &binder).await?;
        let is_param = binder_rows
            .iter()
            .any(|row| row.parameters.iter().any(|p| p.name == name));
        if !is_param {
            return Ok(Some(name));
        }
        cur_macro = binder;
        cur_param = name;
    }
}

/// Whether the actual at syntactic `slot` of a call with `actuals` to the
/// macro `row` evaluates at the site: each pack-relative landing re-proves
/// through the evaluation twin. The shared per-hop proof of the ancestor
/// gate and the named-edge expansion check.
#[allow(clippy::too_many_arguments)]
async fn macro_slot_flows_at_site(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    pin: crate::domain::Context,
    actuals: &[Option<String>],
    slot: usize,
    row: &crate::types::FunctionInfo,
    caller: &str,
    subst: &SubstMap,
    site_file: &str,
    site_line: u32,
    site_index: u32,
    pack_width: Option<u32>,
    visited: &mut std::collections::HashSet<(String, String)>,
) -> Result<bool> {
    for (landing, child_pack) in pack_landings(
        actuals,
        slot,
        false,
        PackState {
            pos: None,
            width: pack_width,
        },
        row,
    ) {
        let inner_param = match landing {
            Landing::Fixed(inner_slot) => {
                let Some(param) = row.parameters.get(inner_slot).map(|p| p.name.clone()) else {
                    continue;
                };
                param
            }
            Landing::Pack(_) => "...".to_string(),
        };
        let extended = extend_subst(subst, caller, actuals, row);
        if Box::pin(param_evaluated_at_site(
            db,
            snapshot,
            pin,
            row,
            &inner_param,
            &extended,
            site_file,
            site_line,
            site_index,
            child_pack,
            visited,
        ))
        .await?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether the body call at `tree_idx` executes at this site: every
/// ancestor slot between it and the top must evaluate here. Body-level
/// proof is not enough — an ancestor macro redefined to drop its slot
/// between the wrapper's definition and the call site never expands the
/// subtree, however live it looks where the wrapper is defined. Ordinary
/// and pointer ancestors evaluate their arguments; parameter ancestors
/// must be called at the site; macro ancestors need an admitted, live
/// definition at the site evaluating the slot; a self-call never expands.
#[allow(clippy::too_many_arguments)]
pub async fn call_executes_at_site(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    pin: crate::domain::Context,
    m: &crate::types::FunctionInfo,
    tree_idx: usize,
    site_file: &str,
    site_line: u32,
    site_index: u32,
    pack_width: Option<u32>,
    subst: &SubstMap,
    visited: &mut std::collections::HashSet<(String, String)>,
) -> Result<bool> {
    // Budget spent: this leg claims nothing; aggregation points
    // mark the truncation.
    if snapshot.exhausted() {
        return Ok(false);
    }
    let mut proof_visited = std::collections::HashSet::new();
    let summary = summarize_macro(db, snapshot, m, pin, &mut proof_visited).await?;
    let mut idx = tree_idx;
    loop {
        let Some((parent, slot)) = summary.tree.get(idx).and_then(|call| call.parent) else {
            return Ok(true);
        };
        let Some(ancestor) = summary.tree.get(parent) else {
            return Ok(false);
        };
        let callee = ancestor.callee.as_str();
        if callee == m.name {
            return Ok(false);
        } else if m.parameters.iter().any(|p| p.name == callee) {
            // The ancestor is this macro's own parameter: the call it
            // names expands only through what the site binds there. A
            // site binding to an ordinary function (or anything unknown)
            // evaluates every argument, so the call stands; a binding to
            // a macro must evaluate this slot at the site
            // (`CALLW(DROP, t)` never runs `t()`), proved through the
            // evaluation twin. No site call found (a nested site hands
            // through outer substitutions) keeps the call: the binding
            // chain (`w <- w2 <- DROP`) is knowable in principle — it is
            // recorded in the leg's outer hops — but threading it through
            // this proof is deferred work, so unknown keeps for now.
            if !site_binding_evaluates(
                db,
                snapshot,
                pin,
                m,
                callee,
                &ancestor.actuals,
                slot,
                site_file,
                site_line,
                site_index,
                pack_width,
                subst,
                visited,
            )
            .await?
            {
                return Ok(false);
            }
            // The entry guard in `param_invoked_inner` breaks the mutual
            // recursion: revisiting this pair is a cycle, and a cycle
            // proves nothing. The ancestor is this macro's own parameter,
            // so its pack is this macro's pack, unchanged.
            if !Box::pin(param_invoked_inner(
                db,
                snapshot,
                pin,
                m,
                callee,
                site_file,
                site_line,
                site_index,
                PackState {
                    pos: None,
                    width: pack_width,
                },
                subst,
                visited,
            ))
            .await?
            {
                return Ok(false);
            }
            idx = parent;
            continue;
        }
        let (rows, scope_name, cut) =
            alias_macro_rows(db, snapshot, pin, site_file, site_line, callee).await?;
        if callee.is_empty() || rows.is_empty() {
            // Ordinary functions and pointer calls evaluate every
            // argument they receive — unless a trip produced the
            // emptiness, which climbs past an unproven level.
            if !callee.is_empty() && cut {
                return Ok(false);
            }
            idx = parent;
            continue;
        }
        let mut flows = false;
        for row in &rows {
            if !admit_definition(row, &rows, site_file, pin) {
                continue;
            }
            let live = scope_at_site(db, snapshot, site_file, &scope_name, site_line)
                .await?
                .is_some_and(|scope| scope.defines_at(&row.file_path, row.line_start));
            if !live {
                continue;
            }
            // Site-scoped evaluation: the row's body-level summary resolves
            // nested macros where the row is defined, but a redefinition
            // at the site can drop the slot — so each landing re-proves at
            // the site.
            if macro_slot_flows_at_site(
                db,
                snapshot,
                pin,
                &ancestor.actuals,
                slot,
                row,
                &m.name,
                &SubstMap::new(),
                site_file,
                site_line,
                site_index,
                pack_width,
                visited,
            )
            .await?
            {
                flows = true;
                break;
            }
        }
        if !flows {
            return Ok(false);
        }
        idx = parent;
    }
}

/// One definition's executability summary, cached on the snapshot: which
/// parameter slots it calls and which it evaluates. The fixpoint runs once
/// per definition per query no matter how many sites hand into it.
/// One definition's executability summary; see `MacroSummary`.
pub async fn summarize_macro(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    m: &crate::types::FunctionInfo,
    pin: crate::domain::Context,
    proof_visited: &mut std::collections::HashSet<String>,
) -> Result<MacroSummary> {
    let key = (
        m.name.clone(),
        m.file_path.clone(),
        m.line_start,
        format!("{:?}", pin),
    );
    if let Some(cached) = snapshot.summaries.borrow().get(&key) {
        return Ok(cached.clone());
    }
    // Budget spent: this summary stays empty and uncached, so later
    // sites re-prove (fast, through the entry checks above) instead
    // of reusing a tripped proof.
    if snapshot.exhausted() {
        return Ok(MacroSummary::default());
    }
    let summarize_was = snapshot.classified();
    // A cycle proves nothing: a definition already under proof above
    // summarizes empty rather than recursing forever. The empty answer is
    // partial by construction, so it poisons the shared set against
    // caching anything built on it.
    if !snapshot.summary_active.borrow_mut().insert(key.clone()) {
        proof_visited.insert(CYCLE_POISON.to_string());
        return Ok(MacroSummary::default());
    }
    let (executing, called, evaluated) =
        proof_fixpoint(ProofCtx { db, snapshot, pin }, m, proof_visited).await?;
    snapshot.summary_active.borrow_mut().remove(&key);
    // The fixpoint proved this same tree, so the executability indexes
    // agree with it.
    let tree = body_call_tree(&m.body);
    let mut summary = MacroSummary::default();
    for (index, param) in m.parameters.iter().enumerate() {
        if called.contains(&param.name) {
            summary.called.push((param.name.clone(), index as u32));
        }
        if evaluated.contains(&param.name) {
            summary.evaluated.push((param.name.clone(), index as u32));
        }
    }
    // Called implies evaluated: a summary that calls slot i evaluates it.
    for entry in summary.called.clone() {
        if !summary.evaluated.contains(&entry) {
            summary.evaluated.push(entry);
        }
    }
    summary.called.sort();
    summary.called.dedup();
    summary.evaluated.sort();
    summary.evaluated.dedup();
    summary.tree = tree;
    summary.executing = executing;
    // Cache every complete proof, top-level or nested: without the
    // poison marker nothing was skipped and nothing re-entered, so the
    // answer is whole under its key no matter how deep the frame. A
    // poisoned computation may still be *right*, but caching it would
    // starve later full proofs, so it stays uncached.
    // A fixpoint that trips mid-run converges short: its partial answer
    // must not poison the cache for later sites, which re-prove instead.
    if !proof_visited.contains(CYCLE_POISON) && !snapshot.tripped_since(summarize_was) {
        snapshot.summaries.borrow_mut().insert(key, summary.clone());
    }
    Ok(summary)
}

/// Parameters this definition provably invokes, by name and slot: the
/// executability proof first. A stored edge a clean body parse refutes is
/// extraction's nesting blindness (`OUT(cb)` into `DROP(cb())` never
/// invokes `cb`), not evidence; an unparseable body refutes nothing.
async fn body_proved_params(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    m: &crate::types::FunctionInfo,
    pin: crate::domain::Context,
    proof_visited: &mut std::collections::HashSet<String>,
) -> Result<Vec<(String, u32)>> {
    Ok(summarize_macro(db, snapshot, m, pin, proof_visited)
        .await?
        .called)
}

/// Parameters this definition provably evaluates, by name and slot:
/// callers thread execution through these, but legs never rest on them.
async fn evaluated_params_inner(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    m: &crate::types::FunctionInfo,
    pin: crate::domain::Context,
    proof_visited: &mut std::collections::HashSet<String>,
) -> Result<Vec<(String, u32)>> {
    Ok(summarize_macro(db, snapshot, m, pin, proof_visited)
        .await?
        .evaluated)
}
/// Whether `name` is already expanding on this proof path: the first
/// components of the visited pairs are exactly the macros from the site
/// macro down to the current one. A call to one of them is an ordinary
/// call — C never re-expands a macro inside its own expansion (blue
/// paint), so the nested occurrence hands nothing on.
fn expanding_contains(visited: &std::collections::HashSet<(String, String)>, name: &str) -> bool {
    visited.iter().any(|(macro_name, _)| macro_name == name)
}

/// The actuals of a C call's `arguments` node: comments are named nodes in
/// tree-sitter-c, so a bare `named_children` count shifts every slot past
/// a comment (`RUN(/* lead */ ignored, live)` hands `live` at slot 1, not
/// 2). Every slot enumeration must go through here.
pub fn call_actuals<'a>(arguments: tree_sitter::Node<'a>) -> Vec<tree_sitter::Node<'a>> {
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment")
        .collect()
}

/// The proved parameter covering a handed site index: an exact slot match,
/// or the `...` bundle covering every trailing index. A trailing actual
/// rides the bundle or nothing at all.
fn proved_position(
    invoked: &[(String, u32)],
    m: &crate::types::FunctionInfo,
    site_index: u32,
) -> Option<(String, u32)> {
    if let Some(hit) = invoked
        .iter()
        .find(|(_, position)| *position == site_index)
        .cloned()
    {
        return Some(hit);
    }
    let slot = variadic_slot(m)? as u32;
    invoked
        .iter()
        .find(|(param, position)| param == "..." && *position == slot && site_index >= slot)
        .map(|_| ("...".to_string(), site_index))
}

/// The invoked-parameter positions of one macro definition row: unresolved
/// `c:macro_parameter_call` edges on this definition's own extent, unioned
/// with invocations the body executability proof confirms. Edges from
/// another definition of the same name do not prove this one invokes
/// anything; the body reading covers overlay rows (no stored edges) and
/// shadowed committed rows alike.
async fn invoked_params(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    m: &crate::types::FunctionInfo,
    pin: crate::domain::Context,
) -> Result<Vec<(String, u32)>> {
    // Budget spent: this leg claims nothing; aggregation points
    // mark the truncation.
    if snapshot.exhausted() {
        return Ok(Vec::new());
    }
    let mut proof_visited = std::collections::HashSet::new();
    invoked_params_inner(db, snapshot, m, pin, &mut proof_visited).await
}

/// Stored `c:macro_parameter_call` edges on one definition's own extent:
/// the fallback where the body does not parse (an unparseable body
/// refutes nothing). Edges from another definition of the same name prove
/// nothing about this one.
async fn stored_param_edges(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    m: &crate::types::FunctionInfo,
) -> Result<Vec<(String, u32)>> {
    let (start, end) = macro_extent(m);
    let mut db_params: Vec<(String, u32)> = Vec::new();
    for edge in db
        .find_unresolved_edges_git_aware(&m.name, &snapshot.git_sha)
        .await?
    {
        if edge.kind != "c:macro_parameter_call" {
            continue;
        }
        if edge.file_path != m.file_path || edge.git_file_hash != m.git_file_hash {
            continue;
        }
        if edge.line < start || edge.line >= end {
            continue;
        }
        if let Some((param, position)) = parse_parameter_evidence(&edge.evidence) {
            db_params.push((param, position));
        }
    }
    Ok(db_params)
}

async fn invoked_params_inner(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    m: &crate::types::FunctionInfo,
    pin: crate::domain::Context,
    proof_visited: &mut std::collections::HashSet<String>,
) -> Result<Vec<(String, u32)>> {
    let mut params = body_proved_params(db, snapshot, m, pin, proof_visited).await?;
    if m.body.contains("##") {
        // Pasted: the body is unknowable, so stored edges from it are
        // guesses, not evidence. Silence, never an edge. (The
        // `##__VA_ARGS__` elision is proof-covered through the bundle
        // marker, so it needs no stored edges.)
    } else if !body_parse_ok(&m.body) {
        // No clean parse, no refutation: the stored edges stand alone.
        // The query runs only here — a parsed body never needs it.
        params.extend(stored_param_edges(db, snapshot, m).await?);
    }
    // Else the body proof stands alone: a stored edge it does not confirm
    // is extraction's nesting blindness, not evidence.
    params.sort();
    params.dedup();
    Ok(params)
}

/// One enclosing call: the callee name, the argument slot the site sits
/// at, and the call's actuals (bare-identifier text where the actual is
/// one).
type EnclosingHop = (String, usize, Vec<Option<String>>);

/// The enclosing macro-or-function calls of the call `callee` at `line`:
/// innermost first, each with the argument slot the site sits at and the
/// call's actuals (bare-identifier text where the actual is one — the hop
/// proofs re-ground pack state from these). Parses `body` (which starts at
/// 1-based `body_start_line`) as a translation unit, falling back to a
/// wrapped statement for macro-body fragments.
/// `None` where the call is not found there: no evidence of death, so the
/// caller keeps the site.
/// Whether the actual hands `want`: a bare identifier, or one under
/// address-of, dereference, parens, or a cast (`&cb`, `*cb`, `(cb)` all
/// carry the value into the call). Anything else is not the target.
fn actual_hands(actual: tree_sitter::Node, bytes: &[u8], want: &str) -> bool {
    let Ok(mut text) = actual.utf8_text(bytes) else {
        return false;
    };
    loop {
        text = text.trim();
        let stripped = text
            .strip_prefix(['&', '*'])
            .map(str::trim_start)
            .unwrap_or(text);
        let unparen = stripped
            .strip_prefix('(')
            .and_then(|inner| inner.strip_suffix(')'))
            .map(str::trim);
        match (unparen, stripped.len() != text.len()) {
            (Some(inner), _) => text = inner,
            (None, true) => text = stripped,
            // No whitespace veto: the loop strips one prefix layer at
            // a time and only a bare single token survives to compare,
            // so `& target` hands exactly what `&target` hands. A
            // multi-token actual never equals the bare parameter name.
            (None, false) => {
                return text == want;
            }
        }
    }
}

fn enclosing_calls(
    body: &str,
    body_start_line: u32,
    line: u32,
    callee: &str,
    target: Option<&str>,
    slot: Option<usize>,
) -> Option<Vec<EnclosingHop>> {
    fn parse(source: &str) -> Option<tree_sitter::Tree> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&tree_sitter_c::LANGUAGE.into()).ok()?;
        // No whole-tree error gate: attribute macros (`__init`,
        // `asmlinkage`) error only their own declarator node while the
        // body parses clean. The find below plus the clean-chain check
        // after it decide; error recovery elsewhere never blocks a call
        // that parsed solid.
        parser.parse(source, None)
    }
    let owned: Vec<u8>;
    let (tree, bytes) = if let Some(tree) = parse(body) {
        owned = body.as_bytes().to_vec();
        (tree, owned.as_slice())
    } else {
        let wrapped = format!("void __macro_via_site(void) {{ {body}; }}");
        let tree = parse(&wrapped)?;
        owned = wrapped.into_bytes();
        (tree, owned.as_slice())
    };
    // Pre-order search for the call: function name matches, one actual
    // holds the handed target, and the span covers the site line. The
    // actual check keeps a same-name call handing another value (or the
    // same lines of another file's same-name function) from counting
    // its enclosers toward this site.
    #[allow(clippy::too_many_arguments)]
    fn find<'a>(
        node: tree_sitter::Node<'a>,
        bytes: &[u8],
        line: u32,
        base: u32,
        callee: &str,
        target: Option<&str>,
        slot: Option<usize>,
    ) -> Option<tree_sitter::Node<'a>> {
        if node.kind() == "call_expression" {
            let name = node
                .child_by_field_name("function")
                .filter(|function| function.kind() == "identifier")
                .and_then(|function| function.utf8_text(bytes).ok());
            if name == Some(callee) {
                let first = base + node.start_position().row as u32;
                let last = base + node.end_position().row as u32;
                if first <= line && line <= last {
                    let mut hands = target.is_none();
                    if let Some(arguments) = node.child_by_field_name("arguments") {
                        if let Some(want) = target {
                            for (index, child) in call_actuals(arguments).into_iter().enumerate() {
                                if actual_hands(child, bytes, want)
                                    && slot.is_none_or(|slot| slot == index)
                                {
                                    hands = true;
                                    break;
                                }
                            }
                        }
                    }
                    if hands {
                        return Some(node);
                    }
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(hit) = find(child, bytes, line, base, callee, target, slot) {
                return Some(hit);
            }
        }
        None
    }
    let mut current = find(
        tree.root_node(),
        bytes,
        line,
        body_start_line,
        callee,
        target,
        slot,
    )?;
    // The call must stand on solid structure: anything on its root path
    // that error recovery touched (a misnested call, a broken argument
    // list) proves nothing, so the site falls back to the lenient answer.
    // Errors off the path — an attribute macro on the declarator — change
    // nothing above the body.
    {
        let mut node = current;
        loop {
            if node.is_error() {
                return None;
            }
            let Some(parent) = node.parent() else {
                break;
            };
            node = parent;
        }
    }
    let mut chain = Vec::new();
    while let Some(parent) = current.parent() {
        if parent.kind() == "call_expression" {
            let name = parent
                .child_by_field_name("function")
                .filter(|function| function.kind() == "identifier")
                .and_then(|function| function.utf8_text(bytes).ok())
                .unwrap_or_default();
            let mut slot = 0usize;
            let mut actuals: Vec<Option<String>> = Vec::new();
            if let Some(arguments) = parent.child_by_field_name("arguments") {
                for (index, child) in call_actuals(arguments).into_iter().enumerate() {
                    if child.start_byte() <= current.start_byte()
                        && current.end_byte() <= child.end_byte()
                    {
                        slot = index;
                    }
                    actuals.push(
                        (child.kind() == "identifier")
                            .then(|| child.utf8_text(bytes).ok().map(str::to_string))
                            .flatten(),
                    );
                }
            }
            chain.push((name.to_string(), slot, actuals));
        }
        current = parent;
    }
    Some(chain)
}

/// Textual `callee(` call spans in `body`: (open-paren, close-paren) byte
/// indices, strings/chars/comments/continuations skipped, `x.callee(` and
/// `p->callee(` excluded like the tree walk. Candidates only: the re-parse
/// validates each one, so a comment naming the callee proves nothing.
fn call_occurrences(body: &str, callee: &str) -> Vec<(usize, usize)> {
    let bytes = body.as_bytes();
    // (index after the token, kind) skipping strings, chars, comments and
    // splices. Returns the index one past the skipped region.
    fn skip_trivia(bytes: &[u8], mut i: usize) -> usize {
        while i < bytes.len() {
            match bytes[i] {
                b'"' => {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'"' {
                        if bytes[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    i += 1;
                }
                b'\'' => {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'\'' {
                        if bytes[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    i += 1;
                }
                b'/' if bytes.get(i + 1) == Some(&b'/') => {
                    while i < bytes.len() && bytes[i] != b'\n' {
                        i += 1;
                    }
                }
                b'/' if bytes.get(i + 1) == Some(&b'*') => {
                    i += 2;
                    while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                        i += 1;
                    }
                    i += 2;
                }
                b'\\' if bytes.get(i + 1) == Some(&b'\n') => i += 2,
                _ => break,
            }
        }
        i
    }
    fn is_ident(b: u8) -> bool {
        b == b'_' || b.is_ascii_alphanumeric()
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        i = skip_trivia(bytes, i);
        if i >= bytes.len() {
            break;
        }
        let b = bytes[i];
        if b == b'_' || b.is_ascii_alphabetic() {
            let start = i;
            while i < bytes.len() && is_ident(bytes[i]) {
                i += 1;
            }
            if &body[start..i] == callee {
                let before = body[..start]
                    .trim_end_matches(|c: char| c.is_whitespace())
                    .as_bytes();
                let member = before.ends_with(b".") || before.ends_with(b"->");
                let mut j = i;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if !member && bytes.get(j) == Some(&b'(') {
                    // Match the parens with the same skipping.
                    let open = j;
                    let mut depth = 0u32;
                    let mut k = open;
                    let mut close = None;
                    while k < bytes.len() {
                        let nk = skip_trivia(bytes, k);
                        if nk != k {
                            k = nk;
                            continue;
                        }
                        match bytes[k] {
                            b'(' => depth += 1,
                            b')' => {
                                depth -= 1;
                                if depth == 0 {
                                    close = Some(k);
                                    break;
                                }
                            }
                            _ => {}
                        }
                        k += 1;
                    }
                    if let Some(close) = close {
                        out.push((open, close));
                        i = close + 1;
                        continue;
                    }
                }
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Every matching call's chain, not just the first: a line holding both a
/// dropped and a live call (`DROP(CALLT()) + CALLT()`) keeps the caller
/// through the live one. Same parse, error gate, and climb as the
/// singular version; only the macro-caller fallback in the named edge
/// needs all of them.
fn enclosing_chains(
    body: &str,
    body_start_line: u32,
    line: u32,
    callee: &str,
) -> Vec<Vec<EnclosingHop>> {
    fn parse(source: &str) -> Option<tree_sitter::Tree> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&tree_sitter_c::LANGUAGE.into()).ok()?;
        parser.parse(source, None)
    }
    fn collect<'a>(
        node: tree_sitter::Node<'a>,
        bytes: &[u8],
        line: u32,
        base: u32,
        callee: &str,
        out: &mut Vec<tree_sitter::Node<'a>>,
    ) {
        if node.kind() == "call_expression" {
            let name = node
                .child_by_field_name("function")
                .filter(|function| function.kind() == "identifier")
                .and_then(|function| function.utf8_text(bytes).ok());
            if name == Some(callee) {
                let first = base + node.start_position().row as u32;
                let last = base + node.end_position().row as u32;
                if first <= line && line <= last {
                    out.push(node);
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            collect(child, bytes, line, base, callee, out);
        }
    }
    fn climb(mut current: tree_sitter::Node<'_>, bytes: &[u8]) -> Option<Vec<EnclosingHop>> {
        {
            let mut node = current;
            loop {
                if node.is_error() {
                    return None;
                }
                let Some(parent) = node.parent() else {
                    break;
                };
                node = parent;
            }
        }
        let mut chain = Vec::new();
        while let Some(parent) = current.parent() {
            if parent.kind() == "call_expression" {
                let name = parent
                    .child_by_field_name("function")
                    .filter(|function| function.kind() == "identifier")
                    .and_then(|function| function.utf8_text(bytes).ok())
                    .unwrap_or_default();
                let mut slot = 0usize;
                let mut actuals: Vec<Option<String>> = Vec::new();
                if let Some(arguments) = parent.child_by_field_name("arguments") {
                    for (index, child) in call_actuals(arguments).into_iter().enumerate() {
                        if child.start_byte() <= current.start_byte()
                            && current.end_byte() <= child.end_byte()
                        {
                            slot = index;
                        }
                        actuals.push(
                            (child.kind() == "identifier")
                                .then(|| child.utf8_text(bytes).ok().map(str::to_string))
                                .flatten(),
                        );
                    }
                }
                chain.push((name.to_string(), slot, actuals));
            }
            current = parent;
        }
        Some(chain)
    }
    let owned: Vec<u8>;
    let (tree, bytes) = if let Some(tree) = parse(body) {
        owned = body.as_bytes().to_vec();
        (tree, owned.as_slice())
    } else {
        let wrapped = format!("void __macro_via_site(void) {{ {body}; }}");
        let Some(tree) = parse(&wrapped) else {
            return Vec::new();
        };
        owned = wrapped.into_bytes();
        (tree, owned.as_slice())
    };
    let mut found = Vec::new();
    let error_tree = tree.root_node().has_error();
    collect(
        tree.root_node(),
        bytes,
        line,
        body_start_line,
        callee,
        &mut found,
    );
    let mut chains = Vec::new();
    for node in found {
        if let Some(chain) = climb(node, bytes) {
            chains.push(chain);
        }
    }
    // A paste or adjacent-token argument (`KERN_ERR pr_fmt(fmt)`) errors
    // the whole cut, hiding every call from the walk — including live ones
    // like every kernel `pr_*_ratelimited` wrapper. Where the tree has
    // errors, re-parse one variant per textual occurrence with that
    // occurrence's interior blanked (length- and line-preserving): the
    // parse validates the candidate, ancestors outside the blanked
    // interior are exact, and a dropped wrapper around the occurrence
    // still proves its drop. Unclosed occurrences never become variants.
    if error_tree {
        let mut variants = 0usize;
        for (open, close) in call_occurrences(body, callee) {
            let first_row = body_start_line + body[..open].matches('\n').count() as u32;
            let last_row = body_start_line + body[..=close].matches('\n').count() as u32;
            if first_row > line || line > last_row {
                continue;
            }
            if variants >= 8 {
                break;
            }
            variants += 1;
            let mut variant = body.as_bytes().to_vec();
            let mut placed = false;
            for byte in variant.iter_mut().take(close).skip(open + 1) {
                if *byte != b'\n' {
                    *byte = b' ';
                    if !placed {
                        *byte = b'0';
                        placed = true;
                    }
                }
            }
            let Some(vtree) = parse(&String::from_utf8_lossy(&variant)) else {
                continue;
            };
            let mut vfound = Vec::new();
            collect(
                vtree.root_node(),
                &variant,
                line,
                body_start_line,
                callee,
                &mut vfound,
            );
            for node in vfound {
                if let Some(chain) = climb(node, &variant) {
                    chains.push(chain);
                }
            }
        }
    }
    chains
}

/// Whether the handover site itself runs: the call handing `target` is
/// found by callee, actual, line, *and slot* together (same-line twin
/// calls hand different actuals, so the slot picks the twin the site
/// names), then every enclosing call must evaluate the slot the site sits
/// at. Ordinary and unknown calls always do; a macro call does only where
/// an admitted, live definition invokes that slot. A site nested in a
/// dropped macro slot (`DROP(INVOKE(f))`) never expands, so it hands
/// nothing on. Unknowable (unparsed bodies, missing rows) keeps the site:
/// silence needs proof.
#[allow(clippy::too_many_arguments)]
async fn site_executes(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    pin: crate::domain::Context,
    site_file: &str,
    site_line: u32,
    site_index: u32,
    callee: &str,
    enclosing: &str,
    target: &str,
) -> Result<bool> {
    // Budget spent: this leg claims nothing; aggregation points
    // mark the truncation.
    if snapshot.exhausted() {
        return Ok(false);
    }
    for (body, body_start) in
        enclosing_body_for(db, snapshot, site_file, site_line, enclosing).await?
    {
        let found = enclosing_calls(
            &body,
            body_start,
            site_line,
            callee,
            Some(target),
            Some(site_index as usize),
        );
        let Some(chain) = found else {
            continue;
        };
        let mut twin_visited = std::collections::HashSet::new();
        for (outer, slot, actuals) in &chain {
            if outer.is_empty() {
                // A call through a pointer value evaluates its arguments.
                continue;
            }
            let (rows, scope_name, cut) =
                alias_macro_rows(db, snapshot, pin, site_file, site_line, outer).await?;
            // A tripped outer drops the site; an ordinary outer with no
            // rows even whole skips below.
            if cut {
                return Ok(false);
            }
            if rows.is_empty() {
                continue;
            }
            let mut runs = false;
            for row in &rows {
                if !admit_definition(row, &rows, site_file, pin) {
                    continue;
                }
                let live = scope_at_site(db, snapshot, site_file, &scope_name, site_line)
                    .await?
                    .is_some_and(|scope| scope.defines_at(&row.file_path, row.line_start));
                if !live {
                    continue;
                }
                // Expansion is evaluation, not invocation: an evaluating
                // wrapper (`unlikely(x)`, `(x)`, `ID(x)`) still expands its
                // slot, so the nested site runs. An unparseable wrapper is
                // unknown, and unknown keeps the site. The proof is
                // site-scoped: a body-level set resolves nested macros
                // where the row is defined, but a redefinition at the
                // site can drop the slot.
                if !body_parse_ok(&row.body) {
                    runs = true;
                    break;
                }
                if macro_slot_flows_at_site(
                    db,
                    snapshot,
                    pin,
                    actuals,
                    *slot,
                    row,
                    outer,
                    &SubstMap::new(),
                    site_file,
                    site_line,
                    site_index,
                    None,
                    &mut twin_visited,
                )
                .await?
                {
                    runs = true;
                    break;
                }
            }
            if !runs {
                return Ok(false);
            }
        }
        // The call was found and every encloser runs.
        return Ok(true);
    }
    Ok(true)
}

/// Push one row's body where it covers the site line: a macro row lends
/// its replacement text (header cut, wrapped so it parses as a unit),
/// anything else its raw body. A handover written inside a macro body
/// (`USEIT() = DROP(INV(t))`) proves against the wrapper's own text;
/// parsing the raw `#define` as a translation unit leaves the call in
/// unparsed `preproc_arg`, so a leg the site never runs survives.
fn push_enclosing_body(
    out: &mut Vec<(String, u32)>,
    seen: &mut std::collections::HashSet<(String, u32)>,
    row: &crate::types::FunctionInfo,
    site_file: &str,
    site_line: u32,
) {
    if row.file_path != site_file {
        return;
    }
    if !seen.insert((row.file_path.clone(), row.line_start)) {
        return;
    }
    let end = row.line_start + row.body.lines().count().max(1) as u32;
    if row.line_start > site_line || site_line >= end {
        return;
    }
    if !is_macro_row(row) {
        out.push((row.body.clone(), row.line_start));
        return;
    }
    let Some(cut) = cut_macro_header(&row.body) else {
        return;
    };
    // The replacement text starts past the header's physical lines; the
    // wrapper's prefix sits on its first line, so tree rows land on file
    // lines by direct offset. The semicolon sits inside: a bare cut is an
    // expression (`REPORT(x)`), and without it the braces misparse and the
    // body call below never matches. GNU elision is scrubbed: `##` in
    // argument position misparses the whole cut (notably every kernel
    // `, ##__VA_ARGS__`), while a pasted callee keeps its silence.
    let header_lines = row.body[..row.body.len() - cut.len()].matches('\n').count() as u32;
    let cut = scrub_gnu_elision(cut);
    out.push((
        format!("void __macro_via_site(void) {{ {{{cut};}} }}"),
        row.line_start + header_lines,
    ));
}

/// The bodies that can enclose a handover site: the enclosing function's
/// row first, then overlay macro rows, then the file text itself (workdir
/// where dirty, blob otherwise). Each with its 1-based start line.
async fn enclosing_body_for(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    site_file: &str,
    site_line: u32,
    enclosing: &str,
) -> Result<Vec<(String, u32)>> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if !enclosing.is_empty() {
        // File-scoped: a same-named static in another file keeps its
        // line numbers out of this file's site. Only rows from the site
        // file whose span covers the site line answer; the whole-file
        // text below remains the fallback.
        if let Ok(rows) = db
            .find_all_functions_git_aware(enclosing, &snapshot.git_sha)
            .await
        {
            for row in rows {
                push_enclosing_body(&mut out, &mut seen, &row, site_file, site_line);
            }
        }
        // Macro rows the function lookup does not carry: a committed
        // macro enclosing a handover site answers from its own text.
        for row in macro_rows_for(db, snapshot, enclosing).await? {
            push_enclosing_body(&mut out, &mut seen, &row, site_file, site_line);
        }
        for row in db.overlay_rows_named(enclosing, &snapshot.git_sha) {
            push_enclosing_body(&mut out, &mut seen, &row, site_file, site_line);
        }
    }
    if snapshot.dirty.contains(site_file) {
        let path = std::path::Path::new(db.repo_path()).join(site_file);
        if let Ok(text) = std::fs::read_to_string(&path) {
            out.push((text, 1));
        }
    } else {
        snapshot.note_blob();
        if let Some(text) =
            blob_text_at(db.repo_path(), &snapshot.git_sha, site_file, &snapshot.repo)?
        {
            out.push((text, 1));
        }
    }
    Ok(out)
}

/// Whether m's invocation of `param` holds at the carried site: calling
/// the parameter, handing it to an ordinary function, or a bare use
/// outside any macro call always stands; a handover through another macro
/// stands only where that macro is live at the site and invokes onward.
/// Visited-guarded; a cycle proves nothing.
#[allow(clippy::too_many_arguments)]
/// Whether `param` of `m` is provably invoked at this site: the parameter
/// itself runs as a call, or an executing handover calls it onward through
/// an admitted, live inner macro. Handing a parameter to an ordinary
/// function evaluates it — never an invocation (`REG(cb)
/// register_cb(cb)` reaches nothing) — and neither is a bare use (`ID(x)
/// (x)` never calls `x`). `site_index` is the site's absolute argument
/// slot; `site_callee` holds the macro called there. Where the proof
/// subject is that macro, the site grounds the pack state (position and
/// width); nested levels thread it through each hop instead, since
/// repacking reshapes every absolute slot.
async fn param_invoked_at_site(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    pin: crate::domain::Context,
    m: &crate::types::FunctionInfo,
    param: &str,
    site_file: &str,
    site_line: u32,
    site_index: u32,
    site_callee: &str,
    subst: &SubstMap,
    visited: &mut std::collections::HashSet<(String, String)>,
) -> Result<bool> {
    // The pack grounds here: the site calls this macro, so the position
    // and width come from the site itself (nested levels thread them
    // through each hop instead; see `PackState`).
    let grounded = m.name == site_callee;
    let pos = (param == "..." && grounded)
        .then(|| site_index.saturating_sub(variadic_slot(m).unwrap_or(0) as u32));
    let width = if grounded {
        site_pack_width(db, snapshot, m, site_file, site_line, site_callee)
    } else {
        None
    };
    param_invoked_inner(
        db,
        snapshot,
        pin,
        m,
        param,
        site_file,
        site_line,
        site_index,
        PackState { pos, width },
        subst,
        visited,
    )
    .await
}

/// The body of `param_invoked_inner`: only entered with the entry guard
/// held, so the mutual recursion with the ancestor gate terminates.
#[allow(clippy::too_many_arguments)]
async fn param_invoked_inner(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    pin: crate::domain::Context,
    m: &crate::types::FunctionInfo,
    param: &str,
    site_file: &str,
    site_line: u32,
    site_index: u32,
    pack: PackState,
    subst: &SubstMap,
    visited: &mut std::collections::HashSet<(String, String)>,
) -> Result<bool> {
    // Entry guard: a revisit is a cycle, and a cycle proves nothing.
    // Removed on the way out so diamonds (not cycles) still prove through
    // every entry point, including the ancestor gate's direct call.
    if !visited.insert((m.name.clone(), param.to_string())) {
        return Ok(false);
    }
    let outcome = param_invoked_proof(
        db, snapshot, pin, m, param, site_file, site_line, site_index, pack, subst, visited,
    )
    .await;
    visited.remove(&(m.name.clone(), param.to_string()));
    outcome
}

/// The proof body of `param_invoked_inner`: only entered with the entry
/// guard held, so the mutual recursion with the ancestor gate terminates.
#[allow(clippy::too_many_arguments)]
async fn param_invoked_proof(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    pin: crate::domain::Context,
    m: &crate::types::FunctionInfo,
    param: &str,
    site_file: &str,
    site_line: u32,
    site_index: u32,
    pack: PackState,
    subst: &SubstMap,
    visited: &mut std::collections::HashSet<(String, String)>,
) -> Result<bool> {
    let is_bundle = param == "...";
    let mut proof_visited = std::collections::HashSet::new();
    let summary = summarize_macro(db, snapshot, m, pin, &mut proof_visited).await?;
    let executing_at = |index: usize| summary.executing.get(index).copied().unwrap_or(false);
    // Direct invocation: the parameter itself runs as a call — where the
    // call itself executes at this site, not just in the body proof.
    for (index, call) in summary.tree.iter().enumerate() {
        if !executing_at(index) || call.callee != param {
            continue;
        }
        if call_executes_at_site(
            db, snapshot, pin, m, index, site_file, site_line, site_index, pack.width, subst,
            visited,
        )
        .await?
        {
            return Ok(true);
        }
    }
    // Only macro handovers remain: one must be live here and invoke on.
    // Ordinary callees evaluate (never invoke); anonymous callees
    // (pointer calls) invoke nothing by name.
    for (index, call) in summary.tree.iter().enumerate() {
        if !executing_at(index) {
            continue;
        }
        let (callee, actuals) = (call.callee.as_str(), &call.actuals);
        if callee == m.name || callee.is_empty() {
            continue;
        }
        for (slot, actual) in actuals.iter().enumerate() {
            let marker = is_bundle && actual.as_deref() == Some(BUNDLE_MARKER);
            if actual.as_deref() != Some(param) && !marker {
                continue;
            }
            let (rows, scope_name, _cut) =
                alias_macro_rows(db, snapshot, pin, site_file, site_line, callee).await?;
            // The handing call itself must execute at this site: a handover
            // nested in a slot the site's definitions drop hands nothing.
            if !call_executes_at_site(
                db, snapshot, pin, m, index, site_file, site_line, site_index, pack.width, subst,
                visited,
            )
            .await?
            {
                continue;
            }
            // Blue paint: a handover through a macro already expanding
            // above is an ordinary call — it never re-expands, so the
            // value stops here.
            if expanding_contains(visited, callee) {
                continue;
            }
            for row in &rows {
                if !admit_definition(row, &rows, site_file, pin) {
                    continue;
                }
                let live = scope_at_site(db, snapshot, site_file, &scope_name, site_line)
                    .await?
                    .is_some_and(|scope| scope.defines_at(&row.file_path, row.line_start));
                if !live {
                    continue;
                }
                for (landing, child_pack) in pack_landings(&call.actuals, slot, marker, pack, row) {
                    let inner_param = match landing {
                        Landing::Fixed(inner_slot) => {
                            let Some(param) =
                                row.parameters.get(inner_slot).map(|p| p.name.clone())
                            else {
                                continue;
                            };
                            param
                        }
                        // The row takes a pack here by construction.
                        Landing::Pack(_) => "...".to_string(),
                    };
                    // No separate cycle key: the entry guard in
                    // `param_invoked_inner` keeps `(row.name, inner_param)`,
                    // so a revisit here is already a proven nothing.
                    let extended = extend_subst(subst, &m.name, &call.actuals, row);
                    let onward = Box::pin(param_invoked_inner(
                        db,
                        snapshot,
                        pin,
                        row,
                        &inner_param,
                        site_file,
                        site_line,
                        site_index,
                        child_pack,
                        &extended,
                        visited,
                    ))
                    .await?;
                    if onward {
                        return Ok(true);
                    }
                }
            }
        }
    }
    // No clean parse, no refutation: the stored edges stand alone (a body
    // the parser chokes on — `#f` stringize, statement expressions —
    // refutes nothing). Pasted bodies stay silent.
    if !m.body.contains("##") && !body_parse_ok(&m.body) {
        for (name, position) in stored_param_edges(db, snapshot, m).await? {
            if name == param && (position == site_index || is_bundle) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Whether the macro's parameter evaluates at the site: the evaluation
/// twin of `param_invoked_at_site`, which the ancestor gate uses where it
/// needs expansion (evaluation), not invocation. Body-level evaluated sets
/// resolve nested macros where they are defined; a redefinition at the
/// site can drop the slot, so each hop re-proves at the site. Shares the
/// visited set (and its entry guard) with the invocation proof: a cycle
/// across the two proves nothing.
#[allow(clippy::too_many_arguments)]
async fn param_evaluated_at_site(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    pin: crate::domain::Context,
    m: &crate::types::FunctionInfo,
    param: &str,
    subst: &SubstMap,
    site_file: &str,
    site_line: u32,
    site_index: u32,
    pack: PackState,
    visited: &mut std::collections::HashSet<(String, String)>,
) -> Result<bool> {
    if !visited.insert((m.name.clone(), param.to_string())) {
        return Ok(false);
    }
    let outcome = evaluated_proof(
        db, snapshot, pin, m, param, subst, site_file, site_line, site_index, pack, visited,
    )
    .await;
    visited.remove(&(m.name.clone(), param.to_string()));
    outcome
}

/// The proof body of `param_evaluated_at_site`: only entered with the entry
/// guard held.
#[allow(clippy::too_many_arguments)]
async fn evaluated_proof(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    pin: crate::domain::Context,
    m: &crate::types::FunctionInfo,
    param: &str,
    subst: &SubstMap,
    site_file: &str,
    site_line: u32,
    site_index: u32,
    pack: PackState,
    visited: &mut std::collections::HashSet<(String, String)>,
) -> Result<bool> {
    // Budget spent: this leg claims nothing; aggregation points
    // mark the truncation.
    if snapshot.exhausted() {
        return Ok(false);
    }
    let is_bundle = param == "...";
    let mut proof_visited = std::collections::HashSet::new();
    let summary = summarize_macro(db, snapshot, m, pin, &mut proof_visited).await?;
    let executing_at = |index: usize| summary.executing.get(index).copied().unwrap_or(false);
    // Direct evaluation: the parameter itself runs as a call — a call
    // evaluates its callee — where the call executes at this site.
    for (index, call) in summary.tree.iter().enumerate() {
        if !executing_at(index) || call.callee != param {
            continue;
        }
        if call_executes_at_site(
            db, snapshot, pin, m, index, site_file, site_line, site_index, pack.width, subst,
            visited,
        )
        .await?
        {
            return Ok(true);
        }
    }
    // Bare reads evaluate where they execute: the innermost enclosing
    // call must execute at this site (the gate covers every level above
    // it), and its slot must evaluate at this site too — a body-level
    // slot test would resolve nested macros where the row is defined,
    // repeating the staleness one level down. A use as a call's callee
    // belongs to the direct arm above, never this scan.
    {
        let called: std::collections::HashSet<String> = summary
            .called
            .iter()
            .map(|(name, _)| name.clone())
            .collect();
        let mut parser = tree_sitter::Parser::new();
        if parser.set_language(&tree_sitter_c::LANGUAGE.into()).is_ok() {
            // The tree spans come from the cut, scrubbed body: parse that
            // same text, or no span ever matches a tree call.
            if let Some(cut) = cut_macro_header(&m.body) {
                let wrapped = format!(
                    "void __macro_via_body(void) {{ {}; }}",
                    scrub_va_elision(cut)
                );
                if let Some(parsed) = parser.parse(&wrapped, None) {
                    if !parsed.root_node().has_error() {
                        let bytes = wrapped.as_bytes();
                        let index_of: std::collections::HashMap<(usize, usize), usize> = summary
                            .tree
                            .iter()
                            .enumerate()
                            .map(|(index, call)| (call.span, index))
                            .collect();
                        let is_param = |name: &str| {
                            m.parameters.iter().any(|p| p.name == name) || name == "..."
                        };
                        let (covered, uses) =
                            collect_param_uses(parsed.root_node(), bytes, &is_param);
                        'uses: for (name, span) in uses {
                            if name != param || covered.contains(&span) {
                                continue;
                            }
                            let Some(node) = find_use_node(parsed.root_node(), span) else {
                                continue;
                            };
                            // The innermost enclosing call: its tree index
                            // grounds the execution gate, its actual index the
                            // slot proof. No enclosing call is top-level body
                            // text, which evaluates where the row expands.
                            let mut child = node;
                            let found = loop {
                                let Some(parent) = child.parent() else {
                                    break None;
                                };
                                if parent.kind() != "call_expression" {
                                    child = parent;
                                    continue;
                                }
                                let is_function = parent
                                    .child_by_field_name("function")
                                    .is_some_and(|function| function.id() == child.id());
                                if is_function {
                                    continue 'uses;
                                }
                                let Some(arguments) = parent.child_by_field_name("arguments")
                                else {
                                    child = parent;
                                    continue;
                                };
                                let Some(arg) = call_actuals(arguments)
                                    .into_iter()
                                    .enumerate()
                                    .find(|(_, named)| {
                                        named.start_byte() <= span.0 && span.1 <= named.end_byte()
                                    })
                                    .map(|(index, _)| index)
                                else {
                                    child = parent;
                                    continue;
                                };
                                let key = (parent.start_byte(), parent.end_byte());
                                let Some(index) = index_of.get(&key).copied() else {
                                    // Pasted regions leave no tree nodes: no
                                    // evidence of death, so the use stands.
                                    break None;
                                };
                                break Some((index, arg));
                            };
                            let Some((index, arg)) = found else {
                                return Ok(true);
                            };
                            if !executing_at(index) {
                                continue;
                            }
                            if !call_executes_at_site(
                                db, snapshot, pin, m, index, site_file, site_line, site_index,
                                pack.width, subst, visited,
                            )
                            .await?
                            {
                                continue;
                            }
                            let call = &summary.tree[index];
                            let callee = call.callee.as_str();
                            if callee.is_empty() {
                                // Ordinary functions and pointer calls evaluate
                                // every argument they receive.
                                return Ok(true);
                            }
                            // A parameter callee resolves through the path
                            // substitution first: the outer actuals may bind
                            // it to a concrete macro (`w <- DROP` above a
                            // nested site), and the rows proof below re-runs
                            // for that binding exactly as for a textual one.
                            // Unresolvable keeps the unknown below.
                            let bound = resolve_subst(db, snapshot, subst, &m.name, callee).await?;
                            let callee = bound.as_deref().unwrap_or(callee);
                            // The alias walk runs only where no function-like
                            // row exists; a callee with rows uses them
                            // directly. Bare function calls still pay the
                            // walk (measured costless on the printk gate).
                            let (rows, scope_name, cut) = if macro_rows_for(db, snapshot, callee)
                                .await?
                                .is_empty()
                            {
                                alias_macro_rows(db, snapshot, pin, site_file, site_line, callee)
                                    .await?
                            } else {
                                (
                                    macro_rows_for(db, snapshot, callee).await?,
                                    callee.to_string(),
                                    false,
                                )
                            };
                            if rows.is_empty() {
                                // No function-like rows and no object alias
                                // behind the name: an ordinary call. An
                                // object alias still expands, so it never
                                // takes this arm. Where the proof tripped,
                                // the parameter drops.
                                if cut {
                                    return Ok(false);
                                }
                                return Ok(true);
                            }
                            if bound.is_none() && m.parameters.iter().any(|p| p.name == callee) {
                                // An unresolvable parameter callee names an
                                // unknown function: the body proof's answer
                                // stands.
                                if called.contains(callee) {
                                    return Ok(true);
                                }
                                continue;
                            }
                            let mut evaluates = false;
                            for row in &rows {
                                if !admit_definition(row, &rows, site_file, pin) {
                                    continue;
                                }
                                let live =
                                    scope_at_site(db, snapshot, site_file, &scope_name, site_line)
                                        .await?
                                        .is_some_and(|scope| {
                                            scope.defines_at(&row.file_path, row.line_start)
                                        });
                                if !live {
                                    continue;
                                }
                                for (landing, child_pack) in pack_landings(
                                    &call.actuals,
                                    arg,
                                    false,
                                    PackState {
                                        pos: None,
                                        width: pack.width,
                                    },
                                    row,
                                ) {
                                    let inner_param = match landing {
                                        Landing::Fixed(inner_slot) => {
                                            let Some(param) = row
                                                .parameters
                                                .get(inner_slot)
                                                .map(|p| p.name.clone())
                                            else {
                                                continue;
                                            };
                                            param
                                        }
                                        Landing::Pack(_) => "...".to_string(),
                                    };
                                    let extended = extend_subst(subst, &m.name, &call.actuals, row);
                                    if Box::pin(param_evaluated_at_site(
                                        db,
                                        snapshot,
                                        pin,
                                        row,
                                        &inner_param,
                                        &extended,
                                        site_file,
                                        site_line,
                                        site_index,
                                        child_pack,
                                        visited,
                                    ))
                                    .await?
                                    {
                                        evaluates = true;
                                        break;
                                    }
                                }
                                if evaluates {
                                    break;
                                }
                            }
                            if evaluates {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }
    }
    // Only macro handovers remain: one must be live here and evaluate on,
    // through the same pack-relative landings as the invocation proof.
    for (index, call) in summary.tree.iter().enumerate() {
        if !executing_at(index) {
            continue;
        }
        let (callee, actuals) = (call.callee.as_str(), &call.actuals);
        if callee == m.name || callee.is_empty() {
            continue;
        }
        for (slot, actual) in actuals.iter().enumerate() {
            let marker = is_bundle && actual.as_deref() == Some(BUNDLE_MARKER);
            if actual.as_deref() != Some(param) && !marker {
                continue;
            }
            let (rows, scope_name, _cut) =
                alias_macro_rows(db, snapshot, pin, site_file, site_line, callee).await?;
            if !call_executes_at_site(
                db, snapshot, pin, m, index, site_file, site_line, site_index, pack.width, subst,
                visited,
            )
            .await?
            {
                continue;
            }
            if expanding_contains(visited, callee) {
                continue;
            }
            for row in &rows {
                if !admit_definition(row, &rows, site_file, pin) {
                    continue;
                }
                let live = scope_at_site(db, snapshot, site_file, &scope_name, site_line)
                    .await?
                    .is_some_and(|scope| scope.defines_at(&row.file_path, row.line_start));
                if !live {
                    continue;
                }
                for (landing, child_pack) in pack_landings(&call.actuals, slot, marker, pack, row) {
                    let inner_param = match landing {
                        Landing::Fixed(inner_slot) => {
                            let Some(param) =
                                row.parameters.get(inner_slot).map(|p| p.name.clone())
                            else {
                                continue;
                            };
                            param
                        }
                        Landing::Pack(_) => "...".to_string(),
                    };
                    let extended = extend_subst(subst, &m.name, &call.actuals, row);
                    let onward = Box::pin(param_evaluated_at_site(
                        db,
                        snapshot,
                        pin,
                        row,
                        &inner_param,
                        &extended,
                        site_file,
                        site_line,
                        site_index,
                        child_pack,
                        visited,
                    ))
                    .await?;
                    if onward {
                        return Ok(true);
                    }
                }
            }
        }
    }
    // No clean parse, no refutation: the stored edges stand alone, exactly
    // like the invocation proof.
    if !m.body.contains("##") && !body_parse_ok(&m.body) {
        for (name, position) in stored_param_edges(db, snapshot, m).await? {
            if name == param && (position == site_index || is_bundle) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// The name a declarator declares, descending through declarator and
/// function-declarator wrappers to the identifier.
fn declarator_name(node: tree_sitter::Node, bytes: &[u8]) -> Option<String> {
    let mut current = node;
    loop {
        match current.kind() {
            "identifier" => {
                return current.utf8_text(bytes).ok().map(str::to_string);
            }
            _ => {
                let mut cursor = current.walk();
                let mut inner = None;
                for child in current.children(&mut cursor) {
                    if child.kind() == "declarator"
                        || child.kind() == "function_declarator"
                        || child.kind() == "identifier"
                    {
                        inner = Some(child);
                        break;
                    }
                }
                current = inner?;
            }
        }
    }
}

/// One call in a dirty file's workdir text: the callee, the argument slot
/// handing a bare-identifier actual, and where. The reverse and forward
/// handover loops join these where the committed argument stores go
/// silent (dirty files suppress their committed rows).
#[derive(Debug, Clone)]
pub struct OverlayCallSite {
    pub callee: String,
    pub index: u32,
    pub target: String,
    pub line: u32,
    pub enclosing: String,
}

/// The call inventory of dirty files: every bare-identifier actual handed
/// to an identifier callee, with its enclosing function. Cached per file
/// per snapshot. Error recovery, not error refusal: a file tree-sitter
/// cannot parse cleanly (`container_of`, statement expressions) still
/// yields the calls outside its `ERROR` subtrees — an unparseable region
/// hides its own calls, never the whole file's.
pub fn overlay_call_sites(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    file: &str,
) -> Result<Vec<OverlayCallSite>> {
    if let Some(cached) = snapshot.dirty_calls.borrow().get(file) {
        return Ok(cached.clone());
    }
    let mut sites = Vec::new();
    let path = std::path::Path::new(db.repo_path()).join(file);
    if let Ok(text) = std::fs::read_to_string(&path) {
        let mut parser = tree_sitter::Parser::new();
        if parser.set_language(&tree_sitter_c::LANGUAGE.into()).is_ok() {
            if let Some(tree) = parser.parse(&text, None) {
                fn walk(
                    node: tree_sitter::Node,
                    bytes: &[u8],
                    enclosing: &str,
                    sites: &mut Vec<OverlayCallSite>,
                ) {
                    let mut enclosing = enclosing.to_string();
                    // Error recovery: an ERROR subtree hides its own
                    // calls, never the rest of the file.
                    if node.is_error() {
                        return;
                    }
                    if node.kind() == "function_definition" {
                        if let Some(declarator) = node.child_by_field_name("declarator") {
                            if let Some(name) = declarator_name(declarator, bytes) {
                                enclosing = name;
                            }
                        }
                    }
                    if node.kind() == "call_expression" {
                        if let Some(name) = node
                            .child_by_field_name("function")
                            .filter(|function| function.kind() == "identifier")
                            .and_then(|function| function.utf8_text(bytes).ok())
                        {
                            if let Some(arguments) = node.child_by_field_name("arguments") {
                                for (index, child) in
                                    call_actuals(arguments).into_iter().enumerate()
                                {
                                    if child.kind() == "identifier" {
                                        if let Ok(target) = child.utf8_text(bytes) {
                                            sites.push(OverlayCallSite {
                                                callee: name.to_string(),
                                                index: index as u32,
                                                target: target.to_string(),
                                                line: child.start_position().row as u32 + 1,
                                                enclosing: enclosing.clone(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        walk(child, bytes, &enclosing, sites);
                    }
                }
                walk(tree.root_node(), text.as_bytes(), "", &mut sites);
            }
        }
    }
    snapshot
        .dirty_calls
        .borrow_mut()
        .insert(file.to_string(), sites.clone());
    Ok(sites)
}

/// The call arities of one file: every identifier-callee call with its
/// 1-based line and actual count. Parsed once per file per query from
/// workdir text where dirty and the committed blob otherwise; ERROR
/// subtrees hide their own calls, like the overlay inventory. Pack widths
/// (and every post-splice slot) derive from these, so a file whose calls
/// cannot be inventoried yields unknown widths, never wrong ones.
pub fn call_arities(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    file: &str,
) -> Result<Vec<CallArity>> {
    if let Some(cached) = snapshot.arities.borrow().get(file) {
        return Ok(cached.clone());
    }
    let mut arities = Vec::new();
    let text = if snapshot.dirty.contains(file) {
        std::fs::read_to_string(std::path::Path::new(db.repo_path()).join(file)).ok()
    } else {
        snapshot.note_blob();
        blob_text_at(db.repo_path(), &snapshot.git_sha, file, &snapshot.repo).unwrap_or(None)
    };
    if let Some(text) = text {
        let mut parser = tree_sitter::Parser::new();
        if parser.set_language(&tree_sitter_c::LANGUAGE.into()).is_ok() {
            if let Some(tree) = parser.parse(&text, None) {
                fn walk(
                    node: tree_sitter::Node,
                    bytes: &[u8],
                    enclosing: &str,
                    arities: &mut Vec<CallArity>,
                ) {
                    let mut enclosing = enclosing.to_string();
                    if node.is_error() {
                        return;
                    }
                    if node.kind() == "function_definition" {
                        if let Some(declarator) = node.child_by_field_name("declarator") {
                            if let Some(name) = declarator_name(declarator, bytes) {
                                enclosing = name;
                            }
                        }
                    }
                    if node.kind() == "call_expression" {
                        if let Some(name) = node
                            .child_by_field_name("function")
                            .filter(|function| function.kind() == "identifier")
                            .and_then(|function| function.utf8_text(bytes).ok())
                        {
                            if let Some(arguments) = node.child_by_field_name("arguments") {
                                arities.push(CallArity {
                                    callee: name.to_string(),
                                    line: node.start_position().row as u32 + 1,
                                    arity: call_actuals(arguments).len() as u32,
                                    enclosing: enclosing.clone(),
                                });
                            }
                        }
                    }
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        walk(child, bytes, &enclosing, arities);
                    }
                }
                walk(tree.root_node(), text.as_bytes(), "", &mut arities);
            }
        }
    }
    snapshot
        .arities
        .borrow_mut()
        .insert(file.to_string(), arities.clone());
    Ok(arities)
}

/// The width of the site macro's pack at one call site: how many trailing
/// actuals the call passes. `None` where the macro takes no pack, the call
/// is unparseable, or twins share the line with different arities (width
/// is unknowable there, and unknown keeps the site).
pub fn site_pack_width(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    m: &crate::types::FunctionInfo,
    site_file: &str,
    site_line: u32,
    site_callee: &str,
) -> Option<u32> {
    let vslot = variadic_slot(m)? as u32;
    let arities = call_arities(db, snapshot, site_file).ok()?;
    let mut widths: Vec<u32> = arities
        .iter()
        .filter(|arity| arity.callee == site_callee && arity.line == site_line)
        .map(|arity| arity.arity.saturating_sub(vslot))
        .collect();
    widths.sort();
    widths.dedup();
    if widths.len() != 1 {
        return None;
    }
    Some(widths[0])
}

/// Whether the call site at (`file`, 1-based `line`) can reach the
/// compiler: outside every dead preprocessor range of that file's text
/// (workdir where dirty, committed blob otherwise). A call inside `#if 0`
/// never runs, so it hands nothing and invokes nothing.
pub fn site_is_live(db: &DatabaseManager, snapshot: &ViaSnapshot, file: &str, line: u32) -> bool {
    if let Some(cached) = snapshot.deadlines.borrow().get(file) {
        return !cached
            .iter()
            .any(|(start, end)| *start <= line && line <= *end);
    }
    let text = if snapshot.dirty.contains(file) {
        std::fs::read_to_string(std::path::Path::new(db.repo_path()).join(file)).ok()
    } else {
        snapshot.note_blob();
        blob_text_at(db.repo_path(), &snapshot.git_sha, file, &snapshot.repo).unwrap_or(None)
    };
    let dead = text
        .map(|text| rescan_preprocessor(&text).dead)
        .unwrap_or_default();
    let live = !dead
        .iter()
        .any(|(start, end)| *start <= line && line <= *end);
    snapshot
        .deadlines
        .borrow_mut()
        .insert(file.to_string(), dead);
    live
}

/// Whether the workdir text of a dirty file still shows `needle` on its
/// `line` (1-based): the stale-site gate. A committed site in a dirty
/// file lists as unreached only while the current text still shows the
/// call; once the edit removes the line's call, the site yields no legs
/// instead of pointing the reader at a line that no longer contains it.
pub fn dirty_line_contains(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    file: &str,
    line: u32,
    needle: &str,
) -> bool {
    if !snapshot.dirty_lines.borrow().contains_key(file) {
        let lines = std::path::Path::new(db.repo_path()).join(file);
        let lines = std::fs::read_to_string(&lines)
            .map(|text| text.lines().map(str::to_string).collect())
            .unwrap_or_default();
        snapshot
            .dirty_lines
            .borrow_mut()
            .insert(file.to_string(), lines);
    }
    snapshot
        .dirty_lines
        .borrow()
        .get(file)
        .and_then(|lines| lines.get(line.saturating_sub(1) as usize))
        .is_some_and(|text| text.contains(needle))
}

/// Reverse handover legs for `target`: argument rows handing it to a macro
/// callee whose admitted definition invokes that parameter position, with
/// the call site inside the macro's live scope. Where the callee only
/// forwards the parameter to another macro that invokes it, the chain
/// threads through (the forward mirror): each pass-through lands in the
/// leg's `outer`, outermost first. A handover that reaches no invocation
/// emits nothing: handed-but-never-called yields no legs.
pub async fn reverse_handover_legs(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    target: &str,
    walk_context: crate::domain::Context,
) -> Result<(Vec<HandoverLeg>, bool, bool)> {
    let mut sites: Vec<HandoverSite> = Vec::new();
    // Set by the chain's depth backstop; returned beside the legs so the
    // display can tell a nesting cut from a work cut.
    let mut truncated = false;
    let mut depth_cut = false;
    for row in db.argument_rows_for_target(target).await? {
        // Every site read charges the shared work limit: a name handed at
        // thousands of sites (printk's `_printk`) must stop somewhere, and
        // the display caps below mark what the reader sees.
        if snapshot.charge_work() {
            truncated = true;
            break;
        }
        // Committed rows in dirty files are already out (row_in_snapshot):
        // the overlay inventory below replaces them.
        if !row_in_snapshot(snapshot, &row.file_path, &row.git_file_hash, false) {
            continue;
        }
        // The site itself must run: a handover nested in a dropped macro
        // slot never expands, so it proves nothing — nor does one inside
        // `#if 0`, which never compiles.
        if !site_is_live(db, snapshot, &row.file_path, row.line) {
            continue;
        }
        if !site_executes(
            db,
            snapshot,
            walk_context,
            &row.file_path,
            row.line,
            row.argument_index,
            &row.callee,
            &row.enclosing_function,
            target,
        )
        .await?
        {
            continue;
        }
        sites.push(HandoverSite {
            callee: row.callee.clone(),
            index: row.argument_index,
            file: row.file_path.clone(),
            line: row.line,
            enclosing: row.enclosing_function.clone(),
        });
    }
    // Dirty files: re-derive handover sites from the workdir call
    // inventory. The database holds no argument facts for uncommitted
    // text, so without this an edited file silently loses (or keeps) the
    // leg: an ordinary call retargeted in the workdir hands its new actual
    // with no row to say so. Sites in dropped slots stay silent.
    for file in db.overlay_dirty_files(&snapshot.git_sha) {
        for site in overlay_call_sites(db, snapshot, &file)? {
            if site.target != target {
                continue;
            }
            if snapshot.charge_work() {
                truncated = true;
                break;
            }
            if !site_is_live(db, snapshot, &file, site.line) {
                continue;
            }
            if !site_executes(
                db,
                snapshot,
                walk_context,
                &file,
                site.line,
                site.index,
                &site.callee,
                &site.enclosing,
                &site.target,
            )
            .await?
            {
                continue;
            }
            sites.push(HandoverSite {
                callee: site.callee.clone(),
                index: site.index,
                file: file.clone(),
                line: site.line,
                enclosing: site.enclosing.clone(),
            });
        }
    }
    // Dirty files: re-derive handover sites from overlay macro bodies. The
    // database holds no argument facts for uncommitted text, so without
    // this an edited header silently loses the leg. The invocation proof
    // still comes from admitted rows (committed or overlay); only the call
    // site is re-derived, at the overlay row's own line.
    for file in db.overlay_dirty_files(&snapshot.git_sha) {
        for row in db.overlay_macros_in_file(&file, &snapshot.git_sha) {
            if !is_macro_row(&row) {
                continue;
            }
            for (_, callee, actuals) in executing_calls(db, snapshot, &row, walk_context).await? {
                for (index, actual) in actuals.iter().enumerate() {
                    if actual.as_deref() != Some(target) {
                        continue;
                    }
                    if !site_is_live(db, snapshot, &file, row.line_start) {
                        continue;
                    }
                    sites.push(HandoverSite {
                        callee: callee.clone(),
                        index: index as u32,
                        file: file.clone(),
                        line: row.line_start,
                        enclosing: row.name.clone(),
                    });
                }
            }
        }
    }
    let mut legs: Vec<HandoverLeg> = Vec::new();
    let mut walk = ReverseWalk {
        db,
        snapshot,
        walk_context,
    };
    for site in &sites {
        let mut visited = std::collections::HashSet::new();
        walk.chain(
            site,
            &mut visited,
            &mut Vec::new(),
            &mut legs,
            &mut truncated,
            &mut depth_cut,
            None,
            &SubstMap::new(),
        )
        .await?;
    }
    legs.sort_by(|a, b| {
        a.macro_name
            .cmp(&b.macro_name)
            .then(a.outer.cmp(&b.outer))
            .then(a.site_file.cmp(&b.site_file))
            .then(a.site_line.cmp(&b.site_line))
    });
    legs.dedup_by(|a, b| {
        a.macro_name == b.macro_name
            && a.macro_line == b.macro_line
            && a.outer == b.outer
            && a.site_file == b.site_file
            && a.site_line == b.site_line
            && a.param == b.param
            && a.position == b.position
    });
    // A trip inside the last site's executability proof lists that site
    // under handed-not-reached with no other marker in the section.
    Ok((legs, truncated || snapshot.exhausted(), depth_cut))
}

/// The shared state of one reverse handover walk: database handles plus
/// the mutable depth budget. One walk per query; recursion reborrows it.
struct ReverseWalk<'a> {
    db: &'a DatabaseManager,
    snapshot: &'a ViaSnapshot,
    walk_context: crate::domain::Context,
}

impl ReverseWalk<'_> {
    /// One chain step: prove the value at this site reaches an invocation
    /// through the site's callee, threading pure forwarders. `outer`
    /// carries the pass-through hops so far, outermost first. `pack` is
    /// the current macro's pack state: `None` at the top (grounded from
    /// the site per row), threaded through each hop below, since repacking
    /// reshapes every absolute slot.
    #[allow(clippy::too_many_arguments)]
    async fn chain(
        &mut self,
        site: &HandoverSite,
        visited: &mut std::collections::HashSet<(String, String)>,
        outer: &mut Vec<OuterHop>,
        legs: &mut Vec<HandoverLeg>,
        truncated: &mut bool,
        depth_cut: &mut bool,
        pack: Option<PackState>,
        subst: &SubstMap,
    ) -> Result<()> {
        // Depth backstop beside the path-local visited set below.
        // Adversarial nesting stops here and says so: a cut chain is a
        // lower bound, never a complete answer.
        if self.snapshot.hop_depth() >= MAX_NAMED_HOPS {
            *depth_cut = true;
            return Ok(());
        }
        self.snapshot.note_hop();
        let rows = macro_rows_for(self.db, self.snapshot, &site.callee).await?;
        for m in &rows {
            // Each definition costs scope + invocation proofs below; a
            // cut stops the walk, and the flag says so.
            if self.snapshot.charge_work() {
                *truncated = true;
                break;
            }
            if !admit_definition(m, &rows, &site.file, self.walk_context) {
                continue;
            }
            // The call site must resolve this macro: its scope at the site
            // covers the definition.
            let live = scope_at_site(self.db, self.snapshot, &site.file, &m.name, site.line)
                .await?
                .is_some_and(|scope| scope.defines_at(&m.file_path, m.line_start));
            if !live {
                continue;
            }
            let invoked = invoked_params(self.db, self.snapshot, m, self.walk_context).await?;
            // The pack grounds per row: the site's trailing actuals shape
            // this macro's pack, and a redefinition may reshape it.
            let cur = pack.unwrap_or_else(|| {
                let vslot = variadic_slot(m).unwrap_or(usize::MAX);
                PackState {
                    pos: (site.index as usize >= vslot).then(|| site.index - vslot as u32),
                    width: site_pack_width(
                        self.db,
                        self.snapshot,
                        m,
                        &site.file,
                        site.line,
                        &site.callee,
                    ),
                }
            });
            if let Some((param, _)) = proved_position(&invoked, m, site.index) {
                // The proof assumes inner macros resolve; the leg stands
                // only where the invocation holds at this site. The proof
                // below threads through nested expansions, so it starts
                // with the macros already expanding above on its visited
                // set: the site macro and every outer hop (blue paint).
                let mut visited = std::collections::HashSet::new();
                visited.insert((m.name.clone(), String::new()));
                for hop in outer.iter() {
                    visited.insert((hop.macro_name.clone(), String::new()));
                }
                let held = Box::pin(param_invoked_inner(
                    self.db,
                    self.snapshot,
                    self.walk_context,
                    m,
                    &param,
                    &site.file,
                    site.line,
                    site.index,
                    cur,
                    subst,
                    &mut visited,
                ))
                .await?;
                if held {
                    legs.push(HandoverLeg {
                        macro_name: m.name.clone(),
                        macro_file: m.file_path.clone(),
                        macro_line: m.line_start,
                        macro_guard: m.guard.clone(),
                        param,
                        position: site.index,
                        site_file: site.file.clone(),
                        site_line: site.line,
                        enclosing: site.enclosing.clone(),
                        outer: outer.clone(),
                    });
                }
            }
            // Thread pure forwarders: the value at this slot flows on into any
            // body call handing the same parameter name to an invoked slot.
            // Past the last named parameter the value can only ride the
            // bundle, so it threads as `...` where this macro takes one.
            // A bundle marker hands on exactly where the `...` does.
            let Some(slot_param) = m
                .parameters
                .get(site.index as usize)
                .map(|p| p.name.clone())
                .or_else(|| {
                    let slot = variadic_slot(m)?;
                    (site.index as usize >= slot).then(|| "...".to_string())
                })
            else {
                continue;
            };
            let bundle_thread = slot_param == "...";
            let mut thread_visited = std::collections::HashSet::new();
            let thread_summary = summarize_macro(
                self.db,
                self.snapshot,
                m,
                self.walk_context,
                &mut thread_visited,
            )
            .await?;
            for (tree_idx, call) in thread_summary.tree.iter().enumerate() {
                if !thread_summary
                    .executing
                    .get(tree_idx)
                    .copied()
                    .unwrap_or(false)
                {
                    continue;
                }
                let (callee, actuals) = (call.callee.as_str(), &call.actuals);
                if callee == m.name || outer.iter().any(|hop| hop.macro_name == callee) {
                    // A self-named body call is never an expansion, and
                    // neither is a call to a macro already expanding above
                    // (blue paint): the value stops here.
                    continue;
                }
                for (slot, actual) in actuals.iter().enumerate() {
                    let hands_on = actual.as_deref() == Some(slot_param.as_str())
                        || (bundle_thread && actual.as_deref() == Some(BUNDLE_MARKER));
                    if !hands_on {
                        continue;
                    }
                    let marker = bundle_thread && actual.as_deref() == Some(BUNDLE_MARKER);
                    // The handing call itself must execute at the carried
                    // site: a forwarder nested in a slot the site's
                    // definitions drop hands nothing on, however it proves
                    // where the wrapper is defined.
                    if !call_executes_at_site(
                        self.db,
                        self.snapshot,
                        self.walk_context,
                        m,
                        tree_idx,
                        &site.file,
                        site.line,
                        site.index,
                        cur.width,
                        subst,
                        visited,
                    )
                    .await?
                    {
                        continue;
                    }
                    let next_rows = macro_rows_for(self.db, self.snapshot, callee).await?;
                    for next in &next_rows {
                        // Admission and liveness resolve at the carried
                        // invocation site, not at the wrapper's definition:
                        // the inner macro expands where the outer call
                        // runs, so a definition that postdates the wrapper
                        // (or dies before the site) binds there.
                        if !admit_definition(next, &next_rows, &site.file, self.walk_context) {
                            continue;
                        }
                        let next_live =
                            scope_at_site(self.db, self.snapshot, &site.file, callee, site.line)
                                .await?
                                .is_some_and(|scope| {
                                    scope.defines_at(&next.file_path, next.line_start)
                                });
                        if !next_live {
                            continue;
                        }
                        // Pack-relative landing, like the site proof: the
                        // next index is pack-encoded (fixed slots stay
                        // absolute; a pack lands at its offset past the
                        // next macro's `...` slot), and the recursion
                        // carries the next level's pack state.
                        for (landing, child_pack) in pack_landings(actuals, slot, marker, cur, next)
                        {
                            let next_index = match landing {
                                Landing::Fixed(inner_slot) => inner_slot as u32,
                                Landing::Pack(pos) => {
                                    let Some(vslot) = variadic_slot(next) else {
                                        continue;
                                    };
                                    vslot as u32 + pos
                                }
                            };
                            let key = (next.name.clone(), site.file.clone());
                            if !visited.insert(key.clone()) {
                                continue;
                            }
                            // The recursion carries the ORIGINAL call site, not
                            // the wrapper's position: liveness below must
                            // answer for where the value was handed, through
                            // every hop. The wrapper lands in `outer`.
                            let next_site = HandoverSite {
                                callee: callee.to_string(),
                                index: next_index,
                                file: site.file.clone(),
                                line: site.line,
                                enclosing: site.enclosing.clone(),
                            };
                            outer.push(OuterHop {
                                macro_name: m.name.clone(),
                                macro_file: m.file_path.clone(),
                                macro_line: m.line_start,
                                param: slot_param.clone(),
                                position: site.index,
                            });
                            let extended = extend_subst(subst, &m.name, actuals, next);
                            Box::pin(self.chain(
                                &next_site,
                                visited,
                                outer,
                                legs,
                                truncated,
                                depth_cut,
                                Some(child_pack),
                                &extended,
                            ))
                            .await?;
                            outer.pop();
                            visited.remove(&key);
                        }
                    }
                }
            }
        }
        self.snapshot.leave_hop();
        Ok(())
    }
}

/// Forward legs out of one macro definition row: its invoked parameters
/// joined to call sites handing an actual for that slot, by
/// file/hash/span/slot. The scope at each site must cover this definition.
pub async fn forward_legs_for_row(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    m: &crate::types::FunctionInfo,
    pin: crate::domain::Context,
) -> Result<(Vec<ForwardLeg>, bool)> {
    let invoked = invoked_params(db, snapshot, m, pin).await?;
    if invoked.is_empty() {
        // No invocations — or a trip before any resolved: the trip
        // silences every leg below, so it marks.
        return Ok((Vec::new(), snapshot.exhausted()));
    }
    let mut legs: Vec<ForwardLeg> = Vec::new();
    let mut truncated = false;
    for row in db.argument_rows_for_callee(&m.name).await? {
        // A `__VA_ARGS__` target is the caller's pack, not a value: it
        // never renders as a handed function.
        if row.target == BUNDLE_MARKER {
            continue;
        }
        // Charged like the reverse sites: thousands of call sites must
        // stop somewhere short of never.
        if snapshot.charge_work() {
            truncated = true;
            break;
        }
        if !row_in_snapshot(snapshot, &row.file_path, &row.git_file_hash, false) {
            continue;
        }
        if !site_is_live(db, snapshot, &row.file_path, row.line) {
            continue;
        }
        // The site itself must run: handing inside a dropped slot proves
        // nothing, in this direction too.
        if !site_executes(
            db,
            snapshot,
            pin,
            &row.file_path,
            row.line,
            row.argument_index,
            &m.name,
            &row.enclosing_function,
            &row.target,
        )
        .await?
        {
            continue;
        }
        let Some((param, _)) = proved_position(&invoked, m, row.argument_index) else {
            continue;
        };
        // A self-named body call is never an expansion: the preprocessor
        // does not re-expand a macro inside itself. No self-edge.
        if row.target == m.name {
            continue;
        }
        // The invocation must hold at this site, not just in the proof.
        let mut visited = std::collections::HashSet::new();
        if !Box::pin(param_invoked_at_site(
            db,
            snapshot,
            pin,
            m,
            &param,
            &row.file_path,
            row.line,
            row.argument_index,
            &m.name,
            &SubstMap::new(),
            &mut visited,
        ))
        .await?
        {
            continue;
        }
        let scope = scope_at_site(db, snapshot, &row.file_path, &m.name, row.line).await?;
        let live = scope
            .as_ref()
            .is_some_and(|scope| scope.defines_at(&m.file_path, m.line_start));
        if !live {
            continue;
        }
        legs.push(ForwardLeg {
            macro_name: m.name.clone(),
            macro_file: m.file_path.clone(),
            macro_line: m.line_start,
            macro_guard: m.guard.clone(),
            param,
            position: row.argument_index,
            actual: row.target.clone(),
            site_file: row.file_path.clone(),
            site_line: row.line,
            site_guard: scope.map(|scope| scope.guard).unwrap_or_default(),
            outer: None,
        });
    }
    // Dirty files: re-derive forward sites from overlay macro bodies. A new
    // call in uncommitted text hands actuals no table row records; the
    // overlay row's own line stands as the site.
    for file in db.overlay_dirty_files(&snapshot.git_sha) {
        for row in db.overlay_macros_in_file(&file, &snapshot.git_sha) {
            if !is_macro_row(&row) {
                continue;
            }
            for (_, callee, actuals) in executing_calls(db, snapshot, &row, pin).await? {
                if callee != m.name {
                    continue;
                }
                if !site_is_live(db, snapshot, &file, row.line_start) {
                    continue;
                }
                for (index, actual) in actuals.iter().enumerate() {
                    let position = index as u32;
                    let Some((param, _)) = invoked.iter().find(|(_, p)| *p == position).cloned()
                    else {
                        continue;
                    };
                    let Some(actual) = actual.as_deref() else {
                        continue;
                    };
                    if actual == m.name || actual == BUNDLE_MARKER {
                        continue;
                    }
                    let scope = scope_at_site(db, snapshot, &file, &m.name, row.line_start).await?;
                    let live = scope
                        .as_ref()
                        .is_some_and(|scope| scope.defines_at(&m.file_path, m.line_start));
                    if !live {
                        continue;
                    }
                    legs.push(ForwardLeg {
                        macro_name: m.name.clone(),
                        macro_file: m.file_path.clone(),
                        macro_line: m.line_start,
                        macro_guard: m.guard.clone(),
                        param,
                        position,
                        actual: actual.to_string(),
                        site_file: file.clone(),
                        site_line: row.line_start,
                        site_guard: scope.map(|scope| scope.guard).unwrap_or_default(),
                        outer: None,
                    });
                }
            }
        }
    }
    // Dirty files: ordinary calls from the workdir inventory. A retargeted
    // call hands its new actual with no committed row to say so; the
    // committed rows for the file stay suppressed above.
    for file in db.overlay_dirty_files(&snapshot.git_sha) {
        for site in overlay_call_sites(db, snapshot, &file)? {
            if site.callee != m.name {
                continue;
            }
            if snapshot.charge_work() {
                truncated = true;
                break;
            }
            let Some((param, _)) = proved_position(&invoked, m, site.index) else {
                continue;
            };
            if site.target == m.name {
                continue;
            }
            let mut visited = std::collections::HashSet::new();
            if !Box::pin(param_invoked_at_site(
                db,
                snapshot,
                pin,
                m,
                &param,
                &file,
                site.line,
                site.index,
                &m.name,
                &SubstMap::new(),
                &mut visited,
            ))
            .await?
            {
                continue;
            }
            if !site_executes(
                db,
                snapshot,
                pin,
                &file,
                site.line,
                site.index,
                &site.callee,
                &site.enclosing,
                &site.target,
            )
            .await?
            {
                continue;
            }
            let scope = scope_at_site(db, snapshot, &file, &m.name, site.line).await?;
            let live = scope
                .as_ref()
                .is_some_and(|scope| scope.defines_at(&m.file_path, m.line_start));
            if !live {
                continue;
            }
            legs.push(ForwardLeg {
                macro_name: m.name.clone(),
                macro_file: m.file_path.clone(),
                macro_line: m.line_start,
                macro_guard: m.guard.clone(),
                param,
                position: site.index,
                actual: site.target.clone(),
                site_file: file.clone(),
                site_line: site.line,
                site_guard: scope.map(|scope| scope.guard).unwrap_or_default(),
                outer: None,
            });
        }
    }
    legs.sort_by(|a, b| {
        a.actual
            .cmp(&b.actual)
            .then(a.site_file.cmp(&b.site_file))
            .then(a.site_line.cmp(&b.site_line))
    });
    legs.dedup_by(|a, b| {
        a.macro_name == b.macro_name
            && a.actual == b.actual
            && a.param == b.param
            && a.position == b.position
            && a.site_file == b.site_file
            && a.site_line == b.site_line
    });
    Ok((legs, truncated))
}

/// The full reverse closure for one name: ordinary (function) callers, macro
/// layers with macro callers expanded while the caller is a macro, and
/// proved handover legs. Path-local visited set; named-hop cap with a
/// truncation flag.
pub struct ReverseClosure {
    pub ordinary: Vec<(String, String)>,
    pub via_nodes: Vec<ViaNode>,
    pub handovers: Vec<HandoverLeg>,
    pub truncated: bool,
    /// A nesting cut stopped some chain: lower bounds, never completeness.
    pub depth_cut: bool,
}

pub async fn reverse_closure(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    target: &str,
    walk_context: crate::domain::Context,
    visited: &mut std::collections::HashSet<(String, String)>,
) -> Result<ReverseClosure> {
    let mut closure = ReverseClosure {
        ordinary: Vec::new(),
        via_nodes: Vec::new(),
        handovers: Vec::new(),
        truncated: false,
        depth_cut: false,
    };
    let (handovers, handover_truncated, handover_depth) =
        reverse_handover_legs(db, snapshot, target, walk_context).await?;
    closure.handovers = handovers;
    closure.truncated = handover_truncated;
    closure.depth_cut = handover_depth;
    let mut nodes = reverse_body_layer(db, snapshot, target, walk_context).await?;
    let mut node_truncated = false;
    let mut node_depth = false;
    for node in &mut nodes {
        if snapshot.hop_depth() >= MAX_NAMED_HOPS {
            // A nesting cut, not a work cut: its own marker below.
            node.depth_cut = true;
            node_depth = true;
            continue;
        }
        // Partition this macro's callers: functions stop the branch,
        // macros recurse. One batched classification for the partition.
        let caller_names: Vec<String> = node.callers.iter().map(|(name, _)| name.clone()).collect();
        let (macros, truncated) = classify_frontier(db, snapshot, &caller_names).await?;
        node_truncated = node_truncated || truncated;
        let mut functions: Vec<(String, String)> = Vec::new();
        let mut macro_names: Vec<String> = Vec::new();
        for (caller, file) in std::mem::take(&mut node.callers) {
            if macros.contains_key(&caller) {
                macro_names.push(caller);
            } else if !truncated {
                // Unclassified under a cut is neither proven function
                // nor proven macro: keeping it would assert a reach-through
                // the proof never examined. The truncation flag above marks
                // the silence.
                functions.push((caller, file));
            }
        }
        functions.sort();
        functions.dedup();
        node.callers = functions;
        macro_names.sort();
        macro_names.dedup();
        // Narrow the context as the walk enters an arch: deeper hops stay
        // inside the architecture this hop landed in.
        let caller_domain = crate::domain::domain_of(&node.hop.file_path);
        let child_context = match walk_context {
            crate::domain::Context::Any => crate::domain::Context::In(caller_domain),
            pinned => pinned,
        };
        snapshot.note_hop();
        for macro_name in macro_names {
            // Breadth is unbounded (only depth has a backstop): each arm
            // charges, and a cut keeps the arms done so far, marked.
            if snapshot.charge_work() {
                node_truncated = true;
                break;
            }
            let key = (macro_name.clone(), node.hop.file_path.clone());
            if !visited.insert(key.clone()) {
                continue;
            }
            let mut deeper = Box::pin(reverse_closure(
                db,
                snapshot,
                &macro_name,
                child_context,
                visited,
            ))
            .await?;
            closure.handovers.append(&mut deeper.handovers);
            node_truncated = node_truncated || deeper.truncated;
            node_depth = node_depth || deeper.depth_cut;
            // The macro caller nests as its own node: the recursive
            // result's ordinary callers reach through it, and flattening
            // the deeper nodes while dropping them loses the chain's
            // terminal callers (f → M2 → M1 → t must keep f under M2).
            // Without an admitted definition that calls this hop, the
            // whole subtree through this name goes with it.
            let rows = macro_rows_for(db, snapshot, &macro_name).await?;
            let mut calling: Vec<&crate::types::FunctionInfo> = rows
                .iter()
                .filter(|row| row_calls_target(row, &node.hop.macro_name))
                .filter(|row| admit_definition(row, &rows, &node.hop.file_path, child_context))
                .collect();
            if calling.is_empty() {
                visited.remove(&key);
                continue;
            }
            calling.sort_by(|a, b| {
                (a.file_path.clone(), a.line_start).cmp(&(b.file_path.clone(), b.line_start))
            });
            let first = calling[0];
            let mut guards: Vec<String> = calling
                .iter()
                .filter_map(|row| row.guard.clone())
                .filter(|guard| !guard.is_empty())
                .collect();
            guards.sort();
            guards.dedup();
            node.deeper.push(ViaNode {
                hop: ViaHop {
                    macro_name: macro_name.clone(),
                    file_path: first.file_path.clone(),
                    line: first.line_start,
                    guard: if guards.is_empty() {
                        None
                    } else {
                        Some(guards.join(" || "))
                    },
                },
                callers: {
                    // Ordinary callers reach through this macro only
                    // where it expands at their site: the recursion
                    // lists name-callers unproven (a weaker claim, fine
                    // at the top level), but a via node asserts
                    // reach-through. A spent budget drops the unproven.
                    let filter_was = snapshot.classified();
                    let mut proven: Vec<(String, String)> = Vec::new();
                    for (caller, file) in std::mem::take(&mut deeper.ordinary) {
                        if Box::pin(named_edge_expands(
                            db,
                            snapshot,
                            child_context,
                            &file,
                            &caller,
                            &macro_name,
                        ))
                        .await?
                        {
                            proven.push((caller, file));
                        }
                    }
                    node_truncated = node_truncated || snapshot.tripped_since(filter_was);
                    proven
                },
                deeper: std::mem::take(&mut deeper.via_nodes),
                truncated: deeper.truncated,
                depth_cut: deeper.depth_cut,
            });
            visited.remove(&key);
        }
        snapshot.leave_hop();
    }
    // Ordinary callers of the target: every caller no macro layer claimed.
    let mut pairs: Vec<(String, String)> = db
        .get_function_callers_with_manifest(target, &snapshot.manifest)
        .await?;
    for row in db.overlay_callers_of(target, &snapshot.git_sha) {
        pairs.push((row.name.clone(), row.file_path.clone()));
    }
    let (macros, truncated) = classify_frontier(
        db,
        snapshot,
        &pairs
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>(),
    )
    .await?;
    node_truncated = node_truncated || truncated;
    for (caller, file) in pairs {
        // Unclassified under a cut is unproven: a macro caller kept
        // here would print as an ordinary caller downstream. The flag
        // above marks the silence.
        if !truncated && !macros.contains_key(&caller) {
            closure.ordinary.push((caller, file));
        }
    }
    closure.ordinary.sort();
    closure.ordinary.dedup();
    prune_husk_nodes(&mut nodes);
    closure.via_nodes = nodes;
    closure.truncated = handover_truncated || node_truncated || snapshot.exhausted();
    closure.depth_cut = closure.depth_cut || handover_depth || node_depth;
    Ok(closure)
}

/// Forward closure out of one macro row: handover legs at every live call
/// site, recursing into actuals that are themselves macros, plus the
/// nested legs where the body hands a parameter to another macro that
/// invokes it. The inner macro resolves at the top-level invocation
/// position, carried through every nesting level in `subst` — never at
/// its textual spot in the outer definition. Every leg's definition is
/// admitted for its own site's build before it renders.
pub struct ForwardClosure {
    pub legs: Vec<ForwardLeg>,
    pub truncated: bool,
    /// Legs before the breadth backstop cut them: the display counts what
    /// the reader does not see honestly.
    pub total_legs: usize,
}

pub async fn forward_closure(
    db: &DatabaseManager,
    snapshot: &ViaSnapshot,
    m: &crate::types::FunctionInfo,
    pin: crate::domain::Context,
    visited: &mut std::collections::HashSet<(String, String)>,
    subst: &std::collections::HashMap<String, ResolvedActual>,
) -> Result<ForwardClosure> {
    let mut walk = ForwardWalk {
        db,
        snapshot,
        pin,
        visited,
        subst: subst.clone(),
    };
    walk.closure(m).await
}

/// The shared state of one forward walk: database handles plus the
/// mutable budgets and the substitution an outer level resolved. One walk
/// per nesting level; a child walk reborrows the budgets and carries its
/// own substitution.
struct ForwardWalk<'a> {
    db: &'a DatabaseManager,
    snapshot: &'a ViaSnapshot,
    pin: crate::domain::Context,
    visited: &'a mut std::collections::HashSet<(String, String)>,
    subst: std::collections::HashMap<String, ResolvedActual>,
}

/// One nested handover site: the outer row handing through, the inner row
/// invoked, and which parameter slot carries the actual.
struct NestedSite<'x> {
    outer: &'x crate::types::FunctionInfo,
    row: &'x crate::types::FunctionInfo,
    rows: &'x [crate::types::FunctionInfo],
    /// The name the outer body actually calls: through an object alias
    /// this differs from the row, and the alias must still resolve to
    /// the row at the carried site.
    callee: &'x str,
    param: &'x str,
    position: u32,
}

/// One invocation site of a macro: the actuals handed per parameter slot
/// (`None` where the site passes a literal or an expression), with the
/// site's own location and guard. Rows group by file and line; a site is
/// kept only where this definition is live.
type SiteGroup = std::collections::HashMap<(String, u32), Vec<(u32, String, String)>>;

struct OuterSite {
    file: String,
    line: u32,
    guard: String,
    actuals: Vec<Option<String>>,
    enclosing: String,
}

/// Split one file/line group's rows into per-call actual vectors. Rows
/// sharing an index with different targets are twin calls on one line
/// (`RUN(a); RUN(b)`), not one call, so each conflicting row starts its
/// own call instead of overwriting its twin's actual. Duplicate rows
/// merge into the call they match.
fn split_call_groups(
    rows: &[(u32, String, String)],
    width: usize,
) -> Vec<(Vec<Option<String>>, String)> {
    let mut calls: Vec<(Vec<Option<String>>, String)> = Vec::new();
    for (index, target, enclosing) in rows {
        // A `__VA_ARGS__` target is the caller's pack, not a value: it
        // leaves a hole, never a pseudo-actual.
        if target == BUNDLE_MARKER {
            continue;
        }
        let slot = *index as usize;
        let placed = calls.iter_mut().find(|(actuals, _)| {
            slot < actuals.len() && actuals[slot].as_deref().is_none_or(|t| t == target)
        });
        match placed {
            Some((actuals, _)) => {
                actuals[slot] = Some(target.clone());
            }
            None => {
                let mut actuals: Vec<Option<String>> = vec![None; width];
                if slot < width {
                    actuals[slot] = Some(target.clone());
                }
                calls.push((actuals, enclosing.clone()));
            }
        }
    }
    calls
}

impl ForwardWalk<'_> {
    fn child(
        &mut self,
        subst: std::collections::HashMap<String, ResolvedActual>,
    ) -> ForwardWalk<'_> {
        ForwardWalk {
            db: self.db,
            snapshot: self.snapshot,
            pin: self.pin,
            visited: &mut *self.visited,
            subst,
        }
    }

    /// Root the closure: depth budget, direct legs, nested legs, then a
    /// stable order with dedupe and the breadth backstop.
    async fn closure(&mut self, m: &crate::types::FunctionInfo) -> Result<ForwardClosure> {
        let mut closure = ForwardClosure {
            legs: Vec::new(),
            truncated: false,
            total_legs: 0,
        };
        if self.snapshot.hop_depth() >= MAX_NAMED_HOPS {
            closure.truncated = true;
            return Ok(closure);
        }
        self.snapshot.note_hop();
        let all_rows = macro_rows_for(self.db, self.snapshot, &m.name).await?;
        self.direct_legs(m, &all_rows, &mut closure).await?;
        self.nested_legs(m, &mut closure).await?;
        closure.legs.sort_by(|a, b| {
            (
                &a.macro_name,
                &a.macro_file,
                a.macro_line,
                &a.actual,
                &a.site_file,
                a.site_line,
            )
                .cmp(&(
                    &b.macro_name,
                    &b.macro_file,
                    b.macro_line,
                    &b.actual,
                    &b.site_file,
                    b.site_line,
                ))
        });
        closure.legs.dedup_by(|a, b| {
            a.macro_name == b.macro_name
                && a.macro_file == b.macro_file
                && a.macro_line == b.macro_line
                && a.actual == b.actual
                && a.param == b.param
                && a.position == b.position
                && a.site_file == b.site_file
                && a.site_line == b.site_line
        });
        // A cut anywhere below silences legs the display would show:
        // mark even where the legs that did render fit the cap.
        closure.truncated = closure.truncated || self.snapshot.exhausted();
        if closure.legs.len() > MAX_FORWARD_LEGS {
            closure.total_legs = closure.legs.len();
            closure.legs.truncate(MAX_FORWARD_LEGS);
            closure.truncated = true;
        } else {
            closure.total_legs = closure.legs.len();
        }
        self.snapshot.leave_hop();
        Ok(closure)
    }

    /// Direct legs for one row: handover legs at every live call site
    /// admitted per site, plus the recursion into actuals that are
    /// themselves macros.
    async fn direct_legs(
        &mut self,
        m: &crate::types::FunctionInfo,
        all_rows: &[crate::types::FunctionInfo],
        closure: &mut ForwardClosure,
    ) -> Result<()> {
        let (row_legs, row_truncated) =
            forward_legs_for_row(self.db, self.snapshot, m, self.pin).await?;
        closure.truncated = closure.truncated || row_truncated;
        for leg in row_legs {
            if admit_definition(m, all_rows, &leg.site_file, self.pin) {
                closure.legs.push(leg.clone());
            }
            // A macro handed as an actual resolves inside its own closure,
            // never here: the deeper walk re-grounds at every site of the
            // inner macro, and those legs' chains bypass this row — listing
            // them claims flows that never pass through it (`M(INNER)`
            // beside `INNER(alpha)` shows `alpha` under `M`). The handed
            // macro itself still lists above; its own node carries its
            // legs. Grounding the inner walk at this site's actuals would
            // recover the linked flow, but no leg records which body call
            // invoked the parameter, so there is nothing sound to ground
            // with.
        }
        Ok(())
    }

    /// Nested legs: the body hands one of this row's parameters to another
    /// macro that invokes it. Concrete body actuals already surface as rows
    /// at their own sites, so only handed-through parameters need
    /// resolving. Pasted actuals stay silent; the `##__VA_ARGS__` elision
    /// reads as the bundle marker and forwards each trailing actual.
    async fn nested_legs(
        &mut self,
        m: &crate::types::FunctionInfo,
        closure: &mut ForwardClosure,
    ) -> Result<()> {
        for (tree_idx, callee, actuals) in
            executing_calls(self.db, self.snapshot, m, self.pin).await?
        {
            if callee == m.name {
                // A self-named body call is never an expansion.
                continue;
            }
            let (rows, _scope_name, _cut) = alias_macro_rows(
                self.db,
                self.snapshot,
                self.pin,
                &m.file_path,
                m.line_start,
                &callee,
            )
            .await?;
            if rows.is_empty() {
                continue;
            }
            if self.snapshot.charge_many(rows.len()) {
                closure.truncated = true;
                break;
            }
            for row in &rows {
                if !admit_definition(row, &rows, &m.file_path, self.pin) {
                    continue;
                }
                let invoked = invoked_params(self.db, self.snapshot, row, self.pin).await?;
                for (param, position) in &invoked {
                    // A splice before the slot shifts it by the pack width,
                    // which this walk does not track: the syntactic landing
                    // is unprovable here, exactly as in the reverse twin.
                    // Slots before any splice still land.
                    if actuals
                        .iter()
                        .take(*position as usize)
                        .any(|actual| actual.as_deref() == Some(BUNDLE_MARKER))
                    {
                        continue;
                    }
                    let Some(name_at) = actuals.get(*position as usize).and_then(|a| a.as_deref())
                    else {
                        continue;
                    };
                    if name_at == BUNDLE_MARKER {
                        // A pack element spliced here lands by offset from
                        // its pack position, never at the splice's own
                        // slot: only an invoked landing emits.
                        for cand in self.resolve_actual(m, name_at).await? {
                            let Some(pos) = cand.pack_pos else {
                                continue;
                            };
                            let landing = position + pos;
                            let Some((landed, _)) =
                                invoked.iter().find(|(_, p)| *p == landing).cloned()
                            else {
                                continue;
                            };
                            // A concrete name's own rows already carry it.
                            let site = NestedSite {
                                outer: m,
                                row,
                                rows: &rows,
                                callee: &callee,
                                param: &landed,
                                position: landing,
                            };
                            if !self.intermediate_expands(m, tree_idx, &cand).await? {
                                continue;
                            }
                            self.emit_leg(&site, &cand, closure).await?;
                        }
                        continue;
                    }
                    // A concrete name's own rows already carry it.
                    let site = NestedSite {
                        outer: m,
                        row,
                        rows: &rows,
                        callee: &callee,
                        param,
                        position: *position,
                    };
                    for cand in self.resolve_actual(m, name_at).await? {
                        if !self.intermediate_expands(m, tree_idx, &cand).await? {
                            continue;
                        }
                        self.emit_leg(&site, &cand, closure).await?;
                    }
                }
                // Pure forwarders invoke nothing themselves: without a
                // per-site recursion the walk stalls at them (OUT → MID →
                // INNER never reaches INNER). Thread every parameter
                // through each live outer site and recurse nested-only;
                // the row's own direct legs belong to its own tree node.
                // A concrete body actual has no call site of its own: its
                // rows carry it where recorded, so only parameters map.
                for site in self.outer_sites(m).await? {
                    let key = (row.name.clone(), format!("{}:{}", site.file, site.line));
                    if !self.visited.insert(key.clone()) {
                        // A back-edge: this row at this site is already on
                        // the stack above. The regress below repeats legs
                        // already unfolding, so cut — and say so, or a
                        // cyclic forwarder chain reads complete.
                        closure.truncated = true;
                        continue;
                    }
                    let mut mapping = self.subst.clone();
                    // Bundle slots fan out: one recursion per trailing
                    // actual, capped — the mapping holds one value per
                    // parameter, and the bundle is many.
                    let mut bundles: Vec<(String, Vec<ResolvedActual>)> = Vec::new();
                    for (slot, param) in row.parameters.iter().enumerate() {
                        let Some(name_at) = actuals.get(slot).and_then(|a| a.as_deref()) else {
                            continue;
                        };
                        if let Some(hit) = self.subst.get(name_at) {
                            mapping.insert(param.name.clone(), hit.clone());
                        } else if name_at == BUNDLE_MARKER && variadic_slot(m).is_some() {
                            let slot = variadic_slot(m).unwrap_or(0);
                            let mut trailing: Vec<ResolvedActual> = Vec::new();
                            for (index, actual) in site.actuals.iter().enumerate() {
                                if index < slot {
                                    continue;
                                }
                                if trailing.len() >= MAX_FORWARD_LEGS {
                                    // The pack fans out wider than the
                                    // display cap: cut and say so.
                                    closure.truncated = true;
                                    break;
                                }
                                if let Some(actual) = actual.clone() {
                                    trailing.push(ResolvedActual {
                                        actual,
                                        site_file: site.file.clone(),
                                        site_line: site.line,
                                        site_guard: site.guard.clone(),
                                        site_index: index as u32,
                                        // The pack position counts every
                                        // trailing actual, named or not: a
                                        // complex actual still occupies its
                                        // slot when the pack splices.
                                        pack_pos: Some(index as u32 - slot as u32),
                                        site_callee: m.name.clone(),
                                        site_enclosing: site.enclosing.clone(),
                                    });
                                }
                            }
                            if !trailing.is_empty() {
                                bundles.push((param.name.clone(), trailing));
                            }
                        } else if let Some(r) = m.parameters.iter().position(|p| p.name == name_at)
                        {
                            if let Some(actual) = site.actuals.get(r).cloned().flatten() {
                                mapping.insert(
                                    param.name.clone(),
                                    ResolvedActual {
                                        actual,
                                        site_file: site.file.clone(),
                                        site_line: site.line,
                                        site_guard: site.guard.clone(),
                                        site_index: r as u32,
                                        pack_pos: None,
                                        site_callee: m.name.clone(),
                                        site_enclosing: site.enclosing.clone(),
                                    },
                                );
                            }
                        }
                    }
                    if bundles.is_empty() {
                        if self
                            .retain_expanding(m, tree_idx, &callee, row, &mut mapping)
                            .await?
                        {
                            let mut child = self.child(mapping);
                            Box::pin(child.nested_legs(row, closure)).await?;
                        }
                    } else {
                        let depth = bundles
                            .iter()
                            .map(|(_, trailing)| trailing.len())
                            .max()
                            .unwrap_or(0);
                        for i in 0..depth {
                            let mut mapping = mapping.clone();
                            for (param, trailing) in &bundles {
                                if let Some(candidate) = trailing.get(i) {
                                    mapping.insert(param.clone(), candidate.clone());
                                }
                            }
                            if self
                                .retain_expanding(m, tree_idx, &callee, row, &mut mapping)
                                .await?
                            {
                                let mut child = self.child(mapping);
                                Box::pin(child.nested_legs(row, closure)).await?;
                            }
                        }
                    }
                    self.visited.remove(&key);
                }
            }
        }
        Ok(())
    }

    /// Drop mapping entries riding sites where the intermediate body
    /// call never expands: values handed there prove nothing below.
    /// True where anything survives for the recursion.
    async fn retain_expanding(
        &self,
        m: &crate::types::FunctionInfo,
        tree_idx: usize,
        callee: &str,
        row: &crate::types::FunctionInfo,
        mapping: &mut std::collections::HashMap<String, ResolvedActual>,
    ) -> Result<bool> {
        let mut dead = Vec::new();
        for (param, cand) in mapping.iter() {
            if !self.intermediate_expands(m, tree_idx, cand).await? {
                dead.push(param.clone());
                continue;
            }
            // The intermediate callee must still name this row where the
            // value rides: a rebound (`MID` → 0) ends the hop even though
            // the call text still stands. Re-resolve at the carried site
            // and require this row, live, among the answer.
            let (site_rows, scope_name, _cut) = alias_macro_rows(
                self.db,
                self.snapshot,
                self.pin,
                &cand.site_file,
                cand.site_line,
                callee,
            )
            .await?;
            let names_row = site_rows.iter().any(|site_row| {
                site_row.file_path == row.file_path && site_row.line_start == row.line_start
            });
            let live = names_row
                && scope_at_site(
                    self.db,
                    self.snapshot,
                    &cand.site_file,
                    &scope_name,
                    cand.site_line,
                )
                .await?
                .is_some_and(|scope| scope.defines_at(&row.file_path, row.line_start));
            if !live {
                dead.push(param.clone());
            }
        }
        for param in dead {
            mapping.remove(&param);
        }
        Ok(!mapping.is_empty())
    }

    /// Every live invocation site of this row, grouped by file and line:
    /// one entry per call, with the actual handed per parameter slot
    /// (`None` where the site passes a literal or an expression).
    async fn outer_sites(&self, m: &crate::types::FunctionInfo) -> Result<Vec<OuterSite>> {
        let mut groups: SiteGroup = std::collections::HashMap::new();
        for site in self.db.argument_rows_for_callee(&m.name).await? {
            if !row_in_snapshot(self.snapshot, &site.file_path, &site.git_file_hash, false) {
                continue;
            }
            groups
                .entry((site.file_path.clone(), site.line))
                .or_default()
                .push((
                    site.argument_index,
                    site.target.clone(),
                    site.enclosing_function.clone(),
                ));
        }
        let mut keys: Vec<(String, u32)> = groups.keys().cloned().collect();
        keys.sort();
        let mut sites: Vec<OuterSite> = Vec::new();
        for (file, line) in keys {
            let scope = scope_at_site(self.db, self.snapshot, &file, &m.name, line).await?;
            let live = scope
                .as_ref()
                .is_some_and(|scope| scope.defines_at(&m.file_path, m.line_start));
            if !live {
                continue;
            }
            if !site_is_live(self.db, self.snapshot, &file, line) {
                continue;
            }
            // Trailing variadic actuals sit past the last named parameter;
            // size for them so the bundle mapping can see each one.
            let rows = &groups[&(file.clone(), line)];
            let widest = rows
                .iter()
                .map(|(index, _, _)| *index as usize + 1)
                .max()
                .unwrap_or(0);
            let width = m.parameters.len().max(widest);
            let guard = scope.map(|scope| scope.guard).unwrap_or_default();
            for (actuals, enclosing) in split_call_groups(rows, width) {
                sites.push(OuterSite {
                    guard: guard.clone(),
                    file: file.clone(),
                    line,
                    actuals,
                    enclosing,
                });
            }
        }
        // Dirty files: the committed rows above go silent there, so the
        // workdir inventory replaces them — a retargeted call keeps its
        // nested forward chain instead of losing it.
        let mut overlay_groups: SiteGroup = std::collections::HashMap::new();
        for file in self.db.overlay_dirty_files(&self.snapshot.git_sha) {
            for site in overlay_call_sites(self.db, self.snapshot, &file)? {
                if site.callee != m.name {
                    continue;
                }
                overlay_groups
                    .entry((file.clone(), site.line))
                    .or_default()
                    .push((site.index, site.target.clone(), site.enclosing.clone()));
            }
        }
        let mut overlay_keys: Vec<(String, u32)> = overlay_groups.keys().cloned().collect();
        overlay_keys.sort();
        for (file, line) in overlay_keys {
            let scope = scope_at_site(self.db, self.snapshot, &file, &m.name, line).await?;
            let live = scope
                .as_ref()
                .is_some_and(|scope| scope.defines_at(&m.file_path, m.line_start));
            if !live {
                continue;
            }
            if !site_is_live(self.db, self.snapshot, &file, line) {
                continue;
            }
            let rows = &overlay_groups[&(file.clone(), line)];
            let widest = rows
                .iter()
                .map(|(index, _, _)| *index as usize + 1)
                .max()
                .unwrap_or(0);
            let width = m.parameters.len().max(widest);
            let guard = scope.map(|scope| scope.guard).unwrap_or_default();
            for (actuals, enclosing) in split_call_groups(rows, width) {
                sites.push(OuterSite {
                    guard: guard.clone(),
                    file: file.clone(),
                    line,
                    actuals,
                    enclosing,
                });
            }
        }
        Ok(sites)
    }

    /// Resolve one body actual handed to an inner macro: an outer
    /// substitution first, else every live call site of this row for that
    /// parameter slot. The bundle marker resolves to every trailing site
    /// actual at or past the `...` slot.
    async fn resolve_actual(
        &self,
        m: &crate::types::FunctionInfo,
        name_at: &str,
    ) -> Result<Vec<ResolvedActual>> {
        let mut candidates: Vec<ResolvedActual> = Vec::new();
        if let Some(hit) = self.subst.get(name_at) {
            candidates.push(hit.clone());
            return Ok(candidates);
        }
        let bundle = name_at == BUNDLE_MARKER && variadic_slot(m).is_some();
        let Some(slot) = (if bundle {
            variadic_slot(m)
        } else {
            m.parameters.iter().position(|p| p.name == name_at)
        }) else {
            return Ok(candidates);
        };
        for site in self.db.argument_rows_for_callee(&m.name).await? {
            if !bundle && site.argument_index != slot as u32 {
                continue;
            }
            if bundle && (site.argument_index as usize) < slot {
                continue;
            }
            if !row_in_snapshot(self.snapshot, &site.file_path, &site.git_file_hash, false) {
                continue;
            }
            // A `__VA_ARGS__` target is the caller's pack, not a value.
            if site.target == BUNDLE_MARKER {
                continue;
            }
            if !site_is_live(self.db, self.snapshot, &site.file_path, site.line) {
                continue;
            }
            let scope =
                scope_at_site(self.db, self.snapshot, &site.file_path, &m.name, site.line).await?;
            let live = scope
                .as_ref()
                .is_some_and(|scope| scope.defines_at(&m.file_path, m.line_start));
            if !live {
                continue;
            }
            candidates.push(ResolvedActual {
                actual: site.target.clone(),
                site_file: site.file_path.clone(),
                site_line: site.line,
                site_guard: scope.map(|scope| scope.guard).unwrap_or_default(),
                site_index: site.argument_index,
                pack_pos: bundle.then(|| site.argument_index - slot as u32),
                site_callee: m.name.clone(),
                site_enclosing: site.enclosing_function.clone(),
            });
        }
        // Dirty files: the committed rows above go silent there, so the
        // workdir inventory replaces them.
        for file in self.db.overlay_dirty_files(&self.snapshot.git_sha) {
            for site in overlay_call_sites(self.db, self.snapshot, &file)? {
                if site.callee != m.name {
                    continue;
                }
                if !bundle && site.index != slot as u32 {
                    continue;
                }
                if bundle && (site.index as usize) < slot {
                    continue;
                }
                // A `__VA_ARGS__` target is the caller's pack, not a value.
                if site.target == BUNDLE_MARKER {
                    continue;
                }
                if !site_is_live(self.db, self.snapshot, &file, site.line) {
                    continue;
                }
                let scope =
                    scope_at_site(self.db, self.snapshot, &file, &m.name, site.line).await?;
                let live = scope
                    .as_ref()
                    .is_some_and(|scope| scope.defines_at(&m.file_path, m.line_start));
                if !live {
                    continue;
                }
                candidates.push(ResolvedActual {
                    actual: site.target.clone(),
                    site_file: file.clone(),
                    site_line: site.line,
                    site_guard: scope.map(|scope| scope.guard).unwrap_or_default(),
                    site_index: site.index,
                    pack_pos: bundle.then(|| site.index - slot as u32),
                    site_callee: m.name.clone(),
                    site_enclosing: site.enclosing.clone(),
                });
            }
        }
        Ok(candidates)
    }

    /// Emit one nested leg. The deeper cascade arrives through the
    /// per-site recursion in `nested_legs`, never here, so one leg is one
    /// handover at one site.
    /// Whether the intermediate body call at `tree_idx` expands at the
    /// candidate's site: every ancestor slot between it and the top must
    /// evaluate there. The body proof alone is not enough — an ancestor
    /// macro redefined to drop its slot between the wrapper's definition
    /// and the call site never expands the subtree, however live it looks
    /// where the wrapper is defined. Unknowable keeps the leg.
    async fn intermediate_expands(
        &self,
        m: &crate::types::FunctionInfo,
        tree_idx: usize,
        cand: &ResolvedActual,
    ) -> Result<bool> {
        let mut visited = std::collections::HashSet::new();
        call_executes_at_site(
            self.db,
            self.snapshot,
            self.pin,
            m,
            tree_idx,
            &cand.site_file,
            cand.site_line,
            cand.site_index,
            // The walk passes no pack width for the site: pack-unknown
            // ancestors keep the leg, like every other width-unknown
            // proof.
            None,
            &SubstMap::new(),
            &mut visited,
        )
        .await
    }

    async fn emit_leg(
        &self,
        site: &NestedSite<'_>,
        cand: &ResolvedActual,
        closure: &mut ForwardClosure,
    ) -> Result<()> {
        let row = site.row;
        if cand.actual == row.name {
            // A self-named actual is never an expansion.
            return Ok(());
        }
        if !admit_definition(row, site.rows, &cand.site_file, self.pin) {
            return Ok(());
        }
        // The inner macro must be live where the outer call expands it:
        // an `#undef` between the definition and the carried site ends it
        // exactly like a direct call there.
        let live = scope_at_site(
            self.db,
            self.snapshot,
            &cand.site_file,
            &row.name,
            cand.site_line,
        )
        .await?
        .is_some_and(|scope| scope.defines_at(&row.file_path, row.line_start));
        if !live {
            return Ok(());
        }
        // The body holds the callee, not the row: where the hop runs
        // through an object alias, the alias must still resolve to this
        // row at the carried site. An `#undef` there ends the hop even
        // though the final row is still live (`OUT` through a rebound
        // `ALIAS` hands a pointer, never invokes it).
        let (site_rows, _, _) = alias_macro_rows(
            self.db,
            self.snapshot,
            self.pin,
            &cand.site_file,
            cand.site_line,
            site.callee,
        )
        .await?;
        if !site_rows.iter().any(|site_row| {
            site_row.file_path == row.file_path && site_row.line_start == row.line_start
        }) {
            return Ok(());
        }
        // The candidate site itself must run: a value handed inside a
        // dropped slot never expands into this leg, in this direction
        // too. The direct legs gate the same way; nested legs carry
        // their own site with them.
        if !site_executes(
            self.db,
            self.snapshot,
            self.pin,
            &cand.site_file,
            cand.site_line,
            cand.site_index,
            &cand.site_callee,
            &cand.site_enclosing,
            &cand.actual,
        )
        .await?
        {
            return Ok(());
        }
        // And it must invoke the parameter at the carried site, not just
        // in the body proof: a redefinition that drops the slot between
        // the wrapper and the site, the leg ends there exactly like the
        // reverse direction.
        let mut visited = std::collections::HashSet::new();
        if !Box::pin(param_invoked_at_site(
            self.db,
            self.snapshot,
            self.pin,
            row,
            site.param,
            &cand.site_file,
            cand.site_line,
            cand.site_index,
            &cand.site_callee,
            &SubstMap::new(),
            &mut visited,
        ))
        .await?
        {
            return Ok(());
        }
        closure.legs.push(ForwardLeg {
            macro_name: row.name.clone(),
            macro_file: row.file_path.clone(),
            macro_line: row.line_start,
            macro_guard: row.guard.clone(),
            param: site.param.to_string(),
            position: site.position,
            actual: cand.actual.clone(),
            site_file: cand.site_file.clone(),
            site_line: cand.site_line,
            site_guard: cand.site_guard.clone(),
            outer: Some((
                site.outer.name.clone(),
                site.outer.file_path.clone(),
                site.outer.line_start,
            )),
        });
        Ok(())
    }
}

/// Cut a `#define` header, leaving the replacement list: the text after the
/// parameter list's closing paren, or after the name for object-like
/// defines. `None` where the header does not parse.
/// Scrub GNU `, ##__VA_ARGS__` elision so lent macro text parses as C: a
/// paste opening an argument (`(##x`, `, ##x`) becomes a `0` placeholder —
/// the value is unknowable, but the call structure and arity survive. A
/// paste anywhere else (notably a pasted callee like `A##B()`) is left
/// alone: the callee is unknowable, so that subtree keeps its silence.
/// Stringize (`#x`) is out of scope: untouched.
fn scrub_gnu_elision(body: &str) -> String {
    let bytes = body.as_bytes();
    let mut out = String::with_capacity(body.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let paste = bytes[i] == b'#'
            && body[i + 1..].starts_with('#')
            && (i == 0 || {
                let mut j = i;
                while j > 0 && bytes[j - 1].is_ascii_whitespace() {
                    j -= 1;
                }
                j > 0 && (bytes[j - 1] == b'(' || bytes[j - 1] == b',')
            });
        if paste {
            out.push('0');
            i += 2;
            while i < bytes.len() && (bytes[i] == b'_' || bytes[i].is_ascii_alphanumeric()) {
                i += 1;
            }
        } else {
            let c = body[i..].chars().next().unwrap();
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

fn cut_macro_header(definition: &str) -> Option<&str> {
    let after_hash = definition.trim_start().strip_prefix('#')?.trim_start();
    let after_define = after_hash.strip_prefix("define")?;
    match after_define.chars().next() {
        Some(next) if next == '_' || next.is_alphanumeric() => return None,
        _ => {}
    }
    let rest = after_define.trim_start();
    let name_len = rest
        .char_indices()
        .take_while(|(_, c)| *c == '_' || c.is_alphanumeric())
        .map(|(i, c)| i + c.len_utf8())
        .last()?;
    let rest = rest[name_len..].trim_start();
    if !rest.starts_with('(') {
        return Some(rest);
    }
    let mut depth = 0u32;
    for (i, c) in rest.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(rest[i + 1..].trim_start());
                }
            }
            _ => {}
        }
    }
    None
}

/// One invocation in a macro body: the callee, each actual argument's
/// identifier text (`None` where the actual is not a bare identifier),
/// and the enclosing call with the argument index this call sits at.
/// Token-pasted bodies (`##` adjacent) yield nothing: a pasted name is not
/// a call, and guessing its value invents edges.
#[derive(Debug, Clone)]
pub struct BodyCall {
    pub callee: String,
    pub actuals: Vec<Option<String>>,
    /// (parent call index, argument index): `None` at the top level. A
    /// call nested in another call's arguments executes only when the
    /// outer call evaluates that slot — ordinary functions always do,
    /// macros only when they invoke it.
    pub parent: Option<(usize, usize)>,
    /// Byte span of the call node in the wrapped source: the bare-use
    /// scan maps enclosing calls back to these indexes.
    pub span: (usize, usize),
}

/// The body actual a GNU `, ##__VA_ARGS__` elision (or a plain
/// `__VA_ARGS__`) leaves behind: the macro's trailing bundle, not one
/// value. Threading maps it to every site actual at or past the `...`
/// slot; anything else under this name yields nothing.
pub const BUNDLE_MARKER: &str = "__VA_ARGS__";

/// Read a GNU `, ##__VA_ARGS__` elision as the bundle marker so the body
/// parses. Every other `##` yields nothing: a pasted name is not a
/// call, and guessing its value invents edges. Scrubbing inside strings
/// or comments is harmless (still a string or a comment afterwards), and
/// a pasted-off identifier yields nothing downstream — no parameter or
/// substitution ever uses it.
fn scrub_va_elision(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    while !rest.is_empty() {
        let Some(hash) = rest.find("##") else {
            out.push_str(rest);
            break;
        };
        let after = rest[hash + 2..].trim_start();
        if after.strip_prefix(BUNDLE_MARKER).is_some() {
            out.push_str(&rest[..hash]);
            out.push_str(BUNDLE_MARKER);
            rest = &after[BUNDLE_MARKER.len()..];
        } else {
            out.push_str(&rest[..hash + 2]);
            rest = &rest[hash + 2..];
        }
    }
    out
}

/// Whether the macro takes a trailing bundle: a `...` parameter, and the
/// slot it sits at.
fn variadic_slot(m: &crate::types::FunctionInfo) -> Option<usize> {
    m.parameters.iter().position(|p| p.name == "...")
}

/// Parse a macro body into its call tree, pre-order (a parent always has
/// a smaller index than its children). Empty where the header does not
/// parse or the tree has errors. An unnameable callee (pointer,
/// parenthesized) still runs and still evaluates its slots, so its subtree
/// threads through an anonymous node — promoting it to top level would
/// claim it always runs. Token pasting keeps its silence per call: under
/// `##` the callee is unknowable and so is everything under it, so that
/// subtree is skipped, never reparented.
pub fn body_call_tree(definition: &str) -> Vec<BodyCall> {
    let Some(body) = cut_macro_header(definition) else {
        return Vec::new();
    };
    let scrubbed = scrub_va_elision(body);
    let body = scrubbed.as_str();
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let wrapped = format!("void __macro_via_body(void) {{ {body}; }}");
    let Some(tree) = parser.parse(&wrapped, None) else {
        return Vec::new();
    };
    if tree.root_node().has_error() {
        return Vec::new();
    }
    fn actual_text(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
        if node.kind() == "identifier" {
            node.utf8_text(source).ok().map(str::to_string)
        } else {
            None
        }
    }
    // Recursive walk so each call knows its parent: children inherit the
    // nearest enclosing call with the argument index they sit under.
    // `pasted` (a `##` survives the elision scrub) silences unnameable
    // subtrees wholesale.
    let pasted = body.contains("##");
    fn walk(
        node: tree_sitter::Node,
        source: &[u8],
        parent: Option<(usize, usize)>,
        pasted: bool,
        out: &mut Vec<BodyCall>,
    ) {
        // A call's own index, reserved before descending: children always
        // sort after their parent.
        let mut here: Option<usize> = None;
        if node.kind() == "call_expression" {
            if let Some(callee) = node
                .child_by_field_name("function")
                .filter(|function| function.kind() == "identifier")
                .and_then(|function| function.utf8_text(source).ok())
            {
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    let actuals: Vec<Option<String>> = call_actuals(arguments)
                        .into_iter()
                        .map(|child| actual_text(child, source))
                        .collect();
                    out.push(BodyCall {
                        callee: callee.to_string(),
                        actuals,
                        parent,
                        span: (node.start_byte(), node.end_byte()),
                    });
                    here = Some(out.len() - 1);
                }
            } else if let Some(arguments) = node.child_by_field_name("arguments") {
                if pasted {
                    return;
                }
                let actuals: Vec<Option<String>> = call_actuals(arguments)
                    .into_iter()
                    .map(|child| actual_text(child, source))
                    .collect();
                out.push(BodyCall {
                    callee: String::new(),
                    actuals,
                    parent,
                    span: (node.start_byte(), node.end_byte()),
                });
                here = Some(out.len() - 1);
            }
        }
        if let Some(call) = here {
            // Distribute one link per named argument: a nested call
            // anywhere under an argument belongs to that slot. Other
            // children (the function name itself) inherit the parent.
            let arguments = node.child_by_field_name("arguments");
            let mut cursor = node.walk();
            let children: Vec<tree_sitter::Node> = node.children(&mut cursor).collect();
            for child in children {
                let link = parent;
                if let Some(args) = arguments {
                    if args.id() == child.id() {
                        for (position, named) in call_actuals(args).into_iter().enumerate() {
                            walk(named, source, Some((call, position)), pasted, out);
                        }
                        continue;
                    }
                }
                walk(child, source, link, pasted, out);
            }
            return;
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            walk(child, source, parent, pasted, out);
        }
    }
    let source = wrapped.as_bytes();
    let mut out: Vec<BodyCall> = Vec::new();
    walk(tree.root_node(), source, None, pasted, &mut out);
    out
}
