// Line scanner for Linux `.S` assembly: exported symbols become
// definitions, and direct branches become call edges. No grammar is
// involved — GAS-macro dialects defeat precise parsing — so this
// reads what chains need (names, spans, branch targets) and nothing
// else. Definitions index on every arch;
// branch edges read on x86 and arm64 paths only, where exact edge tests
// pass for the tables below.

use crate::types::{CallEdge, FunctionInfo};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// The scanner's own version: bump on any behavior change, so a scanner
/// fix re-reads only `.S` (which record `6+asm-N`) and never the
/// grammars' rows.
pub const ASM_VERSION: u32 = 1;

/// Whether this path reads as assembly: uppercase `.S` only, the
/// preprocessed kernel sources. Lowercase `.s` is compiler output and
/// stays out. Linker scripts (`vmlinux.lds.S`) route here too, defining
/// nothing: admitting them records the file as processed instead of
/// re-reading it on every incremental run.
pub fn is_asm_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext == "S")
}

/// A branch that can name a call target: every table entry records
/// where its operand is a global-shaped symbol. Tail jumps to local
/// labels (`.Lfoo`, `1f`) never qualify, so no symbol table is needed
/// and a C definition indexed later still resolves the edge. The tables
/// are explicit rather than prefix-shaped, and exactly x86 plus arm64:
/// a `j*` fallback would read loongarch `jr ra` as a jump, and `jal`
/// and `j` belong to riscv and mips, not to either covered arch. Where
/// the tables apply is a path question, answered in [`reads_branches`].
fn is_branch_mnemonic(mnemonic: &str) -> bool {
    match mnemonic {
        "call" | "callq" | "bl" | "jmp" | "jmpq" | "b" | "cbz" | "cbnz" | "tbz" | "tbnz" => true,
        // x86 condition codes: `j` plus code, ending at `jrcxz`.
        "ja" | "jae" | "jb" | "jbe" | "jc" | "je" | "jz" | "jg" | "jge" | "jl" | "jle" | "jna"
        | "jnae" | "jnb" | "jnbe" | "jnc" | "jne" | "jng" | "jnge" | "jnl" | "jnle" | "jno"
        | "jnp" | "jns" | "jnz" | "jo" | "jp" | "jpe" | "jpo" | "js" | "jcxz" | "jecxz"
        | "jrcxz" => true,
        // arm64 conditions: `b.` plus code. `bc.*` (branch consistent)
        // stays out until an exact edge test needs it.
        "b.eq" | "b.ne" | "b.cs" | "b.hs" | "b.cc" | "b.lo" | "b.mi" | "b.pl" | "b.vs" | "b.vc"
        | "b.hi" | "b.ls" | "b.ge" | "b.lt" | "b.gt" | "b.le" | "b.al" | "b.nv" => true,
        _ => false,
    }
}

/// Which whitespace-separated operand names the target, by position:
///
/// ```text
/// call foo          -> 0
/// cbz x22, label    -> 1
/// tbz x0, #3, label -> 2, skipping `#imm` words
/// ```
///
/// Compare-and-branch tests a register first, so reading the first
/// always would file registers like `x22` as callees (in-tree: `tbnz
/// x22, #22, 1f` inside __swpan_exit_el1). The `#imm` bit number is
/// not the target either, so it is skipped where present.
fn branch_operand_index(mnemonic: &str, rest: &[&str]) -> usize {
    let mut at = match mnemonic {
        "cbz" | "cbnz" => 1,
        "tbz" | "tbnz" => 2,
        _ => 0,
    };
    if matches!(mnemonic, "tbz" | "tbnz") {
        while rest.get(at).is_some_and(|word| word.starts_with('#')) {
            at += 1;
        }
    }
    at
}

/// Cut a `#` comment opening mid-line, before the `;` split, using
/// the file's comment rules: on x86 `#` always comments, so any
/// unquoted one ends the line (`call real #7` names only `real`, as
/// GNU as does); elsewhere the scanner leaves `#` alone, so immediates
/// (`#3`, `#:lo12:x`, `#FLAG`) stand as written. Quote-aware either
/// way: `.ascii "a#b"` is text, not a comment. Both passes share this
/// one normalization, so a label after a symbolic immediate reads the
/// same in each (`tbz x0, #FLAG, local; local: ret` drops `local` in
/// both).
fn cut_hash_comment(line: &str, cut_hash: bool) -> &str {
    if !cut_hash {
        return line;
    }
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (offset, c) in line.char_indices() {
        if let Some(open) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == open {
                quote = None;
            }
        } else if c == '"' || c == '\'' {
            quote = Some(c);
        } else if c == '#' {
            return line[..offset].trim_end();
        }
    }
    line
}

/// Split a line on `;` outside string literals: `.ascii "a; call b"`
/// names no callee through its quoted half (in-tree, `ALTERNATIVE`
/// strings hold `;`-separated replacements). Both quote kinds count,
/// and a backslash escapes the next character inside them.
fn split_statements(line: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (index, c) in line.char_indices() {
        if let Some(open) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == open {
                quote = None;
            }
        } else if c == '"' || c == '\'' {
            quote = Some(c);
        } else if c == ';' {
            segments.push(&line[start..index]);
            start = index + 1;
        }
    }
    segments.push(&line[start..]);
    segments
}

/// The symbol a branch operand names, if it names one: link annotations
/// (`foo@plt`) strip to the symbol, while offsets (`foo+4`), indirection
/// (`*%rax`, `*foo`), immediates, locals (`.Lfoo`, `1f`) and registers
/// are left out. What remains either resolves downstream or misses.
/// The annotation itself must read as one: `foo@` keeps a name it did
/// not earn, and `foo@PLT+4` is not a plain reference (the suffix check
/// is what rejects it — the offset never survives the `@` split intact).
fn branch_target(operand: &str) -> Option<&str> {
    let text = operand.trim_end_matches([',', ';']);
    let mut pieces = text.split('@');
    let base = pieces.next().unwrap_or("");
    if pieces.any(|suffix| {
        suffix.is_empty()
            || !suffix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
    }) {
        return None;
    }
    let mut chars = base.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return None,
    }
    if base
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        Some(base)
    } else {
        None
    }
}

/// The (`macro`, `argument`) of a `MACRO(argument)` line, if the line is
/// one. Starts read the first comma-separated argument at their call
/// site (typed starts keep attributes after the name); ends read the
/// whole argument, so a multi-argument end never closes by prefix.
fn macro_call(line: &str) -> Option<(&str, &str)> {
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    if close < open {
        return None;
    }
    let name = line[..open].trim();
    let argument = line[open + 1..close].trim();
    Some((name, argument))
}

/// Whether the name reads as a symbol: what a definition or an operand
/// may spell. Local numeric and dot labels never qualify in either
/// position, so boot trivia like `SYM_FUNC_START_LOCAL_NOALIGN(.Lx)`
/// stays out of the index.
fn is_symbol(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

/// Whether the macro opens a code definition: function and code starts
/// pair with their ends; anything else (`SYM_DATA`, inner labels,
/// extable helpers) never opens one. The typed family opens like the
/// plain one (491 sites at line start, 490 indexable — one is a `.macro`
/// argument in msr-reg.S — closed by the same `SYM_FUNC_END` by name),
/// and so do the two single-site spellings.
fn is_start_macro(name: &str) -> bool {
    name == "ENTRY"
        || name == "SYM_START"
        || name == "SYM_SIGFUNC_START"
        || name.starts_with("SYM_FUNC_START")
        || name.starts_with("SYM_CODE_START")
        || name.starts_with("SYM_TYPED_FUNC_START")
}

/// Whether the macro closes a code definition. Pairing keys on the name
/// alone, across families: retpoline.S closes `SYM_CODE_START*` symbols
/// with `SYM_FUNC_END`, five times over, so a family match would drop
/// real mitigations. The open and close of one symbol always agree. Bare
/// `END` closes too (187 sites; the 161 mips/arc ones pair with
/// `LEAF`/`NESTED`/`ENTRY_CFI` families outside the scanner and no-op).
fn is_end_macro(name: &str) -> bool {
    name == "ENDPROC"
        || name == "END"
        || name == "SYM_SIGFUNC_END"
        || name.starts_with("SYM_FUNC_END")
        || name.starts_with("SYM_CODE_END")
}

/// Whether branches in this file read as edges: x86 and arm64 paths
/// only. A `bl` on arm or powerpc names a real call, but one this table
/// cannot verify, and a `jmp` on csky names a register — 641 such edges
/// at the commit, none of them checkable — so edges exist only where
/// the exact edge tests pass. `domain_of` maps `arch/` paths and `lib/<sub>/arch`
/// ones (crypto, crc) alike.
fn reads_branches(relative_path: &str) -> bool {
    matches!(
        crate::domain::domain_of(relative_path).arch,
        Some("x86") | Some("arm64")
    )
}

/// Whether `#` opens a comment in this file: x86 only. On arm64 `#`
/// opens an immediate (`#3`, `#SYMBOL` — 413 `#SYMBOL` lines in-tree),
/// never a comment, so cutting there would eat real operands.
fn hash_comments(relative_path: &str) -> bool {
    crate::domain::domain_of(relative_path).arch == Some("x86")
}

struct OpenDef {
    name: String,
    line_start: u32,
    line_end: u32,
    calls: Vec<String>,
}

/// File one closed definition: deduplicated by name with calls unioned
/// (conditional arms define one symbol twice, and the store never holds
/// two live rows for one version).
fn file_def(mut def: OpenDef, defs: &mut Vec<OpenDef>, index: &mut HashMap<String, usize>) {
    def.calls.sort();
    def.calls.dedup();
    if let Some(&at) = index.get(&def.name) {
        let kept = &mut defs[at];
        for call in def.calls {
            if !kept.calls.contains(&call) {
                kept.calls.push(call);
            }
        }
        kept.calls.sort();
    } else {
        index.insert(def.name.clone(), defs.len());
        defs.push(def);
    }
}

/// Strip `//` and `/* */` comments from one physical line, carrying an
/// unterminated block comment into the next line. `@` needs no handling:
/// a detached `@comment` is its own token, never an operand.
fn strip_comments(line: &str, in_block: &mut bool) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    if *in_block {
        if let Some(end) = rest.find("*/") {
            rest = &rest[end + 2..];
            *in_block = false;
        } else {
            return out;
        }
    }
    loop {
        let line_comment = rest.find("//");
        let block_open = rest.find("/*");
        match (line_comment, block_open) {
            // Whichever opens first wins: a `//` swallows a later `/*`,
            // and a block pair leaves a later `//` for the next round.
            (Some(at), Some(open)) if at < open => {
                rest = &rest[..at];
                break;
            }
            (_, Some(open)) => {
                out.push_str(&rest[..open]);
                rest = &rest[open + 2..];
                if let Some(end) = rest.find("*/") {
                    rest = &rest[end + 2..];
                    // Whitespace, not glue: `call/*c*/target` names one
                    // operand, while `calltarget` names none.
                    out.push(' ');
                } else {
                    rest = "";
                    *in_block = true;
                    break;
                }
            }
            (Some(at), None) => {
                rest = &rest[..at];
                break;
            }
            (None, None) => break,
        }
    }
    out.push_str(rest);
    out
}

/// Logical lines with comments stripped and directives dropped: joining
/// continuations first keeps `#define` bodies whole, and both scanner
/// passes read these, so labels and edges see identical lines. Returns
/// the lines with their first physical numbers, plus the last physical
/// number for closing unterminated spans.
fn prepped_lines(source: &str) -> (Vec<(u32, String)>, u32) {
    let mut logical = Vec::new();
    let mut continued: Option<(u32, String)> = None;
    let mut in_block = false;
    let mut last_line: u32 = 0;
    for (number, raw) in source.lines().enumerate() {
        let line_number = number as u32 + 1;
        last_line = line_number;
        let (start, mut text) = continued.take().unwrap_or((line_number, String::new()));
        text.push_str(raw);
        if text.ends_with('\\') {
            text.pop();
            continued = Some((start, text));
            continue;
        }
        // Comment state advances even on directives: an unterminated
        // block comment inside `#define` still comments the next line.
        // (Latent: zero in-tree rows change either way.)
        let cleaned = strip_comments(&text, &mut in_block);
        if text.trim_start().starts_with('#') {
            continue;
        }
        logical.push((start, cleaned));
    }
    if let Some((start, text)) = continued.take() {
        let cleaned = strip_comments(&text, &mut in_block);
        logical.push((start, cleaned));
    }
    (logical, last_line)
}

/// File-local names a branch must not read as calls: plain `label:`
/// definitions (GAS labels are object-local unless `.globl`'d),
/// `SYM_INNER_LABEL`s marked local, minus anything a START macro
/// exports and anything `.globl`/`.global`/`.weak` names. In-tree 34 of
/// 263 edges point at such labels, 7 colliding with an unrelated row by
/// name (`callers done` listing a hibernate loop exit, `callers
/// restore_registers` listing two suspend paths jumping home).
fn local_branch_targets(logical: &[(u32, String)], cut_hash: bool) -> HashSet<String> {
    let mut labels = HashSet::new();
    let mut exported = HashSet::new();
    for (_, line) in logical {
        // Cut `#` comments before the split here too, with the file's
        // rules: the shared normalization is what keeps both passes
        // reading the same line.
        for segment in split_statements(cut_hash_comment(line, cut_hash)) {
            let text = segment.trim();
            if text.is_empty() || text.starts_with('#') {
                continue;
            }
            let mut words = text.split_whitespace();
            match words.next() {
                // `.globl a, b`: linkable from anywhere.
                Some(".globl") | Some(".global") | Some(".weak") => {
                    for name in text.split_whitespace().skip(1) {
                        let name = name.trim_end_matches([',', ';']);
                        if !name.is_empty() {
                            exported.insert(name.to_string());
                        }
                    }
                }
                _ => {}
            }
            if let Some(label) = text
                .split_whitespace()
                .next()
                .and_then(|first| first.strip_suffix(':'))
            {
                let mut chars = label.chars();
                if matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
                    && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
                {
                    labels.insert(label.to_string());
                }
            }
            if let Some((macro_name, argument)) = macro_call(text) {
                if is_start_macro(macro_name) {
                    let symbol = argument.split(',').next().unwrap_or("").trim();
                    if is_symbol(symbol) {
                        exported.insert(symbol.to_string());
                    }
                } else if macro_name.starts_with("SYM_INNER_LABEL") {
                    let mut parts = argument.split(',');
                    if let (Some(name), Some(kind)) = (parts.next(), parts.next()) {
                        let name = name.trim();
                        let kind = kind.trim();
                        if is_symbol(name) {
                            if kind.contains("LOCAL") {
                                labels.insert(name.to_string());
                            } else {
                                exported.insert(name.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    labels.difference(&exported).cloned().collect()
}

/// The definitions of one assembly source: exported symbols with their
/// branch targets, deduplicated by name with calls unioned (conditional
/// arms define one symbol twice).
pub fn scan(source: &str, relative_path: &str, git_hash: &str) -> Vec<FunctionInfo> {
    // Linker scripts (`vmlinux.lds.S`) preprocess with C but describe
    // sections, not code: admit them so they record as processed,
    // defining nothing (their `ENTRY` names the ELF entry point).
    if relative_path.ends_with(".lds.S") {
        return Vec::new();
    }
    let mut defs: Vec<OpenDef> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut open: Option<OpenDef> = None;

    let (logical, last_line) = prepped_lines(source);
    let physical: Vec<&str> = source.lines().collect();
    let read_branches = reads_branches(relative_path);
    let cut_hash = hash_comments(relative_path);
    let local_targets = local_branch_targets(&logical, cut_hash);

    for (line_number, cleaned) in &logical {
        // The `#` comment goes before the `;` split, with the file's
        // rules: on x86 any unquoted `#` ends the line, or a semicolon
        // inside the comment reads as a statement separator; elsewhere
        // `#` opens immediates and the line stands.
        let cleaned: &str = cut_hash_comment(cleaned, cut_hash);
        // A semicolon separates statements, outside string literals;
        // the line number stays the physical one for every segment.
        for segment in split_statements(cleaned) {
            let line = segment.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((macro_name, argument)) = macro_call(line) {
                // The name is the first comma-separated argument: typed
                // starts keep attributes after it
                // (`SYM_TYPED_FUNC_START_ALIGNED(name, 8)`).
                let symbol = argument.split(',').next().unwrap_or("").trim();
                if is_start_macro(macro_name) && is_symbol(symbol) {
                    if let Some(mut previous) = open.take() {
                        // A same-line start cannot end its predecessor
                        // before it began (`START(a); START(b)` never
                        // occurs in-tree); clamp to an empty span rather
                        // than publish an inverted one.
                        previous.line_end = line_number.saturating_sub(1).max(previous.line_start);
                        file_def(previous, &mut defs, &mut index);
                    }
                    open = Some(OpenDef {
                        name: symbol.to_string(),
                        line_start: *line_number,
                        line_end: *line_number,
                        calls: Vec::new(),
                    });
                    continue;
                }
                if is_end_macro(macro_name) {
                    if open.as_ref().is_some_and(|def| def.name == argument) {
                        if let Some(mut def) = open.take() {
                            def.line_end = *line_number;
                            file_def(def, &mut defs, &mut index);
                        }
                    }
                    continue;
                }
            }
            if read_branches {
                if let Some(def) = open.as_mut() {
                    let mut words = line.split_whitespace();
                    if let Some(mnemonic) = words.next() {
                        if is_branch_mnemonic(mnemonic) {
                            let rest: Vec<&str> = words.collect();
                            let at = branch_operand_index(mnemonic, &rest);
                            // The operand must be the whole story: `foo +
                            // i*SIZE` (xen's early_idt_handler_array) names
                            // no callee through its first word, and a
                            // file-local label names none even when its
                            // spelling matches a row elsewhere.
                            if rest.len() == at + 1 {
                                if let Some(target) =
                                    rest.get(at).and_then(|word| branch_target(word))
                                {
                                    if !local_targets.contains(target) {
                                        def.calls.push(target.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if let Some(mut def) = open.take() {
        def.line_end = last_line;
        file_def(def, &mut defs, &mut index);
    }

    defs.into_iter()
        .map(|def| {
            let body = physical
                .get((def.line_start as usize).saturating_sub(1)..def.line_end as usize)
                .unwrap_or(&[])
                .join("\n");
            FunctionInfo {
                name: def.name,
                file_path: relative_path.to_string(),
                git_file_hash: git_hash.to_string(),
                line_start: def.line_start,
                line_end: def.line_end,
                return_type: String::new(),
                parameters: Vec::new(),
                body,
                calls: if def.calls.is_empty() {
                    None
                } else {
                    Some(def.calls.into_iter().map(CallEdge::Plain).collect())
                },
                types: None,
                guard: None,
                qualifier: None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names_of(functions: &[FunctionInfo]) -> Vec<&str> {
        functions.iter().map(|f| f.name.as_str()).collect()
    }

    fn calls_of(functions: &[FunctionInfo], name: &str) -> Vec<String> {
        functions
            .iter()
            .find(|f| f.name == name)
            .and_then(|f| f.calls.clone())
            .unwrap_or_default()
            .into_iter()
            .map(|edge| match edge {
                CallEdge::Plain(call) => call,
                CallEdge::Tagged { call, .. } => call,
            })
            .collect()
    }

    #[test]
    fn matched_delimiters_open_and_close() {
        // Each open family pairs with its end; the span covers both
        // (an exact span is what the entry_SYSCALL_64 gate checks). The
        // end matters, each of them: without one the span would run to
        // the next start or the file end, so trailing size directives
        // after each close pin all three ends, and the orphan call
        // between the definitions must reach no row at all.
        let functions = scan(
            "SYM_FUNC_START(copy_mc_fragile)\n\
             \tcmpl $8, %edx\n\
             SYM_FUNC_END(copy_mc_fragile)\n\
             \t.size copy_mc_fragile, .-copy_mc_fragile\n\
             SYM_CODE_START(entry_SYSCALL_64)\n\
             \tcall do_syscall_64\n\
             SYM_CODE_END(entry_SYSCALL_64)\n\
             call orphan_after_end\n\
             ENTRY(old_style)\n\
             \tret\n\
             ENDPROC(old_style)\n\
             \t.size old_style, .-old_style\n",
            "arch/x86/entry.S",
            "hash",
        );
        assert_eq!(
            names_of(&functions),
            ["copy_mc_fragile", "entry_SYSCALL_64", "old_style"]
        );
        let span_of = |name: &str| {
            let found = functions.iter().find(|f| f.name == name).unwrap();
            (found.line_start, found.line_end)
        };
        assert_eq!(span_of("copy_mc_fragile"), (1, 3));
        assert_eq!(span_of("entry_SYSCALL_64"), (5, 7));
        assert_eq!(span_of("old_style"), (9, 11));
        assert_eq!(calls_of(&functions, "entry_SYSCALL_64"), ["do_syscall_64"]);
        assert!(
            calls_of(&functions, "copy_mc_fragile").is_empty(),
            "{functions:?}"
        );
        for function in &functions {
            assert!(
                !calls_of(&functions, &function.name).contains(&"orphan_after_end".to_string()),
                "{functions:?}"
            );
        }
    }

    #[test]
    fn local_labels_data_and_directives_stay_out() {
        // Inner labels, data symbols, extable helpers and directives are
        // not definitions; local jump targets are not edges. A local
        // label wrapped in a start macro (boot code does this) stays out
        // too: only exported spellings define.
        let functions = scan(
            ".text\n\
             SYM_FUNC_START(fn)\n\
             \tjb .L_local\n\
             \tjmp 1f\n\
             \tcall *%rax\n\
             \tblr x16\n\
             .L_local:\n\
             1:\n\
             SYM_INNER_LABEL(fn_inner, SYM_L_GLOBAL)\n\
             SYM_FUNC_END(fn)\n\
             SYM_FUNC_START_LOCAL_NOALIGN(.Lboot)\n\
             \tret\n\
             SYM_FUNC_END(.Lboot)\n\
             SYM_DATA_START(rodata)\n\
             .quad 0\n\
             SYM_DATA_END(rodata)\n\
             _ASM_EXTABLE(.L_a, .L_b)\n",
            "arch/arm64/f.S",
            "hash",
        );
        assert_eq!(names_of(&functions), ["fn"]);
        assert!(calls_of(&functions, "fn").is_empty(), "{functions:?}");
    }

    #[test]
    fn tail_jump_to_a_global_records() {
        // A tail jump naming a global is the asm-to-C edge (the
        // copy_mc_fragile shape): only the leading dot or digit marks a
        // local, and link annotations strip to the symbol. Conditional
        // branches read the same way on both tables, and a `#` comment
        // after the operand (five sites in-tree) cuts before validation.
        let functions = scan(
            "SYM_FUNC_START(copy_mc_fragile)\n\
             \tjmp copy_mc_fragile_handle_tail\n\
             \tcall printk@plt\n\
             \tcall sev_target # trailing comment\n\
             \tjb cond_target\n\
             \tb.eq arm_target\n\
             SYM_FUNC_END(copy_mc_fragile)\n",
            "arch/x86/lib/copy_mc_64.S",
            "hash",
        );
        assert_eq!(
            calls_of(&functions, "copy_mc_fragile"),
            [
                "arm_target",
                "cond_target",
                "copy_mc_fragile_handle_tail",
                "printk",
                "sev_target"
            ]
        );
    }

    #[test]
    fn compare_and_branch_reads_past_the_register() {
        // `cbz` tests its register first and `tbz` names a bit second:
        // the target is the last operand, never the register. In-tree
        // this is `tbnz x22, #22, 1f` inside __swpan_exit_el1, exercised
        // here literally, and an operand must be the whole story: xen's
        // `early_idt_handler_array + i*SIZE` names no callee through its
        // first word.
        let functions = scan(
            "SYM_FUNC_START(f)\n\
             \tcbz x22, global_cbz_target\n\
             \tcbnz w1, global_cbnz_target\n\
             \ttbz x0, #3, global_tbz_target\n\
             \ttbnz x22, #22, 1f\n\
             \tjmp early_idt_handler_array + i*EARLY_IDT_HANDLER_SIZE\n\
             SYM_FUNC_END(f)\n",
            "arch/arm64/kernel/entry.S",
            "hash",
        );
        assert_eq!(
            calls_of(&functions, "f"),
            [
                "global_cbnz_target",
                "global_cbz_target",
                "global_tbz_target"
            ]
        );
    }

    #[test]
    fn offsets_and_invented_mnemonics_record_nothing() {
        // `foo@PLT+4` is not a plain reference, and neither `jfoo` nor
        // `b.zs` is a branch the tables know: the explicit lists reject
        // all three where prefix fallbacks admitted them.
        let functions = scan(
            "SYM_FUNC_START(f)\n\
             \tcall foo@PLT+4\n\
             \tjfoo sneaky_target\n\
             \tb.zs also_not\n\
             \tcall real_target\n\
             SYM_FUNC_END(f)\n",
            "arch/x86/f.S",
            "hash",
        );
        assert_eq!(calls_of(&functions, "f"), ["real_target"]);
    }

    #[test]
    fn jammed_macros_on_one_line_stay_out() {
        // Two macros jammed onto one line without a semicolon never occur
        // in-tree (no definition site shares its line); the argument
        // validator rejects the splice, so the neighbors hold their spans
        // and no inverted span publishes. Ends read the whole argument,
        // so an end with attributes never closes early either.
        let functions = scan(
            "SYM_FUNC_START(before)\n\
             \tcall g\n\
             SYM_FUNC_END(before)\n\
             SYM_FUNC_END(before) SYM_FUNC_START(jammed)\n\
             SYM_FUNC_START(after)\n\
             \tcall h\n\
             SYM_FUNC_END(after, extra)\n\
             SYM_FUNC_END(after)\n",
            "arch/x86/f.S",
            "hash",
        );
        assert_eq!(names_of(&functions), ["before", "after"]);
        let span_of = |name: &str| {
            let found = functions.iter().find(|f| f.name == name).unwrap();
            (found.line_start, found.line_end)
        };
        assert_eq!(span_of("before"), (1, 3));
        assert_eq!(span_of("after"), (5, 8));
        assert_eq!(calls_of(&functions, "before"), ["g"]);
        assert_eq!(calls_of(&functions, "after"), ["h"]);
    }

    #[test]
    fn quoted_semicolons_and_same_line_starts_stay_honest() {
        // A `;` inside a string literal separates nothing: the branch
        // words in an `ALTERNATIVE` replacement or an `.ascii` payload
        // are quoted text, not edges — while a real `;` still separates
        // two branches. And a second start on its predecessor's line
        // clamps to an empty span rather than an inverted one (neither
        // shape occurs in-tree; both are cheap to pin).
        let functions = scan(
            "SYM_FUNC_START(f)\n\
             \tcall p; call q\n\
             \tALTERNATIVE \"call phantom; movq %rax, %rsp\", \"\"\n\
             \t.ascii \"prefix; call ghost ; suffix\"\n\
             SYM_FUNC_END(f)\n\
             SYM_FUNC_START(a); SYM_FUNC_START(b)\n\
             \tcall r\n\
             SYM_FUNC_END(b)\n",
            "arch/x86/entry/entry_64.S",
            "hash",
        );
        assert_eq!(calls_of(&functions, "f"), ["p", "q"]);
        let span_of = |name: &str| {
            let found = functions.iter().find(|f| f.name == name).unwrap();
            (found.line_start, found.line_end)
        };
        assert_eq!(span_of("a"), (6, 6));
        assert_eq!(span_of("b"), (6, 8));
        assert_eq!(calls_of(&functions, "b"), ["r"]);
    }

    #[test]
    fn hash_comment_cut_before_statement_split() {
        // The `#` comment goes before the `;` split: cutting after it
        // leaves `b bar` standing in `call foo # see a; b bar`, and `b`
        // branches on every architecture. A `#` inside quotes is text,
        // not a comment — and a cut that cannot tell loses the real
        // branch after the literal, while a quote-blind split keeps the
        // phantom inside it.
        let functions = scan(
            "SYM_FUNC_START(commented)\n\
             \tcall foo # see a; b bar\n\
             \t.ascii \"p#q; call ghost\"; call worker\n\
             SYM_FUNC_END(commented)\n",
            "arch/x86/comment.S",
            "hash",
        );
        assert_eq!(calls_of(&functions, "commented"), ["foo", "worker"]);
    }

    #[test]
    fn x86_comment_tail_exports_nothing() {
        // The label pass cuts x86 `#` comments too: `.globl # foo`
        // exports nothing (GNU as ends the directive at `#`), so a
        // local `foo` stays local and calls to it stay dropped. Without
        // the cut the tail's bare `foo` reads as exported.
        let functions = scan(
            "SYM_FUNC_START(u)\n\
             \tcall foo\n\
             SYM_FUNC_END(u)\n\
             foo:\n\
             \tret\n\
             .globl # foo\n",
            "arch/x86/g.S",
            "hash",
        );
        assert!(calls_of(&functions, "u").is_empty(), "{functions:?}");
    }

    #[test]
    fn symbolic_immediate_keeps_its_label_local() {
        // On arm64 `#` opens immediates, symbolic ones included: the
        // label after `tbz x0, #FLAG, local` reads in the label pass
        // exactly as in the branch pass, so no edge leaves for it. On
        // x86 the same `#` always comments: `call real #7` names only
        // `real`, as GNU as does.
        let functions = scan(
            "SYM_FUNC_START(tbz_user)\n\
             \ttbz x0, #FLAG, local; local: ret\n\
             SYM_FUNC_END(tbz_user)\n",
            "arch/arm64/t.S",
            "hash",
        );
        assert!(calls_of(&functions, "tbz_user").is_empty(), "{functions:?}");
        let functions = scan(
            "SYM_FUNC_START(pinned)\n\
             \tcall real #7; call ghost\n\
             SYM_FUNC_END(pinned)\n",
            "arch/x86/p.S",
            "hash",
        );
        assert_eq!(calls_of(&functions, "pinned"), ["real"]);
    }

    #[test]
    fn file_local_labels_are_not_calls() {
        // A plain `name:` label is object-local unless `.globl`'d, and a
        // `SYM_INNER_LABEL` marked local stays home too — even when the
        // spelling matches a row elsewhere. In-tree this is
        // `jmp wakeup_start` inside do_olpc_suspend_lowlevel, plus 33 more
        // edges, 7 of them colliding. `.globl`'d labels and START-opened
        // names stay callable: a start exports by construction.
        let functions = scan(
            "wakeup_start:\n\
             \tret\n\
             SYM_CODE_START(do_olpc_suspend_lowlevel)\n\
             \tjmp wakeup_start\n\
             \tcall save_registers\n\
             SYM_CODE_END(do_olpc_suspend_lowlevel)\n\
             SYM_INNER_LABEL(inner_local, SYM_L_LOCAL)\n\
             \tret lr\n\
             SYM_FUNC_START(uses_inner)\n\
             \tcall inner_local\n\
             \tcall save_registers\n\
             SYM_FUNC_END(uses_inner)\n\
             SYM_FUNC_START(shared)\n\
             shared:\n\
             \tret\n\
             SYM_FUNC_END(shared)\n\
             .globl exported_hook\n\
             exported_hook:\n\
             \tret\n\
             SYM_FUNC_START(other)\n\
             \tcall exported_hook\n\
             \tcall shared\n\
             SYM_FUNC_END(other)\n",
            "arch/x86/platform/olpc/xo1-wakeup.S",
            "hash",
        );
        assert_eq!(
            calls_of(&functions, "do_olpc_suspend_lowlevel"),
            ["save_registers"]
        );
        assert_eq!(calls_of(&functions, "uses_inner"), ["save_registers"]);
        assert_eq!(calls_of(&functions, "other"), ["exported_hook", "shared"]);
    }

    #[test]
    fn sym_start_opens_on_its_first_argument() {
        // `SYM_START` lists linkage and alignment after the name; the
        // name is the first argument. In-tree this is powerpc's
        // `ftrace_ool_stub_text`, closed by a cross-family `SYM_CODE_END`
        // — name pairing again.
        let functions = scan(
            "SYM_START(ftrace_ool_stub_text, SYM_L_GLOBAL, .balign SZL)\n\
             \t.space 32\n\
             SYM_CODE_END(ftrace_ool_stub_text)\n",
            "arch/powerpc/kernel/trace/ftrace_entry.S",
            "hash",
        );
        assert_eq!(names_of(&functions), ["ftrace_ool_stub_text"]);
        let found = functions
            .iter()
            .find(|f| f.name == "ftrace_ool_stub_text")
            .unwrap();
        assert_eq!((found.line_start, found.line_end), (1, 3));
    }

    #[test]
    fn linker_scripts_define_nothing() {
        // `vmlinux.lds.S` routes here so it records as processed, but a
        // linker script describes sections, not code: its `ENTRY` names
        // the ELF entry point, and nothing about it is a definition.
        assert!(is_asm_path(Path::new("arch/x86/entry.S")));
        assert!(is_asm_path(Path::new("arch/x86/kernel/vmlinux.lds.S")));
        assert!(!is_asm_path(Path::new("arch/x86/boot/main.s")));
        let functions = scan(
            "ENTRY(stext)\n\
             SECTIONS\n\
             {\n\
             \t. = ALIGN(8);\n\
             }\n",
            "arch/x86/kernel/vmlinux.lds.S",
            "hash",
        );
        assert!(functions.is_empty(), "{functions:?}");
    }

    #[test]
    fn typed_sigfunc_and_bare_end_open_and_close() {
        // The typed family opens like the plain one (its closes are the
        // same `SYM_FUNC_END`, paired by name), including the aligned
        // spelling whose attribute follows the name — the name is the
        // first argument, never the whole list. A bare `END` closes too
        // (187 sites; the 161 mips/arc ones pair with families outside
        // the scanner and no-op), and the trailing size directives pin
        // each end like the other tests do.
        let functions = scan(
            "SYM_TYPED_FUNC_START(cpu_soft_restart)\n\
             \tbl restart_target\n\
             SYM_FUNC_END(cpu_soft_restart)\n\
             SYM_TYPED_FUNC_START_ALIGNED(imx6_suspend, 8)\n\
             \tbl suspend_target\n\
             SYM_FUNC_END(imx6_suspend)\n\
             SYM_SIGFUNC_START(__vdso_rt_sigreturn)\n\
             \tret\n\
             SYM_SIGFUNC_END(__vdso_rt_sigreturn)\n\
             \t.size __vdso_rt_sigreturn, .-__vdso_rt_sigreturn\n\
             ENTRY(ftrace_stub)\n\
             \tcall ftrace_caller\n\
             END(ftrace_stub)\n\
             \t.size ftrace_stub, .-ftrace_stub\n",
            "arch/arm64/kernel/cpu-reset.S",
            "hash",
        );
        assert_eq!(
            names_of(&functions),
            [
                "cpu_soft_restart",
                "imx6_suspend",
                "__vdso_rt_sigreturn",
                "ftrace_stub"
            ]
        );
        let span_of = |name: &str| {
            let found = functions.iter().find(|f| f.name == name).unwrap();
            (found.line_start, found.line_end)
        };
        assert_eq!(span_of("cpu_soft_restart"), (1, 3));
        assert_eq!(span_of("imx6_suspend"), (4, 6));
        assert_eq!(span_of("__vdso_rt_sigreturn"), (7, 9));
        assert_eq!(span_of("ftrace_stub"), (11, 13));
        assert_eq!(calls_of(&functions, "cpu_soft_restart"), ["restart_target"]);
        assert_eq!(calls_of(&functions, "imx6_suspend"), ["suspend_target"]);
        assert_eq!(calls_of(&functions, "ftrace_stub"), ["ftrace_caller"]);
    }

    #[test]
    fn branches_read_on_x86_and_arm64_paths_only() {
        // Definitions index everywhere, but a `bl` on arm names a call
        // this table cannot verify, and a `jmp` on csky names a register:
        // 641 such edges at the commit, none of them checkable. Edges
        // stay where the exact edge tests pass — x86 and arm64, plus
        // accelerated crypto under lib/crypto/<arch> — while the
        // definition itself still indexes off-arch.
        let gated = scan(
            "SYM_FUNC_START(f)\n\
             \tbl arm_target\n\
             SYM_FUNC_END(f)\n",
            "arch/arm/f.S",
            "hash",
        );
        assert_eq!(names_of(&gated), ["f"]);
        assert!(calls_of(&gated, "f").is_empty(), "{gated:?}");
        let register = scan(
            "SYM_FUNC_START(f)\n\
             \tjmp lr\n\
             SYM_FUNC_END(f)\n",
            "arch/csky/f.S",
            "hash",
        );
        assert!(calls_of(&register, "f").is_empty(), "{register:?}");
        let crypto = scan(
            "SYM_FUNC_START(f)\n\
             \tbl crypto_target\n\
             SYM_FUNC_END(f)\n",
            "lib/crypto/arm64/f.S",
            "hash",
        );
        assert_eq!(calls_of(&crypto, "f"), ["crypto_target"]);
        // ...and the x86 side, plus `lib/<sub>/<arch>` generally: crc's
        // neon copy reads edges where the generic rule would gate them.
        let x86crypto = scan(
            "SYM_FUNC_START(f)\n\
             \tcall x86crypto_target\n\
             SYM_FUNC_END(f)\n",
            "lib/crypto/x86/f.S",
            "hash",
        );
        assert_eq!(calls_of(&x86crypto, "f"), ["x86crypto_target"]);
        let crc = scan(
            "SYM_FUNC_START(f)\n\
             \tbl crc_target\n\
             SYM_FUNC_END(f)\n",
            "lib/crc/arm64/f.S",
            "hash",
        );
        assert_eq!(calls_of(&crc, "f"), ["crc_target"]);
    }

    #[test]
    fn define_continuations_read_as_directives() {
        // `#define` bodies name symbols without defining them: joining
        // backslash continuations first keeps the whole definition under
        // the directive skip. In-tree this is KPROBES_TARGET_START in
        // arch/s390/lib/test_kprobes_asm.S, which once filed a symbol
        // literally called `name` beside the real definitions around it.
        let functions = scan(
            "#define KPROBES_TARGET_START(name) \\\n\
             \tSYM_FUNC_START(name); \\\n\
             \tFTRACE_GEN_NOP_ASM(name)\n\
             SYM_FUNC_START(neighbor)\n\
             \tret\n\
             SYM_FUNC_END(neighbor)\n",
            "arch/s390/lib/test_kprobes_asm.S",
            "hash",
        );
        assert_eq!(names_of(&functions), ["neighbor"]);
    }

    #[test]
    fn preprocessor_and_comments_read_as_nothing() {
        // Directives, conditionals and both comment styles contribute no
        // definitions and no edges, but code between them still reads. A
        // branch hidden inside a block comment stays out even with a
        // definition open around it, while an inline comment between
        // mnemonic and operand reads through even without surrounding
        // spaces. A directive goes whole, before `;` splitting: the
        // `SYM_FUNC_START` past its semicolon must not open.
        let functions = scan(
            "#include <linux/linkage.h>\n\
             #ifdef CONFIG_X86_MCE\n\
             #define X(a); SYM_FUNC_START(sneaky)\n\
             /* block comment\n\
                over two lines */\n\
             SYM_FUNC_START(f) // trailing comment\n\
             \tcall /* inline */ g // trailing call comment\n\
             \tcall/*nospace*/target\n\
             /*\n\
             call hidden_target\n\
             */\n\
             #endif\n\
             SYM_FUNC_END(f)\n",
            "arch/x86/f.S",
            "hash",
        );
        assert_eq!(names_of(&functions), ["f"]);
        assert_eq!(calls_of(&functions, "f"), ["g", "target"]);
    }

    #[test]
    fn conditional_arms_fold_into_one_row() {
        // One symbol under two arms is one row with unioned calls: the
        // store never holds two live rows for one version.
        let functions = scan(
            "#ifdef A\n\
             SYM_FUNC_START(f)\n\
             \tcall g\n\
             SYM_FUNC_END(f)\n\
             #else\n\
             SYM_FUNC_START(f)\n\
             \tcall h\n\
             SYM_FUNC_END(f)\n\
             #endif\n",
            "arch/x86/f.S",
            "hash",
        );
        assert_eq!(names_of(&functions), ["f"]);
        assert_eq!(calls_of(&functions, "f"), ["g", "h"]);
    }
}
