// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use colored::*;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::Path;

#[derive(Debug)]
pub struct DiffParseResult {
    pub modified_functions: HashSet<String>, // Functions that are actually modified (from hunk headers and definitions)
    pub called_functions: HashSet<String>, // Functions that are called in added/removed lines (global)
    pub modified_types: HashSet<String>,   // Types that are modified
    pub modified_macros: HashSet<String>,  // Macros that are modified
    pub function_calls: HashMap<String, HashSet<String>>, // Per-function: which functions does each modified function call
}

/// Per-hunk information for diffinfo output
#[derive(Debug, Clone, Serialize)]
pub struct HunkInfo {
    pub file_path: String,
    pub hunk_header: String,
    pub modifies: Option<String>, // The function being modified (from hunk header)
}

fn expand_tilde(path: &str) -> String {
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home_dir) = std::env::var_os("HOME") {
            let home_path = Path::new(&home_dir);
            return home_path.join(stripped).to_string_lossy().to_string();
        }
    } else if path == "~" {
        if let Some(home_dir) = std::env::var_os("HOME") {
            return Path::new(&home_dir).to_string_lossy().to_string();
        }
    }
    path.to_string()
}

fn resolve_path(path: &str) -> Result<String> {
    // First expand tilde if present
    let expanded_path = expand_tilde(path);
    let path_obj = Path::new(&expanded_path);

    match path_obj.canonicalize() {
        Ok(canonical_path) => Ok(canonical_path.to_string_lossy().to_string()),
        Err(_) => {
            // If canonicalize fails (e.g., file doesn't exist), try to resolve parent directory
            if let Some(parent) = path_obj.parent() {
                if let Some(filename) = path_obj.file_name() {
                    match parent.canonicalize() {
                        Ok(canonical_parent) => Ok(canonical_parent
                            .join(filename)
                            .to_string_lossy()
                            .to_string()),
                        Err(_) => Ok(expanded_path), // Fallback to expanded path
                    }
                } else {
                    Ok(expanded_path)
                }
            } else {
                Ok(expanded_path)
            }
        }
    }
}

pub fn parse_unified_diff(diff_content: &str) -> Result<DiffParseResult> {
    let mut modified_functions = HashSet::new();
    let mut called_functions = HashSet::new();
    let mut modified_types = HashSet::new();
    let mut modified_macros = HashSet::new();
    let mut function_calls: HashMap<String, HashSet<String>> = HashMap::new();
    let lines: Vec<&str> = diff_content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        // Look for file headers for C/C++ files
        if line.starts_with("+++")
            && (line.contains(".c")
                || line.contains(".h")
                || line.contains(".cpp")
                || line.contains(".cc")
                || line.contains(".cxx"))
        {
            // Parse the file being modified
            let file_path = extract_file_path(line);

            // Look for hunk headers: @@ -start,count +start,count @@
            i += 1;
            while i < lines.len() {
                let hunk_line = lines[i];

                if hunk_line.starts_with("@@") {
                    // Parse the hunk to find function context and modifications using walk-back algorithm
                    let hunk_result = parse_hunk_with_walkback(&lines, &mut i, &file_path)?;
                    modified_functions.extend(hunk_result.modified_functions.iter().cloned());
                    called_functions.extend(hunk_result.called_functions.iter().cloned());
                    modified_types.extend(hunk_result.modified_types);
                    modified_macros.extend(hunk_result.modified_macros);

                    // Merge per-function calls
                    for (func_name, calls) in hunk_result.function_calls {
                        function_calls.entry(func_name).or_default().extend(calls);
                    }
                } else if hunk_line.starts_with("---") || hunk_line.starts_with("+++") {
                    // Start of next file
                    break;
                } else {
                    i += 1;
                }
            }
        } else {
            i += 1;
        }
    }

    Ok(DiffParseResult {
        modified_functions,
        called_functions,
        modified_types,
        modified_macros,
        function_calls,
    })
}

/// Extract a function name from a line of C/C++ code.
/// Looks for the last identifier before '(' and validates it.
fn extract_function_name_from_line(line: &str) -> Option<String> {
    let paren_pos = line.find('(')?;
    let before_paren = &line[..paren_pos];
    let last_word = before_paren.split_whitespace().last()?;
    let func_name = last_word.trim_start_matches('*');
    if is_valid_identifier(func_name) && !is_keyword(func_name) {
        Some(func_name.to_string())
    } else {
        None
    }
}

/// Check if a hunk body contains a function definition where the actual
/// modifications are, which may differ from the @@ header function.
///
/// The @@ header shows the function in scope at the start of the hunk, but
/// if the hunk starts with trailing context from a preceding function and
/// then enters a new function definition, the @@ header function is wrong.
///
/// Returns (func_name, line_index) if a definition is found in the hunk body
/// with modifications after it. Returns None if no such definition exists.
fn find_changed_function_in_hunk(hunk_lines: &[&str]) -> Option<(String, usize)> {
    for (i, &line) in hunk_lines.iter().enumerate() {
        // Get content without diff prefix
        let content = if let Some(stripped) = line.strip_prefix(' ') {
            stripped
        } else if let Some(stripped) = line.strip_prefix('+') {
            stripped
        } else if let Some(stripped) = line.strip_prefix('-') {
            stripped
        } else if line.is_empty() {
            continue;
        } else {
            line
        };

        // Function definitions start at column 0 (no leading whitespace)
        if content.is_empty() || content.starts_with(|c: char| c.is_whitespace()) {
            continue;
        }

        let stripped = content.trim();
        if stripped.is_empty() {
            continue;
        }

        // Skip comments and preprocessor
        if stripped.starts_with("//")
            || stripped.starts_with("/*")
            || stripped.starts_with('*')
            || stripped.starts_with('#')
        {
            continue;
        }

        // Skip closing braces and labels
        if stripped == "}" || (stripped.ends_with(':') && !stripped.contains('(')) {
            continue;
        }

        // Must have parens (function parameters)
        if !stripped.contains('(') {
            continue;
        }

        // Skip control flow keywords
        if let Some(before_paren) = stripped.split('(').next() {
            if let Some(last_word) = before_paren.split_whitespace().last() {
                if matches!(
                    last_word,
                    "if" | "while"
                        | "for"
                        | "switch"
                        | "return"
                        | "sizeof"
                        | "typeof"
                        | "case"
                        | "else"
                ) {
                    continue;
                }
            }
        }

        // Check for opening brace on this or following lines
        let mut has_brace = stripped.contains('{');
        if !has_brace {
            for jline in hunk_lines.iter().skip(i + 1).take(19) {
                let jcontent = if let Some(s) = jline.strip_prefix(' ') {
                    s
                } else if let Some(s) = jline.strip_prefix('+') {
                    s
                } else if let Some(s) = jline.strip_prefix('-') {
                    s
                } else if jline.is_empty() {
                    continue;
                } else {
                    jline
                };

                if jcontent.contains('{') {
                    has_brace = true;
                    break;
                }

                let jstripped = jcontent.trim();
                if jstripped.is_empty() {
                    continue;
                }

                // Continuation of function signature (indented or ends with , ( ) )
                let is_continuation = jcontent.starts_with(|c: char| c.is_whitespace())
                    || jstripped.ends_with(',')
                    || jstripped.ends_with('(')
                    || jstripped.ends_with(')');
                if !is_continuation {
                    break;
                }
            }
        }

        if !has_brace {
            continue;
        }

        // Extract function name
        if let Some(func_name) = extract_function_name_from_line(stripped) {
            // Verify there are modifications after this definition
            let has_mods_after = hunk_lines[i + 1..].iter().any(|l| {
                (l.starts_with('+') || l.starts_with('-'))
                    && !l.starts_with("+++")
                    && !l.starts_with("---")
            });
            if has_mods_after {
                return Some((func_name, i));
            }
            return None;
        }
    }

    None
}

/// Parse a unified diff and return per-hunk information
/// Each hunk becomes a HunkInfo entry with the function being modified
pub fn parse_unified_diff_hunks(diff_content: &str) -> Result<Vec<HunkInfo>> {
    let mut hunks = Vec::new();
    let lines: Vec<&str> = diff_content.lines().collect();
    let mut i = 0;
    let mut current_file = String::new();

    while i < lines.len() {
        let line = lines[i];

        // Look for file headers for C/C++ files
        if line.starts_with("+++")
            && (line.contains(".c")
                || line.contains(".h")
                || line.contains(".cpp")
                || line.contains(".cc")
                || line.contains(".cxx"))
        {
            // Parse the file being modified
            current_file = extract_file_path(line);
            i += 1;
        } else if line.starts_with("@@") && !current_file.is_empty() {
            // Found a hunk header
            let hunk_header = line.to_string();
            let header_func = extract_function_from_hunk_header(line);

            // Collect hunk body lines
            let mut hunk_body: Vec<&str> = Vec::new();
            i += 1;
            while i < lines.len() {
                let next_line = lines[i];
                if next_line.starts_with("@@")
                    || next_line.starts_with("---")
                    || next_line.starts_with("+++")
                {
                    break;
                }
                hunk_body.push(next_line);
                i += 1;
            }

            // Check if the hunk body contains a function definition that
            // differs from the @@ header, with modifications after it
            if let Some((body_func, body_func_line)) = find_changed_function_in_hunk(&hunk_body) {
                // Check if there are also modifications before the body function
                let has_mods_before = hunk_body[..body_func_line].iter().any(|l| {
                    (l.starts_with('+') || l.starts_with('-'))
                        && !l.starts_with("+++")
                        && !l.starts_with("---")
                });

                if has_mods_before {
                    // Split: emit two hunks, one for header function, one for body function
                    hunks.push(HunkInfo {
                        file_path: current_file.clone(),
                        hunk_header: hunk_header.clone(),
                        modifies: header_func,
                    });
                    hunks.push(HunkInfo {
                        file_path: current_file.clone(),
                        hunk_header,
                        modifies: Some(body_func),
                    });
                } else {
                    // Only the body function is modified
                    hunks.push(HunkInfo {
                        file_path: current_file.clone(),
                        hunk_header,
                        modifies: Some(body_func),
                    });
                }
            } else {
                // No body function found, use header function
                hunks.push(HunkInfo {
                    file_path: current_file.clone(),
                    hunk_header,
                    modifies: header_func,
                });
            }
        } else if line.starts_with("---") {
            // Reset current file when we see a new file start
            i += 1;
        } else {
            i += 1;
        }
    }

    Ok(hunks)
}

fn extract_file_path(line: &str) -> String {
    // Extract file path from lines like "+++ b/path/to/file.c"
    if let Some(path_start) = line.find("b/") {
        let path = &line[path_start + 2..];
        return path.trim().to_string();
    }

    // Fallback: try to extract any path-like string
    if let Some(space_pos) = line.rfind(' ') {
        return line[space_pos + 1..].trim().to_string();
    }

    "unknown".to_string()
}

fn extract_function_from_hunk_header(hunk_header: &str) -> Option<String> {
    // Parse hunk headers like: @@ -466,9 +419,11 @@ static struct kmemleak_object *mem_pool_alloc(gfp_t gfp)
    // The function context appears after the second "@@"

    if !hunk_header.starts_with("@@") {
        return None;
    }

    // Find the second @@ to get the function context
    let parts: Vec<&str> = hunk_header.splitn(3, "@@").collect();
    if parts.len() < 3 {
        return None;
    }

    let function_context = parts[2].trim();
    if function_context.is_empty() {
        return None;
    }

    // Look for function definition pattern in the context
    // Examples:
    // "static struct kmemleak_object *mem_pool_alloc(gfp_t gfp)"
    // "int some_function(void)"
    // "void another_func(int a, char *b)"

    if let Some(paren_pos) = function_context.find('(') {
        let before_paren = &function_context[..paren_pos];

        // Find the last word before the parenthesis (the function name)
        let words: Vec<&str> = before_paren.split_whitespace().collect();
        if let Some(last_word) = words.last() {
            // Remove any leading * (for pointer return types)
            let func_name = last_word.trim_start_matches('*');

            // Basic validation: function name should be a valid identifier
            if is_valid_identifier(func_name) && !is_keyword(func_name) {
                return Some(func_name.to_string());
            }
        }
    }

    None
}

fn parse_hunk_with_walkback(
    lines: &[&str],
    i: &mut usize,
    _file_path: &str,
) -> Result<DiffParseResult> {
    let mut modified_functions = HashSet::new();
    let mut called_functions = HashSet::new();
    let mut modified_types = HashSet::new();
    let mut modified_macros = HashSet::new();
    let mut function_calls: HashMap<String, HashSet<String>> = HashMap::new();

    // Collect all lines from the hunk (context + modified)
    let mut hunk_lines = Vec::new();
    let mut modified_line_numbers = HashSet::new(); // Track which lines were modified
    let mut current_line = 0;

    // Track calls per line index so we can attribute them to functions later
    let mut line_to_calls: HashMap<usize, HashSet<String>> = HashMap::new();

    // First, extract function name from the hunk header (@@ line)
    // Don't add to modified_functions yet - only if walk-back can't attribute
    // modifications to a function definition found in the hunk body.
    let mut header_func_name: Option<String> = None;
    if *i < lines.len() {
        let hunk_header = lines[*i];
        if let Some(func_name) = extract_function_from_hunk_header(hunk_header) {
            header_func_name = Some(func_name);
        }
    }

    // Skip the @@ line
    *i += 1;

    // Collect all hunk content
    while *i < lines.len() {
        let line = lines[*i];

        // Stop at next hunk or file
        if line.starts_with("@@") || line.starts_with("---") || line.starts_with("+++") {
            break;
        }

        if let Some(stripped) = line.strip_prefix("+") {
            // Added line - track as modified
            hunk_lines.push(stripped); // Remove + prefix
            modified_line_numbers.insert(current_line);

            // Extract function calls from added lines and track by line
            let line_calls = extract_function_calls(stripped);
            called_functions.extend(line_calls.iter().cloned());
            if !line_calls.is_empty() {
                line_to_calls.insert(current_line, line_calls);
            }

            current_line += 1;
        } else if let Some(stripped) = line.strip_prefix("-") {
            // Removed line - track as modified but don't include in reconstructed code
            modified_line_numbers.insert(current_line);

            // Extract function calls from removed lines (for global tracking)
            let line_calls = extract_function_calls(stripped);
            called_functions.extend(line_calls);
            // Don't increment current_line for removed lines
        } else if !line.starts_with("@@") && !line.starts_with("---") && !line.starts_with("+++") {
            // Context line - strip the leading space (diff context prefix) to
            // reconstruct actual source code for walk-back analysis
            let content = line.strip_prefix(' ').unwrap_or(line);
            hunk_lines.push(content);
            current_line += 1;
        }

        *i += 1;
    }

    // Use walk-back algorithm to find modified symbols and attribute calls
    if !hunk_lines.is_empty() {
        let reconstructed_code = hunk_lines.join("\n");
        let reconstructed_lines: Vec<&str> = reconstructed_code.lines().collect();

        // Use walk-back algorithm to extract symbols from modified lines
        let symbols = crate::symbol_walkback::extract_symbols_by_walkback(
            &reconstructed_code,
            &modified_line_numbers,
        );

        // Parse symbols and categorize them
        for symbol in &symbols {
            if let Some(stripped) = symbol.strip_prefix('#') {
                // Macro: "#MACRO_NAME"
                modified_macros.insert(stripped.to_string());
            } else if symbol.contains("()") {
                // Function: "function_name()"
                modified_functions.insert(symbol.trim_end_matches("()").to_string());
            } else if symbol.starts_with("struct ")
                || symbol.starts_with("union ")
                || symbol.starts_with("enum ")
            {
                // Type: "struct foo", "union bar", "enum baz"
                modified_types.insert(symbol.clone());
            } else if symbol.starts_with("typedef ") {
                // Typedef: "typedef foo"
                modified_types.insert(symbol.clone());
            }
        }

        // If any modified lines weren't attributed to a walk-back symbol,
        // the @@ header function is the correct attribution for those changes.
        // This handles the case where modifications are in the header function's
        // body (which is above the hunk start and not visible to walk-back).
        if let Some(ref func_name) = header_func_name {
            let has_unattributed = modified_line_numbers.iter().any(|&line_idx| {
                line_idx < reconstructed_lines.len()
                    && crate::symbol_walkback::find_symbol_for_line(&reconstructed_lines, line_idx)
                        .is_none()
            });
            if has_unattributed {
                modified_functions.insert(func_name.clone());
            }
        }

        // Attribute calls to functions using walk-back
        // For each modified line with calls, find which function it belongs to
        for (line_idx, calls) in &line_to_calls {
            if let Some(containing_func) =
                crate::symbol_walkback::find_symbol_for_line(&reconstructed_lines, *line_idx)
            {
                // Extract function name from the symbol
                if let Some(func_name) =
                    crate::symbol_walkback::extract_function_name_from_symbol(&containing_func)
                {
                    function_calls
                        .entry(func_name)
                        .or_default()
                        .extend(calls.iter().cloned());
                }
            } else if let Some(ref func_name) = header_func_name {
                // Fall back to hunk header function
                function_calls
                    .entry(func_name.clone())
                    .or_default()
                    .extend(calls.iter().cloned());
            }
        }
    }

    Ok(DiffParseResult {
        modified_functions,
        called_functions,
        modified_types,
        modified_macros,
        function_calls,
    })
}

fn extract_function_calls(line: &str) -> HashSet<String> {
    let mut function_calls = HashSet::new();
    let line = line.trim();

    // Skip empty lines, comments, and preprocessor directives
    if line.is_empty() || line.starts_with("//") || line.starts_with("/*") || line.starts_with("#")
    {
        return function_calls;
    }

    // Look for function call patterns: function_name(
    // This catches cases like:
    // - "some_func();"
    // - "if (another_func(param)) {"
    // - "result = third_func(a, b);"
    // - "ptr->method_call(data);"

    let chars = line.chars().peekable();
    let mut current_word = String::new();
    let mut in_string = false;
    let mut escape_next = false;

    for ch in chars {
        if escape_next {
            escape_next = false;
            continue;
        }

        if ch == '\\' {
            escape_next = true;
            continue;
        }

        if ch == '"' || ch == '\'' {
            in_string = !in_string;
            current_word.clear();
            continue;
        }

        if in_string {
            continue;
        }

        if ch == '(' {
            // Found a potential function call
            if !current_word.is_empty() {
                // Clean up the word (remove -> and . for method calls)
                let clean_word = if let Some(arrow_pos) = current_word.rfind("->") {
                    &current_word[arrow_pos + 2..]
                } else if let Some(dot_pos) = current_word.rfind('.') {
                    &current_word[dot_pos + 1..]
                } else {
                    &current_word
                };

                // Remove any leading/trailing whitespace and special chars
                let func_name = clean_word
                    .trim()
                    .trim_start_matches('*')
                    .trim_start_matches('&');

                if is_valid_identifier(func_name) && !is_keyword(func_name) {
                    function_calls.insert(func_name.to_string());
                }
            }
            current_word.clear();
        } else if ch.is_alphanumeric() || ch == '_' || ch == '-' || ch == '>' || ch == '.' {
            current_word.push(ch);
        } else {
            current_word.clear();
        }
    }

    function_calls
}

fn is_valid_identifier(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    // First character must be letter or underscore
    let first_char = name.chars().next().unwrap();
    if !first_char.is_alphabetic() && first_char != '_' {
        return false;
    }

    // Rest must be alphanumeric or underscore
    name.chars()
        .skip(1)
        .all(|c| c.is_alphanumeric() || c == '_')
}

fn is_keyword(name: &str) -> bool {
    matches!(
        name,
        "if" | "else"
            | "for"
            | "while"
            | "do"
            | "switch"
            | "case"
            | "default"
            | "return"
            | "break"
            | "continue"
            | "goto"
            | "sizeof"
            | "typeof"
            | "int"
            | "char"
            | "float"
            | "double"
            | "void"
            | "long"
            | "short"
            | "signed"
            | "unsigned"
            | "const"
            | "static"
            | "extern"
            | "inline"
            | "struct"
            | "union"
            | "enum"
            | "typedef"
            | "auto"
            | "register"
            | "volatile"
    )
}

pub async fn diffinfo(input_file: Option<&str>) -> Result<()> {
    println!("Analyzing diff to extract function information...");

    // Read diff input with proper error handling
    let diff_content = match input_file {
        Some(file_path) => {
            // Resolve symbolic links
            let resolved_path = match resolve_path(file_path) {
                Ok(path) => path,
                Err(e) => {
                    println!(
                        "{} Failed to resolve path '{}': {}",
                        "Error:".red(),
                        file_path,
                        e
                    );
                    return Ok(());
                }
            };

            println!("Reading diff from file: {}", resolved_path.cyan());
            if resolved_path != file_path {
                if file_path.starts_with("~") {
                    println!("  (expanded from: {})", file_path.bright_black());
                } else {
                    println!("  (resolved from: {})", file_path.bright_black());
                }
            }

            match std::fs::read_to_string(&resolved_path) {
                Ok(content) => content,
                Err(e) => {
                    println!(
                        "{} Failed to read diff file '{}': {}",
                        "Error:".red(),
                        resolved_path,
                        e
                    );
                    println!("Please check that the file exists and is readable.");
                    return Ok(()); // Don't fail the command, just return
                }
            }
        }
        None => {
            println!("Reading diff from stdin...");
            let mut content = String::new();
            std::io::stdin().read_to_string(&mut content)?;
            content
        }
    };

    // Parse the unified diff to extract both modified and called functions
    let parse_result = parse_unified_diff(&diff_content)?;

    println!("\n{}", "=".repeat(60));
    println!("{}", "DIFF ANALYSIS".bold().cyan());
    println!("{}", "=".repeat(60));

    if parse_result.modified_functions.is_empty()
        && parse_result.called_functions.is_empty()
        && parse_result.modified_types.is_empty()
        && parse_result.modified_macros.is_empty()
    {
        println!("{} No modifications found in diff", "Result:".yellow());
        return Ok(());
    }

    // Display modified functions
    if !parse_result.modified_functions.is_empty() {
        println!(
            "\n{} {} functions:",
            "MODIFIED FUNCTIONS:".bold().red(),
            parse_result.modified_functions.len()
        );
        let mut sorted_modified: Vec<_> = parse_result.modified_functions.iter().collect();
        sorted_modified.sort();
        for func_name in sorted_modified {
            println!("  {} {}", "●".red(), func_name.bold());
        }
    }

    // Display modified types
    if !parse_result.modified_types.is_empty() {
        println!(
            "\n{} {} types:",
            "MODIFIED TYPES:".bold().magenta(),
            parse_result.modified_types.len()
        );
        let mut sorted_types: Vec<_> = parse_result.modified_types.iter().collect();
        sorted_types.sort();
        for type_name in sorted_types {
            println!("  {} {}", "●".magenta(), type_name.bold());
        }
    }

    // Display modified macros
    if !parse_result.modified_macros.is_empty() {
        println!(
            "\n{} {} macros:",
            "MODIFIED MACROS:".bold().yellow(),
            parse_result.modified_macros.len()
        );
        let mut sorted_macros: Vec<_> = parse_result.modified_macros.iter().collect();
        sorted_macros.sort();
        for macro_name in sorted_macros {
            println!("  {} {}", "●".yellow(), macro_name.bold());
        }
    }

    // Display called functions
    if !parse_result.called_functions.is_empty() {
        println!(
            "\n{} {} functions:",
            "CALLED FUNCTIONS:".bold().cyan(),
            parse_result.called_functions.len()
        );
        let mut sorted_called: Vec<_> = parse_result.called_functions.iter().collect();
        sorted_called.sort();
        for func_name in sorted_called {
            // Skip if it's already in modified functions to avoid duplication
            if !parse_result.modified_functions.contains(func_name) {
                println!("  {} {}", "○".cyan(), func_name);
            }
        }
    }

    // Summary
    let total_modified = parse_result.modified_functions.len()
        + parse_result.modified_types.len()
        + parse_result.modified_macros.len();
    let unique_called = parse_result
        .called_functions
        .iter()
        .filter(|f| !parse_result.modified_functions.contains(*f))
        .count();

    println!("\n{}", "=".repeat(60));
    println!(
        "{} Modified: {} functions, {} types, {} macros",
        "SUMMARY:".bold(),
        parse_result.modified_functions.len(),
        parse_result.modified_types.len(),
        parse_result.modified_macros.len()
    );
    println!(
        "         Called: {} functions (excluding modified)",
        unique_called
    );
    println!("         Total: {} modified symbols", total_modified);
    println!("{}", "=".repeat(60));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_function_in_middle_of_hunk() {
        // Bug: A new function that starts in the middle of a hunk should be detected
        // as a modified function, even though the hunk header shows a different function
        let diff = r#"diff --git a/test.c b/test.c
index abc123..def456 100644
--- a/test.c
+++ b/test.c
@@ -10,5 +10,20 @@ static void existing_function(void)
 	context_line();
+	new_line_added();
+}
+
+static void __eea_pci_remove(struct pci_dev *pdev)
+{
+	pci_disable_device(pdev);
+	kfree(pdev->driver_data);
 }
"#;

        let result = parse_unified_diff(diff).unwrap();

        println!("Modified functions: {:?}", result.modified_functions);
        println!("Called functions: {:?}", result.called_functions);

        // Both functions should be detected as modified
        assert!(
            result.modified_functions.contains("existing_function"),
            "Should find existing_function from hunk header"
        );
        assert!(
            result.modified_functions.contains("__eea_pci_remove"),
            "Should find __eea_pci_remove - new function in middle of hunk"
        );
    }

    #[test]
    fn test_new_file_with_multiple_functions() {
        // New file scenario: all lines are added, no hunk header context
        let diff = r#"diff --git a/drivers/net/test.c b/drivers/net/test.c
new file mode 100644
index 0000000..abc123
--- /dev/null
+++ b/drivers/net/test.c
@@ -0,0 +1,30 @@
+// SPDX-License-Identifier: GPL-2.0
+#include <linux/pci.h>
+
+static void first_function(void)
+{
+	do_something();
+}
+
+static void second_function(int arg)
+{
+	do_other();
+}
+
+static int __eea_pci_remove(struct pci_dev *pdev)
+{
+	pci_disable_device(pdev);
+	return 0;
+}
"#;

        let result = parse_unified_diff(diff).unwrap();

        println!(
            "New file - Modified functions: {:?}",
            result.modified_functions
        );

        // All three functions should be detected
        assert!(
            result.modified_functions.contains("first_function"),
            "Should find first_function"
        );
        assert!(
            result.modified_functions.contains("second_function"),
            "Should find second_function"
        );
        assert!(
            result.modified_functions.contains("__eea_pci_remove"),
            "Should find __eea_pci_remove"
        );
    }

    #[test]
    fn test_bug_diff_functions() {
        // Test with the actual bug.diff content pattern - new files with multiple functions
        let diff = std::fs::read_to_string("/home/clm/local/src/semcode/bug.diff")
            .unwrap_or_else(|_| "".to_string());

        if diff.is_empty() {
            println!("Skipping test - bug.diff not found");
            return;
        }

        let result = parse_unified_diff(&diff).unwrap();

        println!(
            "Bug.diff - Modified functions ({}):",
            result.modified_functions.len()
        );
        let mut funcs: Vec<_> = result.modified_functions.iter().collect();
        funcs.sort();
        for f in &funcs {
            println!("  {}", f);
        }

        // ering_alloc should be found - it's a multi-line function signature
        assert!(
            result.modified_functions.contains("ering_alloc"),
            "Should find ering_alloc (multi-line signature)"
        );
    }

    #[test]
    fn test_multiline_function_signature() {
        // Bug: Multi-line function signatures should be detected
        let diff = r#"diff --git a/test.c b/test.c
new file mode 100644
--- /dev/null
+++ b/test.c
@@ -0,0 +1,20 @@
+#include <linux/types.h>
+
+struct eea_ring *ering_alloc(u32 index, u32 num, struct eea_device *edev,
+			     u8 sq_desc_size, u8 cq_desc_size,
+			     const char *name)
+{
+	struct eea_ring *ering;
+
+	ering = kzalloc(sizeof(*ering), GFP_KERNEL);
+	if (!ering)
+		return NULL;
+
+	return ering;
+}
"#;

        let result = parse_unified_diff(diff).unwrap();

        assert!(
            result.modified_functions.contains("ering_alloc"),
            "Should find ering_alloc despite multi-line signature"
        );
    }

    #[test]
    fn test_function_returning_struct_pointer() {
        // Functions returning struct pointers should not be confused with struct definitions
        let diff = r#"diff --git a/test.c b/test.c
--- a/test.c
+++ b/test.c
@@ -10,0 +10,10 @@
+struct widget *create_widget(int id)
+{
+	struct widget *w = malloc(sizeof(*w));
+	return w;
+}
+
+union data *get_data(void)
+{
+	return &global_data;
+}
"#;

        let result = parse_unified_diff(diff).unwrap();

        assert!(
            result.modified_functions.contains("create_widget"),
            "Should find create_widget (returns struct pointer)"
        );
        assert!(
            result.modified_functions.contains("get_data"),
            "Should find get_data (returns union pointer)"
        );
    }

    #[test]
    fn test_header_function_not_modified() {
        // Bug: When a hunk starts with context from the @@ header function
        // and then enters a new function, the header function should NOT be
        // marked as modified if it has no actual modifications.
        let diff = r#"diff --git a/test.c b/test.c
index abc123..def456 100644
--- a/test.c
+++ b/test.c
@@ -10,8 +10,9 @@ static void old_function(void)
 	return 0;
 }

 static void new_function(void)
 {
+	added_line();
 	existing_line();
 }
"#;

        let result = parse_unified_diff(diff).unwrap();

        println!("Modified functions: {:?}", result.modified_functions);

        // new_function should be detected (it has actual modifications)
        assert!(
            result.modified_functions.contains("new_function"),
            "Should find new_function (has modifications)"
        );

        // old_function should NOT be detected (only context from @@ header)
        assert!(
            !result.modified_functions.contains("old_function"),
            "Should NOT find old_function (only context, no modifications)"
        );
    }

    #[test]
    fn test_split_hunk_both_functions_modified() {
        // When a hunk has modifications in both the @@ header function
        // and a subsequent function, both should be reported.
        let diff = r#"diff --git a/test.c b/test.c
index abc123..def456 100644
--- a/test.c
+++ b/test.c
@@ -10,8 +10,10 @@ static void old_function(void)
+	added_in_old();
 	return 0;
 }

 static void new_function(void)
 {
+	added_in_new();
 	existing_line();
 }
"#;

        let result = parse_unified_diff(diff).unwrap();

        println!("Modified functions: {:?}", result.modified_functions);

        assert!(
            result.modified_functions.contains("old_function"),
            "Should find old_function (has modifications before new function)"
        );
        assert!(
            result.modified_functions.contains("new_function"),
            "Should find new_function (has modifications)"
        );
    }

    #[test]
    fn test_hunks_header_function_not_modified() {
        // parse_unified_diff_hunks should also correctly attribute to the
        // body function, not the @@ header function
        let diff = r#"diff --git a/test.c b/test.c
index abc123..def456 100644
--- a/test.c
+++ b/test.c
@@ -10,8 +10,9 @@ static void old_function(void)
 	return 0;
 }

 static void new_function(void)
 {
+	added_line();
 	existing_line();
 }
"#;

        let hunks = parse_unified_diff_hunks(diff).unwrap();

        assert_eq!(hunks.len(), 1);
        assert_eq!(hunks[0].modifies, Some("new_function".to_string()));
    }

    #[test]
    fn test_hunks_split_both_functions_modified() {
        // parse_unified_diff_hunks should emit two hunk entries when
        // both the header function and a body function are modified
        let diff = r#"diff --git a/test.c b/test.c
index abc123..def456 100644
--- a/test.c
+++ b/test.c
@@ -10,8 +10,10 @@ static void old_function(void)
+	added_in_old();
 	return 0;
 }

 static void new_function(void)
 {
+	added_in_new();
 	existing_line();
 }
"#;

        let hunks = parse_unified_diff_hunks(diff).unwrap();

        assert_eq!(hunks.len(), 2);
        assert_eq!(hunks[0].modifies, Some("old_function".to_string()));
        assert_eq!(hunks[1].modifies, Some("new_function".to_string()));
    }
}
