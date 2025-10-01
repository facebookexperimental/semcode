// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::TreeSitterAnalyzer;
use anyhow::Result;
use colored::*;
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

#[derive(Debug)]
pub struct DiffParseResult {
    pub modified_functions: HashSet<String>, // Functions that are actually modified (from hunk headers and definitions)
    pub called_functions: HashSet<String>,   // Functions that are called in added/removed lines
}

fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home_dir) = std::env::var_os("HOME") {
            let home_path = Path::new(&home_dir);
            return home_path.join(&path[2..]).to_string_lossy().to_string();
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
    let lines: Vec<&str> = diff_content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        // Look for file headers: --- a/path/to/file.c or +++ b/path/to/file.c
        if line.starts_with("+++") && line.contains(".c") {
            // Parse the file being modified
            let file_path = extract_file_path(line);

            // Look for hunk headers: @@ -start,count +start,count @@
            i += 1;
            while i < lines.len() {
                let hunk_line = lines[i];

                if hunk_line.starts_with("@@") {
                    // Parse the hunk to find function context and modifications using tree-sitter
                    let hunk_result = parse_hunk_with_treesitter(&lines, &mut i, &file_path)?;
                    modified_functions.extend(hunk_result.modified_functions);
                    called_functions.extend(hunk_result.called_functions);
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
    })
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

fn parse_hunk_with_treesitter(
    lines: &[&str],
    i: &mut usize,
    _file_path: &str,
) -> Result<DiffParseResult> {
    let mut modified_functions = HashSet::new();
    let mut called_functions = HashSet::new();

    // Collect all lines from the hunk (context + modified)
    let mut hunk_lines = Vec::new();
    let mut modified_line_numbers = HashSet::new(); // Track which lines were modified
    let mut current_line = 0;

    // First, extract function name from the hunk header (@@ line)
    if *i < lines.len() {
        let hunk_header = lines[*i];
        if let Some(func_name) = extract_function_from_hunk_header(hunk_header) {
            modified_functions.insert(func_name);
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

        if line.starts_with("+") {
            // Added line - track as modified
            hunk_lines.push(&line[1..]); // Remove + prefix
            modified_line_numbers.insert(current_line);
            current_line += 1;

            // Also extract function calls from added lines
            let line_called_functions = extract_function_calls(&line[1..]);
            called_functions.extend(line_called_functions);
        } else if line.starts_with("-") {
            // Removed line - track as modified but don't include in reconstructed code
            modified_line_numbers.insert(current_line);

            // Extract function calls from removed lines
            let line_called_functions = extract_function_calls(&line[1..]);
            called_functions.extend(line_called_functions);
            // Don't increment current_line for removed lines
        } else if !line.starts_with("@@") && !line.starts_with("---") && !line.starts_with("+++") {
            // Context line - include in reconstructed code
            hunk_lines.push(line);
            current_line += 1;
        }

        *i += 1;
    }

    // Reconstruct the code snippet and parse with tree-sitter
    if !hunk_lines.is_empty() {
        let reconstructed_code = hunk_lines.join("\n");

        if let Ok(mut analyzer) = TreeSitterAnalyzer::new() {
            // Parse the reconstructed code to find function definitions
            if let Ok(functions) = analyzer.analyze_code_snippet(&reconstructed_code) {
                for func_info in functions {
                    // Check if this function definition intersects with modified lines
                    let func_start_line = func_info.line_start as usize;
                    let func_end_line = func_info.line_end as usize;

                    // If any line in the function's range was modified, include it
                    for line_num in func_start_line..=func_end_line {
                        if modified_line_numbers.contains(&line_num) {
                            modified_functions.insert(func_info.name.clone());
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(DiffParseResult {
        modified_functions,
        called_functions,
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
    println!("{}", "DIFF FUNCTION ANALYSIS".bold().cyan());
    println!("{}", "=".repeat(60));

    if parse_result.modified_functions.is_empty() && parse_result.called_functions.is_empty() {
        println!(
            "{} No function modifications found in diff",
            "Result:".yellow()
        );
        return Ok(());
    }

    // Display modified functions
    if !parse_result.modified_functions.is_empty() {
        println!(
            "\n{} {} functions:",
            "MODIFIED:".bold().red(),
            parse_result.modified_functions.len()
        );
        let mut sorted_modified: Vec<_> = parse_result.modified_functions.iter().collect();
        sorted_modified.sort();
        for func_name in sorted_modified {
            println!("  {} {}", "●".red(), func_name.bold());
        }
    }

    // Display called functions
    if !parse_result.called_functions.is_empty() {
        println!(
            "\n{} {} functions:",
            "CALLED:".bold().cyan(),
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
    let total_unique = parse_result.modified_functions.len()
        + parse_result
            .called_functions
            .iter()
            .filter(|f| !parse_result.modified_functions.contains(*f))
            .count();

    println!("\n{}", "=".repeat(60));
    println!(
        "{} {} modified, {} called, {} total unique functions",
        "SUMMARY:".bold(),
        parse_result.modified_functions.len(),
        parse_result.called_functions.len(),
        total_unique
    );
    println!("{}", "=".repeat(60));

    Ok(())
}
