// SPDX-License-Identifier: MIT OR Apache-2.0
//! Symbol detection using walk-back algorithm
//!
//! This module provides efficient symbol detection by walking backwards from modified lines
//! to find enclosing function, struct, or macro definitions. This is much faster than
//! full TreeSitter parsing while still accurately identifying modified symbols.

use gxhash::{HashSet, HashSetExt};

/// Extract symbols by walking back from modified lines to find function/struct/macro definitions
/// Returns formatted symbol names (e.g., "function_name()", "struct foo", "#MACRO")
pub fn extract_symbols_by_walkback(
    content: &str,
    modified_lines: &HashSet<usize>,
) -> Vec<String> {
    let mut symbols = HashSet::new();
    let lines: Vec<&str> = content.lines().collect();

    // For each modified line, walk back to find the containing symbol
    for &modified_line in modified_lines {
        if let Some(decl_line) = find_symbol_for_line(&lines, modified_line) {
            // Extract just the symbol name from the declaration line
            if let Some(symbol_name) = extract_symbol_name_from_declaration(&decl_line) {
                symbols.insert(symbol_name);
            }
        }
    }

    symbols.into_iter().collect()
}

/// Extract a formatted symbol name from a declaration line
/// Returns "function_name()", "struct foo", or "#MACRO"
fn extract_symbol_name_from_declaration(decl_line: &str) -> Option<String> {
    let trimmed = decl_line.trim();

    // Check for macro
    if trimmed.starts_with("#define ") {
        return extract_macro_name(trimmed).map(|name| format!("#{}", name));
    }

    // Check for struct/union/enum
    if trimmed.starts_with("struct ")
        || trimmed.starts_with("union ")
        || trimmed.starts_with("enum ")
        || trimmed.starts_with("typedef struct ")
        || trimmed.starts_with("typedef union ")
        || trimmed.starts_with("typedef enum ")
    {
        return is_type_definition(trimmed);
    }

    // Check for typedef
    if trimmed.starts_with("typedef ") && trimmed.ends_with(';') {
        return extract_typedef_name(trimmed);
    }

    // Must be a function - extract the name
    extract_function_name(trimmed).map(|name| format!("{}()", name))
}

/// Walk back from a line to find the enclosing function, struct, or macro definition
/// Returns the declaration line for use in diff hunk headers (like git)
pub fn find_symbol_for_line(lines: &[&str], line_idx: usize) -> Option<String> {
    if line_idx >= lines.len() {
        return None;
    }

    // First check if the modified line itself is a single-line definition
    let current_line = lines[line_idx].trim();

    // Check for single-line typedef
    if current_line.starts_with("typedef ") && current_line.ends_with(';') {
        if extract_typedef_name(current_line).is_some() {
            return Some(current_line.to_string());
        }
    }

    // Check for single-line function-like macro
    if current_line.starts_with("#define ") {
        if extract_macro_name(current_line).is_some() {
            return Some(current_line.to_string());
        }
    }

    // Walk backwards looking for a definition
    for i in (0..=line_idx).rev() {
        let line = lines[i];
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }

        // Skip obvious non-definitions at column 0
        if is_false_positive(line) {
            continue;
        }

        // Check for function definition - return the declaration line
        if is_function_definition(line, lines, i).is_some() {
            // Return the trimmed function declaration line
            return Some(trimmed.to_string());
        }

        // Check for struct/union/enum definition - return the declaration line
        if is_type_definition(line).is_some() {
            return Some(trimmed.to_string());
        }

        // Check for macro definition - return the #define line
        if extract_macro_name(trimmed).is_some() {
            return Some(trimmed.to_string());
        }

        // If we hit an indented line and haven't found a definition yet,
        // we're probably inside a function body - keep walking back
        if line.starts_with(|c: char| c.is_whitespace()) {
            continue;
        }

        // If we've walked back more than 50 lines without finding a definition, give up
        if line_idx - i > 50 {
            break;
        }
    }

    None
}

/// Check if a line is a false positive (goto label, case label, etc.)
fn is_false_positive(line: &str) -> bool {
    let trimmed = line.trim();

    // Goto labels: "label:" at column 0
    if !line.starts_with(|c: char| c.is_whitespace()) && trimmed.ends_with(':') {
        // Could be a label, but also could be "public:", "private:", "default:"
        if trimmed.starts_with("case ")
            || trimmed.starts_with("default:")
            || trimmed == "public:"
            || trimmed == "private:"
            || trimmed == "protected:"
        {
            return true;
        }
        // If it's a simple identifier followed by colon, it's probably a goto label
        if trimmed
            .trim_end_matches(':')
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_')
        {
            return true;
        }
    }

    false
}

/// Check if a line looks like a function definition
/// Returns the function name if found
fn is_function_definition(line: &str, lines: &[&str], line_idx: usize) -> Option<String> {
    // Must start at column 0 or with storage class (static, inline, etc.)
    if line.starts_with(|c: char| c.is_whitespace()) {
        return None;
    }

    let trimmed = line.trim();

    // Must have parentheses (function parameters)
    if !trimmed.contains('(') {
        return None;
    }

    // Look for opening brace on this line or within next 20 lines
    let has_brace = trimmed.contains('{')
        || lines
            .get(line_idx + 1..line_idx.saturating_add(20).min(lines.len()))
            .map(|next_lines| next_lines.iter().any(|l| l.trim().starts_with('{')))
            .unwrap_or(false);

    if !has_brace {
        return None;
    }

    // Extract function name from the line
    // Pattern: return_type function_name(params)
    // Could have storage class like: static inline int function_name(params)
    extract_function_name(trimmed)
}

/// Extract function name from a function definition line
fn extract_function_name(line: &str) -> Option<String> {
    // Find the opening parenthesis
    let paren_pos = line.find('(')?;
    let before_paren = &line[..paren_pos];

    // Split by whitespace and get the last token before the paren
    // This handles: "int foo(" -> "foo", "static int foo(" -> "foo"
    let tokens: Vec<&str> = before_paren.split_whitespace().collect();
    let name = tokens.last()?;

    // Remove any pointer/reference markers
    let clean_name = name.trim_start_matches('*').trim_start_matches('&');

    // Must be a valid identifier
    if clean_name.chars().all(|c| c.is_alphanumeric() || c == '_') && !clean_name.is_empty() {
        Some(clean_name.to_string())
    } else {
        None
    }
}

/// Check if a line is a struct/union/enum definition
fn is_type_definition(line: &str) -> Option<String> {
    let trimmed = line.trim();

    // Must start with struct, union, enum, or typedef
    let type_keyword = if trimmed.starts_with("struct ") {
        "struct"
    } else if trimmed.starts_with("union ") {
        "union"
    } else if trimmed.starts_with("enum ") {
        "enum"
    } else if trimmed.starts_with("typedef struct ") {
        "struct"
    } else if trimmed.starts_with("typedef union ") {
        "union"
    } else if trimmed.starts_with("typedef enum ") {
        "enum"
    } else {
        return None;
    };

    // Must have opening brace
    if !trimmed.contains('{') {
        return None;
    }

    // Extract the name after the keyword
    let after_keyword = if trimmed.starts_with("typedef") {
        trimmed.strip_prefix("typedef ")?.trim()
    } else {
        trimmed
    };

    let after_keyword = after_keyword
        .strip_prefix("struct ")
        .or_else(|| after_keyword.strip_prefix("union "))
        .or_else(|| after_keyword.strip_prefix("enum "))?
        .trim();

    // Get the name (first token before '{' or whitespace)
    let name = after_keyword
        .split(|c: char| c.is_whitespace() || c == '{')
        .next()?
        .trim();

    if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        Some(format!("{} {}", type_keyword, name))
    } else {
        None
    }
}

/// Extract macro name from a #define line
fn extract_macro_name(line: &str) -> Option<String> {
    let trimmed = line.trim();

    if !trimmed.starts_with("#define ") {
        return None;
    }

    let after_define = trimmed.strip_prefix("#define ")?.trim();

    // Get the macro name (first token, possibly with parentheses)
    let name_end = after_define
        .find(|c: char| c.is_whitespace() || c == '(')
        .unwrap_or(after_define.len());

    let name = &after_define[..name_end];

    if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        Some(name.to_string())
    } else {
        None
    }
}

/// Extract typedef name from a single-line typedef
fn extract_typedef_name(line: &str) -> Option<String> {
    // Pattern: typedef <type> <name>;
    let trimmed = line.trim().strip_prefix("typedef ")?.trim();
    let without_semicolon = trimmed.strip_suffix(';')?.trim();

    // Get the last token (the typedef name)
    let name = without_semicolon.split_whitespace().last()?;

    if name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        Some(format!("typedef {}", name))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_function_name() {
        assert_eq!(
            extract_function_name("static int foo(int a)"),
            Some("foo".to_string())
        );
        assert_eq!(
            extract_function_name("void *bar(void)"),
            Some("bar".to_string())
        );
        assert_eq!(
            extract_function_name("struct widget *create_widget(int id)"),
            Some("create_widget".to_string())
        );
    }

    #[test]
    fn test_extract_macro_name() {
        assert_eq!(
            extract_macro_name("#define MAX_SIZE 1024"),
            Some("MAX_SIZE".to_string())
        );
        assert_eq!(
            extract_macro_name("#define MIN(a, b) ((a) < (b) ? (a) : (b))"),
            Some("MIN".to_string())
        );
    }

    #[test]
    fn test_is_type_definition() {
        assert_eq!(
            is_type_definition("struct foo {"),
            Some("struct foo".to_string())
        );
        assert_eq!(
            is_type_definition("typedef struct bar {"),
            Some("struct bar".to_string())
        );
    }
}
