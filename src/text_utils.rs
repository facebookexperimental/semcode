// SPDX-License-Identifier: MIT OR Apache-2.0
//! Text processing utilities for semantic code analysis

use regex::Regex;
use std::sync::LazyLock;

// Pre-compiled regexes for preprocessing (major performance optimization)
static ATTR_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"__attribute__\s*\(\([^)]+\)\)").unwrap());

static EXPORT_SYMBOL_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"EXPORT_SYMBOL[^;]*;").unwrap());

static INLINE_ASM_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"asm\s*volatile\s*\([^)]+\)").unwrap());

static WHITESPACE_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());

static SINGLE_COMMENT_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"//[^\n]*").unwrap());

static MULTI_COMMENT_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/\*[\s\S]*?\*/").unwrap());

/// Preprocess code for better vectorization/embedding quality
///
/// This function normalizes C/C++ code by:
/// - Removing kernel-specific macros and attributes
/// - Removing inline assembly
/// - Normalizing whitespace while preserving line structure
/// - Removing comments
/// - Truncating very long functions at safe UTF-8 boundaries
pub fn preprocess_code(code: &str) -> String {
    // Remove kernel-specific macros and attributes (using pre-compiled regexes)
    let code = ATTR_REGEX.replace_all(code, "");
    let code = EXPORT_SYMBOL_REGEX.replace_all(&code, "");

    // Remove inline assembly
    let code = INLINE_ASM_REGEX.replace_all(&code, "");

    // Normalize whitespace but preserve line structure
    let code = WHITESPACE_REGEX.replace_all(&code, |caps: &regex::Captures| {
        let matched = caps.get(0).unwrap().as_str();
        if matched.contains('\n') {
            // Count newlines and preserve one, but collapse multiple newlines to double newline max
            let newline_count = matched.chars().filter(|&c| c == '\n').count();
            if newline_count > 1 {
                "\n\n" // Maximum of double newline for paragraph breaks
            } else {
                "\n" // Single newline
            }
        } else {
            " " // Replace other whitespace with single space
        }
    });

    // Remove single-line comments but preserve structure
    let code = SINGLE_COMMENT_REGEX.replace_all(&code, "");

    // Remove multi-line comments
    let code = MULTI_COMMENT_REGEX.replace_all(&code, "");

    // Truncate very long functions at a safe UTF-8 character boundary
    let code = if code.len() > 8192 {
        // Find the last valid UTF-8 character boundary before or at position 8192
        let mut truncate_pos = 8192;
        while truncate_pos > 0 && !code.is_char_boundary(truncate_pos) {
            truncate_pos -= 1;
        }
        &code[..truncate_pos]
    } else {
        &code
    };

    code.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preprocess_code() {
        let input = r#"
        __attribute__((packed)) struct foo {
            int x;
        };

        // This is a comment
        EXPORT_SYMBOL(foo);

        /* Multi-line
           comment */
        void bar() {
            asm volatile("nop");
        }
        "#;

        let processed = preprocess_code(input);
        assert!(!processed.contains("__attribute__"));
        assert!(!processed.contains("EXPORT_SYMBOL"));
        assert!(!processed.contains("//"));
        assert!(!processed.contains("/*"));
        assert!(!processed.contains("asm volatile"));
    }

    #[test]
    fn test_preprocess_code_preserves_line_structure() {
        let input = r#"if (condition) {
    do_something();
    do_another_thing();
}"#;

        let processed = preprocess_code(input);

        // Should preserve newlines but normalize spaces/tabs
        assert!(processed.contains('\n'), "Should preserve newlines");

        // Should not be collapsed to single line
        assert!(!processed.eq("if (condition) { do_something(); do_another_thing(); }"));

        // Should have basic structure
        assert!(processed.contains("if (condition) {\n"));
        assert!(processed.contains("do_something();\n"));

        println!("Processed: {processed:?}");
    }

    #[test]
    fn test_preprocess_code_utf8_boundary() {
        // Create a string that would be truncated at a non-UTF-8 boundary
        let input = "a".repeat(8190) + "🦀"; // 8190 + 4 bytes for emoji = 8194 bytes
        let processed = preprocess_code(&input);

        // Should be truncated but remain valid UTF-8
        assert!(processed.len() <= 8192);
        assert!(processed.is_ascii() || std::str::from_utf8(processed.as_bytes()).is_ok());
    }
}
