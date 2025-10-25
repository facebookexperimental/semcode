// SPDX-License-Identifier: MIT OR Apache-2.0
//
// SQL utility functions for database operations
//
// This module provides utilities for building SQL queries, particularly
// for formatting large IN clauses efficiently.

/// Format strings for use in SQL IN clauses
///
/// Takes a slice of strings and formats them as SQL-escaped strings
/// wrapped in single quotes. This is commonly used for building WHERE IN clauses.
///
/// # Arguments
/// * `items` - Slice of strings to format
///
/// # Returns
/// Vec of formatted strings with SQL escaping and single quotes
///
/// # Examples
/// ```
/// use semcode::database::sql_utils::format_sql_strings;
///
/// let hashes = vec!["abc123", "def456"];
/// let formatted = format_sql_strings(&hashes);
/// assert_eq!(formatted, vec!["'abc123'", "'def456'"]);
/// ```
pub fn format_sql_strings(items: &[impl AsRef<str>]) -> Vec<String> {
    items
        .iter()
        .map(|item| format!("'{}'", item.as_ref().replace("'", "''")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_sql_strings_empty() {
        let items: Vec<String> = vec![];
        let result = format_sql_strings(&items);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_format_sql_strings_single() {
        let items = vec!["test"];
        let result = format_sql_strings(&items);
        assert_eq!(result, vec!["'test'"]);
    }

    #[test]
    fn test_format_sql_strings_multiple() {
        let items = vec!["abc", "def", "ghi"];
        let result = format_sql_strings(&items);
        assert_eq!(result, vec!["'abc'", "'def'", "'ghi'"]);
    }

    #[test]
    fn test_format_sql_strings_with_quotes() {
        let items = vec!["test's", "a'b'c"];
        let result = format_sql_strings(&items);
        assert_eq!(result, vec!["'test''s'", "'a''b''c'"]);
    }

    #[test]
    fn test_format_sql_strings_hashes() {
        // Test typical hash values
        let items = vec!["abc123def456", "1234567890abcdef", "fedcba0987654321"];
        let result = format_sql_strings(&items);
        assert_eq!(
            result,
            vec!["'abc123def456'", "'1234567890abcdef'", "'fedcba0987654321'"]
        );
    }

    #[test]
    fn test_format_sql_strings_large_batch() {
        // Test with larger batch (100 items)
        let items: Vec<String> = (0..100).map(|i| format!("hash_{}", i)).collect();
        let result = format_sql_strings(&items);
        assert_eq!(result.len(), 100);
        assert_eq!(result[0], "'hash_0'");
        assert_eq!(result[99], "'hash_99'");
    }

    #[test]
    fn test_format_sql_strings_special_chars() {
        let items = vec!["test\nline", "test\ttab", "test\\slash"];
        let result = format_sql_strings(&items);
        assert_eq!(result, vec!["'test\nline'", "'test\ttab'", "'test\\slash'"]);
    }

    #[test]
    fn test_format_sql_strings_empty_string() {
        let items = vec![""];
        let result = format_sql_strings(&items);
        assert_eq!(result, vec!["''"]);
    }

    #[test]
    fn test_format_sql_strings_unicode() {
        let items = vec!["测试", "тест", "🦀"];
        let result = format_sql_strings(&items);
        assert_eq!(result, vec!["'测试'", "'тест'", "'🦀'"]);
    }

    #[test]
    fn test_format_sql_strings_very_large_batch() {
        // Test with 1000 items to verify performance characteristics
        let items: Vec<String> = (0..1000).map(|i| format!("item_{}", i)).collect();
        let result = format_sql_strings(&items);
        assert_eq!(result.len(), 1000);
        assert_eq!(result[0], "'item_0'");
        assert_eq!(result[500], "'item_500'");
        assert_eq!(result[999], "'item_999'");
    }
}
