// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Collection transformation utilities
//
// This module provides utilities for transforming and collecting data
// from collections efficiently.

use gxhash::HashSet;

/// Extract paths from collection and collect into a HashSet
///
/// Takes a collection of items that can provide String paths via a closure,
/// and collects them into a HashSet. This is a generic utility for path
/// collection operations.
///
/// # Arguments
/// * `items` - Slice of items to extract paths from
/// * `extractor` - Function that extracts a String from each item
///
/// # Returns
/// HashSet of extracted paths
///
/// # Examples
/// ```
/// use gxhash::HashSet;
/// use semcode::collection_utils::collect_paths;
///
/// struct Item { path: String }
/// let items = vec![
///     Item { path: "a".to_string() },
///     Item { path: "b".to_string() },
/// ];
/// let paths = collect_paths(&items, |item| item.path.clone());
/// assert_eq!(paths.len(), 2);
/// ```
pub fn collect_paths<T, F>(items: &[T], extractor: F) -> HashSet<String>
where
    F: Fn(&T) -> String,
{
    items.iter().map(extractor).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct TestItem {
        path: String,
    }

    #[test]
    fn test_collect_paths_empty() {
        let items: Vec<TestItem> = vec![];
        let result = collect_paths(&items, |item| item.path.clone());
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_collect_paths_single() {
        let items = vec![TestItem {
            path: "test/file.rs".to_string(),
        }];
        let result = collect_paths(&items, |item| item.path.clone());
        assert_eq!(result.len(), 1);
        assert!(result.contains("test/file.rs"));
    }

    #[test]
    fn test_collect_paths_multiple() {
        let items = vec![
            TestItem {
                path: "src/main.rs".to_string(),
            },
            TestItem {
                path: "src/lib.rs".to_string(),
            },
            TestItem {
                path: "tests/test.rs".to_string(),
            },
        ];
        let result = collect_paths(&items, |item| item.path.clone());
        assert_eq!(result.len(), 3);
        assert!(result.contains("src/main.rs"));
        assert!(result.contains("src/lib.rs"));
        assert!(result.contains("tests/test.rs"));
    }

    #[test]
    fn test_collect_paths_duplicates() {
        let items = vec![
            TestItem {
                path: "src/main.rs".to_string(),
            },
            TestItem {
                path: "src/lib.rs".to_string(),
            },
            TestItem {
                path: "src/main.rs".to_string(),
            },
        ];
        let result = collect_paths(&items, |item| item.path.clone());
        // HashSet deduplicates
        assert_eq!(result.len(), 2);
        assert!(result.contains("src/main.rs"));
        assert!(result.contains("src/lib.rs"));
    }

    #[test]
    fn test_collect_paths_large_collection() {
        // Test with 1000 items
        let items: Vec<TestItem> = (0..1000)
            .map(|i| TestItem {
                path: format!("file_{}.rs", i),
            })
            .collect();
        let result = collect_paths(&items, |item| item.path.clone());
        assert_eq!(result.len(), 1000);
        assert!(result.contains("file_0.rs"));
        assert!(result.contains("file_999.rs"));
    }

    #[test]
    fn test_collect_paths_very_large_collection() {
        // Test with 5000 items to verify scalability
        let items: Vec<TestItem> = (0..5000)
            .map(|i| TestItem {
                path: format!("file_{}.rs", i),
            })
            .collect();
        let result = collect_paths(&items, |item| item.path.clone());
        assert_eq!(result.len(), 5000);
        assert!(result.contains("file_0.rs"));
        assert!(result.contains("file_2500.rs"));
        assert!(result.contains("file_4999.rs"));
    }

    #[test]
    fn test_collect_paths_with_special_chars() {
        let items = vec![
            TestItem {
                path: "src/mod-name.rs".to_string(),
            },
            TestItem {
                path: "tests/test_file.rs".to_string(),
            },
            TestItem {
                path: "examples/ex.1.rs".to_string(),
            },
        ];
        let result = collect_paths(&items, |item| item.path.clone());
        assert_eq!(result.len(), 3);
        assert!(result.contains("src/mod-name.rs"));
        assert!(result.contains("tests/test_file.rs"));
        assert!(result.contains("examples/ex.1.rs"));
    }

    #[test]
    fn test_collect_paths_unicode() {
        let items = vec![
            TestItem {
                path: "测试/文件.rs".to_string(),
            },
            TestItem {
                path: "тест/файл.rs".to_string(),
            },
        ];
        let result = collect_paths(&items, |item| item.path.clone());
        assert_eq!(result.len(), 2);
        assert!(result.contains("测试/文件.rs"));
        assert!(result.contains("тест/файл.rs"));
    }

    #[test]
    fn test_collect_paths_empty_strings() {
        let items = vec![
            TestItem {
                path: "".to_string(),
            },
            TestItem {
                path: "file.rs".to_string(),
            },
        ];
        let result = collect_paths(&items, |item| item.path.clone());
        assert_eq!(result.len(), 2);
        assert!(result.contains(""));
        assert!(result.contains("file.rs"));
    }

    #[test]
    fn test_collect_paths_custom_extractor() {
        // Test with a different extractor function
        struct CustomItem {
            id: usize,
        }
        let items = vec![CustomItem { id: 1 }, CustomItem { id: 2 }];
        let result = collect_paths(&items, |item| format!("id_{}", item.id));
        assert_eq!(result.len(), 2);
        assert!(result.contains("id_1"));
        assert!(result.contains("id_2"));
    }
}
