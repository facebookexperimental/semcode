// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Collection transformation utilities
//
// This module provides utilities for transforming and collecting data
// from collections efficiently with parallel processing.

use gxhash::HashSet;
use rayon::prelude::*;

use crate::consts::{COLLECTION_PARALLEL_THRESHOLD, FILTER_PARALLEL_THRESHOLD};

/// Extract paths from collection and collect into a HashSet
///
/// Takes a collection of items that can provide String paths via a closure,
/// and collects them into a HashSet. This is a generic utility for path
/// collection operations. Automatically uses parallel processing for
/// collections over COLLECTION_PARALLEL_THRESHOLD.
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
    F: Fn(&T) -> String + Sync + Send,
    T: Sync,
{
    if items.len() < COLLECTION_PARALLEL_THRESHOLD {
        // Sequential for small collections (better cache locality)
        items.iter().map(extractor).collect()
    } else {
        // Parallel for large collections
        items.par_iter().map(extractor).collect()
    }
}

/// Filter items by a predicate with optional limit
///
/// Filters a collection of items using a predicate function and optionally
/// limits the number of results. Returns the filtered items and whether the
/// limit was hit. Automatically uses parallel processing for large collections
/// (>= 500 items) when no limit is specified or limit is large.
///
/// # Arguments
/// * `items` - Vector of items to filter (consumed)
/// * `predicate` - Function that returns true for items to keep
/// * `limit` - Maximum number of items to return (0 = unlimited)
///
/// # Returns
/// Tuple of (filtered items, limit_hit flag)
///
/// # Note
/// When using parallel processing (large collections), result order may differ
/// from sequential processing, but all matching items will be included.
pub fn filter_with_limit<T, F>(items: Vec<T>, predicate: F, limit: usize) -> (Vec<T>, bool)
where
    F: Fn(&T) -> bool + Sync + Send,
    T: Send,
{
    let use_parallel = items.len() >= FILTER_PARALLEL_THRESHOLD
        && (limit == 0 || limit > FILTER_PARALLEL_THRESHOLD / 2);

    if !use_parallel {
        // Sequential for small collections or when early termination is beneficial
        let mut filtered = Vec::new();
        let mut limit_hit = false;

        for item in items {
            if predicate(&item) {
                if limit > 0 && filtered.len() >= limit {
                    limit_hit = true;
                    break;
                }
                filtered.push(item);
            }
        }

        (filtered, limit_hit)
    } else {
        // Parallel for large collections with no/large limits
        let filtered: Vec<T> = items
            .into_par_iter()
            .filter(|item| predicate(item))
            .collect();

        let limit_hit = limit > 0 && filtered.len() > limit;
        let final_filtered = if limit > 0 && filtered.len() > limit {
            filtered.into_iter().take(limit).collect()
        } else {
            filtered
        };

        (final_filtered, limit_hit)
    }
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

    // Tests for filter_with_limit

    #[test]
    fn test_filter_with_limit_empty() {
        let items: Vec<i32> = vec![];
        let (filtered, limit_hit) = filter_with_limit(items, |_| true, 10);
        assert_eq!(filtered.len(), 0);
        assert!(!limit_hit);
    }

    #[test]
    fn test_filter_with_limit_no_limit() {
        let items = vec![1, 2, 3, 4, 5];
        let (filtered, limit_hit) = filter_with_limit(items, |x| x % 2 == 0, 0);
        assert_eq!(filtered, vec![2, 4]);
        assert!(!limit_hit);
    }

    #[test]
    fn test_filter_with_limit_under_limit() {
        let items = vec![1, 2, 3, 4, 5];
        let (filtered, limit_hit) = filter_with_limit(items, |x| x % 2 == 0, 10);
        assert_eq!(filtered, vec![2, 4]);
        assert!(!limit_hit);
    }

    #[test]
    fn test_filter_with_limit_at_limit() {
        let items = vec![2, 4, 6, 8, 10];
        let (filtered, limit_hit) = filter_with_limit(items, |x| x % 2 == 0, 3);
        assert_eq!(filtered, vec![2, 4, 6]);
        assert!(limit_hit);
    }

    #[test]
    fn test_filter_with_limit_over_limit() {
        let items = vec![2, 4, 6, 8, 10, 12];
        let (filtered, limit_hit) = filter_with_limit(items, |x| x % 2 == 0, 2);
        assert_eq!(filtered, vec![2, 4]);
        assert!(limit_hit);
    }

    #[test]
    fn test_filter_with_limit_all_filtered_out() {
        let items = vec![1, 3, 5, 7, 9];
        let (filtered, limit_hit) = filter_with_limit(items, |x| x % 2 == 0, 10);
        assert_eq!(filtered.len(), 0);
        assert!(!limit_hit);
    }

    #[test]
    fn test_filter_with_limit_strings() {
        let items = vec![
            "test.rs".to_string(),
            "main.rs".to_string(),
            "lib.rs".to_string(),
            "test_helper.rs".to_string(),
        ];
        let (filtered, limit_hit) = filter_with_limit(items, |s| s.contains("test"), 1);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0], "test.rs");
        assert!(limit_hit);
    }

    #[test]
    fn test_filter_with_limit_large_collection() {
        let items: Vec<i32> = (0..1000).collect();
        let (filtered, limit_hit) = filter_with_limit(items, |x| x % 2 == 0, 100);
        assert_eq!(filtered.len(), 100);
        assert!(limit_hit);
        assert_eq!(filtered[0], 0);
        assert_eq!(filtered[99], 198);
    }

    #[test]
    fn test_filter_with_limit_complex_predicate() {
        let items: Vec<i32> = (0..50).collect();
        let (filtered, limit_hit) = filter_with_limit(items, |x| x % 3 == 0 && x % 5 == 0, 2);
        assert_eq!(filtered, vec![0, 15]);
        assert!(limit_hit);
    }

    #[test]
    fn test_filter_with_limit_preserve_order() {
        let items = vec![10, 5, 20, 15, 30, 25];
        let (filtered, limit_hit) = filter_with_limit(items, |x| x % 5 == 0, 3);
        assert_eq!(filtered, vec![10, 5, 20]);
        assert!(limit_hit);
    }
}
