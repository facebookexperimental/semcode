// SPDX-License-Identifier: MIT OR Apache-2.0
use std::collections::HashMap;
use std::sync::Mutex;

const LINES_PER_PAGE: usize = 50;
const MAX_UNRELATED_QUERIES: usize = 5;

/// Pagination cache for MCP server responses
/// Stores paginated results and tracks access patterns for automatic cleanup
pub struct PageCache {
    // Outer map: query_key -> (page_num -> page_content)
    cache: Mutex<HashMap<String, PagedQuery>>,
}

struct PagedQuery {
    pages: HashMap<usize, String>,
    total_pages: usize,
    last_accessed_page: usize,
    unrelated_query_count: usize,
}

impl PageCache {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Paginate content and return the requested page
    /// If page is None, returns the entire content unpaginated
    /// If page is Some(n), returns page n with pagination info
    pub fn get_page(&self, query_key: &str, content: &str, page: Option<usize>) -> (String, bool) {
        // If no page specified, return entire content without caching
        let Some(requested_page) = page else {
            return (content.to_string(), false);
        };

        let mut cache = self.cache.lock().unwrap();

        // Check if query already exists in cache
        if let Some(paged_query) = cache.get_mut(query_key) {
            // Query found in cache
            paged_query.unrelated_query_count = 0; // Reset counter

            // Check if requested page exists
            if requested_page == 0 || requested_page > paged_query.total_pages {
                // Invalid page number
                return (
                    format!(
                        "Error: Invalid page number {}. Valid range: 1-{}",
                        requested_page, paged_query.total_pages
                    ),
                    false,
                );
            }

            // Get the page content
            let page_content = paged_query
                .pages
                .get(&requested_page)
                .expect("Page should exist");

            // Update last accessed page
            paged_query.last_accessed_page = requested_page;

            // Check if this is the last page
            let is_last_page = requested_page == paged_query.total_pages;
            let result = format_page_output(page_content, requested_page, paged_query.total_pages);

            // If last page accessed, remove from cache
            if is_last_page {
                cache.remove(query_key);
            }

            return (result, true);
        }

        // Query not in cache - paginate and cache it
        let lines: Vec<&str> = content.lines().collect();
        let total_lines = lines.len();
        let total_pages = total_lines.div_ceil(LINES_PER_PAGE); // Ceiling division

        if total_pages == 0 {
            return (format!("Page 1 of 1\n\n{}", content), false);
        }

        // Check if requested page is valid
        if requested_page == 0 || requested_page > total_pages {
            return (
                format!(
                    "Error: Invalid page number {}. Valid range: 1-{}",
                    requested_page, total_pages
                ),
                false,
            );
        }

        // Create pages
        let mut pages = HashMap::new();
        for page_num in 1..=total_pages {
            let start_idx = (page_num - 1) * LINES_PER_PAGE;
            let end_idx = std::cmp::min(start_idx + LINES_PER_PAGE, total_lines);
            let page_content = lines[start_idx..end_idx].join("\n");
            pages.insert(page_num, page_content);
        }

        // Get the requested page
        let page_content = pages.get(&requested_page).expect("Page should exist");
        let result = format_page_output(page_content, requested_page, total_pages);

        // Check if this is the last page (and only page, don't cache)
        let is_last_page = requested_page == total_pages;

        // Only cache if not the last page
        if !is_last_page {
            // Increment unrelated query count for all other queries
            for paged_query in cache.values_mut() {
                paged_query.unrelated_query_count += 1;
            }

            // Remove queries that have exceeded the unrelated query limit
            cache
                .retain(|_, paged_query| paged_query.unrelated_query_count < MAX_UNRELATED_QUERIES);

            // Insert new query
            cache.insert(
                query_key.to_string(),
                PagedQuery {
                    pages,
                    total_pages,
                    last_accessed_page: requested_page,
                    unrelated_query_count: 0,
                },
            );
        }

        (result, true)
    }

    /// Clear all cached queries (useful for testing or manual cleanup)
    #[allow(dead_code)]
    pub fn clear(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
    }

    /// Get number of cached queries (useful for testing)
    #[allow(dead_code)]
    pub fn cache_size(&self) -> usize {
        let cache = self.cache.lock().unwrap();
        cache.len()
    }
}

fn format_page_output(content: &str, page_num: usize, total_pages: usize) -> String {
    format!("Page {} of {}\n\n{}", page_num, total_pages, content)
}

impl Default for PageCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_pagination() {
        let cache = PageCache::new();
        let content = "line1\nline2\nline3";
        let (result, _paginated) = cache.get_page("test", content, None);
        assert_eq!(result, content);
    }

    #[test]
    fn test_single_page() {
        let cache = PageCache::new();
        let content = "line1\nline2\nline3";
        let (result, _paginated) = cache.get_page("test", content, Some(1));
        assert!(result.contains("Page 1 of 1"));
        assert!(result.contains("line1\nline2\nline3"));
    }

    #[test]
    fn test_multiple_pages() {
        let cache = PageCache::new();
        let mut lines = Vec::new();
        for i in 1..=100 {
            lines.push(format!("line{}", i));
        }
        let content = lines.join("\n");

        // Get page 1
        let (result1, _) = cache.get_page("test", &content, Some(1));
        assert!(result1.contains("Page 1 of 2"));
        assert!(result1.contains("line1"));
        assert!(!result1.contains("line51"));

        // Get page 2
        let (result2, _) = cache.get_page("test", &content, Some(2));
        assert!(result2.contains("Page 2 of 2"));
        assert!(result2.contains("line51"));
    }

    #[test]
    fn test_cache_removal_on_last_page() {
        let cache = PageCache::new();
        let mut lines = Vec::new();
        for i in 1..=100 {
            lines.push(format!("line{}", i));
        }
        let content = lines.join("\n");

        // Get page 1 (should cache)
        cache.get_page("test", &content, Some(1));
        assert_eq!(cache.cache_size(), 1);

        // Get page 2 (last page, should remove from cache)
        cache.get_page("test", &content, Some(2));
        assert_eq!(cache.cache_size(), 0);
    }

    #[test]
    fn test_unrelated_query_cleanup() {
        let cache = PageCache::new();
        let content = "a\n".repeat(100);

        // Create first cached query
        cache.get_page("query1", &content, Some(1));
        assert_eq!(cache.cache_size(), 1);

        // Create 5 new queries (each should increment unrelated count)
        for i in 2..=6 {
            cache.get_page(&format!("query{}", i), &content, Some(1));
        }

        // query1 should have been removed (5 unrelated queries)
        // All 5 newer queries (query2-query6) should still be cached
        assert_eq!(cache.cache_size(), 5);
    }

    #[test]
    fn test_invalid_page_number() {
        let cache = PageCache::new();
        let content = "line1\nline2\nline3";

        // Page 0 is invalid
        let (result, _) = cache.get_page("test", content, Some(0));
        assert!(result.contains("Error: Invalid page number"));

        // Page 2 is invalid (only 1 page exists)
        let (result, _) = cache.get_page("test", content, Some(2));
        assert!(result.contains("Error: Invalid page number"));
    }
}
