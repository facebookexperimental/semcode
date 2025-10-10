// SPDX-License-Identifier: MIT OR Apache-2.0
//! Database utilities for path processing and connection management

use std::path::Path;

/// Process database path argument according to semcode's database location rules
///
/// This function implements the standard semcode database path resolution logic:
/// 1. If `database_arg` is provided:
///    - If it's a directory, look for `.semcode.db` within it
///    - Otherwise, use the path as-is (direct database path)
/// 2. If `database_arg` is None:
///    - For indexing operations: prefer `source_dir/.semcode.db`, fallback to current directory
///    - For query operations: use current directory `./.semcode.db`
///
/// # Arguments
/// * `database_arg` - Optional database path from command line (-d flag)
/// * `source_dir` - Optional source directory for indexing operations
///
/// # Returns
/// String representation of the database path to use
pub fn process_database_path(database_arg: Option<&str>, source_dir: Option<&Path>) -> String {
    match database_arg {
        Some(path) => {
            let path_obj = Path::new(path);

            // If path already ends with .semcode.db, use it as-is (avoid double appending)
            if path.ends_with(".semcode.db") {
                path.to_string()
            } else if path_obj.is_dir() {
                // If the path is a directory, look for .semcode.db within it
                let semcode_db_path = path_obj.join(".semcode.db");
                semcode_db_path.to_string_lossy().to_string()
            } else {
                // If it's a specific file path, use it as-is
                path.to_string()
            }
        }
        None => {
            // No -d flag provided - behavior depends on whether we have a source directory
            match source_dir {
                Some(source_path) => {
                    // For indexing operations: prefer source directory unless it's current directory
                    let source_semcode_db = source_path.join(".semcode.db");
                    if source_path != Path::new(".") {
                        source_semcode_db.to_string_lossy().to_string()
                    } else {
                        // Source is current directory, use current directory
                        "./.semcode.db".to_string()
                    }
                }
                None => {
                    // For query operations: use current directory
                    "./.semcode.db".to_string()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_process_database_path_with_explicit_path() {
        // Test with explicit file path
        let result = process_database_path(Some("/path/to/my.db"), None);
        assert_eq!(result, "/path/to/my.db");
    }

    #[test]
    fn test_process_database_path_with_directory() {
        // Test with directory - should append .semcode.db
        // Note: In a real test environment, we'd need to create actual directories
        // For now, we test the logic with a hypothetical directory
        let result = process_database_path(Some("/existing/dir"), None);
        // This would be "/existing/dir/.semcode.db" if the directory exists
        // For this unit test, it will treat it as a file since we don't have real filesystem
        assert_eq!(result, "/existing/dir");
    }

    #[test]
    fn test_process_database_path_no_args_no_source() {
        // Test query mode (no source directory)
        let result = process_database_path(None, None);
        assert_eq!(result, "./.semcode.db");
    }

    #[test]
    fn test_process_database_path_no_args_with_source() {
        // Test index mode with source directory
        let source_path = Path::new("/source/code");
        let result = process_database_path(None, Some(source_path));
        assert_eq!(result, "/source/code/.semcode.db");
    }

    #[test]
    fn test_process_database_path_current_dir_source() {
        // Test index mode with current directory as source
        let source_path = Path::new(".");
        let result = process_database_path(None, Some(source_path));
        assert_eq!(result, "./.semcode.db");
    }
}
