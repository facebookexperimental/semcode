// SPDX-License-Identifier: MIT OR Apache-2.0
//! Database utilities for path processing and connection management

use std::path::Path;

/// Process database path argument according to semcode's database location rules
///
/// This function implements the standard semcode database path resolution logic:
/// 1. If `database_arg` is provided:
///    - If it's a directory, look for `.semcode.db` within it
///    - Otherwise, use the path as-is (direct database path)
/// 2. If `database_arg` is None, check the `SEMCODE_DB` environment variable
///    (same directory/suffix semantics as the `-d` flag)
/// 3. If neither is set:
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
        Some(path) => resolve_path(path),
        None => {
            // Check SEMCODE_DB environment variable before falling back to
            // source-dir or current-dir defaults.
            if let Ok(env_path) = std::env::var("SEMCODE_DB") {
                let env_path = env_path.trim();
                if !env_path.is_empty() {
                    return resolve_path(env_path);
                }
            }

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

/// Normalize a database path: append `.semcode.db` to directories, pass
/// paths that already end with `.semcode.db` through unchanged, and
/// return anything else as-is.
fn resolve_path(path: &str) -> String {
    let path_obj = Path::new(path);

    if path.ends_with(".semcode.db") {
        path.to_string()
    } else if path_obj.is_dir() {
        path_obj.join(".semcode.db").to_string_lossy().to_string()
    } else {
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::Mutex;

    /// Serializes tests that read or write the SEMCODE_DB environment variable.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

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
        let _guard = ENV_LOCK.lock().unwrap();
        let saved = std::env::var("SEMCODE_DB").ok();
        std::env::remove_var("SEMCODE_DB");

        let result = process_database_path(None, None);
        assert_eq!(result, "./.semcode.db");

        if let Some(v) = saved {
            std::env::set_var("SEMCODE_DB", v);
        }
    }

    #[test]
    fn test_process_database_path_no_args_with_source() {
        let _guard = ENV_LOCK.lock().unwrap();
        let saved = std::env::var("SEMCODE_DB").ok();
        std::env::remove_var("SEMCODE_DB");

        let source_path = Path::new("/source/code");
        let result = process_database_path(None, Some(source_path));
        assert_eq!(result, "/source/code/.semcode.db");

        if let Some(v) = saved {
            std::env::set_var("SEMCODE_DB", v);
        }
    }

    #[test]
    fn test_process_database_path_current_dir_source() {
        let _guard = ENV_LOCK.lock().unwrap();
        let saved = std::env::var("SEMCODE_DB").ok();
        std::env::remove_var("SEMCODE_DB");

        let source_path = Path::new(".");
        let result = process_database_path(None, Some(source_path));
        assert_eq!(result, "./.semcode.db");

        if let Some(v) = saved {
            std::env::set_var("SEMCODE_DB", v);
        }
    }

    #[test]
    fn test_env_var_used_when_no_flag() {
        let _guard = ENV_LOCK.lock().unwrap();
        let saved = std::env::var("SEMCODE_DB").ok();
        std::env::set_var("SEMCODE_DB", "/data/my-project.semcode.db");

        let result = process_database_path(None, None);
        assert_eq!(result, "/data/my-project.semcode.db");

        // Also overrides source_dir fallback
        let result = process_database_path(None, Some(Path::new("/source/code")));
        assert_eq!(result, "/data/my-project.semcode.db");

        match saved {
            Some(v) => std::env::set_var("SEMCODE_DB", v),
            None => std::env::remove_var("SEMCODE_DB"),
        }
    }

    #[test]
    fn test_flag_overrides_env_var() {
        let _guard = ENV_LOCK.lock().unwrap();
        let saved = std::env::var("SEMCODE_DB").ok();
        std::env::set_var("SEMCODE_DB", "/env/path.semcode.db");

        let result = process_database_path(Some("/flag/path.semcode.db"), None);
        assert_eq!(result, "/flag/path.semcode.db");

        match saved {
            Some(v) => std::env::set_var("SEMCODE_DB", v),
            None => std::env::remove_var("SEMCODE_DB"),
        }
    }

    #[test]
    fn test_empty_env_var_ignored() {
        let _guard = ENV_LOCK.lock().unwrap();
        let saved = std::env::var("SEMCODE_DB").ok();
        std::env::set_var("SEMCODE_DB", "");

        let result = process_database_path(None, None);
        assert_eq!(result, "./.semcode.db");

        match saved {
            Some(v) => std::env::set_var("SEMCODE_DB", v),
            None => std::env::remove_var("SEMCODE_DB"),
        }
    }
}
