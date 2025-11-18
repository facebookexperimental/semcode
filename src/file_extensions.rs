// SPDX-License-Identifier: MIT OR Apache-2.0

/// Centralized source of truth for file extensions supported by semcode
///
/// This module provides a single location for all file extension definitions
/// to ensure consistency across the codebase.
/// All supported file extensions for code analysis (without leading dot)
pub const SUPPORTED_EXTENSIONS: &[&str] = &[
    "c",   // C source files
    "h",   // C/C++ header files
    "cc",  // C++ source files
    "cpp", // C++ source files
    "cxx", // C++ source files
    "c++", // C++ source files
    "hh",  // C++ header files
    "hpp", // C++ header files
    "hxx", // C++ header files
    "h++", // C++ header files
    "rs",  // Rust source files
    "py",  // Python source files
];

/// Default extensions for indexing (subset of SUPPORTED_EXTENSIONS)
pub const DEFAULT_EXTENSIONS: &[&str] = &["c", "h", "rs"];

/// Returns a Vec<String> of all supported extensions
pub fn supported_extensions() -> Vec<String> {
    SUPPORTED_EXTENSIONS.iter().map(|s| s.to_string()).collect()
}

/// Returns a Vec<String> of default extensions
pub fn default_extensions() -> Vec<String> {
    DEFAULT_EXTENSIONS.iter().map(|s| s.to_string()).collect()
}

/// Returns a comma-separated string of default extensions (for clap default_value)
pub fn default_extensions_string() -> String {
    DEFAULT_EXTENSIONS.join(",")
}

/// Check if a file path has a supported extension (for tree-sitter analysis)
/// This checks extensions that tree-sitter can analyze
pub fn is_supported_for_analysis(file_path: &str) -> bool {
    if let Some(ext) = std::path::Path::new(file_path).extension() {
        let ext_str = ext.to_string_lossy();
        SUPPORTED_EXTENSIONS.contains(&ext_str.as_ref())
    } else {
        false
    }
}

/// Check if a file path is a C/C++ file (for symbol extraction)
/// Symbol extraction is only supported for C/C++ files currently
pub fn is_c_cpp_file(file_path: &str) -> bool {
    file_path.ends_with(".c")
        || file_path.ends_with(".h")
        || file_path.ends_with(".cc")
        || file_path.ends_with(".cpp")
        || file_path.ends_with(".cxx")
        || file_path.ends_with(".c++")
        || file_path.ends_with(".hh")
        || file_path.ends_with(".hpp")
        || file_path.ends_with(".hxx")
        || file_path.ends_with(".h++")
}

/// Check if a file path is a Python file
pub fn is_python_file(file_path: &str) -> bool {
    file_path.ends_with(".py")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_extensions() {
        let exts = supported_extensions();
        assert!(exts.contains(&"c".to_string()));
        assert!(exts.contains(&"rs".to_string()));
        assert!(exts.contains(&"cpp".to_string()));
    }

    #[test]
    fn test_default_extensions() {
        let exts = default_extensions();
        assert_eq!(exts, vec!["c", "h", "rs"]);
    }

    #[test]
    fn test_default_extensions_string() {
        assert_eq!(default_extensions_string(), "c,h,rs");
    }

    #[test]
    fn test_is_supported_for_analysis() {
        assert!(is_supported_for_analysis("test.c"));
        assert!(is_supported_for_analysis("test.rs"));
        assert!(is_supported_for_analysis("test.cpp"));
        assert!(is_supported_for_analysis("test.hpp"));
        assert!(is_supported_for_analysis("test.py"));
        assert!(!is_supported_for_analysis("test.txt"));
    }

    #[test]
    fn test_is_c_cpp_file() {
        assert!(is_c_cpp_file("test.c"));
        assert!(is_c_cpp_file("test.h"));
        assert!(is_c_cpp_file("test.cpp"));
        assert!(is_c_cpp_file("test.hpp"));
        assert!(is_c_cpp_file("test.cxx"));
        assert!(is_c_cpp_file("test.hxx"));
        assert!(!is_c_cpp_file("test.rs"));
        assert!(!is_c_cpp_file("test.py"));
    }

    #[test]
    fn test_is_python_file() {
        assert!(is_python_file("test.py"));
        assert!(!is_python_file("test.c"));
        assert!(!is_python_file("test.rs"));
        assert!(!is_python_file("test.txt"));
    }
}
