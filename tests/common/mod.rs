// SPDX-License-Identifier: MIT OR Apache-2.0
//! Common test helpers and fixtures for clangd integration tests

#![allow(dead_code)]

use assert_cmd::Command;
use rstest::*;
use std::path::PathBuf;
use tempfile::TempDir;

/// Expected counts for test_sample.c without clangd enrichment
pub const EXPECTED_FUNCTIONS: u32 = 15;
pub const EXPECTED_TYPES: u32 = 8;
pub const EXPECTED_MACROS_WITHOUT_CLANGD: u32 = 4; // Function-like only
pub const EXPECTED_MACROS_WITH_CLANGD: u32 = 8; // All macros with USRs

/// Test environment wrapper that manages temporary directories and git setup
pub struct TestEnv {
    temp_dir: TempDir,
}

impl TestEnv {
    /// Create a new test environment with default compile_commands.json
    pub fn new() -> Self {
        Self::with_compile_commands("compile_commands.json")
    }

    /// Create a test environment with a specific compile_commands.json file
    pub fn with_compile_commands(compile_commands_file: &str) -> Self {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");

        // Copy test files from fixtures
        let fixtures = fixtures_dir();
        std::fs::copy(
            fixtures.join("test_sample.c"),
            temp_dir.path().join("test_sample.c"),
        )
        .expect("Failed to copy test_sample.c");

        std::fs::copy(
            fixtures.join(compile_commands_file),
            temp_dir.path().join("compile_commands.json"),
        )
        .unwrap_or_else(|_| panic!("Failed to copy {}", compile_commands_file));

        // Initialize git (required for indexing)
        Self::init_git(&temp_dir);

        Self { temp_dir }
    }

    /// Create a minimal test environment with custom file content
    pub fn with_custom_file(filename: &str, content: &str) -> Self {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");

        std::fs::write(temp_dir.path().join(filename), content)
            .expect("Failed to write custom file");

        Self::init_git(&temp_dir);

        Self { temp_dir }
    }

    /// Get the path to the temporary directory
    pub fn path(&self) -> &std::path::Path {
        self.temp_dir.path()
    }

    /// Get the path to the database
    pub fn db_path(&self) -> PathBuf {
        self.path().join(".semcode.db")
    }

    /// Initialize git repository in the temp directory
    fn init_git(temp_dir: &TempDir) {
        Command::new("git")
            .current_dir(temp_dir.path())
            .args(["init", "-q"])
            .output()
            .expect("Failed to init git");

        Command::new("git")
            .current_dir(temp_dir.path())
            .args(["add", "."])
            .output()
            .expect("Failed to git add");

        Command::new("git")
            .current_dir(temp_dir.path())
            .args(["commit", "-qm", "test"])
            .output()
            .expect("Failed to git commit");
    }
}

/// rstest fixture that provides a clean test environment
#[fixture]
pub fn test_env() -> TestEnv {
    TestEnv::new()
}

/// Builder for running semcode-index with various options
pub struct IndexRunner<'a> {
    env: &'a TestEnv,
    use_clangd: bool,
    compile_commands: Option<PathBuf>,
}

impl<'a> IndexRunner<'a> {
    /// Create a new index runner for the given test environment
    pub fn new(env: &'a TestEnv) -> Self {
        Self {
            env,
            use_clangd: false,
            compile_commands: None,
        }
    }

    /// Enable clangd enrichment
    pub fn with_clangd(mut self) -> Self {
        self.use_clangd = true;
        self
    }

    /// Use a custom compile_commands.json path
    pub fn with_compile_commands_path(mut self, path: PathBuf) -> Self {
        self.compile_commands = Some(path);
        self
    }

    /// Run semcode-index and return the output
    pub fn run(self) -> std::process::Output {
        let mut cmd = Command::cargo_bin("semcode-index").expect("Failed to find semcode-index");

        cmd.current_dir(self.env.path())
            .arg("--clear")
            .arg("--source")
            .arg(".")
            .arg("--database")
            .arg(self.env.db_path());

        if self.use_clangd {
            cmd.arg("--use-clangd");
        }

        if let Some(cc_path) = self.compile_commands {
            cmd.arg("--compile-commands").arg(cc_path);
        }

        cmd.output().expect("Failed to run semcode-index")
    }

    /// Run and return an assert_cmd::Assert for fluent assertions
    pub fn assert(self) -> assert_cmd::assert::Assert {
        let mut cmd = Command::cargo_bin("semcode-index").expect("Failed to find semcode-index");

        cmd.current_dir(self.env.path())
            .arg("--clear")
            .arg("--source")
            .arg(".")
            .arg("--database")
            .arg(self.env.db_path());

        if self.use_clangd {
            cmd.arg("--use-clangd");
        }

        if let Some(cc_path) = self.compile_commands {
            cmd.arg("--compile-commands").arg(cc_path);
        }

        cmd.assert()
    }
}

/// Helper for asserting on command output
pub struct OutputAsserter {
    pub stderr: String,
    pub combined: String,
}

impl OutputAsserter {
    /// Create a new output asserter from command output
    pub fn new(output: &std::process::Output) -> Self {
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined = format!("{}{}", stdout, stderr);

        Self {
            stderr,
            combined,
        }
    }

    /// Assert that the command succeeded
    pub fn assert_success(&self, output: &std::process::Output) {
        assert!(
            output.status.success(),
            "Command failed:\n{}",
            self.combined
        );
    }

    /// Assert expected indexing counts
    pub fn assert_counts(&self, functions: u32, types: u32, macros: u32) {
        assert!(
            self.combined
                .contains(&format!("Functions indexed: {}", functions)),
            "Expected {} functions. Output:\n{}",
            functions,
            self.combined
        );
        assert!(
            self.combined
                .contains(&format!("Types indexed: {}", types)),
            "Expected {} types. Output:\n{}",
            types,
            self.combined
        );
        assert!(
            self.combined
                .contains(&format!("Macros indexed: {}", macros)),
            "Expected {} macros. Output:\n{}",
            macros,
            self.combined
        );
    }

    /// Assert that enrichment statistics are present
    pub fn assert_enrichment_stats(&self) {
        assert!(
            self.combined.contains("Clangd Enrichment Statistics"),
            "Should show enrichment statistics. Output:\n{}",
            self.combined
        );
    }

    /// Assert enrichment counts
    pub fn assert_enrichment_counts(&self, functions: u32, types: u32) {
        assert!(
            self.combined
                .contains(&format!("Functions enriched with USR: {}", functions)),
            "Expected {} functions enriched. Output:\n{}",
            functions,
            self.combined
        );
        assert!(
            self.combined
                .contains(&format!("Types enriched with USR: {}", types)),
            "Expected {} types enriched. Output:\n{}",
            types,
            self.combined
        );
    }

    /// Assert that compile commands were found
    pub fn assert_compile_commands(&self, count: u32) {
        assert!(
            self.combined
                .contains(&format!("Files with compile commands: {}", count)),
            "Expected {} files with compile commands. Output:\n{}",
            count,
            self.combined
        );
    }

    /// Assert no enrichment occurred
    pub fn assert_no_enrichment(&self) {
        assert!(
            !self.combined.contains("Clangd Enrichment Statistics"),
            "Should not show enrichment without --use-clangd. Output:\n{}",
            self.combined
        );
        assert!(
            !self.combined.contains("Functions enriched with USR"),
            "Should not show USR enrichment. Output:\n{}",
            self.combined
        );
    }

    /// Assert that output contains a pattern
    pub fn assert_contains(&self, pattern: &str) {
        assert!(
            self.combined.contains(pattern),
            "Output should contain '{}'. Output:\n{}",
            pattern,
            self.combined
        );
    }

    /// Assert that output does NOT contain a pattern
    pub fn assert_not_contains(&self, pattern: &str) {
        assert!(
            !self.combined.contains(pattern),
            "Output should NOT contain '{}'. Output:\n{}",
            pattern,
            self.combined
        );
    }
}

/// Get the path to test fixtures directory
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("clangd_integration")
}

/// Check if libclang is available on this system (Linux only)
pub fn is_libclang_available() -> bool {
    use std::process::Command;

    // Try to find libclang using ldconfig
    if let Ok(output) = Command::new("ldconfig").arg("-p").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("libclang.so") || stdout.contains("libclang-") {
            return true;
        }
    }

    // Fallback: check common library paths
    std::path::Path::new("/usr/lib/libclang.so").exists()
        || std::path::Path::new("/usr/lib/x86_64-linux-gnu/libclang.so").exists()
        || std::path::Path::new("/usr/lib64/libclang.so").exists()
}

/// Skip test if libclang is not available
#[macro_export]
macro_rules! skip_if_no_libclang {
    () => {
        if !$crate::common::is_libclang_available() {
            eprintln!("Skipping test: libclang not available");
            return;
        }
    };
}

/// Predicates for common assertions
pub mod predicates {
    use predicates::str::ContainsPredicate;

    /// Predicate that matches enrichment statistics output
    pub fn has_enrichment_stats() -> ContainsPredicate {
        predicates::str::contains("Clangd Enrichment Statistics")
    }

    /// Predicate that matches function count
    pub fn has_function_count(count: u32) -> ContainsPredicate {
        predicates::str::contains(format!("Functions indexed: {}", count))
    }

    /// Predicate that matches type count
    pub fn has_type_count(count: u32) -> ContainsPredicate {
        predicates::str::contains(format!("Types indexed: {}", count))
    }

    /// Predicate that matches macro count
    pub fn has_macro_count(count: u32) -> ContainsPredicate {
        predicates::str::contains(format!("Macros indexed: {}", count))
    }

    /// Predicate that matches enriched function count
    pub fn has_enriched_functions(count: u32) -> ContainsPredicate {
        predicates::str::contains(format!("Functions enriched with USR: {}", count))
    }

    /// Predicate that matches enriched type count
    pub fn has_enriched_types(count: u32) -> ContainsPredicate {
        predicates::str::contains(format!("Types enriched with USR: {}", count))
    }
}
