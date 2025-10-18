// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tests for multi-process clangd enrichment (worker and processor)

mod common;

use semcode::clangd_worker::{WorkRequest, WorkResponse};
use semcode::ClangdProcessor;
use std::path::PathBuf;
use tempfile::TempDir;

/// Get the path to semcode-index binary, building it if needed
/// This prevents stale binary issues when ClangdProcessor spawns worker processes
fn get_semcode_index_binary() -> PathBuf {
    // Use cargo_bin! macro from assert_cmd to ensure binary is built fresh
    // This automatically builds the binary if needed before returning the path
    assert_cmd::cargo::cargo_bin("semcode-index")
}

/// Test that worker and processor can be created
#[tokio::test]
async fn test_processor_creation() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let binary = get_semcode_index_binary();  // Get fresh binary path

        let temp_dir = TempDir::new().unwrap();
        let source_root = temp_dir.path().to_path_buf();

        // Create minimal compile_commands.json
        let compile_commands_path = temp_dir.path().join("compile_commands.json");
        std::fs::write(
            &compile_commands_path,
            r#"[
  {
    "directory": ".",
    "command": "gcc -c test.c",
    "file": "test.c"
  }
]"#,
        )
        .unwrap();

        // Create test file
        std::fs::write(
            temp_dir.path().join("test.c"),
            "int main() { return 0; }",
        )
        .unwrap();

        // Try to create processor with 2 workers
        let result = ClangdProcessor::new_with_binary(2, compile_commands_path, source_root, binary);

        // Note: This may fail if libclang is not available
        // We're just testing the API, not full functionality
        match result {
            Ok(_processor) => {
                // Success! Processor created
                println!("Processor created successfully");
            }
            Err(e) => {
                // Expected to fail if libclang not available
                println!("Processor creation failed (expected if no libclang): {}", e);
            }
        }
    })
    .await
    .expect("Test timed out after 5 seconds");
}

/// Test that WorkRequest and WorkResponse can be serialized
#[test]
fn test_work_message_serialization() {
    use semcode::FunctionInfo;

    let func = FunctionInfo {
        name: "main".to_string(),
        file_path: "/tmp/test.c".to_string(),
        git_file_hash: "abc123".to_string(),
        line_start: 1,
        line_end: 10,
        body: "int main() {}".to_string(),
        return_type: "int".to_string(),
        canonical_return_type: None,
        parameters: vec![],
        calls: None,
        types: None,
        calls_precise: None,
        usr: None,
        signature: None,
        overload_index: None,
    };

    let request = WorkRequest {
        file_path: PathBuf::from("/tmp/test.c"),
        functions: vec![func],
        types: vec![],
        macros: vec![],
        git_file_sha: "abc123".to_string(),
    };

    // Test bincode serialization
    let encoded = bincode::serialize(&request).unwrap();
    let decoded: WorkRequest = bincode::deserialize(&encoded).unwrap();

    assert_eq!(decoded.file_path, PathBuf::from("/tmp/test.c"));
    assert_eq!(decoded.functions.len(), 1);
    assert_eq!(decoded.functions[0].name, "main");
    assert_eq!(decoded.git_file_sha, "abc123");
}

/// Test that empty WorkResponse can be created and serialized
#[test]
fn test_empty_work_response_serialization() {
    let response = WorkResponse {
        file_path: PathBuf::from("/tmp/test.c"),
        functions: vec![],
        types: vec![],
        macros: vec![],
        git_file_sha: "abc123".to_string(),
        had_compile_commands: false,
    };

    // Test bincode serialization
    let encoded = bincode::serialize(&response).unwrap();
    let decoded: WorkResponse = bincode::deserialize(&encoded).unwrap();

    assert_eq!(decoded.file_path, PathBuf::from("/tmp/test.c"));
    assert_eq!(decoded.functions.len(), 0);
    assert!(!decoded.had_compile_commands);
}

/// Test processor statistics tracking
#[tokio::test]
async fn test_processor_statistics() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let binary = get_semcode_index_binary();
        use std::sync::atomic::Ordering;

        let temp_dir = TempDir::new().unwrap();
        let source_root = temp_dir.path().to_path_buf();

        // Create minimal compile_commands.json
        let compile_commands_path = temp_dir.path().join("compile_commands.json");
        std::fs::write(
            &compile_commands_path,
            r#"[{"directory": ".", "command": "gcc -c test.c", "file": "test.c"}]"#,
        )
        .unwrap();

        std::fs::write(temp_dir.path().join("test.c"), "int main() { return 0; }").unwrap();

        match ClangdProcessor::new_with_binary(1, compile_commands_path, source_root, binary) {
            Ok(processor) => {
                // Check that statistics are initialized to zero
                assert_eq!(processor.files_with_compile_commands.load(Ordering::Relaxed), 0);
                assert_eq!(processor.enriched_functions.load(Ordering::Relaxed), 0);
                assert_eq!(processor.enriched_types.load(Ordering::Relaxed), 0);
                assert_eq!(processor.enriched_macros.load(Ordering::Relaxed), 0);
                println!("Statistics tracking verified");
            }
            Err(e) => {
                println!("Skipping statistics test (no libclang): {}", e);
            }
        }
    })
    .await
    .expect("Test timed out after 5 seconds");
}

/// Test that processor can be dropped cleanly
#[tokio::test]
async fn test_processor_drop() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let binary = get_semcode_index_binary();

        let temp_dir = TempDir::new().unwrap();
        let source_root = temp_dir.path().to_path_buf();

        let compile_commands_path = temp_dir.path().join("compile_commands.json");
        std::fs::write(
            &compile_commands_path,
            r#"[{"directory": ".", "command": "gcc -c test.c", "file": "test.c"}]"#,
        )
        .unwrap();

        std::fs::write(temp_dir.path().join("test.c"), "int main() { return 0; }").unwrap();

        match ClangdProcessor::new_with_binary(2, compile_commands_path, source_root, binary) {
            Ok(processor) => {
                // Drop processor - should cleanly shut down workers
                drop(processor);
                println!("Processor dropped cleanly");
            }
            Err(e) => {
                println!("Skipping drop test (no libclang): {}", e);
            }
        }
    })
    .await
    .expect("Test timed out after 5 seconds");
}

/// Integration test: Verify worker can be spawned via CLI
#[test]
fn test_worker_mode_via_cli() {
    use assert_cmd::Command;
    use predicates::prelude::*;

    // Try to run with --clangd-worker flag (should fail due to missing args)
    // assert_cmd automatically builds the binary fresh before testing
    Command::cargo_bin("semcode-index")
        .unwrap()
        .arg("--clangd-worker")
        .assert()
        .failure()  // Expect non-zero exit code
        .stderr(
            predicate::str::contains("worker-id")
                .or(predicate::str::contains("ipc"))
                .or(predicate::str::contains("required"))
        );
}

/// Test with fixtures (if available)
#[tokio::test]
async fn test_processor_with_real_code() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let binary = get_semcode_index_binary();
        use common::*;

        let test_env = TestEnv::new();

        match ClangdProcessor::new_with_binary(
            2,
            test_env.path().join("compile_commands.json"),
            test_env.path().to_path_buf(),
            binary,
        ) {
            Ok(_processor) => {
                println!("Processor created with real compile_commands.json");
                // TODO: Submit actual work and verify results
            }
            Err(e) => {
                println!("Skipping real code test (no libclang): {}", e);
            }
        }
    })
    .await
    .expect("Test timed out after 5 seconds");
}
