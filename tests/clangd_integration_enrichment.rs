// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for clangd enrichment functionality

mod common;

use common::*;
use common::predicates::*;
use rstest::*;

#[rstest]
fn test_index_with_clangd(test_env: TestEnv) {
    skip_if_no_libclang!();

    IndexRunner::new(&test_env)
        .with_clangd()
        .assert()
        .success()
        .stdout(has_enrichment_stats())
        .stdout(has_function_count(EXPECTED_FUNCTIONS))
        .stdout(has_enriched_functions(EXPECTED_FUNCTIONS))
        .stdout(has_enriched_types(EXPECTED_TYPES));
}

#[rstest]
fn test_clangd_with_absolute_paths(test_env: TestEnv) {
    skip_if_no_libclang!();

    let test_sample = test_env.path().join("test_sample.c");
    let cc = test_env.path().join("compile_commands_absolute.json");

    std::fs::write(&cc, format!(
        r#"[{{"command":"gcc -c {} -o test.o","directory":"{}","file":"{}"}}]"#,
        test_sample.display(), test_env.path().display(), test_sample.display()
    )).unwrap();

    IndexRunner::new(&test_env)
        .with_clangd()
        .with_compile_commands_path(cc)
        .assert()
        .success()
        .stdout(has_enriched_functions(EXPECTED_FUNCTIONS))
        .stdout(has_enriched_types(EXPECTED_TYPES));
}

#[tokio::test]
async fn test_enrichment_persists_to_database() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        skip_if_no_libclang!();

        let test_env = TestEnv::new();
        IndexRunner::new(&test_env).with_clangd().assert().success();

        let db = semcode::DatabaseManager::new(
            test_env.db_path().to_str().unwrap(),
            test_env.path().to_str().unwrap().to_string(),
        ).await.unwrap();

        // Verify function enrichment
        let func = &db.find_all_functions("free_list").await.unwrap()[0];
        assert!(func.usr.as_ref().unwrap().starts_with("c:@F@"));
        assert!(func.signature.as_ref().unwrap().contains("free_list"));

        // Verify type enrichment
        let type_info = db.find_type("Point").await.unwrap().unwrap();
        assert!(type_info.usr.as_ref().unwrap().starts_with("c:@"));
    })
    .await
    .expect("Test timed out after 5 seconds");
}

#[tokio::test]
async fn test_macro_usr_enrichment() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        skip_if_no_libclang!();

        let test_env = tempfile::tempdir().unwrap();
        let fixtures = fixtures_dir();

        for f in ["test_macro_usr.c", "compile_commands_macro_test.json"] {
            std::fs::copy(fixtures.join(f), test_env.path().join(
                if f.contains("macro_test") { "compile_commands.json" } else { f }
            )).unwrap();
        }

        // Init git
        for args in [vec!["init", "-q"], vec!["add", "."], vec!["commit", "-qm", "test"]] {
            assert_cmd::Command::new("git").current_dir(test_env.path()).args(&args).output().unwrap();
        }

        let db_path = test_env.path().join(".semcode.db");
        assert_cmd::Command::cargo_bin("semcode-index").unwrap()
            .current_dir(test_env.path())
            .args(["--clear", "--source", ".", "--database"])
            .arg(&db_path)
            .arg("--use-clangd")
            .assert()
            .success();

        let db = semcode::DatabaseManager::new(
            db_path.to_str().unwrap(),
            test_env.path().to_str().unwrap().to_string(),
        ).await.unwrap();

        let mac = db.find_macro("MAX").await.unwrap().unwrap();
        assert!(mac.usr.as_ref().unwrap().starts_with("c:"));
    })
    .await
    .expect("Test timed out after 5 seconds");
}
