// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tests for database persistence of enrichment data

mod common;

use common::*;
use pretty_assertions::assert_eq;

#[tokio::test]
async fn test_enrichment_retrieval_all_paths() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        skip_if_no_libclang!();

        let test_env = TestEnv::new();
        IndexRunner::new(&test_env).with_clangd().assert().success();

        let db = semcode::DatabaseManager::new(
            test_env.db_path().to_str().unwrap(),
            test_env.path().to_str().unwrap().to_string(),
        ).await.unwrap();

        // Test function enrichment
        let func = &db.find_all_functions("create_point").await.unwrap()[0];
        assert!(func.usr.as_ref().unwrap().starts_with("c:@F@"));
        assert!(func.signature.is_some() && func.canonical_return_type.is_some());

        // Test type enrichment via find_type
        let type_info = db.find_type("Point").await.unwrap().unwrap();
        assert!(type_info.usr.as_ref().unwrap().starts_with("c:@"));
        assert!(type_info.canonical_name.is_some());

        // Test macro enrichment
        let mac = db.find_macro("MAX").await.unwrap().unwrap();
        if let Some(usr) = &mac.usr {
            assert!(usr.starts_with("c:"));
        }

        // Test bulk retrieval
        let all_types = db.get_all_types().await.unwrap();
        let point = all_types.iter().find(|t| t.name == "Point").unwrap();
        assert!(point.usr.is_some());

        // Test get_by_names
        let types_by_name = db.get_types_by_names(&["Point".to_string()]).await.unwrap();
        let point_by_name = types_by_name.get("Point").unwrap();
        assert!(point_by_name.usr.is_some() && point_by_name.canonical_name.is_some());

        // Verify consistency
        assert_eq!(type_info.usr, point.usr);
        assert_eq!(type_info.usr, point_by_name.usr);
    })
    .await
    .expect("Test timed out after 5 seconds");
}

#[tokio::test]
async fn test_enrichment_with_custom_db_path() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        skip_if_no_libclang!();

        let test_env = TestEnv::new();
        let custom_db = test_env.path().join("custom.semcode.db");

        assert_cmd::Command::cargo_bin("semcode-index").unwrap()
            .current_dir(test_env.path())
            .args(["--clear", "--source", ".", "--database"])
            .arg(&custom_db)
            .arg("--use-clangd")
            .assert()
            .success();

        let db = semcode::DatabaseManager::new(
            custom_db.to_str().unwrap(),
            test_env.path().to_str().unwrap().to_string(),
        ).await.unwrap();

        let functions = db.find_all_functions("create_point").await.unwrap();
        assert!(!functions.is_empty() && functions[0].usr.is_some());
    })
    .await
    .expect("Test timed out after 5 seconds");
}
