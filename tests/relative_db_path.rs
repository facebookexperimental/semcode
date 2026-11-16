// SPDX-License-Identifier: MIT OR Apache-2.0
//
// A database named by a relative path opens as a local directory, whatever
// its first component is called.
use semcode::DatabaseManager;

/// A relative path whose first component starts with `db` names a local
/// directory, not a LanceDB Cloud database.
#[tokio::test]
async fn relative_path_starting_with_db_opens_locally() {
    // Relative to the working directory, which is where a relative `-d`
    // resolves; removed when `dir` drops.
    let dir = tempfile::Builder::new()
        .prefix("db")
        .tempdir_in(".")
        .unwrap();
    let first_component = dir.path().file_name().unwrap().to_str().unwrap();
    let db_path = format!("{first_component}/.semcode.db");
    assert!(db_path.starts_with("db"), "{db_path}");

    let db = DatabaseManager::new(&db_path, ".".to_string())
        .await
        .unwrap();
    db.create_tables().await.unwrap();

    assert!(
        dir.path().join(".semcode.db").is_dir(),
        "tables were not written under {db_path}"
    );
    assert!(db
        .list_tables()
        .await
        .unwrap()
        .iter()
        .any(|t| t == "functions"));
}
