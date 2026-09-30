// SPDX-License-Identifier: MIT OR Apache-2.0
//
// An index written by an older semcode does not hold what a newer one
// extracts. It has to say so, or every later run trusts it and skips the
// files that would have produced the missing rows.
use semcode::{DatabaseManager, SCHEMA_VERSION};

async fn manager(dir: &std::path::Path) -> DatabaseManager {
    let db = DatabaseManager::new(
        dir.join(".semcode.db").to_str().unwrap(),
        dir.to_string_lossy().into_owned(),
    )
    .await
    .unwrap();
    db.create_tables().await.unwrap();
    db
}

#[tokio::test]
async fn a_fresh_index_is_current() {
    let dir = tempfile::tempdir().unwrap();
    let db = manager(dir.path()).await;

    assert_eq!(
        db.stored_schema_version().await.unwrap(),
        Some(SCHEMA_VERSION)
    );
    assert!(!db.index_predates_reader().await.unwrap());
}

#[tokio::test]
async fn an_index_that_predates_versioning_is_not_current() {
    // What an older semcode leaves behind: tables with rows in them and no
    // record of what wrote them. Creating the missing table must not claim
    // the rows are as new as the build that found them.
    let dir = tempfile::tempdir().unwrap();
    let db = manager(dir.path()).await;
    drop(db);

    let path = dir.path().join(".semcode.db").join("schema_meta.lance");
    std::fs::remove_dir_all(&path).expect("schema_meta should exist to be removed");

    let db = manager(dir.path()).await;
    assert_eq!(db.stored_schema_version().await.unwrap(), Some(0));
    assert!(
        db.index_predates_reader().await.unwrap(),
        "an index of unknown vintage was taken for a current one"
    );

    // Once the tree has been read again, it holds what this build writes.
    db.record_index_build(&["c".to_string(), "h".to_string()], false)
        .await
        .unwrap();
    assert!(!db.index_predates_reader().await.unwrap());
}

#[tokio::test]
async fn an_index_records_how_it_was_built() {
    // Rebuilding an index for different extensions changes what a query can
    // find, so what it was built for has to be written down rather than
    // assumed.
    let dir = tempfile::tempdir().unwrap();
    let db = manager(dir.path()).await;

    assert_eq!(db.recorded_index_options().await.unwrap(), None);

    db.record_index_build(&["c".to_string(), "h".to_string()], true)
        .await
        .unwrap();
    assert_eq!(
        db.recorded_index_options().await.unwrap(),
        Some((vec!["c".to_string(), "h".to_string()], true))
    );

    // Indexing again with other options replaces them rather than adding a
    // second answer.
    db.record_index_build(&["rs".to_string()], false)
        .await
        .unwrap();
    assert_eq!(
        db.recorded_index_options().await.unwrap(),
        Some((vec!["rs".to_string()], false))
    );
}

#[tokio::test]
async fn a_file_read_by_this_extractor_may_be_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let db = manager(dir.path()).await;

    db.mark_file_processed(
        "fs/read_write.c".to_string(),
        Some("deadbeef".to_string()),
        "cafe1234".to_string(),
    )
    .await
    .unwrap();

    let skippable = db.processed_by_this_extractor().await.unwrap();
    assert!(
        skippable.contains("cafe1234"),
        "a file this build read is not in the skip set: {skippable:?}"
    );
    assert!(
        !db.index_predates_reader().await.unwrap(),
        "a file this build read makes the index look stale"
    );
}

#[tokio::test]
async fn a_file_read_by_an_older_extractor_is_forgotten() {
    // After the whole tree has been read, a row still carrying an older
    // version is content the tree does not have. Left in place, one such row
    // makes the index answer "older than this build" for ever, and
    // re-indexing never clears the refusal it is meant to clear.
    let dir = tempfile::tempdir().unwrap();
    let db = manager(dir.path()).await;

    db.mark_file_processed(
        "fs/super.c".to_string(),
        Some("deadbeef".to_string()),
        "cafe1234".to_string(),
    )
    .await
    .unwrap();

    // Nothing is older than this build, so nothing is forgotten.
    assert_eq!(db.forget_older_processed_files().await.unwrap(), 0);
    assert!(db
        .processed_by_this_extractor()
        .await
        .unwrap()
        .contains("cafe1234"));

    // A row from an older extractor goes, and the index stops calling itself
    // stale on the strength of it.
    db.forget_processed_before(SCHEMA_VERSION + 1)
        .await
        .unwrap();
    assert!(db.processed_by_this_extractor().await.unwrap().is_empty());
}

#[tokio::test]
async fn tables_written_before_the_guard_column_are_started_again() {
    // A version 9 index has `functions` and `object_macros` without `guard`,
    // and the merge key names it: every insert into such a table fails, so
    // re-indexing, the one repair a user will try, could never succeed.
    let dir = tempfile::tempdir().unwrap();
    let db = manager(dir.path()).await;
    db.record_branch_indexed("main", "cafe1234", None)
        .await
        .unwrap();
    for name in ["functions", "object_macros"] {
        let table = db.connection().open_table(name).execute().await.unwrap();
        let schema = table.schema().await.unwrap();
        let older = std::sync::Arc::new(arrow_schema::Schema::new(
            schema
                .fields()
                .iter()
                .filter(|field| field.name() != "guard")
                .cloned()
                .collect::<Vec<_>>(),
        ));
        db.connection().drop_table(name, &[]).await.unwrap();
        db.connection()
            .create_empty_table(name, older)
            .execute()
            .await
            .unwrap();
    }
    drop(db);

    let db = manager(dir.path()).await;
    for name in ["functions", "object_macros"] {
        let table = db.connection().open_table(name).execute().await.unwrap();
        let schema = table.schema().await.unwrap();
        assert!(
            schema.fields().iter().any(|field| field.name() == "guard"),
            "{name} still lacks the guard column"
        );
    }
    // The branch's functions went with the table, so it is not current.
    assert!(!db.is_branch_current("main", "cafe1234").await.unwrap());
    db.insert_functions(vec![semcode::FunctionInfo {
        name: "pick".to_string(),
        file_path: "pick.h".to_string(),
        git_file_hash: "abc".to_string(),
        line_start: 1,
        line_end: 1,
        return_type: String::new(),
        parameters: Vec::new(),
        body: "#define pick(x) x".to_string(),
        calls: None,
        types: None,
        guard: Some("defined(CONFIG_A)".to_string()),
    }])
    .await
    .unwrap();
}
