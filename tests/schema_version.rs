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
async fn an_index_without_a_mark_is_stamped_not_dropped() {
    // What an older semcode leaves behind: tables with rows in them and no
    // record of what wrote them. Creating the missing table must not claim
    // the rows are as new as the build that found them -- but on its own the
    // missing mark proves nothing about the rows: the mark may have been lost
    // while the rows and their processed records are current, and dropping
    // those rows while their files count as read would leave holes no reindex
    // fills. With no stale processed record behind them, reopening stamps the
    // current version and drops nothing; staleness is carried by the
    // processed records, which still name the older extractor.
    let dir = tempfile::tempdir().unwrap();
    let db = manager(dir.path()).await;
    drop(db);

    let path = dir.path().join(".semcode.db").join("schema_meta.lance");
    std::fs::remove_dir_all(&path).expect("schema_meta should exist to be removed");

    let db = manager(dir.path()).await;
    assert_eq!(
        db.stored_schema_version().await.unwrap(),
        Some(SCHEMA_VERSION)
    );
    assert!(
        !db.index_predates_reader().await.unwrap(),
        "an empty index with no stale record was taken for an older one"
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
async fn tables_written_before_the_key_columns_are_started_again() {
    // An older index has `functions` without a merge-key column the merge
    // key names (`guard` since version 10, `qualifier` since 11), and every
    // insert into such a table fails, so re-indexing, the one repair a user
    // will try, could never succeed. `object_macros` carries `guard` only.
    let dir = tempfile::tempdir().unwrap();
    let db = manager(dir.path()).await;
    db.record_branch_indexed("main", "cafe1234", None)
        .await
        .unwrap();
    for (name, missing) in [
        ("functions", vec!["guard", "qualifier"]),
        ("object_macros", vec!["guard"]),
    ] {
        let table = db.connection().open_table(name).execute().await.unwrap();
        let schema = table.schema().await.unwrap();
        let older = std::sync::Arc::new(arrow_schema::Schema::new(
            schema
                .fields()
                .iter()
                .filter(|field| !missing.contains(&field.name().as_str()))
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
    for (name, missing) in [
        ("functions", vec!["guard", "qualifier"]),
        ("object_macros", vec!["guard"]),
    ] {
        let table = db.connection().open_table(name).execute().await.unwrap();
        let schema = table.schema().await.unwrap();
        for column in missing {
            assert!(
                schema.fields().iter().any(|field| field.name() == column),
                "{name} still lacks the {column} column"
            );
        }
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
        qualifier: None,
    }])
    .await
    .unwrap();
}

#[tokio::test]
async fn tables_are_started_again_across_the_v12_bump() {
    // Version 12 changed what a row means (line_start in the functions merge
    // key, qualifier on types), so rows an older build wrote cannot be merged
    // correctly. Opening such an index starts functions and types again and
    // stamps the current version, instead of trusting the old rows or
    // refusing every insert.
    let dir = tempfile::tempdir().unwrap();
    let db = manager(dir.path()).await;
    db.insert_functions(vec![semcode::FunctionInfo {
        name: "get".to_string(),
        file_path: "box.cpp".to_string(),
        git_file_hash: "abc".to_string(),
        line_start: 9,
        line_end: 9,
        return_type: String::new(),
        parameters: Vec::new(),
        body: "int get();".to_string(),
        calls: None,
        types: None,
        guard: None,
        qualifier: Some("ns::Box".to_string()),
    }])
    .await
    .unwrap();
    db.insert_types(vec![semcode::TypeInfo {
        name: "Box".to_string(),
        file_path: "box.cpp".to_string(),
        git_file_hash: "abc".to_string(),
        line_start: 3,
        kind: "struct".to_string(),
        size: None,
        members: Vec::new(),
        definition: "struct Box {};".to_string(),
        types: None,
        qualifier: None,
    }])
    .await
    .unwrap();

    // The file's processed record still names the version 11 extractor, the
    // way a real version 11 index reads. That stale record is what proves
    // old rows are in the tables and starts them again.
    db.mark_files_processed(vec![semcode::ProcessedFileRecord {
        file: "box.cpp".to_string(),
        git_sha: None,
        git_file_sha: "abc".to_string(),
        extractor_version: Some(11),
    }])
    .await
    .unwrap();

    // Backdate the stamp the way an index written by version 11 reads.
    let table = db
        .connection()
        .open_table("schema_meta")
        .execute()
        .await
        .unwrap();
    table.delete("key = 'schema_version'").await.unwrap();
    let schema = std::sync::Arc::new(arrow_schema::Schema::new(vec![
        arrow_schema::Field::new("key", arrow_schema::DataType::Utf8, false),
        arrow_schema::Field::new("value", arrow_schema::DataType::Utf8, false),
    ]));
    let batch = arrow::record_batch::RecordBatch::try_new(
        schema,
        vec![
            std::sync::Arc::new(arrow::array::StringArray::from(vec!["schema_version"]))
                as arrow::array::ArrayRef,
            std::sync::Arc::new(arrow::array::StringArray::from(vec!["11"]))
                as arrow::array::ArrayRef,
        ],
    )
    .unwrap();
    table.add(vec![batch]).execute().await.unwrap();
    drop(db);

    let db = manager(dir.path()).await;
    assert_eq!(
        db.stored_schema_version().await.unwrap(),
        Some(SCHEMA_VERSION)
    );
    assert!(
        db.get_all_functions().await.unwrap().is_empty(),
        "functions written by version 11 survived the v12 migration"
    );
    assert!(
        db.get_all_types().await.unwrap().is_empty(),
        "types written by version 11 survived the v12 migration"
    );

    // The stale processed record survives the migration, so the index still
    // refuses to trust itself until the tree is read again -- the drop above
    // is repaired by the re-read the refusal forces.
    assert!(
        db.index_predates_reader().await.unwrap(),
        "an index holding version 11 rows was taken for a current one"
    );
    db.forget_older_processed_files().await.unwrap();
    db.record_index_build(&["cpp".to_string()], false)
        .await
        .unwrap();
    assert!(!db.index_predates_reader().await.unwrap());

    // The migrated tables still take rows under the new key.
    db.insert_functions(vec![semcode::FunctionInfo {
        name: "get".to_string(),
        file_path: "box.cpp".to_string(),
        git_file_hash: "abc".to_string(),
        line_start: 9,
        line_end: 9,
        return_type: "int".to_string(),
        parameters: Vec::new(),
        body: "int get() { return 1; }".to_string(),
        calls: None,
        types: None,
        guard: None,
        qualifier: Some("ns::Box".to_string()),
    }])
    .await
    .unwrap();
    assert_eq!(db.get_all_functions().await.unwrap().len(), 1);

    // Reopening a current index drops nothing.
    drop(db);
    let db = manager(dir.path()).await;
    assert_eq!(db.get_all_functions().await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_real_v11_index_starts_functions_and_types_again() {
    // A v11 index as v11 really wrote it: processed_files carries an Int64
    // extractor_version holding 11, and schema_version reads 11. The order
    // matters: the processed migration runs first and empties the table, so the staleness decision has to be taken before
    // it, while the Int64 column still proves the index predates v12.
    // Without that, the old function and type rows survive beside the
    // re-read rows, whose new qualifiers and guards no longer match them.
    let dir = tempfile::tempdir().unwrap();
    let db = manager(dir.path()).await;
    db.insert_functions(vec![semcode::FunctionInfo {
        name: "get".to_string(),
        file_path: "box.cpp".to_string(),
        git_file_hash: "abc".to_string(),
        line_start: 9,
        line_end: 9,
        return_type: "int".to_string(),
        parameters: Vec::new(),
        body: "int get() { return 1; }".to_string(),
        calls: None,
        types: None,
        guard: None,
        qualifier: None,
    }])
    .await
    .unwrap();
    db.insert_types(vec![semcode::TypeInfo {
        name: "Box".to_string(),
        file_path: "box.cpp".to_string(),
        git_file_hash: "abc".to_string(),
        line_start: 3,
        kind: "struct".to_string(),
        size: None,
        members: Vec::new(),
        definition: "struct Box {};".to_string(),
        types: None,
        qualifier: None,
    }])
    .await
    .unwrap();

    // processed_files with the v11 Int64 column and one v11 row.
    let table = db
        .connection()
        .open_table("processed_files")
        .execute()
        .await
        .unwrap();
    let schema = table.schema().await.unwrap();
    let older = std::sync::Arc::new(arrow_schema::Schema::new(
        schema
            .fields()
            .iter()
            .map(|f| {
                if f.name() == "extractor_version" {
                    arrow_schema::Field::new(
                        "extractor_version",
                        arrow_schema::DataType::Int64,
                        true,
                    )
                } else {
                    (**f).clone()
                }
            })
            .collect::<Vec<_>>(),
    ));
    db.connection()
        .drop_table("processed_files", &[])
        .await
        .unwrap();
    db.connection()
        .create_empty_table("processed_files", older.clone())
        .execute()
        .await
        .unwrap();
    let table = db
        .connection()
        .open_table("processed_files")
        .execute()
        .await
        .unwrap();
    let batch = arrow::record_batch::RecordBatch::try_new(
        older,
        vec![
            std::sync::Arc::new(arrow::array::StringArray::from(vec!["box.cpp"]))
                as arrow::array::ArrayRef,
            std::sync::Arc::new(arrow::array::StringArray::from(vec![None::<&str>]))
                as arrow::array::ArrayRef,
            std::sync::Arc::new(arrow::array::StringArray::from(vec!["abc"]))
                as arrow::array::ArrayRef,
            std::sync::Arc::new(arrow::array::Int64Array::from(vec![Some(11)]))
                as arrow::array::ArrayRef,
        ],
    )
    .unwrap();
    table.add(vec![batch]).execute().await.unwrap();

    // schema_version backdated the way an index written by version 11 reads.
    let meta = db
        .connection()
        .open_table("schema_meta")
        .execute()
        .await
        .unwrap();
    meta.delete("key = 'schema_version'").await.unwrap();
    let schema = std::sync::Arc::new(arrow_schema::Schema::new(vec![
        arrow_schema::Field::new("key", arrow_schema::DataType::Utf8, false),
        arrow_schema::Field::new("value", arrow_schema::DataType::Utf8, false),
    ]));
    let batch = arrow::record_batch::RecordBatch::try_new(
        schema,
        vec![
            std::sync::Arc::new(arrow::array::StringArray::from(vec!["schema_version"]))
                as arrow::array::ArrayRef,
            std::sync::Arc::new(arrow::array::StringArray::from(vec!["11"]))
                as arrow::array::ArrayRef,
        ],
    )
    .unwrap();
    meta.add(vec![batch]).execute().await.unwrap();
    drop(db);

    let db = manager(dir.path()).await;
    assert!(
        db.get_all_functions().await.unwrap().is_empty(),
        "v11 function rows survived a real v11->v12 open"
    );
    assert!(
        db.get_all_types().await.unwrap().is_empty(),
        "v11 type rows survived a real v11->v12 open"
    );
    assert_eq!(
        db.stored_schema_version().await.unwrap(),
        Some(SCHEMA_VERSION)
    );
}
