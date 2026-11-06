// SPDX-License-Identifier: MIT OR Apache-2.0
//
// What an insert does when a batch holds the same row twice.
//
// A batch built from several commits holds the same file at the same content
// hash more than once: a file unchanged between two commits is analysed under
// each. `merge_insert` refuses a batch in which two source rows match one
// target row, so the duplicate does not become a duplicate row -- it fails the
// insert of everything batched with it, and the tree indexes with an error.
use semcode::DatabaseManager;
use semcode::{DispatchSite, Registration};
use std::sync::Arc;

async fn database() -> (tempfile::TempDir, Arc<DatabaseManager>) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(
        DatabaseManager::new(
            dir.path().join(".semcode.db").to_str().unwrap(),
            dir.path().to_string_lossy().into_owned(),
        )
        .await
        .unwrap(),
    );
    db.create_tables().await.unwrap();
    (dir, db)
}

fn registration() -> Registration {
    Registration {
        container_type: "kernel_clone_args".into(),
        container_base_type: None,
        container_field: None,
        member: "set_tid".into(),
        target: "set_tid".into(),
        file_path: "kernel/fork.c".into(),
        git_file_hash: "f0e2e131a9a5af7b25e71c1d28af1a6aebdc4319".into(),
        byte_start: 77208,
        line: 3060,
        enclosing_function: "sys_clone3".into(),
        kind: semcode::RegistrationKind::Assignment,
    }
}

#[tokio::test]
async fn a_batch_holding_one_row_twice_still_inserts() {
    let (_dir, db) = database().await;

    // The row exists first, as it does after the commit that introduced the
    // file has been indexed. A later batch that holds it twice then has two
    // source rows matching one target row, which is what merge_insert refuses:
    //
    //     Ambiguous merge inserts are prohibited: multiple source rows match
    //     the same target row on (file_path = "kernel/fork.c", ...)
    db.insert_registrations(vec![registration()]).await.unwrap();

    db.insert_registrations(vec![registration(), registration()])
        .await
        .expect("a batch holding an existing row twice must still insert");

    let found = db.find_registrations_of("set_tid").await.unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
}

#[tokio::test]
async fn a_batch_holding_one_dispatch_site_twice_still_inserts() {
    let (_dir, db) = database().await;
    let site = DispatchSite {
        caller_name: "io_submit_one".into(),
        file_path: "fs/aio.c".into(),
        git_file_hash: "f57fa21a250353019f78e56dda9ca1be2667892a".into(),
        byte_start: 58144,
        line: 2000,
        member: "ki_complete".into(),
        receiver_expr: Some("iocb".into()),
        receiver_type: None,
        receiver_base_type: None,
        receiver_field: None,
        kind: semcode::DispatchKind::MemberArrow,
        target: None,
    };

    db.insert_dispatch_sites(vec![site.clone()]).await.unwrap();

    db.insert_dispatch_sites(vec![site.clone(), site])
        .await
        .expect("a batch holding an existing site twice must still insert");
}

#[tokio::test]
async fn two_definitions_at_different_lines_both_insert() {
    // The v12 merge key carries line_start: two definitions that share a
    // name, guard and owner are two rows, and neither insert may refuse the
    // batch the way a same-key duplicate once did.
    let (_dir, db) = database().await;

    let definition = |line_start: u32, body: &str| semcode::FunctionInfo {
        name: "get".into(),
        file_path: "box.cpp".into(),
        git_file_hash: "abc123".into(),
        line_start,
        line_end: line_start + 2,
        return_type: "int".into(),
        parameters: Vec::new(),
        body: body.into(),
        calls: None,
        types: None,
        guard: None,
        qualifier: Some("ns::Box".into()),
    };
    db.insert_functions(vec![
        definition(5, "int get() { return 1; }"),
        definition(9, "int get(int x) { return x; }"),
    ])
    .await
    .expect("two definitions at different lines must both insert");

    let found = db
        .find_all_functions("get")
        .await
        .unwrap()
        .into_iter()
        .filter(|f| f.file_path == "box.cpp")
        .collect::<Vec<_>>();
    assert_eq!(found.len(), 2, "{found:#?}");
}
