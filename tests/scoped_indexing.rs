// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Scope and self-call regressions: `--include` used to be accepted but
// never read (every run indexed the whole repo tree at HEAD), and a bare
// `self.method()` call vanished from call tracing instead of tagging its
// owner. Both now have end-to-end coverage: the old code indexes the
// out-of-scope file and records no edge, so these fail without the fix.
use semcode::{git, CallEdge, DatabaseManager};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

fn git_run(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Semcode Test")
        .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
        .env("GIT_COMMITTER_NAME", "Semcode Test")
        .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

async fn scoped_tree() -> (tempfile::TempDir, Arc<DatabaseManager>, String) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::create_dir_all(repo.join("rust/kernel")).unwrap();
    std::fs::create_dir_all(repo.join("drivers")).unwrap();
    std::fs::write(
        repo.join("rust/kernel/a.rs"),
        "pub fn inside() -> i32 {\n    1\n}\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("drivers/x.c"),
        "int outside(void)\n{\n    return 0;\n}\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "scope fixture"]);
    let sha = git::get_git_sha(repo).unwrap().unwrap();

    let db = Arc::new(
        DatabaseManager::new(
            repo.join(".semcode.db").to_str().unwrap(),
            repo.to_string_lossy().into_owned(),
        )
        .await
        .unwrap(),
    );
    db.create_tables().await.unwrap();
    (dir, db, sha)
}

#[tokio::test]
async fn include_dirs_restrict_enumeration() {
    let (_dir, db, sha) = scoped_tree().await;
    let extensions = ["c".to_string(), "rs".to_string()];
    let repo = _dir.path();
    semcode::git_range::process_git_tree(
        repo,
        &sha,
        &extensions,
        db.clone(),
        false,
        1,
        &[PathBuf::from("rust/kernel")],
    )
    .await
    .unwrap();

    let inside = db
        .find_all_functions_git_aware("inside", &sha)
        .await
        .unwrap();
    assert_eq!(inside.len(), 1, "{inside:?}");
    let outside = db
        .find_all_functions_git_aware("outside", &sha)
        .await
        .unwrap();
    assert!(
        outside.is_empty(),
        "drivers/ must stay out of scope: {outside:?}"
    );
}

#[tokio::test]
async fn source_subdir_restricts_enumeration() {
    let (_dir, db, sha) = scoped_tree().await;
    let extensions = ["c".to_string(), "rs".to_string()];
    let repo = _dir.path();
    semcode::git_range::process_git_tree(
        &repo.join("rust"),
        &sha,
        &extensions,
        db.clone(),
        false,
        1,
        &[],
    )
    .await
    .unwrap();

    let inside = db
        .find_all_functions_git_aware("inside", &sha)
        .await
        .unwrap();
    assert_eq!(inside.len(), 1, "{inside:?}");
    let outside = db
        .find_all_functions_git_aware("outside", &sha)
        .await
        .unwrap();
    assert!(
        outside.is_empty(),
        "drivers/ must stay out of scope: {outside:?}"
    );
}

async fn self_call_tree() -> (tempfile::TempDir, Arc<DatabaseManager>, String) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::create_dir_all(repo.join("rust/priv")).unwrap();
    std::fs::write(
        repo.join("rust/priv/box.rs"),
        "struct Box;\nimpl Box {\n    fn get(&self) -> i32 {\n        self.read()\n    }\n    fn read(&self) -> i32 {\n        1\n    }\n}\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "self call fixture"]);
    let sha = git::get_git_sha(repo).unwrap().unwrap();

    let db = Arc::new(
        DatabaseManager::new(
            repo.join(".semcode.db").to_str().unwrap(),
            repo.to_string_lossy().into_owned(),
        )
        .await
        .unwrap(),
    );
    db.create_tables().await.unwrap();
    let extensions = ["rs".to_string()];
    semcode::git_range::process_git_tree(repo, &sha, &extensions, db.clone(), false, 1, &[])
        .await
        .unwrap();
    (dir, db, sha)
}

#[tokio::test]
async fn bare_self_call_tags_its_enclosing_owner() {
    let (_dir, db, sha) = self_call_tree().await;

    let get_rows = db.find_all_functions_git_aware("get", &sha).await.unwrap();
    assert_eq!(get_rows.len(), 1, "{get_rows:?}");
    let calls = get_rows[0]
        .calls
        .clone()
        .expect("get calls self.read, so it must record an edge");
    assert_eq!(calls.len(), 1, "{calls:?}");
    match &calls[0] {
        CallEdge::Tagged { call, owner } => {
            assert_eq!(call, "read");
            assert!(owner.contains("Box"), "{owner}");
        }
        other => panic!("bare self.read must tag its owner, got {other:?}"),
    }

    // The reverse lookup reads the tagged half too.
    let callers = db
        .get_function_callers_git_aware("Box::read", &sha)
        .await
        .unwrap();
    assert!(callers.contains(&"get".to_string()), "{callers:?}");
}

#[tokio::test]
async fn empty_scope_indexes_everything() {
    // No bound means the whole tree: the same fixture that the scope
    // tests above keep out of drivers/ must include it here. This pins
    // the contract and proves the fixture discriminates.
    let (_dir, db, sha) = scoped_tree().await;
    let extensions = ["c".to_string(), "rs".to_string()];
    let repo = _dir.path();
    semcode::git_range::process_git_tree(repo, &sha, &extensions, db.clone(), false, 1, &[])
        .await
        .unwrap();

    let inside = db
        .find_all_functions_git_aware("inside", &sha)
        .await
        .unwrap();
    assert_eq!(inside.len(), 1, "{inside:?}");
    let outside = db
        .find_all_functions_git_aware("outside", &sha)
        .await
        .unwrap();
    assert_eq!(outside.len(), 1, "{outside:?}");
}
