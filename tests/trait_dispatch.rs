// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Trait dispatch end to end: trait method calls read through install
// sites. Concrete and generic callers in one file force both joins.
use semcode::{git, DatabaseManager};
use std::path::Path;
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

async fn trait_tree() -> (tempfile::TempDir, Arc<DatabaseManager>, String) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("shapes.rs"),
        "pub trait Display {\n\
         \tfn fmt(&self) -> i32;\n\
         }\n\
         pub struct Foo;\n\
         pub struct Bar;\n\
         pub struct Wrap<T>(T);\n\
         impl Display for Foo {\n\
         \tfn fmt(&self) -> i32 {\n\
         \t\t1\n\
         \t}\n\
         }\n\
         impl Display for Bar {\n\
         \tfn fmt(&self) -> i32 {\n\
         \t\t2\n\
         \t}\n\
         }\n\
         impl<T: Display> Display for Wrap<T> {\n\
         \tfn fmt(&self) -> i32 {\n\
         \t\t3\n\
         \t}\n\
         }\n\
         pub fn show(f: Foo) -> i32 {\n\
         \tf.fmt()\n\
         }\n\
         pub fn render<T: Display>(v: T) -> i32 {\n\
         \tv.fmt()\n\
         }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "trait dispatch fixture"]);
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
async fn implementors_lists_every_impl_of_the_trait_method() {
    let (_dir, db, sha) = trait_tree().await;

    let found = db
        .find_registrations_for_slot_git_aware("Display", "fmt", &sha)
        .await
        .unwrap();
    assert_eq!(found.len(), 3, "{found:?}");
    let mut targets: Vec<_> = found.iter().map(|r| r.target.as_str()).collect();
    targets.sort();
    assert_eq!(
        targets,
        vec!["Bar::fmt", "Foo::fmt", "Wrap<T>::fmt"],
        "{found:?}"
    );
}

#[tokio::test]
async fn a_generic_impl_answers_for_its_bare_owner() {
    // A bare owner reaches a generic install site (the `Wrap<T>` row
    // forces the argument strip).
    let (_dir, db, sha) = trait_tree().await;

    let found = db.find_indirect_callers("Wrap::fmt", &sha).await.unwrap();
    let names: Vec<_> = found.iter().map(|c| c.caller_name.as_str()).collect();
    assert_eq!(names, vec!["render"], "{names:?}");
}

#[tokio::test]
async fn trait_method_calls_resolve_through_the_trait() {
    let (_dir, db, sha) = trait_tree().await;

    // A concrete call answers through its type (two implementors force
    // the choice).
    let callers = db.find_indirect_callers("Foo::fmt", &sha).await.unwrap();
    let names: Vec<_> = callers.iter().map(|c| c.caller_name.as_str()).collect();
    assert!(names.contains(&"show"), "{names:?}");

    // A generic call answers through every impl of its bound (two
    // implementors force the multiplicity).
    assert!(names.contains(&"render"), "{names:?}");
    let bar_callers = db.find_indirect_callers("Bar::fmt", &sha).await.unwrap();
    let bar_names: Vec<_> = bar_callers.iter().map(|c| c.caller_name.as_str()).collect();
    assert_eq!(bar_names, vec!["render"], "{bar_names:?}");
}
