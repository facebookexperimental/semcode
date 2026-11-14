// SPDX-License-Identifier: MIT OR Apache-2.0

use semcode::{git, DatabaseManager};
use std::path::Path;
use std::process::Command;

fn git_run(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(repo)
        // Do not inherit developer's git configuration.
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

#[tokio::test]
async fn failed_commit_enumeration_preserves_indexed_branch_tip() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q", "--initial-branch=main"]);
    let mut commits = Vec::new();
    for message in ["base", "missing", "tip"] {
        git_run(repo, &["commit", "-q", "--allow-empty", "-m", message]);
        commits.push(git::get_git_sha(repo).unwrap().unwrap());
    }

    let db_path = repo.join(".semcode.db");
    let db = DatabaseManager::new(
        db_path.to_str().unwrap(),
        repo.to_string_lossy().into_owned(),
    )
    .await
    .unwrap();
    db.create_tables().await.unwrap();
    db.record_branch_indexed("main", &commits[0], None)
        .await
        .unwrap();

    // The tip still resolves, but walking its history fails at its parent.
    let missing = &commits[1];
    std::fs::remove_file(
        repo.join(".git/objects")
            .join(&missing[..2])
            .join(&missing[2..]),
    )
    .unwrap();
    Command::new(env!("CARGO_BIN_EXE_semcode-index"))
        .arg("--source")
        .arg(repo)
        .arg("--database")
        .arg(&db_path)
        .args(["--branch", "main", "--update-branches"])
        .status()
        .unwrap();

    let db = DatabaseManager::new(
        db_path.to_str().unwrap(),
        repo.to_string_lossy().into_owned(),
    )
    .await
    .unwrap();
    assert_eq!(
        db.get_branch_tip("main").await.unwrap(),
        Some(commits[0].clone())
    );
}
