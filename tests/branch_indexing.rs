// SPDX-License-Identifier: MIT OR Apache-2.0

use semcode::{git, DatabaseManager};
use std::path::Path;
use std::process::Command;

#[test]
fn lore_conflicts_with_branch_indexing_flags() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join(".semcode.db");
    let branch_args: &[&[&str]] = &[
        &["--branch", "no-such-branch"],
        &["--branches", "main,stable"],
        &["--all-branches"],
        &["--remote-branches"],
        &["--update-branches"],
    ];
    for args in branch_args {
        let output = Command::new(env!("CARGO_BIN_EXE_semcode-index"))
            .arg("--source")
            .arg(dir.path())
            .arg("--database")
            .arg(&db_path)
            .arg("--lore")
            .args(*args)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(
            stderr.contains("cannot be used with")
                && stderr.contains("--lore")
                && stderr.contains(args[0]),
            "{args:?}: {stderr}"
        );
    }
}

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

/// A file the pipeline cannot read fails the run, so the branch keeps the
/// tip it was last indexed at and the next update reads the file again.
#[tokio::test]
async fn failed_file_read_preserves_indexed_branch_tip() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q", "--initial-branch=main"]);
    git_run(repo, &["commit", "-q", "--allow-empty", "-m", "base"]);
    let base = git::get_git_sha(repo).unwrap().unwrap();
    std::fs::write(
        repo.join("a.c"),
        "int a_function(void)\n{\n\treturn 0;\n}\n",
    )
    .unwrap();
    git_run(repo, &["add", "a.c"]);
    git_run(repo, &["commit", "-q", "-m", "tip"]);

    let db_path = repo.join(".semcode.db");
    let db = DatabaseManager::new(
        db_path.to_str().unwrap(),
        repo.to_string_lossy().into_owned(),
    )
    .await
    .unwrap();
    db.create_tables().await.unwrap();
    db.record_branch_indexed("main", &base, None).await.unwrap();
    drop(db);

    // The tip's tree still lists a.c, but its blob cannot be read.
    let blob = String::from_utf8(
        Command::new("git")
            .args(["rev-parse", "HEAD:a.c"])
            .current_dir(repo)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let blob = blob.trim();
    std::fs::remove_file(repo.join(".git/objects").join(&blob[..2]).join(&blob[2..])).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_semcode-index"))
        .arg("--source")
        .arg(repo)
        .arg("--database")
        .arg(&db_path)
        .args(["--branch", "main", "--update-branches"])
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "indexing must fail when a file cannot be read"
    );

    let db = DatabaseManager::new(
        db_path.to_str().unwrap(),
        repo.to_string_lossy().into_owned(),
    )
    .await
    .unwrap();
    assert_eq!(db.get_branch_tip("main").await.unwrap(), Some(base));
}
