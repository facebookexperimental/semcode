// SPDX-License-Identifier: MIT OR Apache-2.0
//
// What a query answers when the index holds more revisions than the caller
// asked about.
use semcode::{git, DatabaseManager};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

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

fn head_of(repo: &Path) -> String {
    git::get_git_sha(repo).unwrap().unwrap()
}

/// Which revisions the index was built from.
#[derive(Copy, Clone, PartialEq)]
enum Indexed {
    /// Both branches, so every revision the tests ask about is in the index.
    Both,
    /// `main` alone, so `topic` is a revision the index has files for and
    /// content for only at another revision.
    MainOnly,
}

async fn two_branches() -> (tempfile::TempDir, Arc<DatabaseManager>, String, String) {
    two_branches_indexing(Indexed::Both).await
}

/// A repository with two branches.
///
/// `shared.c` is on both, with different contents. `only_on_topic.c` is on
/// `topic` alone, so a query that says it wants `main` is asking about a tree
/// that never contained `topic_only`.
async fn two_branches_indexing(
    indexed: Indexed,
) -> (tempfile::TempDir, Arc<DatabaseManager>, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();

    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("shared.c"),
        "int shared_function(void)\n{\n\
\tint a = 1;\n\
\tint b = 2;\n\
\tint c = a + b + 42;\n\
\tchar buf[64];\n\
\tsnprintf(buf, sizeof(buf), \"%d\", c);\n\
\treturn c + (int)strlen(buf);\n}\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "shared"]);
    git_run(repo, &["branch", "-M", "main"]);
    let main_sha = head_of(repo);

    git_run(repo, &["checkout", "-q", "-b", "topic"]);
    std::fs::write(
        repo.join("only_on_topic.c"),
        "struct topic_only_state {\n\
\tint counter;\n\
\tchar label[32];\n};\n\n\
typedef struct topic_only_state topic_only_state_t;\n\n\
int topic_only(void)\n{\n\
\tint x = 10;\n\
\tint y = 20;\n\
\tint z = x * y + 7;\n\
\tchar tmp[64];\n\
\tsnprintf(tmp, sizeof(tmp), \"topic %d\", z);\n\
\treturn z + (int)strlen(tmp);\n}\n",
    )
    .unwrap();
    // shared.c differs between the branches, so `topic` holds content that an
    // index built from `main` alone has never seen.
    std::fs::write(
        repo.join("shared.c"),
        "int shared_function(void)\n{\n\
\tint a = 3;\n\
\tint b = 4;\n\
\tint c = a * b + 42;\n\
\tchar buf[64];\n\
\tsnprintf(buf, sizeof(buf), \"topic %d\", c);\n\
\treturn c + (int)strlen(buf);\n}\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "topic"]);
    let topic_sha = head_of(repo);

    let db = Arc::new(
        DatabaseManager::new(
            repo.join(".semcode.db").to_str().unwrap(),
            repo.to_string_lossy().into_owned(),
        )
        .await
        .unwrap(),
    );
    db.create_tables().await.unwrap();

    let extensions = ["c".to_string(), "h".to_string()];
    let revisions: Vec<&String> = match indexed {
        Indexed::Both => vec![&main_sha, &topic_sha],
        Indexed::MainOnly => vec![&main_sha],
    };
    for sha in revisions {
        semcode::git_range::process_git_tree(repo, sha, &extensions, db.clone(), false, 1)
            .await
            .unwrap();
    }

    // Leave the checkout on main: the caller asks about main, and main is
    // what is on disk.
    git_run(repo, &["checkout", "-q", "main"]);

    (dir, db, main_sha, topic_sha)
}

#[tokio::test]
async fn a_function_from_another_branch_is_not_answered_for_this_one() {
    // `topic_only` exists only on `topic`. Asked for at `main`, the file it
    // lives in is not in that tree, so the answer is that it is not there —
    // where it does live is a separate question, which the index can answer.
    let (_dir, db, main_sha, topic_sha) = two_branches().await;

    let found = db
        .find_all_functions_git_aware("topic_only", &main_sha)
        .await
        .unwrap();
    assert!(
        found.is_empty(),
        "answered from another revision: {found:?}"
    );

    // The absence belongs to the revision, not to a missing row: the index
    // holds the function, and answers for it where it does exist.
    let row = db.find_function("topic_only").await.unwrap().unwrap();
    assert_eq!(row.file_path, "only_on_topic.c");
    assert_eq!(
        db.find_all_functions_git_aware("topic_only", &topic_sha)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn a_single_function_lookup_is_not_answered_from_another_branch() {
    // The same, through the lookup that returns one match and reaches the
    // absence with a manifest rather than with a commit.
    let (_dir, db, main_sha, topic_sha) = two_branches().await;

    assert!(
        db.find_function_git_aware("topic_only", &main_sha)
            .await
            .unwrap()
            .is_none(),
        "answered from another revision"
    );
    assert!(
        db.find_function_git_aware("topic_only", &topic_sha)
            .await
            .unwrap()
            .is_some(),
        "not answered at its own revision"
    );
}

#[tokio::test]
async fn a_type_from_another_branch_is_not_answered_for_this_one() {
    // Types and typedefs have their own lookups, and had their own fallbacks.
    let (_dir, db, main_sha, topic_sha) = two_branches().await;

    let types = db
        .find_types_git_aware("topic_only_state", &main_sha)
        .await
        .unwrap();
    assert!(
        types.is_empty(),
        "answered from another revision: {types:?}"
    );
    assert_eq!(
        db.find_types_git_aware("topic_only_state", &topic_sha)
            .await
            .unwrap()
            .len(),
        1,
        "not answered at its own revision"
    );

    assert!(
        db.find_typedef_git_aware("topic_only_state_t", &main_sha)
            .await
            .unwrap()
            .is_none(),
        "typedef answered from another revision"
    );
    assert!(
        db.find_typedef_git_aware("topic_only_state_t", &topic_sha)
            .await
            .unwrap()
            .is_some(),
        "typedef not answered at its own revision"
    );
}

#[tokio::test]
async fn content_the_index_never_read_is_not_answered_from_the_revision_it_did() {
    // The second leak, which is not a resolution failure: `shared.c` is in
    // both trees with different contents, and the index holds only `main`.
    // Asked at `topic` the path resolves, no row carries the blob it resolves
    // to, and the answer used to be `main`'s row.
    let (_dir, db, main_sha, topic_sha) = two_branches_indexing(Indexed::MainOnly).await;

    let found = db
        .find_all_functions_git_aware("shared_function", &topic_sha)
        .await
        .unwrap();
    assert!(
        found.is_empty(),
        "answered with content from another revision: {found:?}"
    );

    // Same name, same path, and the revision that was indexed still answers.
    let found = db
        .find_all_functions_git_aware("shared_function", &main_sha)
        .await
        .unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].file_path, "shared.c");
}

#[tokio::test]
async fn a_function_on_this_branch_is_answered_for_it() {
    // The control: whatever the patch does to the case above, this one has to
    // keep working, at either revision.
    let (_dir, db, main_sha, topic_sha) = two_branches().await;

    for sha in [&main_sha, &topic_sha] {
        let found = db
            .find_all_functions_git_aware("shared_function", sha)
            .await
            .unwrap();
        assert_eq!(found.len(), 1, "at {sha}: {found:?}");
        assert_eq!(found[0].file_path, "shared.c");
    }
}

#[tokio::test]
async fn a_function_added_on_a_branch_is_answered_for_that_branch() {
    let (_dir, db, _main_sha, topic_sha) = two_branches().await;

    let found = db
        .find_all_functions_git_aware("topic_only", &topic_sha)
        .await
        .unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].file_path, "only_on_topic.c");
}
