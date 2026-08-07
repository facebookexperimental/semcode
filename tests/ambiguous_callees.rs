// SPDX-License-Identifier: MIT OR Apache-2.0
//
// What a callee query answers when the tree defines the name more than once.
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

/// A tree that defines `report` twice, as the kernel defines `pr_warn` nine
/// times: once for the kernel proper and once for a userspace tool, calling
/// different functions.
async fn tree_with_two_definitions() -> (tempfile::TempDir, Arc<DatabaseManager>, String) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();

    git_run(repo, &["init", "-q"]);
    std::fs::create_dir_all(repo.join("tools")).unwrap();
    std::fs::write(
        repo.join("kernel.c"),
        "int report(int level)\n{\n\
\treturn emit_to_log(level);\n}\n\n\
int caller(void)\n{\n\
\treturn report(3);\n}\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("tools/host.c"),
        "int report(int level)\n{\n\
\treturn fprintf(stderr, \"%d\", level);\n}\n",
    )
    .unwrap();
    std::fs::create_dir_all(repo.join("drivers")).unwrap();
    // A third definition with a body that calls nothing. It is not a
    // prototype: a reader asking what `report` calls has three answers here,
    // and "nothing" is one of them.
    std::fs::write(
        repo.join("drivers/quiet.c"),
        "int report(int level)\n{\n\treturn level;\n}\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("only_declared.c"),
        "extern int elsewhere(int level);\n\n\
int uses_it(void)\n{\n\
\treturn elsewhere(1);\n}\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "two definitions"]);
    git_run(repo, &["branch", "-M", "main"]);
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
    let extensions = ["c".to_string(), "h".to_string()];
    semcode::git_range::process_git_tree(repo, &sha, &extensions, db.clone(), false, 1)
        .await
        .unwrap();

    (dir, db, sha)
}

#[tokio::test]
async fn both_definitions_of_a_name_are_reported_with_their_files() {
    let (_dir, db, sha) = tree_with_two_definitions().await;

    let definitions = db
        .get_function_callees_by_definition_git_aware("report", &sha)
        .await
        .unwrap();

    assert_eq!(definitions.len(), 3, "{definitions:?}");
    let kernel = definitions
        .iter()
        .find(|d| d.file_path.ends_with("kernel.c"))
        .unwrap_or_else(|| panic!("{definitions:?}"));
    let host = definitions
        .iter()
        .find(|d| d.file_path.ends_with("tools/host.c"))
        .unwrap_or_else(|| panic!("{definitions:?}"));
    assert!(
        kernel.callees.iter().any(|c| c == "emit_to_log"),
        "{kernel:?}"
    );
    assert!(host.callees.iter().any(|c| c == "fprintf"), "{host:?}");
    // Neither definition's callees leak into the other's answer, which is what
    // reporting one of the two used to do.
    assert!(!kernel.callees.iter().any(|c| c == "fprintf"), "{kernel:?}");
}

#[tokio::test]
async fn a_name_defined_once_still_has_one_answer() {
    let (_dir, db, sha) = tree_with_two_definitions().await;

    let definitions = db
        .get_function_callees_by_definition_git_aware("caller", &sha)
        .await
        .unwrap();
    assert_eq!(definitions.len(), 1, "{definitions:?}");
    assert!(
        definitions[0].callees.iter().any(|c| c == "report"),
        "{definitions:?}"
    );

    // And the single-answer path, which a call chain walks, is unchanged.
    let callees = db
        .get_function_callees_git_aware("caller", &sha)
        .await
        .unwrap();
    assert!(callees.iter().any(|c| c == "report"), "{callees:?}");
}

#[tokio::test]
async fn a_definition_that_calls_nothing_is_still_an_answer() {
    // Filtering on "records calls" would drop this one and report the tree as
    // agreeing with itself when it does not.
    let (_dir, db, sha) = tree_with_two_definitions().await;

    let definitions = db
        .get_function_callees_by_definition_git_aware("report", &sha)
        .await
        .unwrap();
    let quiet = definitions
        .iter()
        .find(|d| d.file_path.ends_with("drivers/quiet.c"))
        .unwrap_or_else(|| panic!("{definitions:?}"));
    assert!(quiet.callees.is_empty(), "{quiet:?}");
    assert!(quiet.is_definition, "{quiet:?}");
    assert!(
        definitions.iter().all(|d| d.is_definition),
        "{definitions:?}"
    );
}

#[tokio::test]
async fn an_edited_file_answers_for_itself() {
    // The working directory is what the reader is looking at. A callee query
    // that answers from the commit describes a file they have already changed.
    let (dir, db, sha) = tree_with_two_definitions().await;
    std::fs::write(
        dir.path().join("kernel.c"),
        "int report(int level)\n{\n\treturn emit_to_console(level);\n}\n\n\
int caller(void)\n{\n\treturn report(3);\n}\n",
    )
    .unwrap();

    let definitions = db
        .get_function_callees_by_definition_git_aware("report", &sha)
        .await
        .unwrap();
    let edited = definitions
        .iter()
        .find(|d| d.file_path.ends_with("kernel.c"))
        .unwrap_or_else(|| panic!("{definitions:?}"));
    assert!(
        edited.callees.iter().any(|c| c == "emit_to_console"),
        "{edited:?}"
    );
    // The committed answer for that file is gone rather than reported beside
    // the edited one, which would be two answers for one file.
    assert!(
        !edited.callees.iter().any(|c| c == "emit_to_log"),
        "{edited:?}"
    );
    assert_eq!(
        definitions
            .iter()
            .filter(|d| d.file_path.ends_with("kernel.c"))
            .count(),
        1,
        "{definitions:?}"
    );
}

#[tokio::test]
async fn a_declaration_beside_a_definition_is_not_a_second_answer() {
    // `elsewhere` is declared and never defined here. A prototype records no
    // calls, so it cannot make the answer ambiguous, and asking about a name
    // the tree only declares still says so rather than reporting nothing.
    let (_dir, db, sha) = tree_with_two_definitions().await;

    let definitions = db
        .get_function_callees_by_definition_git_aware("elsewhere", &sha)
        .await
        .unwrap();
    assert!(
        definitions.iter().all(|d| d.callees.is_empty()),
        "{definitions:?}"
    );
    assert!(
        definitions.iter().all(|d| !d.is_definition),
        "{definitions:?}"
    );
}
