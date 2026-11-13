// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Callers of a function at each revision of a file indexed in separate
// `--git` runs: every version keeps its own call edges.
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

fn commit_all(repo: &Path, message: &str) -> String {
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", message]);
    head_of(repo)
}

/// `f` as written at one revision: its body calls each of `callees`.
fn caller_source(callees: &[&str]) -> String {
    let calls: String = callees
        .iter()
        .map(|callee| format!("\ttotal += {callee}(total);\n"))
        .collect();
    format!(
        "int f(int seed)\n{{\n\
\tint total = seed * 3 + 1;\n\
{calls}\
\tif (total < 0)\n\
\t\treturn -1;\n\
\treturn total;\n}}\n"
    )
}

/// Names of the database's callers of `callee` at `revision`.
///
/// Asks the index alone through the revision's manifest, so the working
/// copy cannot contribute an answer the index lost.
async fn callers_at(db: &DatabaseManager, callee: &str, revision: &str) -> Vec<String> {
    let manifest = db.git_manifest_cached(revision).await.unwrap();
    let mut names: Vec<String> = db
        .get_function_callers_with_manifest(callee, &manifest)
        .await
        .unwrap()
        .into_iter()
        .map(|(name, _file)| name)
        .collect();
    names.sort();
    names.dedup();
    names
}

/// `a.c` changes in c1 and again in c2, and each change is indexed by its
/// own `process_git_range()` call. The second run writes the edges of the
/// second version of `a.c`; the first version's edges must still answer
/// for c1.
///
/// Two runs rather than one `c0..c2` range: one run could put both versions
/// in one batch, where the defect this guards against does not show.
#[tokio::test]
async fn each_file_version_keeps_its_callers_across_git_runs() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();

    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("lib.c"),
        "int g(int x)\n{\n\treturn x + 1;\n}\n\nint h(int x)\n{\n\treturn x * 2;\n}\n",
    )
    .unwrap();
    let c0 = commit_all(repo, "c0: lib.c");

    std::fs::write(repo.join("a.c"), caller_source(&["g"])).unwrap();
    let c1 = commit_all(repo, "c1: f calls g");

    std::fs::write(repo.join("a.c"), caller_source(&["g", "h"])).unwrap();
    let c2 = commit_all(repo, "c2: f calls g and h");

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
    for range in [format!("{c0}..{c1}"), format!("{c1}..{c2}")] {
        semcode::git_range::process_git_range(
            &repo.to_path_buf(),
            &range,
            &extensions,
            db.clone(),
            false,
            1,
            &[],
        )
        .await
        .unwrap();
    }

    assert_eq!(callers_at(&db, "g", &c1).await, ["f"], "callers of g at c1");
    assert_eq!(callers_at(&db, "g", &c2).await, ["f"], "callers of g at c2");
    assert_eq!(callers_at(&db, "h", &c2).await, ["f"], "callers of h at c2");
    assert!(
        callers_at(&db, "h", &c1).await.is_empty(),
        "f does not call h at c1"
    );
}
