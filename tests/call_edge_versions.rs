// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Callers of a function at each version of a file, where the versions are
// indexed in separate `--git` runs or as separate `--branches` tips: every
// version keeps its own call edges.
use semcode::{git, DatabaseManager};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

fn git_run(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(repo)
        // Run in `repo` even when started under another git command, such
        // as a hook or `git rebase --exec`, which exports these.
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_PREFIX")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_CONFIG_PARAMETERS")
        // Do not inherit developer's git configuration.
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Semcode Test")
        .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
        .env("GIT_COMMITTER_NAME", "Semcode Test")
        .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
        // Fixed dates, so a fixture's commit SHAs are the same on every run.
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
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

const MATH_BASELINE: &str = "int add_numbers(int a, int b)\n{\n\treturn a + b;\n}\n\n\
int compute(int x)\n{\n\treturn add_numbers(x, 1);\n}\n";

const MATH_MASTER_EXTRA: &str = "\nint scaled_sum(int a, int b, int scale)\n{\n\
\treturn add_numbers(a, b) * scale;\n}\n";

const REPORT: &str = "int report(int x)\n{\n\treturn add_numbers(x, 2);\n}\n";

/// A repository with branches `master` and `baseline`, and their tips.
struct Branches {
    _dir: tempfile::TempDir,
    repo: PathBuf,
    master: String,
    baseline: String,
}

/// `baseline` holds `math.c` and `report.c`; `master` is one commit on top
/// that adds `scaled_sum()` to `math.c`. `report.c` is the same blob on both
/// branches, so only `math.c` differs between the tips.
fn two_branches() -> Branches {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().to_path_buf();

    git_run(&repo, &["init", "-q"]);
    // Name the first branch here, so git's default initial branch name
    // cannot collide with `master` below.
    git_run(&repo, &["symbolic-ref", "HEAD", "refs/heads/baseline"]);
    std::fs::write(repo.join("math.c"), MATH_BASELINE).unwrap();
    std::fs::write(repo.join("report.c"), REPORT).unwrap();
    let baseline = commit_all(&repo, "baseline: compute and report call add_numbers");

    git_run(&repo, &["checkout", "-q", "-b", "master"]);
    std::fs::write(
        repo.join("math.c"),
        format!("{MATH_BASELINE}{MATH_MASTER_EXTRA}"),
    )
    .unwrap();
    let master = commit_all(&repo, "master: scaled_sum calls add_numbers");

    Branches {
        _dir: dir,
        repo,
        master,
        baseline,
    }
}

/// Indexes each branch as `semcode-index --branches` does on a fresh
/// database: the tree at the branch tip, then the branch record, one branch
/// after another in the order given.
async fn index_branches(db: &Arc<DatabaseManager>, repo: &Path, names: &[&str]) {
    let extensions = ["c".to_string(), "h".to_string()];
    for name in names {
        let branch = git::get_branch_info(repo, name).unwrap();
        assert!(
            db.get_branch_tip(name).await.unwrap().is_none(),
            "{name} has no recorded tip, so its whole tree is indexed"
        );
        semcode::git_range::process_git_tree(
            repo,
            &branch.tip_commit,
            &extensions,
            db.clone(),
            false,
            1,
            &[],
        )
        .await
        .unwrap();
        db.record_branch_indexed(name, &branch.tip_commit, branch.remote.as_deref())
            .await
            .unwrap();
    }
}

/// Indexes both branches in `order` into a fresh database and checks the
/// callers of `add_numbers()` at each tip: each tip answers with the callers
/// in its own `math.c` and in the shared `report.c`.
async fn check_callers_at_each_tip(order: &[&str]) {
    let branches = two_branches();
    let db = Arc::new(
        DatabaseManager::new(
            branches.repo.join(".semcode.db").to_str().unwrap(),
            branches.repo.to_string_lossy().into_owned(),
        )
        .await
        .unwrap(),
    );
    db.create_tables().await.unwrap();

    index_branches(&db, &branches.repo, order).await;

    assert_eq!(
        callers_at(&db, "add_numbers", &branches.master).await,
        ["compute", "report", "scaled_sum"],
        "callers of add_numbers at the master tip"
    );
    assert_eq!(
        callers_at(&db, "add_numbers", &branches.baseline).await,
        ["compute", "report"],
        "callers of add_numbers at the baseline tip"
    );
}

/// `--branches master,baseline`: indexing `baseline` second rewrites
/// `math.c`, and the callers in `master`'s `math.c` must survive it.
#[tokio::test]
async fn each_branch_keeps_its_callers_master_first() {
    check_callers_at_each_tip(&["master", "baseline"]).await;
}

/// `--branches baseline,master`: indexing `master` second rewrites `math.c`,
/// and the callers in `baseline`'s `math.c` must survive it.
#[tokio::test]
async fn each_branch_keeps_its_callers_baseline_first() {
    check_callers_at_each_tip(&["baseline", "master"]).await;
}
