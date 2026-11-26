// Assembly definitions join the call graph in both directions: a C
// caller reaches into `.S`, and an asm tail jump reaches back out to C.
// The fixture mirrors the in-tree copy_mc shape (a SYM_FUNC_START body
// jumping to a C function its C caller also names).
use semcode::{git, DatabaseManager};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

fn git_run(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_PREFIX")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_CONFIG_PARAMETERS")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Semcode Test")
        .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
        .env("GIT_COMMITTER_NAME", "Semcode Test")
        .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

async fn asm_tree() -> (tempfile::TempDir, Arc<DatabaseManager>, String) {
    let dir = tempfile::tempdir().unwrap();
    let repo: PathBuf = dir.path().into();
    git_run(&repo, &["init", "-q"]);
    std::fs::write(
        repo.join("glue.c"),
        "int c_target(void)\n{\n\treturn 1;\n}\n\n\
         int c_caller(void)\n{\n\treturn asm_fn() + c_target();\n}\n",
    )
    .unwrap();
    std::fs::create_dir_all(repo.join("arch/x86")).unwrap();
    std::fs::write(
        repo.join("arch/x86/code.S"),
        "#include <linux/linkage.h>\n\
         SYM_FUNC_START(asm_fn)\n\
         \tjmp c_target\n\
         SYM_FUNC_END(asm_fn)\n",
    )
    .unwrap();
    git_run(&repo, &["add", "."]);
    git_run(&repo, &["commit", "-q", "-m", "asm fixture"]);
    let sha = git::get_git_sha(&repo).unwrap().unwrap();

    let db = Arc::new(
        DatabaseManager::new(
            repo.join(".semcode.db").to_str().unwrap(),
            repo.to_string_lossy().into_owned(),
        )
        .await
        .unwrap(),
    );
    db.create_tables().await.unwrap();
    // Default extensions: this is the wiring under test (an explicit
    // `["c", "S"]` would pass with the default list still missing `S`).
    let extensions = semcode::file_extensions::default_extensions();
    semcode::git_range::process_git_tree(&repo, &sha, &extensions, db.clone(), false, 1, &[])
        .await
        .unwrap();
    (dir, db, sha)
}

#[tokio::test]
async fn asm_definitions_join_the_graph_both_ways() {
    let (_dir, db, sha) = asm_tree().await;

    // The definition itself: without asm indexing no row names `asm_fn`
    // at all (the C rows name it only as a callee).
    let defined = db.find_function_git_aware("asm_fn", &sha).await.unwrap();
    assert!(
        defined
            .as_ref()
            .is_some_and(|row| row.file_path.ends_with("arch/x86/code.S")),
        "asm_fn must be defined by the .S file, defined: {defined:?}"
    );

    // Into assembly: the C caller names the asm definition. This holds
    // through the C row alone, so it pins the direction, not the
    // indexing; the definition assertion above pins that.
    let callers: Vec<String> = db
        .get_function_callers_git_aware("asm_fn", &sha)
        .await
        .unwrap();
    assert!(
        callers.iter().any(|n| n == "c_caller"),
        "c_caller must reach asm_fn, callers: {callers:?}"
    );

    // Out of assembly: the tail jump names the C function beside the
    // C caller, so the round trip assembles.
    let back: Vec<String> = db
        .get_function_callers_git_aware("c_target", &sha)
        .await
        .unwrap();
    for want in ["c_caller", "asm_fn"] {
        assert!(
            back.iter().any(|n| n == want),
            "{want} must reach c_target, callers: {back:?}"
        );
    }

    // Forward: the asm definition's own edges name the C target.
    let callees: Vec<String> = db
        .get_function_callees_git_aware("asm_fn", &sha)
        .await
        .unwrap();
    assert!(
        callees.iter().any(|n| n == "c_target"),
        "asm_fn must reach c_target, callees: {callees:?}"
    );
}

async fn move_tree() -> (tempfile::TempDir, PathBuf, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let repo: PathBuf = dir.path().into();
    git_run(&repo, &["init", "-q"]);
    std::fs::create_dir_all(repo.join("arch/x86")).unwrap();
    std::fs::create_dir_all(repo.join("drivers")).unwrap();
    std::fs::write(
        repo.join("glue.c"),
        "int c_target(void)\n{\n\treturn 1;\n}\n\n\
         int c_caller(void)\n{\n\treturn asm_fn() + extra_fn() + c_target();\n}\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("arch/x86/code.S"),
        "SYM_FUNC_START(asm_fn)\n\
         \tjmp c_target\n\
         SYM_FUNC_END(asm_fn)\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("drivers/extra.S"),
        "SYM_FUNC_START(extra_fn)\n\
         \tjmp c_target\n\
         SYM_FUNC_END(extra_fn)\n",
    )
    .unwrap();
    git_run(&repo, &["add", "."]);
    git_run(&repo, &["commit", "-q", "-m", "v1"]);
    let sha1 = git::get_git_sha(&repo).unwrap().unwrap();
    git_run(&repo, &["mv", "arch/x86/code.S", "drivers/code.S"]);
    git_run(&repo, &["mv", "drivers/extra.S", "arch/x86/extra.S"]);
    git_run(&repo, &["commit", "-q", "-m", "v2 moves both files"]);
    let sha2 = git::get_git_sha(&repo).unwrap().unwrap();
    (dir, repo, sha1, sha2)
}

async fn index_db(repo: &Path, db_name: &str) -> Arc<DatabaseManager> {
    let db = Arc::new(
        DatabaseManager::new(
            repo.join(db_name).to_str().unwrap(),
            repo.to_string_lossy().into_owned(),
        )
        .await
        .unwrap(),
    );
    db.create_tables().await.unwrap();
    db
}

async fn graph_at(
    db: &DatabaseManager,
    sha: &str,
) -> (
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Option<String>,
    Option<String>,
) {
    let mut callees_asm = db
        .get_function_callees_git_aware("asm_fn", sha)
        .await
        .unwrap();
    let mut callees_extra = db
        .get_function_callees_git_aware("extra_fn", sha)
        .await
        .unwrap();
    let mut callers = db
        .get_function_callers_git_aware("c_target", sha)
        .await
        .unwrap();
    callees_asm.sort();
    callees_extra.sort();
    callers.sort();
    let asm_def = db.find_function_git_aware("asm_fn", sha).await.unwrap();
    let extra_def = db.find_function_git_aware("extra_fn", sha).await.unwrap();
    (
        callees_asm,
        callees_extra,
        callers,
        asm_def.map(|row| row.file_path),
        extra_def.map(|row| row.file_path),
    )
}

#[tokio::test]
async fn moved_asm_files_match_a_fresh_index() {
    // Reuse keys on (blob, path): the arch gate reads the path, so a
    // move must re-analyze even though neither blob changed. After
    // arch/x86/code.S moves to drivers/ its edge goes missing, and
    // after drivers/extra.S moves to arch/x86/ its edge appears; an
    // incremental run over the move must answer exactly like a fresh
    // index of the new tree in both directions.
    let (_dir, repo, _sha1, sha2) = move_tree().await;
    let extensions = semcode::file_extensions::default_extensions();

    // Fresh: the whole v2 tree at once.
    let fresh = index_db(&repo, "fresh.db").await;
    semcode::git_range::process_git_tree(&repo, &sha2, &extensions, fresh.clone(), false, 1, &[])
        .await
        .unwrap();
    let fresh_graph = graph_at(&fresh, &sha2).await;

    // Incremental: v1 by SHA, then the move commit as a range.
    let ranged = index_db(&repo, "ranged.db").await;
    let sha1 = {
        let output = Command::new("git")
            .args(["rev-parse", "HEAD~1"])
            .current_dir(&repo)
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    };
    semcode::git_range::process_git_tree(&repo, &sha1, &extensions, ranged.clone(), false, 1, &[])
        .await
        .unwrap();
    semcode::git_range::process_git_range(
        &repo,
        &format!("{sha1}..{sha2}"),
        &extensions,
        ranged.clone(),
        false,
        1,
        &[],
    )
    .await
    .unwrap();
    let ranged_graph = graph_at(&ranged, &sha2).await;

    assert_eq!(ranged_graph, fresh_graph, "incremental must match fresh");
    let (callees_asm, callees_extra, callers, asm_path, extra_path) = fresh_graph;
    assert!(
        callees_asm.is_empty(),
        "drivers asm_fn reads no edges: {callees_asm:?}"
    );
    assert_eq!(callees_extra, ["c_target"], "x86 extra_fn keeps its edge");
    assert!(
        callers.contains(&"extra_fn".to_string()),
        "callers: {callers:?}"
    );
    assert!(
        !callers.contains(&"asm_fn".to_string()),
        "callers: {callers:?}"
    );
    assert!(
        asm_path
            .as_deref()
            .is_some_and(|p| p.ends_with("drivers/code.S")),
        "{asm_path:?}"
    );
    assert!(
        extra_path
            .as_deref()
            .is_some_and(|p| p.ends_with("arch/x86/extra.S")),
        "{extra_path:?}"
    );
}

#[tokio::test]
async fn linker_scripts_record_as_processed_without_definitions() {
    // `.lds.S` routes through the asm branch and defines nothing, but
    // the file must record as processed: otherwise every incremental
    // run re-reads all 63 linker scripts, and a launch whose first
    // changed file is one re-indexes HEAD's commit every time.
    let dir = tempfile::tempdir().unwrap();
    let repo: PathBuf = dir.path().into();
    git_run(&repo, &["init", "-q"]);
    std::fs::write(repo.join("vmlinux.lds.S"), "ENTRY(stext)\nSECTIONS { }\n").unwrap();
    git_run(&repo, &["add", "."]);
    git_run(&repo, &["commit", "-q", "-m", "lds fixture"]);
    let sha = git::get_git_sha(&repo).unwrap().unwrap();
    let db = index_db(&repo, "lds.db").await;
    let extensions = semcode::file_extensions::default_extensions();
    semcode::git_range::process_git_tree(&repo, &sha, &extensions, db.clone(), false, 1, &[])
        .await
        .unwrap();
    let output = Command::new("git")
        .args(["rev-parse", &format!("{sha}:vmlinux.lds.S")])
        .current_dir(&repo)
        .output()
        .unwrap();
    let blob = String::from_utf8(output.stdout).unwrap().trim().to_string();
    assert!(
        db.is_file_processed_at_path(&blob, "vmlinux.lds.S")
            .await
            .unwrap(),
        "lds must record as processed"
    );
    assert!(
        db.find_function_git_aware("stext", &sha)
            .await
            .unwrap()
            .is_none(),
        "lds ENTRY must define nothing"
    );
}

#[tokio::test]
async fn identical_copies_under_both_paths_both_read() {
    // In-run dedup keys every file on (blob, path): the same blob under
    // `drivers/` and `arch/x86/` must both index, or the x86 copy's
    // edges depend on which path the tree walk enumerates first. Only
    // the x86 copy contributes edges (the drivers copy is gated out),
    // so the callers assertion pins which copy read while the marks pin
    // that both did.
    let dir = tempfile::tempdir().unwrap();
    let repo: PathBuf = dir.path().into();
    git_run(&repo, &["init", "-q"]);
    std::fs::create_dir_all(repo.join("arch/x86")).unwrap();
    std::fs::create_dir_all(repo.join("drivers")).unwrap();
    std::fs::write(
        repo.join("glue.c"),
        "int c_target(void)\n{\n\treturn 1;\n}\n",
    )
    .unwrap();
    git_run(&repo, &["add", "."]);
    git_run(&repo, &["commit", "-q", "-m", "base"]);
    let asm = "SYM_FUNC_START(copy_fn)\n\
               \tjmp c_target\n\
               SYM_FUNC_END(copy_fn)\n";
    std::fs::write(repo.join("arch/x86/copy.S"), asm).unwrap();
    std::fs::write(repo.join("drivers/copy.S"), asm).unwrap();
    git_run(&repo, &["add", "."]);
    git_run(&repo, &["commit", "-q", "-m", "copies"]);
    let sha = git::get_git_sha(&repo).unwrap().unwrap();
    let db = index_db(&repo, "copy.db").await;
    let extensions = semcode::file_extensions::default_extensions();
    // Through the range path, where in-run dedup decides: the tree path
    // has no sent check at all.
    let output = Command::new("git")
        .args(["rev-parse", "HEAD~1"])
        .current_dir(&repo)
        .output()
        .unwrap();
    let base = String::from_utf8(output.stdout).unwrap().trim().to_string();
    semcode::git_range::process_git_range(
        &repo,
        &format!("{base}..{sha}"),
        &extensions,
        db.clone(),
        false,
        1,
        &[],
    )
    .await
    .unwrap();
    let output = Command::new("git")
        .args(["rev-parse", &format!("{sha}:arch/x86/copy.S")])
        .current_dir(&repo)
        .output()
        .unwrap();
    let blob = String::from_utf8(output.stdout).unwrap().trim().to_string();
    for path in ["arch/x86/copy.S", "drivers/copy.S"] {
        assert!(
            db.is_file_processed_at_path(&blob, path).await.unwrap(),
            "{path} must record as processed"
        );
    }
    let callers = db
        .get_function_callers_git_aware("c_target", &sha)
        .await
        .unwrap();
    assert!(
        callers.iter().any(|n| n == "copy_fn"),
        "the x86 copy must reach c_target, callers: {callers:?}"
    );
}

#[tokio::test]
async fn identical_c_copies_both_read_and_rerun_sends_nothing() {
    // The C/H half of the same-blob case: GPT's round-3 demo put one
    // `.c` blob under two paths, and the range path kept first-wins
    // while the tree path read both. Both copies must read on the range
    // path too — and a second identical run must change nothing, since
    // every pair records as processed on the first run.
    let dir = tempfile::tempdir().unwrap();
    let repo: PathBuf = dir.path().into();
    git_run(&repo, &["init", "-q"]);
    std::fs::create_dir_all(repo.join("a")).unwrap();
    std::fs::create_dir_all(repo.join("b")).unwrap();
    git_run(&repo, &["commit", "-q", "--allow-empty", "-m", "base"]);
    let body = "int twin_fn(void)\n{\n\treturn 1;\n}\n";
    std::fs::write(repo.join("a/twin.c"), body).unwrap();
    std::fs::write(repo.join("b/twin.c"), body).unwrap();
    git_run(&repo, &["add", "."]);
    git_run(&repo, &["commit", "-q", "-m", "copies"]);
    let sha = git::get_git_sha(&repo).unwrap().unwrap();
    let db = index_db(&repo, "twins.db").await;
    let extensions = semcode::file_extensions::default_extensions();
    let output = Command::new("git")
        .args(["rev-parse", "HEAD~1"])
        .current_dir(&repo)
        .output()
        .unwrap();
    let base = String::from_utf8(output.stdout).unwrap().trim().to_string();
    let range = format!("{base}..{sha}");
    let first = semcode::git_range::process_git_range(
        &repo,
        &range,
        &extensions,
        db.clone(),
        false,
        1,
        &[],
    )
    .await
    .unwrap();
    // Both copies read on the first run: one send per path.
    assert_eq!(first.sent, 2, "{first:?}");
    let output = Command::new("git")
        .args(["rev-parse", &format!("{sha}:a/twin.c")])
        .current_dir(&repo)
        .output()
        .unwrap();
    let blob = String::from_utf8(output.stdout).unwrap().trim().to_string();
    for path in ["a/twin.c", "b/twin.c"] {
        assert!(
            db.is_file_processed_at_path(&blob, path).await.unwrap(),
            "{path} must record as processed"
        );
    }
    let mut paths: Vec<String> = db
        .find_all_functions("twin_fn")
        .await
        .unwrap()
        .into_iter()
        .map(|f| f.file_path)
        .collect();
    paths.sort();
    assert_eq!(paths, vec!["a/twin.c".to_string(), "b/twin.c".to_string()]);
    // A second identical run writes nothing new: every pair above
    // already records as processed, so the rows must come back
    // unchanged.
    let second = semcode::git_range::process_git_range(
        &repo,
        &range,
        &extensions,
        db.clone(),
        false,
        1,
        &[],
    )
    .await
    .unwrap();
    assert_eq!(second.sent, 0, "{second:?}");
    let mut rerun: Vec<String> = db
        .find_all_functions("twin_fn")
        .await
        .unwrap()
        .into_iter()
        .map(|f| f.file_path)
        .collect();
    rerun.sort();
    assert_eq!(rerun, paths, "the rerun must add no rows");
}
