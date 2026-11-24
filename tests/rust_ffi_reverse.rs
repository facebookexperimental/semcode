// A `bindings::` call from Rust names the C function it spells: the
// reverse lookup must find the Rust caller beside the C ones, whether
// the file imports the shim, spells out the crate path, or names the
// extern crate with no import at all.
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

async fn ffi_tree() -> (tempfile::TempDir, Arc<DatabaseManager>, String) {
    let dir = tempfile::tempdir().unwrap();
    let repo: PathBuf = dir.path().into();
    git_run(&repo, &["init", "-q"]);
    std::fs::write(
        repo.join("seq.c"),
        "int seq_printf(const char *fmt)\n{\n\treturn 0;\n}\n\n\
         int c_seq_user(void)\n{\n\treturn seq_printf(\"x\");\n}\n",
    )
    .unwrap();
    std::fs::create_dir_all(repo.join("rust")).unwrap();
    std::fs::write(
        repo.join("rust/imported.rs"),
        "use crate::bindings;\n\
         fn rust_seq_imported() -> u32 {\n\
         \tbindings::seq_printf()\n\
         }\n",
    )
    .unwrap();
    // No import: the shim resolves as the extern crate the kernel
    // passes with `--extern bindings`, the pattern of print.rs.
    std::fs::write(
        repo.join("rust/plain.rs"),
        "use crate::fmt;\n\
         fn rust_seq_unimported() -> u32 {\n\
         \tbindings::seq_printf()\n\
         }\n",
    )
    .unwrap();
    // A local module wins over the shim: this caller keeps its
    // spelling and must not resolve to the C function.
    std::fs::write(
        repo.join("rust/shadowed.rs"),
        "mod bindings {\n\
         \tpub fn seq_printf() -> u32 { 1 }\n\
         }\n\
         fn rust_seq_shadowed() -> u32 {\n\
         \tbindings::seq_printf()\n\
         }\n",
    )
    .unwrap();
    // The full crate path names the same shim and strips too.
    std::fs::write(
        repo.join("rust/fullpath.rs"),
        "fn rust_seq_full_path() -> u32 {\n\
         \tcrate::bindings::seq_printf()\n\
         }\n",
    )
    .unwrap();
    git_run(&repo, &["add", "."]);
    git_run(&repo, &["commit", "-q", "-m", "ffi fixture"]);
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
    let extensions = ["c".to_string(), "rs".to_string()];
    semcode::git_range::process_git_tree(&repo, &sha, &extensions, db.clone(), false, 1, &[])
        .await
        .unwrap();
    (dir, db, sha)
}

#[tokio::test]
async fn bindings_calls_answer_the_c_function_in_both_directions() {
    let (_dir, db, sha) = ffi_tree().await;

    let callers: Vec<String> = db
        .get_function_callers_git_aware("seq_printf", &sha)
        .await
        .unwrap();
    for want in [
        "c_seq_user",
        "rust_seq_imported",
        "rust_seq_unimported",
        "rust_seq_full_path",
    ] {
        assert!(
            callers.iter().any(|n| n.ends_with(want)),
            "{want} must call seq_printf, callers: {callers:?}"
        );
    }

    // Forward: each Rust caller names the C function, not the shim.
    for caller in [
        "rust_seq_imported",
        "rust_seq_unimported",
        "rust_seq_full_path",
    ] {
        let callees: Vec<String> = db
            .get_function_callees_git_aware(caller, &sha)
            .await
            .unwrap();
        assert!(
            callees.iter().any(|n| n.ends_with("seq_printf")),
            "{caller} must reach seq_printf, callees: {callees:?}"
        );
        assert!(
            callees.iter().all(|n| !n.contains("bindings")),
            "{caller} must not name the shim, callees: {callees:?}"
        );
    }

    // No phantom edges: the C caller calls nobody's reverse, and the
    // shadowed Rust caller keeps its own module's spelling.
    let idle: Vec<String> = db
        .get_function_callers_git_aware("c_seq_user", &sha)
        .await
        .unwrap();
    assert!(idle.is_empty(), "nothing calls c_seq_user: {idle:?}");
    assert!(
        !callers.iter().any(|n| n.ends_with("rust_seq_shadowed")),
        "shadowed caller must not reach the C function: {callers:?}"
    );
    // Positive shadow control: the file was indexed, and its edge kept
    // the module spelling, so this passes only if the file contributed.
    let shadow_callees: Vec<String> = db
        .get_function_callees_git_aware("rust_seq_shadowed", &sha)
        .await
        .unwrap();
    assert!(
        shadow_callees.iter().any(|n| n == "bindings::seq_printf"),
        "shadowed edge must keep its spelling: {shadow_callees:?}"
    );
}
