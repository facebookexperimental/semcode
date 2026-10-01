// SPDX-License-Identifier: MIT OR Apache-2.0
//
// A name one file defines once per configuration: every arm is reported, and
// a chain walks every arm, because an audit has to see every branch.
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

/// `sched.h`'s shape: `_cond_resched()` once per configuration, and only one
/// arm reaches `rcu_all_qs()`. A second header has a caller under
/// `CONFIG_PREEMPTION` of a name defined once per value of that symbol.
async fn tree() -> (tempfile::TempDir, Arc<DatabaseManager>, String) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("sched.h"),
        "#ifndef _SCHED_H\n\
#define _SCHED_H\n\
#ifdef CONFIG_PREEMPT_DYNAMIC\n\
static inline int _cond_resched(void)\n{\n\treturn dynamic_cond_resched();\n}\n\
#elif !defined(CONFIG_PREEMPTION)\n\
static inline int _cond_resched(void)\n{\n\treturn __cond_resched();\n}\n\
#else\n\
static inline int _cond_resched(void)\n{\n\treturn 0;\n}\n\
#endif\n\
static inline int cond_resched(void)\n{\n\treturn _cond_resched();\n}\n\
#endif\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("core.c"),
        "int __cond_resched(void)\n{\n\trcu_all_qs();\n\treturn 1;\n}\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("preempt.h"),
        "#ifdef CONFIG_PREEMPTION\n\
static inline int preempt_path(void)\n{\n\treturn which_side();\n}\n\
#endif\n\
#ifdef CONFIG_PREEMPTION\n\
static inline int which_side(void)\n{\n\treturn preemptible_side();\n}\n\
#else\n\
static inline int which_side(void)\n{\n\treturn voluntary_side();\n}\n\
#endif\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "arms"]);
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

fn plain(bytes: Vec<u8>) -> String {
    let text = String::from_utf8(bytes).unwrap();
    // Strip ANSI colour.
    let mut out = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[tokio::test]
async fn every_arm_is_reported_with_its_guard() {
    let (_dir, db, sha) = tree().await;
    let all = db
        .find_all_functions_git_aware("_cond_resched", &sha)
        .await
        .unwrap();
    let guards: Vec<Option<&str>> = all.iter().map(|f| f.guard.as_deref()).collect();
    assert_eq!(
        guards,
        vec![
            Some("defined(CONFIG_PREEMPT_DYNAMIC)"),
            Some("!defined(CONFIG_PREEMPT_DYNAMIC) && !defined(CONFIG_PREEMPTION)"),
            Some("!defined(CONFIG_PREEMPT_DYNAMIC) && defined(CONFIG_PREEMPTION)"),
        ],
        "{all:#?}"
    );

    let chosen = db
        .find_function_git_aware_reporting("_cond_resched", &sha, semcode::domain::Context::Any)
        .await
        .unwrap()
        .chosen()
        .unwrap();
    let note = chosen.ambiguity_note(semcode::Surface::Repl).unwrap();
    assert!(note.contains("one definition per configuration"), "{note}");
    assert!(note.contains("No build compiles more than one"), "{note}");
}

#[tokio::test]
async fn a_chain_reaches_what_only_one_arm_calls() {
    // The motivating route: cond_resched -> _cond_resched -> __cond_resched
    // -> rcu_all_qs, which exists only through the !CONFIG_PREEMPTION arm.
    let (_dir, db, sha) = tree().await;
    let callees = db
        .get_function_callees_git_aware("_cond_resched", &sha)
        .await
        .unwrap();
    assert!(
        callees.iter().any(|c| c == "__cond_resched"),
        "the arm that does something is not walked: {callees:?}"
    );
    assert!(
        callees.iter().any(|c| c == "dynamic_cond_resched"),
        "{callees:?}"
    );

    let mut out = Vec::new();
    semcode::callchain::show_callchain_to_writer(&db, "cond_resched", &mut out, &sha)
        .await
        .unwrap();
    let text = plain(out);
    assert!(text.contains("rcu_all_qs"), "{text}");
    assert!(
        text.contains("under !defined(CONFIG_PREEMPT_DYNAMIC) && !defined(CONFIG_PREEMPTION)"),
        "{text}"
    );
}

#[tokio::test]
async fn an_arm_a_path_contradicts_is_shown_and_not_walked() {
    // preempt_path exists only under CONFIG_PREEMPTION, so the
    // !CONFIG_PREEMPTION arm of which_side cannot run below it.
    let (_dir, db, sha) = tree().await;
    let mut out = Vec::new();
    semcode::callchain::show_callchain_to_writer(&db, "preempt_path", &mut out, &sha)
        .await
        .unwrap();
    let text = plain(out);
    assert!(text.contains("preemptible_side"), "{text}");
    assert!(
        text.contains("cannot run here: defined(CONFIG_PREEMPTION) holds above"),
        "{text}"
    );
    assert!(!text.contains("voluntary_side"), "{text}");
}
