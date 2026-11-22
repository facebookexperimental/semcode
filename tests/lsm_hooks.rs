use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use semcode::{git, DatabaseManager};

fn plain(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        for c in chars.by_ref() {
            if c == 'm' {
                break;
            }
        }
    }
    out
}

fn git_run(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(repo)
        .args(args)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .status()
        .unwrap();
    assert!(status.success());
}

async fn index_repo(repo: &Path) -> (Arc<DatabaseManager>, String) {
    let git_sha = git::get_git_sha(repo).unwrap().unwrap();
    let db_path = repo.join(".semcode.db");
    let db = Arc::new(
        DatabaseManager::new(
            db_path.to_str().unwrap(),
            repo.to_string_lossy().into_owned(),
        )
        .await
        .unwrap(),
    );
    db.create_tables().await.unwrap();
    semcode::git_range::process_git_tree(
        repo,
        &git_sha,
        &["c".to_string(), "h".to_string()],
        db.clone(),
        false,
        1,
        &[],
    )
    .await
    .unwrap();
    (db, git_sha)
}

async fn callers_text(db: &DatabaseManager, name: &str, sha: &str) -> String {
    let mut out = Vec::new();
    semcode::callchain::show_callers_to_writer(db, name, &mut out, false, sha)
        .await
        .unwrap();
    plain(&String::from_utf8(out).unwrap())
}

async fn callees_text(db: &DatabaseManager, name: &str, sha: &str) -> String {
    let mut out = Vec::new();
    semcode::callchain::show_callees_to_writer(db, name, &mut out, false, sha)
        .await
        .unwrap();
    plain(&String::from_utf8(out).unwrap())
}

async fn implementors_text(
    db: &DatabaseManager,
    container: &str,
    member: &str,
    sha: &str,
) -> String {
    let mut out = Vec::new();
    semcode::callchain::show_implementors_to_writer(db, container, member, &mut out, sha)
        .await
        .unwrap();
    plain(&String::from_utf8(out).unwrap())
}

const LSM_H: &str = r#"
#define LSM_HOOK_INIT(NAME, HOOK) { .scalls = 0, .hook = HOOK }
#define call_int_hook(HOOK, ...) hook_##HOOK(__VA_ARGS__)
#define call_void_hook(HOOK, ...) hook_##HOOK(__VA_ARGS__)
"#;

fn write_repo(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    for (name, contents) in files {
        std::fs::write(repo.join(name), contents).unwrap();
    }
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    dir
}

/// An installer plus an int dispatch site resolves through the hook head.
#[tokio::test]
async fn lsm_int_hook_resolves() {
    let dir = write_repo(&[
        ("lsm.h", LSM_H),
        (
            "hooks.c",
            "#include \"lsm.h\"\nint sel_file_open(void) { return 0; }\nint hook_table[] = { LSM_HOOK_INIT(file_open, sel_file_open) };\n",
        ),
        (
            "sec.c",
            "#include \"lsm.h\"\nint hook_file_open(int a) { return a; }\nint security_file_open(int a) { return call_int_hook(file_open, a); }\n",
        ),
    ]);
    let (db, sha) = index_repo(dir.path()).await;
    let text = callers_text(&db, "sel_file_open", &sha).await;
    assert!(text.contains("security_file_open"), "{text}");
    assert!(text.contains("file_open"), "{text}");
}

/// A void hook resolves the same way.
#[tokio::test]
async fn lsm_void_hook_resolves() {
    let dir = write_repo(&[
        ("lsm.h", LSM_H),
        (
            "hooks.c",
            "#include \"lsm.h\"\nvoid sel_cred_free(void) {}\nint hook_table[] = { LSM_HOOK_INIT(cred_free, sel_cred_free) };\n",
        ),
        (
            "sec.c",
            "#include \"lsm.h\"\nvoid hook_cred_free(void) {}\nvoid security_cred_free(void) { call_void_hook(cred_free); }\n",
        ),
    ]);
    let (db, sha) = index_repo(dir.path()).await;
    let text = callers_text(&db, "sel_cred_free", &sha).await;
    assert!(text.contains("security_cred_free"), "{text}");
}

/// An ordinary member call never joins an LSM registration, and the LSM
/// dispatch site never joins the ordinary registration.
#[tokio::test]
async fn lsm_negative_both_directions() {
    let dir = write_repo(&[
        ("lsm.h", LSM_H),
        (
            "hooks.c",
            "#include \"lsm.h\"\nint sel_file_open(void) { return 0; }\nint hook_table[] = { LSM_HOOK_INIT(file_open, sel_file_open) };\n",
        ),
        (
            "ops.c",
            "struct fops { int (*file_open)(void); };\nint real_open(void) { return 1; }\nstruct fops o = { .file_open = real_open };\nint use_ops(struct fops *o) { return o->file_open(); }\n",
        ),
        (
            "sec.c",
            "#include \"lsm.h\"\nint hook_file_open(int a) { return a; }\nint security_file_open(int a) { return call_int_hook(file_open, a); }\n",
        ),
    ]);
    let (db, sha) = index_repo(dir.path()).await;
    // Ordinary member call reaches the ordinary install, not the LSM one.
    let text = callers_text(&db, "real_open", &sha).await;
    assert!(text.contains("use_ops"), "{text}");
    assert!(!text.contains("security_file_open"), "{text}");
    // LSM dispatch reaches the LSM install, not the ordinary one.
    let text = callers_text(&db, "sel_file_open", &sha).await;
    assert!(text.contains("security_file_open"), "{text}");
    assert!(!text.contains("use_ops"), "{text}");
    assert!(!text.contains("real_open"), "{text}");
}

/// A pasted installer target records no row: the bpf template shape has
/// the paste text directly in a `#define` body, as in hooks.c there.
#[tokio::test]
async fn lsm_paste_target_stores_no_row() {
    let dir = write_repo(&[
        ("lsm.h", "#define LSM_HOOK_INIT(NAME, HOOK) { .scalls = 0 }\n"),
        (
            "hooks.c",
            "#include \"lsm.h\"\n#define LSM_HOOK(RET, DEFAULT, NAME, ...) LSM_HOOK_INIT(NAME, bpf_lsm_##NAME)\n",
        ),
    ]);
    let (db, sha) = index_repo(dir.path()).await;
    let found = db
        .find_registrations_for_slot_git_aware("static_calls_table", "file_open", &sha)
        .await
        .unwrap();
    assert!(found.is_empty(), "{found:?}");
}

/// A concrete two-identifier installer beside the template extracts:
/// the bpf `inode_free_security` row survives the paste guard.
#[tokio::test]
async fn lsm_concrete_installer_beside_template() {
    let dir = write_repo(&[
        ("lsm.h", "#define LSM_HOOK_INIT(NAME, HOOK) { .scalls = 0 }\n"),
        (
            "hooks.c",
            "#include \"lsm.h\"\n#define LSM_HOOK(RET, DEFAULT, NAME, ...) LSM_HOOK_INIT(NAME, bpf_lsm_##NAME)\nint hook_table[] = { LSM_HOOK_INIT(inode_free_security, bpf_inode_storage_free) };\n",
        ),
    ]);
    let (db, sha) = index_repo(dir.path()).await;
    let found = db
        .find_registrations_for_slot_git_aware("static_calls_table", "inode_free_security", &sha)
        .await
        .unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].target, "bpf_inode_storage_free");
}

/// The template parameter NAME is never a slot, even where the paste
/// guard is what skips the row.
#[tokio::test]
async fn lsm_template_name_is_no_slot() {
    let dir = write_repo(&[
        ("lsm.h", "#define LSM_HOOK_INIT(NAME, HOOK) { .scalls = 0 }\n"),
        (
            "hooks.c",
            "#include \"lsm.h\"\n#define LSM_HOOK(RET, DEFAULT, NAME, ...) LSM_HOOK_INIT(NAME, bpf_lsm_##NAME)\n",
        ),
    ]);
    let (db, sha) = index_repo(dir.path()).await;
    let found = db
        .find_registrations_for_slot_git_aware("static_calls_table", "NAME", &sha)
        .await
        .unwrap();
    assert!(found.is_empty(), "{found:?}");
}

/// The dispatch macros' own parameter HOOK is never a member.
#[tokio::test]
async fn lsm_hook_parameter_is_no_member() {
    let dir = write_repo(&[(
        "sec.c",
        "#define call_int_hook(HOOK, ...) hook_##HOOK(__VA_ARGS__)\nint f(int a) { return call_int_hook(file_open, a); }\n",
    )]);
    let (db, _sha) = index_repo(dir.path()).await;
    let found = db.find_dispatch_sites_by_member("HOOK").await.unwrap();
    assert!(found.is_empty(), "{found:?}");
}

/// `lsm_for_each_hook` iteration is not a dispatch site.
#[tokio::test]
async fn lsm_for_each_hook_yields_no_site() {
    let dir = write_repo(&[(
        "sec.c",
        "int table[4];\n#define lsm_for_each_hook(s, N) for (s = table; s < table + 4; s++)\nvoid walk(void) { int *s; lsm_for_each_hook(s, file_open); }\n",
    )]);
    let (db, _sha) = index_repo(dir.path()).await;
    let found = db.find_dispatch_sites_by_member("file_open").await.unwrap();
    assert!(found.is_empty(), "{found:?}");
}

/// Implementors display lists the LSM row under its slot.
#[tokio::test]
async fn lsm_implementors_lists_slot() {
    let dir = write_repo(&[
        ("lsm.h", LSM_H),
        (
            "hooks.c",
            "#include \"lsm.h\"\nint sel_file_open(void) { return 0; }\nint hook_table[] = { LSM_HOOK_INIT(file_open, sel_file_open) };\n",
        ),
    ]);
    let (db, sha) = index_repo(dir.path()).await;
    let text = implementors_text(&db, "static_calls_table", "file_open", &sha).await;
    assert!(text.contains("sel_file_open"), "{text}");
    assert!(text.contains("lsm_hook"), "{text}");
}

/// Direct callees name no implementations: dispatch surfaces in the
/// Dispatches section, never among callees.
#[tokio::test]
async fn lsm_forward_negative() {
    let dir = write_repo(&[
        ("lsm.h", LSM_H),
        (
            "hooks.c",
            "#include \"lsm.h\"\nint sel_file_open(void) { return 0; }\nint hook_table[] = { LSM_HOOK_INIT(file_open, sel_file_open) };\n",
        ),
        (
            "sec.c",
            "#include \"lsm.h\"\nint hook_file_open(int a) { return a; }\nint security_file_open(int a) { return call_int_hook(file_open, a); }\n",
        ),
    ]);
    let (db, sha) = index_repo(dir.path()).await;
    let text = callees_text(&db, "security_file_open", &sha).await;
    assert!(!text.contains("sel_file_open"), "{text}");
}

/// Forward dispatch shows exactly the slot's installs: five int
/// implementations (which also exercises the >3 truncation the display
/// applies) and two void ones, with the macro name and slot kind on
/// each site.
#[tokio::test]
async fn lsm_forward_dispatch_lists_slot() {
    let dir = write_repo(&[
        ("lsm.h", LSM_H),
        (
            "hooks.c",
            "#include \"lsm.h\"\nint sel_a(void) { return 0; }\nint sel_b(void) { return 0; }\nint sel_c(void) { return 0; }\nint sel_d(void) { return 0; }\nint sel_e(void) { return 0; }\nvoid void_a(void) {}\nvoid void_b(void) {}\nint hook_table[] = { LSM_HOOK_INIT(file_open, sel_a), LSM_HOOK_INIT(file_open, sel_b), LSM_HOOK_INIT(file_open, sel_c), LSM_HOOK_INIT(file_open, sel_d), LSM_HOOK_INIT(file_open, sel_e), LSM_HOOK_INIT(cred_free, void_a), LSM_HOOK_INIT(cred_free, void_b) };\n",
        ),
        (
            "ops.c",
            "struct fops { int (*file_open)(void); };\nint real_open(void) { return 1; }\nstruct fops o = { .file_open = real_open };\nint use_ops(struct fops *p) { return p->file_open(); }\nint use_untyped(struct unknown *u) { return u->file_open(); }\n",
        ),
        (
            "sec.c",
            "#include \"lsm.h\"\nint security_file_open(int a) { return call_int_hook(file_open, a); }\nvoid security_cred_free(void) { call_void_hook(cred_free); }\n",
        ),
    ]);
    let (db, sha) = index_repo(dir.path()).await;
    let resolved = db
        .resolve_dispatches_in(
            &[
                "security_file_open".to_string(),
                "security_cred_free".to_string(),
            ],
            &sha,
        )
        .await
        .unwrap();
    let open = resolved.get("security_file_open").expect("slot dispatch");
    assert_eq!(open.len(), 1, "{open:?}");
    assert_eq!(open[0].member, "file_open");
    assert_eq!(open[0].receiver_expr, "call_int_hook");
    assert_eq!(open[0].container_type, "static_calls_table");
    assert_eq!(
        open[0].lsm_kind,
        Some(semcode::DispatchKind::LsmHookInt),
        "{open:?}"
    );
    assert_eq!(open[0].targets.len(), 5, "{open:?}");
    for name in ["sel_a", "sel_b", "sel_c", "sel_d", "sel_e"] {
        assert!(
            open[0].targets.iter().any(|t| t.ends_with(name)),
            "{name} missing: {open:?}"
        );
    }
    let free = resolved.get("security_cred_free").expect("void dispatch");
    assert_eq!(free.len(), 1, "{free:?}");
    assert_eq!(free[0].receiver_expr, "call_void_hook");
    assert_eq!(
        free[0].lsm_kind,
        Some(semcode::DispatchKind::LsmHookVoid),
        "{free:?}"
    );
    assert_eq!(free[0].targets.len(), 2, "{free:?}");
}

/// A non-LSM row planted in the slot container never joins: the
/// extractor cannot produce one, so this goes in at the store level
/// with a manifest-valid hash borrowed from a real row.
#[tokio::test]
async fn lsm_forward_ignores_planted_row() {
    let dir = write_repo(&[
        ("lsm.h", LSM_H),
        (
            "hooks.c",
            "#include \"lsm.h\"\nint sel_file_open(void) { return 0; }\nint hook_table[] = { LSM_HOOK_INIT(file_open, sel_file_open) };\n",
        ),
        (
            "sec.c",
            "#include \"lsm.h\"\nint security_file_open(int a) { return call_int_hook(file_open, a); }\n",
        ),
    ]);
    let (db, sha) = index_repo(dir.path()).await;
    let rows = db
        .find_registrations_for_slot_git_aware("static_calls_table", "file_open", &sha)
        .await
        .unwrap();
    assert!(!rows.is_empty(), "fixture installed nothing");
    db.insert_registrations(vec![semcode::Registration {
        container_type: "static_calls_table".to_string(),
        member: "file_open".to_string(),
        target: "planted_fn".to_string(),
        file_path: rows[0].file_path.clone(),
        git_file_hash: rows[0].git_file_hash.clone(),
        byte_start: 0,
        line: 9999,
        enclosing_function: String::new(),
        kind: semcode::RegistrationKind::DesignatedInit,
        container_base_type: None,
        container_field: None,
    }])
    .await
    .unwrap();
    let resolved = db
        .resolve_dispatches_in(&["security_file_open".to_string()], &sha)
        .await
        .unwrap();
    let open = resolved.get("security_file_open").expect("slot dispatch");
    assert_eq!(open[0].targets.len(), 1, "{open:?}");
    assert!(
        !open[0].targets.iter().any(|t| t.ends_with("planted_fn")),
        "{open:?}"
    );
}

/// Same-member ordinary sites gain nothing from the slot: the typed
/// one joins its own install, the untyped one joins nothing.
#[tokio::test]
async fn lsm_forward_ordinary_sites_gain_nothing() {
    let dir = write_repo(&[
        ("lsm.h", LSM_H),
        (
            "hooks.c",
            "#include \"lsm.h\"\nint sel_file_open(void) { return 0; }\nint hook_table[] = { LSM_HOOK_INIT(file_open, sel_file_open) };\n",
        ),
        (
            "ops.c",
            "struct fops { int (*file_open)(void); };\nint real_open(void) { return 1; }\nstruct fops o = { .file_open = real_open };\nint use_ops(struct fops *p) { return p->file_open(); }\nint use_untyped(struct unknown *u) { return u->file_open(); }\n",
        ),
        (
            "sec.c",
            "#include \"lsm.h\"\nint security_file_open(int a) { return call_int_hook(file_open, a); }\n",
        ),
    ]);
    let (db, sha) = index_repo(dir.path()).await;
    let resolved = db
        .resolve_dispatches_in(&["use_ops".to_string(), "use_untyped".to_string()], &sha)
        .await
        .unwrap();
    let ops = resolved.get("use_ops").expect("typed site dispatches");
    assert_eq!(ops.len(), 1, "{ops:?}");
    assert_eq!(ops[0].lsm_kind, None, "{ops:?}");
    assert_eq!(ops[0].targets.len(), 1, "{ops:?}");
    assert!(ops[0].targets[0].ends_with("real_open"), "{ops:?}");
    assert!(
        resolved.get("use_untyped").is_none_or(Vec::is_empty),
        "{resolved:?}"
    );
}

/// The forward surfaces reuse the reverse legs' stacking phrases.
#[test]
fn lsm_forward_phrases_branch_on_flavor() {
    assert!(
        semcode::callchain::lsm_dispatch_phrase(semcode::DispatchKind::LsmHookInt)
            .contains("first non-default return wins")
    );
    assert!(
        semcode::callchain::lsm_dispatch_phrase(semcode::DispatchKind::LsmHookVoid)
            .contains("every installed implementation runs")
    );
}

/// Display branches on hook flavor: int warns about shadowing, void
/// promises every implementation runs.
#[tokio::test]
async fn lsm_display_branches_on_flavor() {
    let dir = write_repo(&[
        ("lsm.h", LSM_H),
        (
            "hooks.c",
            "#include \"lsm.h\"\nint sel_file_open(void) { return 0; }\nvoid sel_cred_free(void) {}\nint hook_table[] = { LSM_HOOK_INIT(file_open, sel_file_open), LSM_HOOK_INIT(cred_free, sel_cred_free) };\n",
        ),
        (
            "sec.c",
            "#include \"lsm.h\"\nint hook_file_open(int a) { return a; }\nvoid hook_cred_free(void) {}\nint security_file_open(int a) { return call_int_hook(file_open, a); }\nvoid security_cred_free(void) { call_void_hook(cred_free); }\n",
        ),
    ]);
    let (db, sha) = index_repo(dir.path()).await;
    let text = callers_text(&db, "sel_file_open", &sha).await;
    assert!(text.contains("first non-default return wins"), "{text}");
    let text = callers_text(&db, "sel_cred_free", &sha).await;
    assert!(
        text.contains("every installed implementation runs"),
        "{text}"
    );
}
