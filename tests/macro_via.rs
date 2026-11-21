// SPDX-License-Identifier: MIT OR Apache-2.0
//
// B3 macro via-traversal: index small trees shaped like the kernel's
// printk/BUG/predicates, then assert the exact resolved paths — forward,
// reverse, guarded, scoped and cross-revision — plus the negatives.
//
// Only exact paths are asserted, never caller-count deltas.
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use semcode::{git, DatabaseManager};

/// Output is written for a terminal, and the colour sequences sit between
/// the words a test wants to match.
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

/// A tree shaped like printk: a handing macro, a forwarding macro, a
/// wrapper macro, a never-invoking macro, a self-named macro and a
/// two-armed macro with distinct callees.
fn write_fixture(repo: &Path) {
    std::fs::write(
        repo.join("macros.h"),
        "#define EMIT_WRAP(_fn, x) _fn(x)\n\
         #define LOG_MSG(s) EMIT_WRAP(emit_fn, s)\n\
         #define LOUD(s) LOG_MSG(s)\n\
         #define DROP(cb) 0\n\
         #define SELF(x) SELF(x)\n\
         #if KIND\n\
         #define MODEFN(x) kind_fn(x)\n\
         #else\n\
         #define MODEFN(x) other_fn(x)\n\
         #endif\n\
         void emit_fn(const char *s);\n\
         void kind_fn(int x);\n\
         void other_fn(int x);\n\
         #define INNER(cb, x) cb(x)\n\
         #define OUT(cb, y) INNER(cb, y)\n\
         void nest_target(int v);\n\
         #define REPORT(x) emit_fn(x)\n\
         #define RREPORT(x) REPORT(x)\n\
         #define INNER2(cb, x) cb(x)\n\
         #define MID2(cb, y) INNER2(cb, y)\n\
         #define OUT2(cb, z) MID2(cb, z)\n\
         void deep_target(int v);\n\
         #define RUN2(invoke, ignore) invoke()\n\
         void slot_target(void);\n\
         #define DROP2(x) 0\n\
         #define OUTD(cb) DROP2(cb())\n\
         void discard_target(void);\n\
         #define EMIT3(fmt, ...) emit3_fn(fmt, ##__VA_ARGS__)\n\
         #define LOG3(fmt, ...) EMIT3(fmt, ##__VA_ARGS__)\n\
         void emit3_fn(const char *f, ...);\n\
         void var_target(int v);\n\
         #define OUTU(cb) INNERU(cb)\n\
         #define INNERU(cb) cb()\n\
         #undef INNERU\n\
         void site_target(void);\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("user.c"),
        "#include \"macros.h\"\n\
         int caller_one(void) { LOG_MSG(\"hi\"); return 0; }\n\
         int caller_loud(void) { LOUD(\"hi\"); return 0; }\n\
         void emit_fn(const char *s) { (void)s; }\n\
         int caller_two(void) { DROP(emit_fn); return 0; }\n\
         int caller_self(void) { SELF(1); return 0; }\n\
         int caller_mode(void) { MODEFN(1); return 0; }\n\
         void kind_fn(int x) { (void)x; }\n\
         void other_fn(int x) { (void)x; }\n\
         void nest_target(int v) { (void)v; }\n\
         int caller_nest(void) { OUT(nest_target, 1); return 0; }\n\
         int caller_report(void) { RREPORT(\"hi\"); return 0; }\n\
         void deep_target(int v) { (void)v; }\n\
         int caller_deep(void) { OUT2(deep_target, 1); return 0; }\n\
         void slot_target(void) { }\n\
         int caller_slot(void) { RUN2(slot_target, slot_target); return 0; }\n\
         void discard_target(void) { }\n\
         int caller_discard(void) { OUTD(discard_target); return 0; }\n\
         void emit3_fn(const char *f, ...) { (void)f; }\n\
         void var_target(int v) { (void)v; }\n\
         int caller_var(void) { LOG3(\"x\", var_target); return 0; }\n\
         void site_target(void) { }\n\
         int caller_site(void) { OUTU(site_target); return 0; }\n",
    )
    .unwrap();
}

async fn index_fixture(repo: &Path) -> (Arc<DatabaseManager>, String) {
    git_run(repo, &["init", "-q"]);
    write_fixture(repo);
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    index_repo(repo).await
}

/// Index the `.c`/`.h` files already committed at `repo`: for tests with
/// their own fixture text instead of the shared one.
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

async fn chain_text(db: &DatabaseManager, name: &str, sha: &str) -> String {
    let mut out = Vec::new();
    semcode::callchain::show_callchain_to_writer(db, name, &mut out, sha)
        .await
        .unwrap();
    plain(&String::from_utf8(out).unwrap())
}

/// The exact reverse path: `callers emit_fn` reaches caller_one through
/// EMIT_WRAP and LOG_MSG, with per-hop evidence.
#[tokio::test]
async fn reverse_exact_path_through_macros() {
    let dir = tempfile::tempdir().unwrap();
    let (db, sha) = index_fixture(dir.path()).await;
    let text = callers_text(&db, "emit_fn", &sha).await;
    assert!(text.contains("Via Macros"), "{text}");
    assert!(text.contains("via EMIT_WRAP"), "{text}");
    assert!(text.contains("caller_one"), "{text}");
    // The proved handover keeps its reachability claim.
    assert!(text.contains("Handed over:"), "{text}");
    assert!(text.contains("EMIT_WRAP() argument 0"), "{text}");
    // Ordered chain with definition locations: the handover names the
    // macro that invokes, and the via tree nests the caller under it.
    let emit_wrap = text.find("via EMIT_WRAP (macros.h:1)").expect("hop line");
    let caller_at = text[emit_wrap..].find("caller_one").expect("nested caller");
    assert!(
        text[emit_wrap..emit_wrap + caller_at].contains("macros.h:2"),
        "{text}"
    );
}

/// The exact forward path: caller_one → LOG_MSG → EMIT_WRAP → emit_fn,
// with the handover leg on the macro.
#[tokio::test]
async fn forward_exact_path_through_macros() {
    let dir = tempfile::tempdir().unwrap();
    let (db, sha) = index_fixture(dir.path()).await;
    let text = chain_text(&db, "caller_one", &sha).await;
    assert!(text.contains("LOG_MSG"), "{text}");
    assert!(text.contains("EMIT_WRAP"), "{text}");
    assert!(text.contains("emit_fn"), "{text}");
    assert!(text.contains("via EMIT_WRAP"), "{text}");
}

/// Nested forwarding: caller_nest → OUT → INNER → nest_target. OUT never
/// invokes its parameter itself; it hands it to INNER, which does. The leg
/// carries both definitions and the top-level site.
#[tokio::test]
async fn nested_macro_forward_path() {
    let dir = tempfile::tempdir().unwrap();
    let (db, sha) = index_fixture(dir.path()).await;
    let text = chain_text(&db, "caller_nest", &sha).await;
    assert!(text.contains("OUT"), "{text}");
    assert!(text.contains("INNER"), "{text}");
    assert!(text.contains("nest_target"), "{text}");
    assert!(text.contains("→ INNER"), "{text}");
}

/// Two-deep forwarding: caller_deep → OUT2 → MID2 → INNER2 →
/// deep_target. MID2 only forwards; without per-site recursion the walk
/// stalls at it and INNER2 never resolves.
#[tokio::test]
async fn forward_two_deep_through_pure_forwarder() {
    let dir = tempfile::tempdir().unwrap();
    let (db, sha) = index_fixture(dir.path()).await;
    let text = chain_text(&db, "caller_deep", &sha).await;
    for name in ["OUT2", "MID2", "INNER2", "deep_target"] {
        assert!(text.contains(name), "{text}");
    }
    assert!(text.contains("→ INNER2"), "{text}");
}

/// Reverse two-deep: deep_target is handed to OUT2, which forwards
/// through MID2 to INNER2. The chain names every hop with the top site.
#[tokio::test]
async fn reverse_two_deep_through_pure_forwarder() {
    let dir = tempfile::tempdir().unwrap();
    let (db, sha) = index_fixture(dir.path()).await;
    let text = callers_text(&db, "deep_target", &sha).await;
    assert!(text.contains("Handed over:"), "{text}");
    for name in ["OUT2", "MID2", "INNER2", "caller_deep"] {
        assert!(text.contains(name), "{text}");
    }
}

/// Reverse trees carry no forward legs: handover actuals are chain
/// links in the forward direction only. Listing them under Reverse
/// Chain would read as callers pointing the wrong way.
#[tokio::test]
async fn reverse_tree_carries_no_forward_legs() {
    let dir = tempfile::tempdir().unwrap();
    let (db, sha) = index_fixture(dir.path()).await;
    let text = chain_text(&db, "OUT2", &sha).await;
    let forward_at = text.find("Forward Chain").expect("forward section");
    assert!(!text[..forward_at].contains("deep_target"), "{text}");
    assert!(text[forward_at..].contains("deep_target"), "{text}");
}

/// Slot-exact reachability: RUN2 invokes slot 0 and ignores slot 1, so
/// only argument 0 keeps the claim. One proved slot's proof never
/// covers its sibling.
#[tokio::test]
async fn proved_slot_does_not_cover_sibling_slot() {
    let dir = tempfile::tempdir().unwrap();
    let (db, sha) = index_fixture(dir.path()).await;
    let text = callers_text(&db, "slot_target", &sha).await;
    assert!(text.contains("Handed over:"), "{text}");
    assert!(text.contains("RUN2() argument 0"), "{text}");
    // Exact section membership: argument 1 sits under the unreached
    // header, never under the reached claim.
    let unreached_at = text
        .find("Handed, not reached:")
        .expect("unreached section");
    assert!(text[unreached_at..].contains("RUN2() argument 1"), "{text}");
    let reached_at = text.find("Handed over:").expect("reached section");
    assert!(
        !text[reached_at..unreached_at].contains("RUN2() argument 1"),
        "{text}"
    );
}

/// A call discarded by the outer macro never executes: OUTD hands its
/// callback to DROP2, which drops the slot, so the callback is handed
/// but never invoked — no proved leg, even though the body names it.
#[tokio::test]
async fn discarded_nested_call_proves_no_invocation() {
    let dir = tempfile::tempdir().unwrap();
    let (db, sha) = index_fixture(dir.path()).await;
    let text = callers_text(&db, "discard_target", &sha).await;
    assert!(!text.contains("Handed over:"), "{text}");
    assert!(text.contains("Handed, not reached:"), "{text}");
    assert!(text.contains("OUTD() argument 0"), "{text}");
}

/// Nested macros compose in reverse: caller_loud → LOUD → LOG_MSG →
// EMIT_WRAP → emit_fn.
#[tokio::test]
async fn nested_macro_reverse_path() {
    let dir = tempfile::tempdir().unwrap();
    let (db, sha) = index_fixture(dir.path()).await;
    let text = callers_text(&db, "emit_fn", &sha).await;
    assert!(text.contains("LOUD"), "{text}");
    assert!(text.contains("caller_loud"), "{text}");
}

/// Reverse nesting through named hops: caller_report → RREPORT →
/// REPORT → emit_fn, every hop named in its body. Without nested via
/// nodes the recursive result's ordinary callers are dropped and the
/// terminal caller vanishes.
#[tokio::test]
async fn reverse_nested_nodes_keep_terminal_callers() {
    let dir = tempfile::tempdir().unwrap();
    let (db, sha) = index_fixture(dir.path()).await;
    let text = callers_text(&db, "emit_fn", &sha).await;
    let report = text.find("via REPORT (macros.h:17)").expect("outer hop");
    let after_report = &text[report..];
    let rreport = after_report.find("via RREPORT (macros.h:18)");
    assert!(rreport.is_some(), "nested hop missing: {text}");
    assert!(
        after_report[rreport.unwrap()..].contains("caller_report"),
        "{text}"
    );
}

/// Handed but never invoked: DROP takes emit_fn and calls nothing, so the
// site is listed without any reachability claim.
#[tokio::test]
async fn handed_but_never_called_stays_silent() {
    let dir = tempfile::tempdir().unwrap();
    let (db, sha) = index_fixture(dir.path()).await;
    let text = callers_text(&db, "emit_fn", &sha).await;
    assert!(text.contains("Handed, not reached:"), "{text}");
    assert!(text.contains("DROP() argument 0"), "{text}");
    assert!(
        !text.contains("a caller of that reaches it:\n  DROP"),
        "{text}"
    );
    // The proved handover keeps its claim in the same output: gating must
    // not drop everything.
    assert!(text.contains("Handed over:"), "{text}");
    assert!(text.contains("EMIT_WRAP() argument 0"), "{text}");
}

/// A self-named macro body is never an expansion: no self handover leg,
// and the reverse walk terminates.
#[tokio::test]
async fn self_named_macro_has_no_self_edge() {
    let dir = tempfile::tempdir().unwrap();
    let (db, sha) = index_fixture(dir.path()).await;
    let (legs, _, _) = semcode::callchain::forward_handover_display(&db, &sha, "SELF")
        .await
        .unwrap();
    assert!(legs.is_empty(), "{legs:?}");
    // Terminates rather than spins.
    let text = callers_text(&db, "SELF", &sha).await;
    assert!(!text.contains("via SELF (handed"), "{text}");
}

/// Guard union: both arms' callees resolve, each with its guard.
#[tokio::test]
async fn guarded_arms_contribute_their_union() {
    let dir = tempfile::tempdir().unwrap();
    let (db, sha) = index_fixture(dir.path()).await;
    let text = chain_text(&db, "caller_mode", &sha).await;
    assert!(text.contains("kind_fn"), "{text}");
    assert!(text.contains("other_fn"), "{text}");
    assert!(text.contains("KIND"), "{text}");
}

/// Cross-revision: the macro body changes, the caller does not, and the
// chain follows the new body — with file:line, not just names.
#[tokio::test]
async fn chain_follows_the_new_macro_body() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    write_fixture(repo);
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "v1"]);
    let old = git::get_git_sha(repo).unwrap().unwrap();

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
        &old,
        &["c".to_string(), "h".to_string()],
        db.clone(),
        false,
        1,
        &[],
    )
    .await
    .unwrap();

    // v2 hands a different function: same caller, new body.
    std::fs::write(
        repo.join("macros.h"),
        "#define EMIT_WRAP(_fn, x) _fn(x)\n\
         #define LOG_MSG(s) EMIT_WRAP(other_fn, s)\n\
         void emit_fn(const char *s);\n\
         void other_fn(int x);\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "v2"]);
    let new = git::get_git_sha(repo).unwrap().unwrap();
    semcode::git_range::process_git_tree(
        repo,
        &new,
        &["c".to_string(), "h".to_string()],
        db.clone(),
        false,
        1,
        &[],
    )
    .await
    .unwrap();

    let text = callers_text(&db, "other_fn", &new).await;
    assert!(text.contains("via EMIT_WRAP"), "{text}");
    assert!(text.contains("caller_one"), "{text}");
    assert!(text.contains("macros.h:1"), "{text}");
    // The old revision still resolves the old body.
    let old_text = callers_text(&db, "emit_fn", &old).await;
    assert!(old_text.contains("via EMIT_WRAP"), "{old_text}");
}

/// BUG-style admission: a generic caller reaches printk through the
// arch-less macro with its guard; an x86 caller resolves to the x86 macro
// and never appears.
#[tokio::test]
async fn arch_admission_keeps_generic_and_drops_x86() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::create_dir_all(repo.join("include/asm-generic")).unwrap();
    std::fs::create_dir_all(repo.join("arch/x86/include/asm")).unwrap();
    std::fs::create_dir_all(repo.join("arch/x86/kernel")).unwrap();
    std::fs::create_dir_all(repo.join("kernel")).unwrap();
    std::fs::write(
        repo.join("include/asm-generic/bug.h"),
        "#ifndef HAVE_ARCH_BUG\n#define BUG() printk_fn(\"bug\")\n#endif\nvoid printk_fn(const char *s);\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("arch/x86/include/asm/bug.h"),
        "#define BUG() do { x86_bug(); printk_fn(\"bug\"); } while (0)\nvoid x86_bug(void);\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("kernel/core.c"),
        "int generic_caller(void) { BUG(); return 0; }\nvoid printk_fn(const char *s) { (void)s; }\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("arch/x86/kernel/x.c"),
        "int x86_caller(void) { BUG(); return 0; }\nvoid x86_bug(void) {}\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let sha = git::get_git_sha(repo).unwrap().unwrap();
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
        &sha,
        &["c".to_string(), "h".to_string()],
        db.clone(),
        false,
        1,
        &[],
    )
    .await
    .unwrap();

    let text = callers_text(&db, "printk_fn", &sha).await;
    assert!(text.contains("generic_caller"), "{text}");
    assert!(text.contains("HAVE_ARCH_BUG"), "{text}");
    // Each build's callers stay under its own definition: the x86 group
    // holds only the x86 caller even though both bodies call printk_fn.
    // Without the arch-less-only rule the generic caller leaks into it.
    let x86_at = text
        .find("via BUG (arch/x86/include/asm/bug.h:")
        .expect("x86 node renders");
    let after = &text[x86_at..];
    let next_via = after["via BUG (arch".len()..]
        .find("via ")
        .map(|i| i + "via BUG (arch".len());
    let group = &after[..next_via.unwrap_or(after.len())];
    assert!(group.contains("x86_caller"), "{text}");
    assert!(!group.contains("generic_caller"), "{text}");
}

/// A dirty header re-derives the leg from the overlay: uncommitted body
// change, same committed revision.
#[tokio::test]
async fn dirty_header_rederives_the_handover_leg() {
    let dir = tempfile::tempdir().unwrap();
    let (db, sha) = index_fixture(dir.path()).await;
    // Uncommitted: EMIT_WRAP now invokes with other_fn.
    std::fs::write(
        dir.path().join("macros.h"),
        "#define EMIT_WRAP(_fn, x) _fn(x)\n\
         #define LOG_MSG(s) EMIT_WRAP(other_fn, s)\n\
         #define DROP(cb) 0\n\
         void emit_fn(const char *s);\n\
         void other_fn(int x);\n",
    )
    .unwrap();
    db.note_repl_command();
    let text = callers_text(&db, "other_fn", &sha).await;
    assert!(text.contains("via EMIT_WRAP"), "{text}");
}

/// Second-level helper: admitted callers carry the via chain; the x86
// caller never renders under an asm-generic hop.
#[tokio::test]
async fn second_level_edges_carry_admission() {
    let dir = tempfile::tempdir().unwrap();
    let (db, sha) = index_fixture(dir.path()).await;
    let (map, _) = semcode::callchain::macro_second_levels(
        &db,
        &sha,
        &["LOG_MSG".to_string()],
        semcode::domain::Context::Any,
    )
    .await
    .unwrap();
    let edges = map.get("LOG_MSG").expect("LOG_MSG level");
    assert!(
        edges.iter().any(|edge| edge.name == "caller_one"),
        "{edges:?}"
    );
    assert!(
        edges
            .iter()
            .all(|edge| edge.via_suffix().contains("via LOG_MSG")),
        "{edges:?}"
    );
}

/// File identity in cross-file scope: a live `RUN` at live.h:1 must not
/// validate a same-numbered dead `RUN` at dead.h:1 that was undefined
/// before its own end of file. Only live.h is included, so the dead
/// header's invoking definition lends no handover.
#[tokio::test]
async fn cross_file_scope_keeps_definition_identity() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(repo.join("live.h"), "#define RUN(cb) 0\n").unwrap();
    std::fs::write(repo.join("dead.h"), "#define RUN(cb) cb()\n#undef RUN\n").unwrap();
    std::fs::write(
        repo.join("user.c"),
        "#include \"live.h\"\nvoid t(void) { }\nint s(void) { RUN(t); return 0; }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let sha = git::get_git_sha(repo).unwrap().unwrap();
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
        &sha,
        &["c".to_string(), "h".to_string()],
        db.clone(),
        false,
        1,
        &[],
    )
    .await
    .unwrap();

    let text = callers_text(&db, "t", &sha).await;
    assert!(!text.contains("dead.h"), "{text}");
    assert!(!text.contains("Handed over:"), "{text}");
    assert!(text.contains("Handed, not reached:"), "{text}");
    assert!(text.contains("RUN() argument 0"), "{text}");
}

/// Variadic receipt without invocation: caller_var → LOG3 → EMIT3 →
/// emit3_fn. The trailing actual rides the `...` bundle, but emit3_fn
/// only receives it as a variadic argument and never calls it.
/// Evaluation is not invocation: the site lists as handed, never reached.
#[tokio::test]
async fn variadic_bundle_holds_trailing_actuals() {
    let dir = tempfile::tempdir().unwrap();
    let (db, sha) = index_fixture(dir.path()).await;
    let text = callers_text(&db, "var_target", &sha).await;
    assert!(!text.contains("Handed over:"), "{text}");
    assert!(text.contains("Handed, not reached:"), "{text}");
    assert!(text.contains("LOG3() argument 1"), "{text}");
}

/// The inner macro binds at the carried site: INNERU is `#undef`'d before
/// the call, so no forward leg passes through it — while the live twin
/// OUT binds each leg to its own call site.
#[tokio::test]
async fn inner_scope_binds_at_the_carried_site() {
    let dir = tempfile::tempdir().unwrap();
    let (db, sha) = index_fixture(dir.path()).await;
    let (dead, _, _) = semcode::callchain::forward_handover_display(&db, &sha, "OUTU")
        .await
        .unwrap();
    assert!(dead.is_empty(), "{dead:?}");
    let (live, _, _) = semcode::callchain::forward_handover_display(&db, &sha, "OUT")
        .await
        .unwrap();
    assert!(
        live.iter()
            .any(|(actual, file, ..)| actual == "nest_target" && file.ends_with("user.c")),
        "{live:?}"
    );
}

/// Retarget suppression: the workdir stops invoking through EMIT_WRAP, so
/// the committed leg must go silent — not linger beside the new text.
#[tokio::test]
async fn dirty_retarget_suppresses_the_old_leg() {
    let dir = tempfile::tempdir().unwrap();
    let (db, sha) = index_fixture(dir.path()).await;
    let before = callers_text(&db, "emit_fn", &sha).await;
    assert!(before.contains("via EMIT_WRAP"), "{before}");
    std::fs::write(
        dir.path().join("macros.h"),
        "#define EMIT_WRAP(_fn, x) 0\n\
         #define LOG_MSG(s) EMIT_WRAP(emit_fn, s)\n",
    )
    .unwrap();
    db.note_repl_command();
    let after = callers_text(&db, "emit_fn", &sha).await;
    assert!(!after.contains("via EMIT_WRAP"), "{after}");
}

/// Delete suppression: the workdir deletes EMIT_WRAP outright. The
/// committed row hands over nothing the new text never performs.
#[tokio::test]
async fn dirty_delete_suppresses_the_old_leg() {
    let dir = tempfile::tempdir().unwrap();
    let (db, sha) = index_fixture(dir.path()).await;
    let before = callers_text(&db, "emit_fn", &sha).await;
    assert!(before.contains("via EMIT_WRAP"), "{before}");
    std::fs::write(
        dir.path().join("macros.h"),
        "#define LOG_MSG(s) emit_fn(s)\n",
    )
    .unwrap();
    db.note_repl_command();
    let after = callers_text(&db, "emit_fn", &sha).await;
    assert!(!after.contains("EMIT_WRAP"), "{after}");
}

/// Cross-revision gating: after the delete commits, the old revision still
/// answers from its own text — the workdir overlay belongs to HEAD, not to
/// every sha ever queried.
#[tokio::test]
async fn overlay_does_not_bleed_across_revisions() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    write_fixture(repo);
    git_run(repo, &["init", "-q"]);
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "base"]);
    let sha_a = git::get_git_sha(repo).unwrap().unwrap();
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
        &sha_a,
        &["c".to_string(), "h".to_string()],
        db.clone(),
        false,
        1,
        &[],
    )
    .await
    .unwrap();
    std::fs::write(repo.join("macros.h"), "#define LOG_MSG(s) emit_fn(s)\n").unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "delete"]);
    let sha_b = git::get_git_sha(repo).unwrap().unwrap();
    semcode::git_range::process_git_tree(
        repo,
        &sha_b,
        &["c".to_string(), "h".to_string()],
        db.clone(),
        false,
        1,
        &[],
    )
    .await
    .unwrap();
    let at_a = callers_text(&db, "emit_fn", &sha_a).await;
    assert!(at_a.contains("via EMIT_WRAP"), "{at_a}");
    let at_b = callers_text(&db, "emit_fn", &sha_b).await;
    assert!(!at_b.contains("EMIT_WRAP"), "{at_b}");
}

/// Named-edge drop: `DN(NM())` with `DN(x) 0` never expands its argument,
/// so the caller handing through it reaches nothing — while the same call
/// through an evaluating wrapper still binds.
#[tokio::test]
async fn named_call_in_dropped_slot_reaches_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(repo.join("m.h"), "#define NM() target()\n#define DN(x) 0\n").unwrap();
    std::fs::write(
        repo.join("u.c"),
        "#include \"m.h\"\nvoid target(void) { }\nint snamed(void) { DN(NM()); return 0; }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let text = callers_text(&db, "target", &sha).await;
    assert!(text.contains("NM"), "{text}");
    assert!(!text.contains("snamed"), "{text}");
}

/// Same-line twins with a dropped twin: `RUN(t, live)` hands both, but the
/// inner `RUN(live, t)` sits in `DROP`'s discarded slot, so only `live`
/// (through the outer call) is reached. Slot-exact matching keeps each
/// twin's site on its own call.
#[tokio::test]
async fn same_line_twins_keep_their_own_slots() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("m.h"),
        "#define RUN(a, b) b()\n#define DROP(x) 0\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("u.c"),
        "#include \"m.h\"\nvoid live(void) { }\nvoid t(void) { }\nint s(void) { RUN(t, live); DROP(RUN(live, t)); return 0; }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let live = callers_text(&db, "live", &sha).await;
    assert!(live.contains("via RUN"), "{live}");
    let text = callers_text(&db, "t", &sha).await;
    assert!(!text.contains("Via Macros"), "{text}");
}

/// Intermediate drop: `WRAP(v)` nests its `INNER(v)` call inside `MID2`,
/// which the site redefines to discard its slot. The body proof still
/// sees a live chain where the wrapper is defined, but the forward leg
/// must not emit — the intermediate call never expands at the site.
#[tokio::test]
async fn nested_call_in_dropped_slot_emits_no_forward_leg() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("m.h"),
        "#define INNER(x) x()\n#define MID2(y) y()\n#define WRAP(v) MID2(INNER(v))\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("u.c"),
        "#define MID2(y) 0\nvoid target(void) { }\nvoid s(void) { WRAP(target); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let snapshot = semcode::snapshot_for(&db, &sha).await.unwrap();
    let rows = semcode::macro_rows_for(&db, &snapshot, "WRAP")
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let mut budget = semcode::ViaBudget::default();
    let mut visited = std::collections::HashSet::new();
    let subst = std::collections::HashMap::new();
    let closure = semcode::forward_closure(
        &db,
        &snapshot,
        &rows[0],
        semcode::domain::Context::Any,
        &mut budget,
        &mut visited,
        &subst,
    )
    .await
    .unwrap();
    assert!(
        !closure.legs.iter().any(|leg| leg.actual == "target"),
        "{:?}",
        closure
            .legs
            .iter()
            .map(|leg| (&leg.actual, &leg.macro_name))
            .collect::<Vec<_>>()
    );
}

/// Attribute macros on the declarator (`__init`, `asmlinkage`) error only
/// their own tree-sitter node while the body parses clean: a caller
/// written that way still reaches through the macro it calls. The
/// whole-tree error gate dropped every such caller from the gate.
#[tokio::test]
async fn attribute_macro_caller_keeps_its_via_leg() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(repo.join("m.h"), "#define EMIT(x) x()\n").unwrap();
    std::fs::write(
        repo.join("u.c"),
        "#include \"m.h\"\nvoid target(void) { }\nstatic int __init attr_setup(char *str) { (void)str; EMIT(target); return 0; }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let text = callers_text(&db, "target", &sha).await;
    assert!(text.contains("attr_setup"), "{text}");
    assert!(text.contains("via EMIT"), "{text}");
}

/// A twelve-deep pure-forwarder chain still reaches the target through
/// every hop, and answers on a linear curve: summaries cache every
/// complete proof, so each depth adds one fixpoint instead of re-proving
/// the whole chain below it. Timings print per depth; the assertion pins
/// the path, not the clock.
#[tokio::test]
async fn deep_forwarder_chain_reaches_through_every_hop() {
    for depth in [6usize, 8, 10, 12] {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        git_run(repo, &["init", "-q"]);
        let mut header = String::new();
        for i in 1..=depth {
            if i < depth {
                header.push_str(&format!("#define M{i}(cb) M{}(cb)\n", i + 1));
            } else {
                header.push_str(&format!("#define M{i}(cb) cb()\n"));
            }
        }
        std::fs::write(repo.join("m.h"), &header).unwrap();
        std::fs::write(
            repo.join("u.c"),
            "#include \"m.h\"\nvoid target(void) { }\nint s(void) { M1(target); return 0; }\n",
        )
        .unwrap();
        git_run(repo, &["add", "."]);
        git_run(repo, &["commit", "-q", "-m", "fixture"]);
        let (db, sha) = index_repo(repo).await;
        let t0 = std::time::Instant::now();
        let text = callers_text(&db, "target", &sha).await;
        eprintln!("chain depth {depth}: callers took {:?}", t0.elapsed());
        assert!(text.contains("via M1"), "{text}");
        assert!(text.contains('s'), "{text}");
    }
}

/// A query pinned to an old revision never sees workdir state warmed by
/// a query at HEAD: the overlay belongs to the checked-out revision, so
/// the second answer must name the old caller, not the dirty one.
#[tokio::test]
async fn pinned_revision_ignores_warmed_workdir_overlay() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("u.c"),
        "void target(void) { }\n#define APPLY(cb) cb()\nint old_user(void) { return APPLY(target); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "A"]);
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
    let first = callers_text(&db, "target", &git_sha).await;
    assert!(first.contains("old_user"), "{first}");
    // A second commit, then an uncommitted rename: HEAD answers ghost,
    // the pinned answer must stay old_user in this same process.
    std::fs::write(repo.join("note.txt"), "second commit\n").unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "B"]);
    let git_sha = git::get_git_sha(repo).unwrap().unwrap();
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
    std::fs::write(
        repo.join("u.c"),
        "void target(void) { }\n#define APPLY(cb) cb()\nint ghost_dirty(void) { return APPLY(target); }\n",
    )
    .unwrap();
    db.note_repl_command();
    // Warms the workdir index inside this same process, like an MCP
    // session serving consecutive requests.
    let head = callers_text(&db, "target", &git_sha).await;
    assert!(head.contains("ghost_dirty"), "{head}");
    let pinned = callers_text(&db, "target", &first_sha(&git_sha, repo)).await;
    assert!(pinned.contains("old_user"), "{pinned}");
    assert!(!pinned.contains("ghost_dirty"), "{pinned}");
}

fn first_sha(_head: &str, repo: &std::path::Path) -> String {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD~1"])
        .current_dir(repo)
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// A forward closure lists its own root's handovers only: `INNER` is
/// called from both `A` and `B`, but `A`'s closure must not carry `beta`
/// (handed at `B`'s site), nor `B`'s `alpha`. Three levels pin the
/// middle row's outer sites, where unscoped re-grounding would leak
/// nested-only legs from other macros into each root's display.
#[tokio::test]
async fn forward_closure_stays_within_its_own_sites() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "#define DEEP(x) x()\n#define INNER(f) DEEP(f)\n#define A(f) INNER(f)\n#define B(f) INNER(f)\nint alpha(void) { return 1; }\nint beta(void) { return 2; }\nint a(void) { return A(alpha); }\nint b(void) { return B(beta); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let snapshot = semcode::snapshot_for(&db, &sha).await.unwrap();
    for (root, own, foreign) in [("A", "alpha", "beta"), ("B", "beta", "alpha")] {
        let rows = semcode::macro_rows_for(&db, &snapshot, root).await.unwrap();
        assert_eq!(rows.len(), 1);
        let mut budget = semcode::ViaBudget::default();
        let mut visited = std::collections::HashSet::new();
        let subst = std::collections::HashMap::new();
        let closure = semcode::forward_closure(
            &db,
            &snapshot,
            &rows[0],
            semcode::domain::Context::Any,
            &mut budget,
            &mut visited,
            &subst,
        )
        .await
        .unwrap();
        let actuals: Vec<&str> = closure.legs.iter().map(|leg| leg.actual.as_str()).collect();
        assert!(actuals.contains(&own), "{root}: {actuals:?}");
        assert!(!actuals.contains(&foreign), "{root}: {actuals:?}");
    }
}

/// A forward display lists the root's own handovers only: `M(INNER)`
/// hands the macro `INNER` at its site, but `INNER(alpha)` at another
/// site never flows through `M` — its chain bypasses `M` entirely.
/// Appending the inner macro's whole closure would leak nested-only
/// legs from other macros into the root's display.
#[tokio::test]
async fn forward_display_drops_other_macros_nested_legs() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "#define INNER(x) x()\n#define M(f) f()\nint alpha(void) { return 1; }\nint s1(void) { return INNER(alpha); }\nint s2(void) { return M(INNER); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let (legs, total, trunc) = semcode::callchain::forward_handover_display(&db, &sha, "M")
        .await
        .unwrap();
    assert_eq!(total, 1, "{legs:?}");
    assert!(!trunc, "{legs:?}");
    assert!(
        legs.iter()
            .any(|(actual, file, line, _, _)| { actual == "INNER" && file == "a.c" && *line == 5 }),
        "{legs:?}"
    );
    assert!(
        !legs.iter().any(|(actual, _, _, _, _)| actual == "alpha"),
        "{legs:?}"
    );
}

/// A cyclic forwarder chain (`A` through `B` back to `A`, both called
/// from real code) cuts its regress at the back-edge: the closure must
/// say so instead of reading complete with no marker.
#[tokio::test]
async fn forward_cycle_marks_truncation() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "#define A(f) B(f)\n#define B(g) A(g)\nint alpha(void) { return 1; }\nint beta(void) { return 2; }\nint s1(void) { return A(alpha); }\nint s2(void) { return B(beta); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let snapshot = semcode::snapshot_for(&db, &sha).await.unwrap();
    let rows = semcode::macro_rows_for(&db, &snapshot, "A").await.unwrap();
    assert_eq!(rows.len(), 1);
    let mut budget = semcode::ViaBudget::default();
    let mut visited = std::collections::HashSet::new();
    let subst = std::collections::HashMap::new();
    let closure = semcode::forward_closure(
        &db,
        &snapshot,
        &rows[0],
        semcode::domain::Context::Any,
        &mut budget,
        &mut visited,
        &subst,
    )
    .await
    .unwrap();
    assert!(
        closure.truncated,
        "legs: {:?}",
        closure
            .legs
            .iter()
            .map(|leg| &leg.actual)
            .collect::<Vec<_>>()
    );
}

/// An object alias to a dropping macro is not an ordinary function: the
/// twin must follow the alias and drop the slot, not report the callback
/// as evaluated. (R6-1.)
#[tokio::test]
async fn twin_follows_object_alias_to_drop() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "#define DROP(x) 0\n#define ALIAS DROP\n#define I(x) 0\n#define O(x) I(x)\n#define RUN(f) f()\nint target(void) { return 1; }\n#undef I\n#define I(x) ALIAS((x))\nint ghost(void) { return O(RUN(target)); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let text = callers_text(&db, "target", &sha).await;
    assert!(!text.contains("via RUN"), "{text}");
    assert!(text.contains("not reached"), "{text}");
}

/// A forward hop through an alias must re-resolve at the carried site: an
/// `#undef` there ends the hop even though the final row is still live.
/// (R6-2.)
#[tokio::test]
async fn forward_alias_rebound_at_site_drops_leg() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "int tgt(void) { return 1; }\nint noop(int (*f)(void)) { return f != 0; }\nint (*ALIAS)(int (*f)(void)) = noop;\n#define RUN(f) f()\n#define ALIAS RUN\n#define OUT(f) ALIAS(f)\n#undef ALIAS\nint caller(void) { return OUT(tgt); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let (legs, _, _) = semcode::callchain::forward_handover_display(&db, &sha, "OUT")
        .await
        .unwrap();
    assert!(
        !legs.iter().any(|(actual, _, _, _, _)| actual == "tgt"),
        "{legs:?}"
    );
}

/// A terminator in a definitely-taken arm fires unconditionally: `#undef`
/// under `%:if 1` ends the definition whatever its spelling. (R6-3.)
#[tokio::test]
async fn taken_arm_undef_ends_interval() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "static void digraph_leaf(void) {}\nstatic void DIGRAPH_RUN(void (*cb)(void)) { (void)cb; }\n#define DIGRAPH_RUN(cb) cb()\n%:if 1\n#undef DIGRAPH_RUN\n%:endif\nvoid digraph_caller(void) { DIGRAPH_RUN(digraph_leaf); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let text = callers_text(&db, "digraph_leaf", &sha).await;
    assert!(!text.contains("via DIGRAPH_RUN"), "{text}");
}

/// `#undef X` with no live `#define` proves `defined(X)` false below it:
/// an `#elifdef` arm under an explicitly undefined flag never runs.
/// (R6-4.)
#[tokio::test]
async fn elifdef_after_undef_stays_dead() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "void elif_leaf(void) {}\n#define ELIF_RUN(cb) cb()\n#undef R6_FLAG\nvoid elif_caller(void) {\n#if 0\n#elifdef R6_FLAG\n    ELIF_RUN(elif_leaf);\n#endif\n}\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let text = callers_text(&db, "elif_leaf", &sha).await;
    assert!(!text.contains("via ELIF_RUN"), "{text}");
}

/// `& target` hands exactly what `&target` hands: the single-token proof
/// strips one prefix layer at a time, and a multi-token actual never
/// equals the bare parameter. (R6-6.)
#[tokio::test]
async fn spaced_address_actual_still_drops() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "#define INV(cb) cb()\n#define DROP(x) 0\nint target(void) { return 1; }\nint drop_space(void) { return DROP(INV(& target)); }\nint keep_bare(void) { return INV(target); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let text = callers_text(&db, "target", &sha).await;
    assert!(text.contains("drop_space"), "{text}");
    assert!(!text.contains("via INV (a.c:1) at a.c:4"), "{text}");
    assert!(text.contains("via INV (a.c:1) at a.c:5"), "{text}");
}

/// A rebound intermediate ends the forward hop: `MID` → 0 at the site
/// means the recursion into the old row proves nothing. (R6-8.)
#[tokio::test]
async fn forward_rebound_intermediate_drops_leg() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "int tgt(void) { return 1; }\n#define RUN(f) f()\n#define MID(f) RUN(f)\n#define OUT(f) MID(f)\n#undef MID\n#define MID(f) 0\nint caller(void) { return OUT(tgt); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let (legs, _, _) = semcode::callchain::forward_handover_display(&db, &sha, "OUT")
        .await
        .unwrap();
    assert!(
        !legs.iter().any(|(actual, _, _, _, _)| actual == "tgt"),
        "{legs:?}"
    );
}

/// A two-hop alias rebound suppresses the dropped argument: after the
/// rebind the live chain ends at the dropping macro. (R6-10.)
#[tokio::test]
async fn two_hop_alias_rebound_drops_leg() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "static int ac_leaf(void) { return 1; }\n#define AC_INVOKE(f) f()\n#define AC_PASS(x) (x)\n#define AC_DROP(x) 0\n#define AC_ALIAS AC_PASS\n#define AC_HOP AC_ALIAS\nint ac_before(void) { return AC_HOP(AC_INVOKE(ac_leaf)); }\n#undef AC_ALIAS\n#define AC_ALIAS AC_DROP\nint ac_after(void) { return AC_HOP(AC_INVOKE(ac_leaf)); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let text = callers_text(&db, "ac_leaf", &sha).await;
    assert!(text.contains("via AC_INVOKE (a.c:2) at a.c:7"), "{text}");
    assert!(!text.contains("via AC_INVOKE (a.c:2) at a.c:10"), "{text}");
}

/// A commented parenthesized zero is still zero, and `_1` is still an
/// identifier: separators never quote, and literals start with a digit.
/// (R6-11.)
#[tokio::test]
async fn commented_separator_zero_stays_dead() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "void separator_leaf(void) {}\n#define SEPARATOR_RUN(cb) cb()\nvoid separator_caller(void) {\n#if (0'0) /* zero */\n    SEPARATOR_RUN(separator_leaf);\n#endif\n}\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let text = callers_text(&db, "separator_leaf", &sha).await;
    assert!(!text.contains("via SEPARATOR_RUN"), "{text}");
}

/// `#define _1 0` then `#if _1`: the arm is symbolic, so the live `#else`
/// leg must survive. (R6-11, identifier half.)
#[tokio::test]
async fn underscore_identifier_keeps_else_leg() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "void u_leaf(void) {}\n#define U_RUN(cb) cb()\n#define _1 0\nvoid u_caller(void) {\n#if _1\n    U_RUN(u_leaf);\n#else\n    u_leaf();\n#endif\n}\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let text = callers_text(&db, "u_leaf", &sha).await;
    assert!(text.contains("u_caller"), "{text}");
}

/// Same-line twins binding different actuals leave no single proof: the
/// sibling's evaluation must not discharge this site's. (S1.)
#[tokio::test]
async fn twin_sibling_binding_does_not_discharge() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "#define DROP(x) 0\n#define CALLW(w, cb) w(cb())\nint tgt(void) { return 1; }\nint other(void) { return 2; }\nint ordinary(int v) { return v; }\nint f1(void) { return CALLW(DROP, tgt); }\nint f(void) { return CALLW(DROP, tgt) + CALLW(ordinary, other); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let text = callers_text(&db, "tgt", &sha).await;
    assert!(!text.contains("via CALLW"), "{text}");
}

/// A binding site written inside a macro body still binds: the proof
/// scans covering macro bodies, not just raw file text. (S2.)
#[tokio::test]
async fn binding_site_inside_macro_body_binds() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "#define DROP(x) 0\n#define CALLW(w, cb) w(cb())\n#define USEW() CALLW(DROP, tgt)\nint tgt(void) { return 1; }\nint m(void) { return USEW(); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let text = callers_text(&db, "tgt", &sha).await;
    assert!(!text.contains("via CALLW"), "{text}");
}

/// A call by name inside a macro body runs the dropping-wrapper check:
/// `OUTERM` expanding `DROP(CALLT())` never reaches through `CALLT`.
/// (M1.)
#[tokio::test]
async fn named_call_in_macro_body_drops() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "#define CALLT() tgt()\n#define DROP(x) 0\n#define OUTERM() DROP(CALLT())\nint tgt(void) { return 1; }\nint n1(void) { return DROP(CALLT()); }\nint n5(void) { return OUTERM(); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let text = callers_text(&db, "tgt", &sha).await;
    assert!(!text.contains("n5"), "{text}");
    assert!(!text.contains("via OUTERM"), "{text}");
}

/// Multi-line wrappers keep their keepers: the dropping-wrapper check runs
/// on every physical line the definition covers, and a line holding both a
/// dropped and a live call keeps the caller through the live one. (M1,
/// multi-line half.)
#[tokio::test]
async fn named_call_in_macro_body_multiline() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "#define CALLT() tgt()\n#define DROP(x) 0\nint ordinary(int v) { return v; }\n#define OUTERML() \\\n\tDROP(CALLT())\n#define OUTERKL() \\\n\tordinary(CALLT())\n#define OUTERMIX() DROP(CALLT()) + CALLT()\n#define OUTERDODROP() do { \\\n\t(void)DROP(CALLT()); \\\n} while (0)\nint tgt(void) { return 1; }\nint n6(void) { return OUTERML(); }\nint k3(void) { return OUTERKL(); }\nint k6(void) { return OUTERMIX(); }\nvoid n7(void) { OUTERDODROP(); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let text = callers_text(&db, "tgt", &sha).await;
    assert!(!text.contains("n6"), "{text}");
    assert!(!text.contains("via OUTERML"), "{text}");
    assert!(!text.contains("n7"), "{text}");
    assert!(!text.contains("via OUTERDODROP"), "{text}");
    assert!(text.contains("k3"), "{text}");
    assert!(text.contains("via OUTERKL"), "{text}");
    assert!(text.contains("k6"), "{text}");
    assert!(text.contains("via OUTERMIX"), "{text}");
}

/// A binding site on a continuation line still binds: the covering-define
/// scan spans the whole definition, and the keeper beside the dropper
/// still proves. (S2, multi-line half.)
#[tokio::test]
async fn binding_site_inside_macro_body_multiline() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "#define DROP(x) 0\n#define CALLW(w, cb) w(cb())\n#define USEW() \\\n\tCALLW(DROP, tgt)\n#define USEWK() \\\n\tCALLW(ordinary, tgt2)\nint tgt(void) { return 1; }\nint tgt2(void) { return 1; }\nint ordinary(int v) { return v; }\nint m(void) { return USEW(); }\nint mk(void) { return USEWK(); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let dropped = callers_text(&db, "tgt", &sha).await;
    assert!(!dropped.contains("via CALLW"), "{dropped}");
    let kept = callers_text(&db, "tgt2", &sha).await;
    assert!(kept.contains("mk"), "{kept}");
    assert!(kept.contains("via CALLW"), "{kept}");
}

/// Kernel-shaped wrappers survive paste and adjacent tokens: a GNU
/// statement-expression body with `##__VA_ARGS__` and an unexpanded
/// `KERN_ERR`-style prefix still routes the call, guarded arms included.
#[tokio::test]
async fn kernel_shaped_wrapper_routes_through_paste() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "void printk(const char *fmt, ...);\nint ready(void) { return 1; }\n#ifdef CONFIG_X\n#define RLIM(fmt, ...) \\\n\t({ \\\n\t\tif (ready()) \\\n\t\t\tprintk(fmt, ##__VA_ARGS__); \\\n\t})\n#else\n#define RLIM(fmt, ...) ready()\n#endif\n#define WRAP(fmt, ...) RLIM(fmt, ##__VA_ARGS__)\nvoid rl_user(void) { WRAP(\"x\"); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let text = callers_text(&db, "printk", &sha).await;
    assert!(text.contains("rl_user"), "{text}");
    assert!(text.contains("via RLIM"), "{text}");
    assert!(text.contains("via WRAP"), "{text}");
}

/// A rebound intermediate ends the forward tree: `INV` is `0` at `m`'s
/// site, so `m`'s chain stops at `USEIT` and never names `tgt`. (R6-5,
/// forward half.)
#[tokio::test]
async fn forward_rebound_body_ends_tree() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "#define INV(cb) cb()\n#define USEIT() INV(tgt)\n#undef INV\n#define INV(cb) 0\nint tgt(void) { return 1; }\nvoid m(void) { USEIT(); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let text = chain_text(&db, "m", &sha).await;
    assert!(text.contains("USEIT"), "{text}");
    assert!(!text.contains("tgt"), "{text}");
}

/// A parameter callee binds through the outer actuals: `OUT_BAD` threads
/// `DROP`, which never runs its slot, so the nested site hands nothing;
/// `OUT_GOOD` threads an ordinary function, so its site still proves.
/// (R6-7.)
#[tokio::test]
async fn nested_param_callee_binds_outer_actuals() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "#define DROP(x) 0\n#define CALLW(w, cb) w(cb())\n#define OUT_BAD(cb) CALLW(DROP, cb)\n#define OUT_GOOD(cb) CALLW(ordinary, cb)\nint killed(void) { return 1; }\nint kept(void) { return 2; }\nint ordinary(int v) { return v; }\nint drop_nested(void) { return OUT_BAD(killed); }\nint keep_nested(void) { return OUT_GOOD(kept); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let dropped = callers_text(&db, "killed", &sha).await;
    assert!(
        !dropped.contains("drop_nested") || dropped.contains("not reached"),
        "{dropped}"
    );
    assert!(!dropped.contains("via CALLW"), "{dropped}");
    assert!(!dropped.contains("via OUT_BAD"), "{dropped}");
    let kept = callers_text(&db, "kept", &sha).await;
    assert!(kept.contains("keep_nested"), "{kept}");
    assert!(kept.contains("via CALLW"), "{kept}");
}

/// An `#undef` under a provably-taken arm fires: `#undef FLAG` makes the
/// `#ifndef FLAG` arm certain, so its `#undef RUN` ends the interval and
/// the caller below never reaches through `RUN`.
#[tokio::test]
async fn scoped_true_undef_ends_interval() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "int target(void) { return 1; }\n#define RUN(f) f()\n#undef FLAG\n#ifndef FLAG\n#undef RUN\n#endif\nint caller(void) { return RUN(target); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let text = callers_text(&db, "target", &sha).await;
    assert!(!text.contains("via RUN"), "{text}");
}

/// KNOWN LIMITATION: a fork that kills on both tines still lists. The
/// two `#undef RUN`s fire under complementary conditions (`BRANCH` vs the
/// `FLAG` it clears), so `RUN` is dead in every build — but each
/// terminator is uncertain alone, and the overlap engine does not do the
/// disjunction. Pinned so the gap stays visible until it does.
#[tokio::test]
async fn scoped_fork_undef_known_limitation() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "int target(void) { return 1; }\n#define RUN(f) f()\n#define FLAG 1\n#if BRANCH\n#undef RUN\n#undef FLAG\n#endif\n#ifdef FLAG\n#undef RUN\n#endif\nint caller(void) { return RUN(target); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let text = callers_text(&db, "target", &sha).await;
    assert!(text.contains("via RUN"), "{text}");
}

/// An `#undef` under an unknown condition proves nothing: the guarded
/// caller may still compile with the flag defined, so the leg stands.
#[tokio::test]
async fn scoped_silence_symbolic_undef_keeps_leg() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "void target(void) {}\n#define RUN(f) f()\n#define FLAG 1\n#if BRANCH\n#undef FLAG\n#endif\n#ifdef FLAG\nvoid caller(void) { RUN(target); }\n#endif\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let text = callers_text(&db, "target", &sha).await;
    assert!(text.contains("caller"), "{text}");
    assert!(text.contains("via RUN"), "{text}");
}

/// A parenthesized alias never invokes the macro: `(A)(x)` calls the
/// function `A`, so a dropping macro `A` beside it ends nothing and the
/// leg through the alias stands.
#[tokio::test]
async fn parenthesized_alias_never_invokes_macro() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "static int ap_leaf(void) { return 1; }\nstatic int (AP_DROP)(int x) { return x; }\n#define AP_DROP(x) 0\n#define AP_ALIAS (AP_DROP)\n#define AP_CALL() ap_leaf()\nint ap_caller(void) { return AP_ALIAS(AP_CALL()); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let text = callers_text(&db, "ap_leaf", &sha).await;
    assert!(text.contains("ap_caller"), "{text}");
}

/// Same-line twins binding different ordinary functions still prove: a
/// function call evaluates every argument, so either twin discharges the
/// slot. A dropping twin still silences (`DROP` may end the slot, and the
/// site cannot attribute).
#[tokio::test]
async fn twin_ordinary_disagreement_still_evaluates() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "#define DROP(x) 0\n#define CALLW(w, cb) w(cb())\nint a(void) { return 1; }\nint b(void) { return 2; }\nint c(void) { return 3; }\nint d(void) { return 4; }\nint e(void) { return 5; }\nint ordinary(int v) { return v; }\nint ordinary2(int v) { return v; }\nint t1(void) { return CALLW(ordinary, a) + CALLW(ordinary, b); }\nint t2(void) { return CALLW(ordinary, c) + CALLW(ordinary2, d); }\nint t3(void) { return CALLW(DROP, e) + CALLW(DROP, e); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    for leaf in ["a", "b", "c", "d"] {
        let text = callers_text(&db, leaf, &sha).await;
        assert!(text.contains("via CALLW"), "{leaf}: {text}");
    }
    let dropped = callers_text(&db, "e", &sha).await;
    assert!(!dropped.contains("via CALLW"), "{dropped}");
}

/// A bundle's head fills fixed slots first: `W(tgt, 1, other)` spreads
/// `__VA_ARGS__` over `SEL`'s `a` and `b`, so `b()` invokes `other` while
/// `tgt` never runs.
#[tokio::test]
async fn pack_head_fills_fixed_slots_first() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("a.c"),
        "int tgt(void) { return 1; }\nint other(void) { return 2; }\n#define SEL(a, b, ...) b()\n#define W(f, ...) SEL(__VA_ARGS__, f, other)\nint caller(void) { return W(tgt, 1, other); }\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    let (db, sha) = index_repo(repo).await;
    let reached = callers_text(&db, "other", &sha).await;
    assert!(reached.contains("caller"), "{reached}");
    assert!(reached.contains("via SEL"), "{reached}");
    let dropped = callers_text(&db, "tgt", &sha).await;
    assert!(!dropped.contains("via W"), "{dropped}");
    assert!(!dropped.contains("via SEL"), "{dropped}");
}
