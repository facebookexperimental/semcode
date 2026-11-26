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
        &["rs".to_string()],
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

async fn calls_text(db: &DatabaseManager, name: &str, sha: &str) -> String {
    let mut out = Vec::new();
    semcode::callchain::show_callees_to_writer(db, name, &mut out, false, sha)
        .await
        .unwrap();
    plain(&String::from_utf8(out).unwrap())
}

const LIB_RS: &str = r#"
pub trait Alloc { fn alloc() -> u32; }
pub struct Bump;
impl Alloc for Bump { fn alloc() -> u32 { 1 } }
pub struct Other;
impl Other { pub fn alloc() -> u32 { 2 } }
pub fn use_it<T: Alloc>() -> u32 { T::alloc() }
pub fn opaque<U>() -> u32 { U::alloc() }
pub struct Holder<T: Alloc> { pub x: T }
impl<T: Alloc> Holder<T> { pub fn go(&self) -> u32 { T::alloc() } }
pub struct Buf;
impl Buf { pub fn cast<T>(&self) -> u32 { 0 } }
pub fn use_cast(b: &Buf) -> u32 { b.cast::<u32>() }
pub trait Greet { fn target(&self) -> u32 { 0 } }
pub struct O;
impl Greet for O { fn target(&self) -> u32 { 1 } }
pub fn use_greet<T: Greet>() -> u32 { T::target() }
"#;

fn write_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(repo.join("lib.rs"), LIB_RS).unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);
    dir
}

/// A bounded head resolves to the bound's implementations: `use_it`
/// reaches `Bump::alloc` through the `Alloc` slot, while the unbounded
/// `opaque` and the inherent `Other::alloc` stay out on both sides.
#[tokio::test]
async fn bounded_head_resolves_override() {
    let dir = write_repo();
    let (db, sha) = index_repo(dir.path()).await;
    let text = callers_text(&db, "alloc", &sha).await;
    assert!(text.contains("use_it"), "{text}");
    assert!(text.contains("Alloc"), "{text}");
    assert!(text.contains("bound match"), "{text}");
    assert!(!text.contains("opaque"), "{text}");
}

/// An impl-level bound counts: `Holder::go` reads `T` from the `impl`
/// header, not from a function parameter.
#[tokio::test]
async fn impl_level_bound_counts() {
    let dir = write_repo();
    let (db, sha) = index_repo(dir.path()).await;
    let text = callers_text(&db, "alloc", &sha).await;
    assert!(text.contains("go"), "{text}");
}

/// A turbofish method dispatches through its receiver: the head
/// renames to the declared type (`Buf::cast`), which the owner match
/// resolves. Bare `cast` never matched qualified heads, before or
/// after — that engine semantic is out of scope.
#[tokio::test]
async fn turbofish_method_dispatches_through_receiver() {
    let dir = write_repo();
    let (db, sha) = index_repo(dir.path()).await;
    let text = callers_text(&db, "Buf::cast", &sha).await;
    assert!(text.contains("use_cast"), "{text}");
    let text = calls_text(&db, "use_cast", &sha).await;
    assert!(text.contains("Buf::cast"), "{text}");
    assert!(!text.contains("b.cast"), "{text}");
}

/// The kept plain edge never double-answers: `T::alloc` lists once in
/// the caller's heads even with the bound site beside it.
#[tokio::test]
async fn kept_edge_lists_once() {
    let dir = write_repo();
    let (db, sha) = index_repo(dir.path()).await;
    let text = calls_text(&db, "use_it", &sha).await;
    assert_eq!(text.matches("T::alloc").count(), 1, "{text}");
}

/// The override resolves strongly through the bound: `use_greet`
/// reaches `O::target` with a bound-match leg.
#[tokio::test]
async fn override_resolves_through_bound() {
    let dir = write_repo();
    let (db, sha) = index_repo(dir.path()).await;
    let text = callers_text(&db, "target", &sha).await;
    assert!(text.contains("use_greet"), "{text}");
    assert!(text.contains("bound match"), "{text}");
}

/// The trait default installs nowhere: the `Greet::target` slot holds
/// only the override row. A caveat, not a miss.
#[tokio::test]
async fn default_installs_nowhere() {
    let dir = write_repo();
    let (db, sha) = index_repo(dir.path()).await;
    let found = db
        .find_registrations_for_slot_git_aware("Greet", "target", &sha)
        .await
        .unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].target.ends_with("O::target"), "{found:?}");
}
