// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Index C++ through the C++ grammar (.h stays on C) and check the
// definitions and calls a codebase writes are findable.
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use semcode::{file_survey, git, DatabaseManager};

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

/// Functions and classes the tests look up.
fn write_fixture(repo: &Path) {
    std::fs::write(
        repo.join("a.cpp"),
        "class A {\n\
         public:\n\
         \tvoid f();\n\
         \tint g() const noexcept { return v; }\n\
         \tA();\n\
         \t~A();\n\
         private:\n\
         \tint v = 0;\n\
         };\n\
         \n\
         void A::f() { begin(); }\n\
         A::A() : v(0) { init(); }\n\
         A::~A() { shutdown(); }\n\
         \n\
         class Node;\n\
         Node *make_node() { return 0; }\n\
         \n\
         void run_all(A &e) { prepare(); e.f(); }\n\
         \n\
         template<typename T>\n\
         T pick(T a, T b) { return a > b ? a : b; }\n\
         \n\
         int use_lambda(int x)\n\
         {\n\
         \tauto twice = [](int v) { return v + v; };\n\
         \treturn twice(x);\n\
         }\n",
    )
    .unwrap();

    std::fs::write(
        repo.join("b.cpp"),
        "class B {\n\
         public:\n\
         \tvoid f();\n\
         };\n\
         \n\
         void B::f() { f(); }\n",
    )
    .unwrap();
}

/// Special members and template methods the tests look up.
fn write_shapes(repo: &Path) {
    std::fs::write(
        repo.join("shapes.cpp"),
        "class E {\n\
         public:\n\
         \t~E() { cleanup(); }\n\
         \tE &operator=(const E &o) { return *this; }\n\
         \tbool operator==(const E &o) const { return true; }\n\
         };\n\
         \n\
         class D {\n\
         public:\n\
         \tD *clone() { return 0; }\n\
         };\n\
         \n\
         template<typename T>\n\
         struct Box {\n\
         \tT get();\n\
         };\n\
         \n\
         template<typename T>\n\
         T Box<T>::get() { return T(); }\n\
         \n\
         namespace ns {\n\
         void helper() {}\n\
         }\n\
         \n\
         #define CALL_QUAL() ns::helper()\n\
         \n\
         void invoke_qual() { CALL_QUAL(); }\n\
         void cleanup() { assist(); }\n\
         void assist() {}\n",
    )
    .unwrap();
}

/// A header the C grammar cannot parse.
fn write_header(repo: &Path) {
    std::fs::write(
        repo.join("c.h"),
        "template<typename T>\n\
         T id(T v) { return v; }\n\
         \n\
         class C {\n\
         \tint read() const { return v; }\n\
         \tint v;\n\
         };\n",
    )
    .unwrap();
}

async fn index_fixture(repo: &Path) -> (Arc<DatabaseManager>, String) {
    git_run(repo, &["init", "-q"]);
    write_fixture(repo);
    write_shapes(repo);
    write_header(repo);
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);

    let git_sha = git::get_git_sha(repo).unwrap().unwrap();
    let db = Arc::new(
        DatabaseManager::new(
            repo.join(".semcode.db").to_str().unwrap(),
            repo.to_string_lossy().into_owned(),
        )
        .await
        .unwrap(),
    );
    db.create_tables().await.unwrap();

    semcode::git_range::process_git_tree(
        repo,
        &git_sha,
        &["cpp".to_string(), "h".to_string()],
        db.clone(),
        false,
        1,
    )
    .await
    .unwrap();

    (db, git_sha)
}

#[tokio::test]
async fn a_qualified_method_definition_is_indexed_under_its_qualified_name() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_fixture(dir.path()).await;

    let method = db
        .find_function_git_aware("B::f", &git_sha)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("B::f was not indexed"));
    assert_eq!(method.file_path, "b.cpp");
    // The row stores the bare name; the class is the qualifier.
    assert_eq!(method.name, "f");
    assert_eq!(method.qualifier.as_deref(), Some("B"));

    let callees = db
        .get_function_callees_by_definition_git_aware("B::f", &git_sha)
        .await
        .unwrap();
    // one definition, the b.cpp row, calling the bare f
    assert_eq!(callees.len(), 1, "{callees:?}");
    assert_eq!(callees[0].file_path, "b.cpp");
    assert_eq!(callees[0].callees, vec!["f".to_string()]);
}

#[tokio::test]
async fn method_definitions_in_class_and_out_of_class_share_a_name() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_fixture(dir.path()).await;

    // in-class and out-of-class spellings share one key
    for name in ["A::f", "A::g"] {
        let found = db.find_function_git_aware(name, &git_sha).await.unwrap();
        assert!(found.is_some(), "{name} was not indexed");
    }

    // constructors and destructors index like any other definition
    for name in ["A::A", "A::~A"] {
        let found = db.find_function_git_aware(name, &git_sha).await.unwrap();
        assert!(found.is_some(), "{name} was not indexed");
    }

    // the destructor row carries its bare name under the class
    let dtor = db
        .find_function_git_aware("A::~A", &git_sha)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(dtor.name, "~A");
    assert_eq!(dtor.qualifier.as_deref(), Some("A"));

    // the callees of the spelled definition: the split-aware query
    // addresses the owner, so a.cpp's f does not answer for b.cpp's
    let callees = db
        .get_function_callees_by_definition_git_aware("A::f", &git_sha)
        .await
        .unwrap();
    assert_eq!(callees.len(), 1, "{callees:?}");
    assert_eq!(callees[0].qualifier.as_deref(), Some("A"));
    assert_eq!(callees[0].callees, vec!["begin".to_string()]);
}

#[tokio::test]
async fn free_functions_templates_and_pointer_returns_are_indexed() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_fixture(dir.path()).await;

    for name in ["run_all", "pick", "make_node", "use_lambda"] {
        let found = db.find_function_git_aware(name, &git_sha).await.unwrap();
        assert!(found.is_some(), "{name} was not indexed");
    }

    // a template function indexes under its declared name, unowned
    let pick = db
        .find_function_git_aware("pick", &git_sha)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pick.file_path, "a.cpp");
    assert_eq!(pick.name, "pick");
    assert_eq!(pick.qualifier, None);

    let callees = db
        .get_function_callees_git_aware("run_all", &git_sha)
        .await
        .unwrap();
    assert_eq!(callees, vec!["prepare".to_string()]);

    // a lambda is not indexed; a call through it is
    let no_lambda = db.find_function_git_aware("twice", &git_sha).await.unwrap();
    assert!(no_lambda.is_none(), "a lambda was indexed as a function");
    let callees = db
        .get_function_callees_git_aware("use_lambda", &git_sha)
        .await
        .unwrap();
    assert_eq!(callees, vec!["twice".to_string()]);
}

#[tokio::test]
async fn cpp_files_parse_clean_and_h_stay_on_the_c_grammar() {
    let dir = tempfile::tempdir().unwrap();
    git_run(dir.path(), &["init", "-q"]);
    write_fixture(dir.path());
    write_header(dir.path());

    for file in ["a.cpp", "b.cpp"] {
        let survey = file_survey::survey_file(dir.path(), Path::new(file)).unwrap();
        assert_eq!(survey.parse_errors, 0, "{file} did not parse clean");
    }

    let survey = file_survey::survey_file(dir.path(), Path::new("c.h")).unwrap();
    assert!(
        survey.parse_errors > 0,
        "c.h parsed clean; .h is no longer routed to C"
    );
}

#[tokio::test]
async fn in_class_special_members_store_bare_under_their_class() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_fixture(dir.path()).await;

    // a qualified spelling addresses the row its owner owns
    for name in ["E::~E", "E::operator=", "E::operator==", "D::clone"] {
        let found = db.find_function_git_aware(name, &git_sha).await.unwrap();
        assert!(found.is_some(), "{name} was not indexed");
    }

    // the bare spelling finds the owned rows too: a lookup without an
    // owner addresses every row of the name, and the row answers with
    // the owner it carries
    let dtor = db
        .find_function_git_aware("~E", &git_sha)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("~E was not indexed"));
    assert_eq!(dtor.name, "~E");
    assert_eq!(dtor.qualifier.as_deref(), Some("E"));
    let assign = db
        .find_function_git_aware("operator=", &git_sha)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("operator= was not indexed"));
    assert_eq!(assign.name, "operator=");
    assert_eq!(assign.qualifier.as_deref(), Some("E"));
    let clone = db
        .find_function_git_aware("clone", &git_sha)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("clone was not indexed"));
    assert_eq!(clone.name, "clone");
    assert_eq!(clone.qualifier.as_deref(), Some("D"));

    let callees = db
        .get_function_callees_by_definition_git_aware("E::~E", &git_sha)
        .await
        .unwrap();
    assert_eq!(callees.len(), 1, "{callees:?}");
    assert_eq!(callees[0].callees, vec!["cleanup".to_string()]);
}

#[tokio::test]
async fn a_template_methods_spellings_share_one_key() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_fixture(dir.path()).await;

    // template arguments are not part of the key: the query spells the
    // owner without them and the row stores them nowhere
    let found = db
        .find_function_git_aware("Box::get", &git_sha)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("Box::get was not indexed"));
    assert_eq!(found.name, "get");
    assert_eq!(found.qualifier.as_deref(), Some("Box"));
    let gone = db
        .find_function_git_aware("Box<T>::get", &git_sha)
        .await
        .unwrap();
    assert!(gone.is_none(), "Box<T>::get was indexed as its own key");
}

#[tokio::test]
async fn a_cpp_macro_value_records_its_qualified_calls() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_fixture(dir.path()).await;

    // the namespace row itself carries its chain in the qualifier
    let helper = db
        .find_function_git_aware("ns::helper", &git_sha)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("ns::helper was not indexed"));
    assert_eq!(helper.name, "helper");
    assert_eq!(helper.qualifier.as_deref(), Some("ns"));

    // a qualified call in a macro value stores the bare callee: edges
    // join on the name a definition is found by
    let callers = db
        .get_function_callers_git_aware("helper", &git_sha)
        .await
        .unwrap();
    assert!(
        callers.iter().any(|caller| caller == "CALL_QUAL"),
        "CALL_QUAL's call to ns::helper was not recorded: {callers:?}"
    );
    // no edge keeps the qualification the call site wrote
    let qualified = db
        .get_function_callers_git_aware("ns::helper", &git_sha)
        .await
        .unwrap();
    assert!(
        !qualified.iter().any(|caller| caller == "CALL_QUAL"),
        "the qualified spelling was stored as an edge: {qualified:?}"
    );
}

/// Owner-model fixtures the tests look up: a definition behind a
/// preprocessor arm, extern "C", friends, a spelling that restates its
/// namespace, and operator spacing.
fn write_owners(repo: &Path) {
    std::fs::write(
        repo.join("owners.cpp"),
        "namespace ns {\n\
         #ifdef FEATURE\n\
         void gated() {}\n\
         #endif\n\
         extern \"C\" {\n\
         void api() {}\n\
         }\n\
         class D {\n\
         public:\n\
         \tfriend void df() { help(); }\n\
         };\n\
         class Outer {\n\
         public:\n\
         \tvoid m();\n\
         \tvoid n();\n\
         };\n\
         void ns::Outer::m() {}\n\
         void Outer::n() {}\n\
         int pick(int a, int b) { return a; }\n\
         }\n\
         extern \"C\" void bare_api() {}\n\
         class C {\n\
         public:\n\
         \tfriend void fr() { assist(); }\n\
         };\n\
         template<typename T>\n\
         T choose(T a, T b) { return a; }\n\
         void call_choose() {\n\
         \tint a = choose<int>(1, 2);\n\
         \tint b = ns::pick<int>(3, 4);\n\
         }\n\
         class K {\n\
         public:\n\
         \tK &operator =(const K &o) { return *this; }\n\
         };\n\
         K &K::operator=(const K &o) { return *this; }\n         struct ops {\n         \tint (*read)(void);\n         };\n         namespace ns {\n         int my_read(void) { return 0; }\n         int handler(void) { return 1; }\n         int callback(void) { return 2; }\n         }\n         struct ops built = { .read = &ns::handler };\n         void install(struct ops *ops) { ops->read = ns::my_read; }\n         void cb(int (*fn)(void)) {}\n         void hand_over(void) { cb(ns::callback); }\n         class Q {\n         public:\n         \tQ &operator=(const Q &o);\n         };\n         Q &Q::operator=(const Q &o);\n         Q &operator+(const Q &o);\n         class P {\n         public:\n         \t~P();\n         };\n         P::~P() {}\n         void use_p(P *p) { p->~P(); }\n",
    )
    .unwrap();
}

async fn index_owners(dir: &Path) -> (Arc<DatabaseManager>, String) {
    git_run(dir, &["init", "-q"]);
    write_owners(dir);
    git_run(dir, &["add", "."]);
    git_run(dir, &["commit", "-q", "-m", "fixture"]);

    let git_sha = git::get_git_sha(dir).unwrap().unwrap();
    let db = Arc::new(
        DatabaseManager::new(
            dir.join(".semcode.db").to_str().unwrap(),
            dir.to_string_lossy().into_owned(),
        )
        .await
        .unwrap(),
    );
    db.create_tables().await.unwrap();

    semcode::git_range::process_git_tree(
        dir,
        &git_sha,
        &["cpp".to_string(), "h".to_string()],
        db.clone(),
        false,
        1,
    )
    .await
    .unwrap();

    (db, git_sha)
}

#[tokio::test]
async fn a_definition_behind_a_preprocessor_arm_keeps_its_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_owners(dir.path()).await;
    let survey = file_survey::survey_file(dir.path(), Path::new("owners.cpp")).unwrap();
    assert_eq!(survey.parse_errors, 0, "owners.cpp did not parse clean");

    // the #ifdef arm is a guard, never an owner
    let gated = db
        .find_function_git_aware("ns::gated", &git_sha)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("ns::gated was not indexed"));
    assert_eq!(gated.name, "gated");
    assert_eq!(gated.qualifier.as_deref(), Some("ns"));
    assert_eq!(gated.guard.as_deref(), Some("defined(FEATURE)"));
}

#[tokio::test]
async fn a_bare_template_call_records_its_edge() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_owners(dir.path()).await;

    // choose<int> and ns::pick<int> both store the bare callee
    let callees = db
        .get_function_callees_git_aware("call_choose", &git_sha)
        .await
        .unwrap();
    assert_eq!(callees, vec!["choose".to_string(), "pick".to_string()]);
    let callers = db
        .get_function_callers_git_aware("choose", &git_sha)
        .await
        .unwrap();
    assert!(
        callers.iter().any(|caller| caller == "call_choose"),
        "the bare template call was not recorded: {callers:?}"
    );
}

#[tokio::test]
async fn extern_c_definitions_are_owned_by_the_namespace_around_them() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_owners(dir.path()).await;

    let api = db
        .find_function_git_aware("ns::api", &git_sha)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("ns::api was not indexed"));
    assert_eq!(api.qualifier.as_deref(), Some("ns"));
    let bare = db
        .find_function_git_aware("bare_api", &git_sha)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("bare_api was not indexed"));
    assert_eq!(bare.qualifier, None);
}

#[tokio::test]
async fn a_friend_is_owned_by_the_namespace_not_the_class() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_owners(dir.path()).await;

    let df = db
        .find_function_git_aware("ns::df", &git_sha)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("ns::df was not indexed"));
    assert_eq!(df.qualifier.as_deref(), Some("ns"));

    let fr = db
        .find_function_git_aware("fr", &git_sha)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("fr was not indexed"));
    assert_eq!(fr.qualifier, None);

    let absent = db.find_function_git_aware("C::fr", &git_sha).await.unwrap();
    assert!(
        absent.is_none(),
        "C::fr answered for a namespace-scope friend: {absent:?}"
    );
    let rows = db
        .find_all_functions_git_aware("df", &git_sha)
        .await
        .unwrap();
    assert!(
        rows.iter()
            .all(|row| row.qualifier.as_deref() != Some("ns::D")),
        "the class leaked into a friend's owner: {rows:?}"
    );
}

#[tokio::test]
async fn a_spelling_restating_its_namespace_stores_the_owner_once() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_owners(dir.path()).await;

    // `void ns::Outer::m` inside `namespace ns` writes the scope once
    let m = db
        .find_function_git_aware("ns::Outer::m", &git_sha)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("ns::Outer::m was not indexed"));
    assert_eq!(m.qualifier.as_deref(), Some("ns::Outer"));
    let rows = db
        .find_all_functions_git_aware("ns::Outer::m", &git_sha)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");

    // the sibling that does not restate the namespace reads the same
    let n = db
        .find_function_git_aware("ns::Outer::n", &git_sha)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("ns::Outer::n was not indexed"));
    assert_eq!(n.qualifier.as_deref(), Some("ns::Outer"));
}

#[tokio::test]
async fn operator_spellings_share_one_row_regardless_of_spacing() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_owners(dir.path()).await;

    // `operator =` in class and `operator=` out of class are one key
    let rows = db
        .find_all_functions_git_aware("K::operator=", &git_sha)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].name, "operator=");
    assert_eq!(rows[0].qualifier.as_deref(), Some("K"));
}

#[tokio::test]
async fn a_qualified_assignment_installs_its_bare_function() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_owners(dir.path()).await;

    // `ops->read = ns::my_read` stores the bare target the row joins by
    let registrations = db
        .find_registrations_of_git_aware("my_read", &git_sha)
        .await
        .unwrap();
    let row = registrations
        .iter()
        .find(|row| row.container_type == "ops" && row.member == "read")
        .unwrap_or_else(|| panic!("the qualified assignment was not recorded: {registrations:?}"));
    assert_eq!(row.target, "my_read");
    assert_eq!(row.container_type, "ops");
}

#[tokio::test]
async fn a_qualified_initializer_installs_its_bare_function() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_owners(dir.path()).await;

    // `.read = &ns::handler` addresses the function the row joins by
    let registrations = db
        .find_registrations_of_git_aware("handler", &git_sha)
        .await
        .unwrap();
    let row = registrations
        .iter()
        .find(|row| row.container_type == "ops" && row.member == "read")
        .unwrap_or_else(|| panic!("the qualified initializer was not recorded: {registrations:?}"));
    assert_eq!(row.target, "handler");
}

#[tokio::test]
async fn a_qualified_argument_is_handed_over_by_its_bare_name() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _git_sha) = index_owners(dir.path()).await;

    // `cb(ns::callback)` hands the callback over under its bare name
    let handed = db.find_argument_functions_of("callback").await.unwrap();
    let row = handed
        .iter()
        .find(|row| row.callee == "cb")
        .unwrap_or_else(|| panic!("the qualified handover was not recorded: {handed:?}"));
    assert_eq!(row.target, "callback");
    assert!(!row.taken_address, "{row:?}");
}

#[tokio::test]
async fn an_out_of_class_operator_prototype_records_a_row() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_owners(dir.path()).await;

    // `Q &Q::operator=(const Q &o);` returns through a reference
    let found = db
        .find_function_git_aware("Q::operator=", &git_sha)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("Q::operator= was not indexed"));
    assert_eq!(found.name, "operator=");
    assert_eq!(found.qualifier.as_deref(), Some("Q"));

    // a free operator prototype names itself at file scope
    let free = db
        .find_function_git_aware("operator+", &git_sha)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("operator+ was not indexed"));
    assert_eq!(free.name, "operator+");
    assert_eq!(free.qualifier, None);
}

#[tokio::test]
async fn an_explicit_destructor_call_records_its_edge() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_owners(dir.path()).await;

    // `p->~P()` names the function it runs
    let callees = db
        .get_function_callees_git_aware("use_p", &git_sha)
        .await
        .unwrap();
    assert_eq!(callees, vec!["~P".to_string()]);
}

#[tokio::test]
async fn a_c_file_keeps_its_bare_targets_untouched() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("ops.c"),
        "struct ops {\n\
         \tint (*read)(void);\n\
         };\n\
         int handler(void) { return 0; }\n\
         struct ops built = { .read = &handler };\n\
         void install(struct ops *ops) { ops->read = handler; }\n\
         void cb(int (*fn)(void)) {}\n\
         void hand_over(void) { cb(handler); }\n",
    )
    .unwrap();
    git_run(dir.path(), &["init", "-q"]);
    git_run(dir.path(), &["add", "."]);
    git_run(dir.path(), &["commit", "-q", "-m", "fixture"]);
    let git_sha = git::get_git_sha(dir.path()).unwrap().unwrap();
    let db = Arc::new(
        DatabaseManager::new(
            dir.path().join(".semcode.db").to_str().unwrap(),
            dir.path().to_string_lossy().into_owned(),
        )
        .await
        .unwrap(),
    );
    db.create_tables().await.unwrap();
    semcode::git_range::process_git_tree(
        dir.path(),
        &git_sha,
        &["c".to_string()],
        db.clone(),
        false,
        1,
    )
    .await
    .unwrap();

    // the C spellings store the same rows the C++ ones normalize to
    let registrations = db
        .find_registrations_of_git_aware("handler", &git_sha)
        .await
        .unwrap();
    assert_eq!(registrations.len(), 2, "{registrations:?}");
    assert!(
        registrations
            .iter()
            .all(|row| row.target == "handler" && row.container_type == "ops"),
        "{registrations:?}"
    );
    let handed = db.find_argument_functions_of("handler").await.unwrap();
    assert!(
        handed
            .iter()
            .any(|row| row.callee == "cb" && !row.taken_address),
        "{handed:?}"
    );
}
