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

    let callees = db
        .get_function_callees_git_aware("B::f", &git_sha)
        .await
        .unwrap();
    assert!(
        callees.iter().any(|callee| callee == "f"),
        "the call to f was not recorded: {callees:?}"
    );
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

    let callees = db
        .get_function_callees_git_aware("A::f", &git_sha)
        .await
        .unwrap();
    assert_eq!(callees, vec!["begin".to_string()]);
}

#[tokio::test]
async fn free_functions_templates_and_pointer_returns_are_indexed() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_fixture(dir.path()).await;

    for name in ["run_all", "pick", "make_node", "use_lambda"] {
        let found = db.find_function_git_aware(name, &git_sha).await.unwrap();
        assert!(found.is_some(), "{name} was not indexed");
    }

    // a template function indexes under its declared name
    let pick = db
        .find_function_git_aware("pick", &git_sha)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pick.file_path, "a.cpp");

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
async fn in_class_special_members_store_under_qualified_names() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_fixture(dir.path()).await;

    // in-class spellings store under the qualified key
    for name in ["E::~E", "E::operator=", "E::operator==", "D::clone"] {
        let found = db.find_function_git_aware(name, &git_sha).await.unwrap();
        assert!(found.is_some(), "{name} was not indexed");
    }
    for name in ["~E", "operator=", "operator==", "clone"] {
        let found = db.find_function_git_aware(name, &git_sha).await.unwrap();
        assert!(found.is_none(), "{name} was indexed as its own key");
    }

    let callees = db
        .get_function_callees_git_aware("E::~E", &git_sha)
        .await
        .unwrap();
    assert_eq!(callees, vec!["cleanup".to_string()]);
}

#[tokio::test]
async fn a_template_methods_spellings_share_one_key() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_fixture(dir.path()).await;

    // template arguments are not part of the key
    let found = db
        .find_function_git_aware("Box::get", &git_sha)
        .await
        .unwrap();
    assert!(found.is_some(), "Box::get was not indexed");
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

    // a qualified call in a macro value keeps its qualification
    let callers = db
        .get_function_callers_git_aware("ns::helper", &git_sha)
        .await
        .unwrap();
    assert!(
        callers.iter().any(|caller| caller == "CALL_QUAL"),
        "CALL_QUAL's call to ns::helper was not recorded: {callers:?}"
    );
    let mangled = db
        .get_function_callers_git_aware("helper", &git_sha)
        .await
        .unwrap();
    assert!(
        !mangled.iter().any(|caller| caller == "CALL_QUAL"),
        "the qualified call was recorded as the unqualified helper: {mangled:?}"
    );
}
