// SPDX-License-Identifier: MIT OR Apache-2.0
//
// What a command that must give ONE answer says when the tree defines the name
// more than once. A callee query reports every definition; `callers`, `func`
// and `callchain` start from one, so what they owe the reader is the choice.
use semcode::{git, DatabaseManager};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

fn git_run(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_AUTHOR_NAME", "Semcode Test")
        .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
        .env("GIT_COMMITTER_NAME", "Semcode Test")
        .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

/// The shape of `pr_warn` in Linux, reduced: the definition the tree's own code
/// calls sits in a header, a host tool under `tools/` defines the same name in
/// a `.c` file, and a second language defines a method that is stored under the
/// bare name.
async fn tree_shaped_like_pr_warn() -> (tempfile::TempDir, Arc<DatabaseManager>, String) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();

    git_run(repo, &["init", "-q"]);
    std::fs::create_dir_all(repo.join("arch/x86/tools")).unwrap();
    std::fs::create_dir_all(repo.join("include/linux")).unwrap();
    std::fs::create_dir_all(repo.join("rust/kernel")).unwrap();

    // What the tree's own code calls.
    std::fs::write(
        repo.join("include/linux/printk.h"),
        "static inline int report(int level)\n{\n\treturn emit(level);\n}\n",
    )
    .unwrap();
    // A host program that happens to share the tree. Note the path: `tools` is
    // a component, not a prefix, so a prefix test does not see it.
    std::fs::write(
        repo.join("arch/x86/tools/decoder_test.c"),
        "int report(int level)\n{\n\treturn fprintf(stderr, \"%d\", level);\n}\n",
    )
    .unwrap();
    // A method in another language, stored under its bare name.
    std::fs::write(
        repo.join("rust/kernel/device.rs"),
        "impl Device {\n    pub fn report(&self, level: i32) {\n        self.printk(level);\n    }\n}\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("driver.c"),
        "#include <linux/printk.h>\n\nint probe(void)\n{\n\treturn report(3);\n}\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(
        repo,
        &["commit", "-q", "-m", "three definitions of one name"],
    );
    git_run(repo, &["branch", "-M", "main"]);
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
    let extensions = ["c".to_string(), "h".to_string(), "rs".to_string()];
    semcode::git_range::process_git_tree(repo, &sha, &extensions, db.clone(), false, 1)
        .await
        .unwrap();

    (dir, db, sha)
}

#[tokio::test]
async fn a_single_answer_names_the_definitions_it_set_aside() {
    let (_dir, db, sha) = tree_shaped_like_pr_warn().await;

    let chosen = db
        .find_function_git_aware_reporting("report", &sha)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("report should resolve"));

    // Every other definition is named, so the reader can ask again about one.
    assert_eq!(chosen.others.len(), 2, "{:?}", chosen.others);
    let note = chosen
        .ambiguity_note()
        .unwrap_or_else(|| panic!("three definitions, so there is a choice to report"));
    assert!(note.contains("defined 3 times"), "{note}");
    assert!(note.contains("arch/x86/tools/decoder_test.c"), "{note}");
    assert!(note.contains("rust/kernel/device.rs"), "{note}");
}

#[tokio::test]
async fn the_answer_is_not_another_program_in_the_same_tree() {
    let (_dir, db, sha) = tree_shaped_like_pr_warn().await;

    let chosen = db
        .find_function_git_aware_reporting("report", &sha)
        .await
        .unwrap()
        .unwrap();

    // Ranked by the older ladder this is decoder_test.c: a `.c` file beats a
    // header. It is a host tool, and nothing in the tree it is asked about
    // reaches it.
    assert_eq!(
        chosen.function.file_path, "include/linux/printk.h",
        "chose {}:{}",
        chosen.function.file_path, chosen.function.line_start
    );
}

#[tokio::test]
async fn the_chain_lists_the_callees_of_the_definition_it_names() {
    // The header and the callee list are two answers about one function, and
    // they were ranked in two places. The header preferred the program being
    // audited and the callee list preferred a long `.c` body, so a chain named
    // one definition and then walked another.
    let (_dir, db, sha) = tree_shaped_like_pr_warn().await;

    let named = db
        .find_function_git_aware_reporting("report", &sha)
        .await
        .unwrap()
        .unwrap();
    let walked = db
        .get_function_callees_git_aware("report", &sha)
        .await
        .unwrap();

    assert_eq!(named.function.file_path, "include/linux/printk.h");
    assert!(walked.contains(&"emit".to_string()), "{walked:?}");
    assert!(
        !walked.contains(&"fprintf".to_string()),
        "walked the host tool's body while naming {}: {walked:?}",
        named.function.file_path
    );
}

#[tokio::test]
async fn a_name_defined_once_reports_no_choice() {
    let (_dir, db, sha) = tree_shaped_like_pr_warn().await;

    let chosen = db
        .find_function_git_aware_reporting("probe", &sha)
        .await
        .unwrap()
        .unwrap();
    assert!(chosen.others.is_empty(), "{:?}", chosen.others);
    // A note on every answer is noise, and noise is skipped rather than read.
    assert!(chosen.ambiguity_note().is_none());
}

#[tokio::test]
async fn every_definition_is_listed_in_the_same_order_twice() {
    let (_dir, db, sha) = tree_shaped_like_pr_warn().await;

    let first = db
        .find_all_functions_git_aware("report", &sha)
        .await
        .unwrap();
    let again = db
        .find_all_functions_git_aware("report", &sha)
        .await
        .unwrap();
    let paths = |list: &[semcode::FunctionInfo]| -> Vec<String> {
        list.iter().map(|f| f.file_path.clone()).collect()
    };
    // The candidate files are resolved through a hash map, so two runs used to
    // answer in different orders, which reads as the tree having changed.
    assert_eq!(paths(&first), paths(&again), "{:?}", paths(&first));
    assert!(paths(&first).windows(2).all(|pair| pair[0] <= pair[1]));
}

#[tokio::test]
async fn each_definition_answers_with_its_own_callees() {
    let (_dir, db, sha) = tree_shaped_like_pr_warn().await;

    // This is what the `func` command joins on: one row per definition, keyed
    // by where it was read. Asking by name once per definition returns the
    // same preferred answer every time, which attributed a host tool's callees
    // to the header the kernel calls.
    let definitions = db
        .get_function_callees_by_definition_git_aware("report", &sha)
        .await
        .unwrap();
    let callees_at = |needle: &str| -> Vec<String> {
        definitions
            .iter()
            .find(|d| d.file_path.ends_with(needle))
            .unwrap_or_else(|| panic!("no row for {needle}: {definitions:?}"))
            .callees
            .clone()
    };
    assert!(callees_at("include/linux/printk.h").contains(&"emit".to_string()));
    assert!(callees_at("arch/x86/tools/decoder_test.c").contains(&"fprintf".to_string()));
    assert!(!callees_at("include/linux/printk.h").contains(&"fprintf".to_string()));
}

#[tokio::test]
async fn the_listing_shows_each_definition_its_own_calls() {
    // The defect this pins is in what `func` prints, not in what the database
    // returns: it looped over the definitions and asked by name inside the
    // loop, so all three blocks carried one definition's calls. On Linux that
    // printed the callees of arch/x86/tools/insn_decoder_test.c under
    // include/linux/printk.h, nine times.
    let (_dir, db, sha) = tree_shaped_like_pr_warn().await;

    let mut out: Vec<u8> = Vec::new();
    semcode::search::query_function_or_macro_to_writer_verbose(&db, "report", &sha, &mut out, true)
        .await
        .unwrap();
    // Colour is written unconditionally and stripped by the stream on the way
    // to a terminal, so a writer sees the escapes and a plain `find` misses
    // every heading.
    let printed = strip_colour(&String::from_utf8(out).unwrap());

    // Each block runs from its file heading to the next one, so a call listed
    // in the wrong block fails here rather than being found somewhere.
    let block_for = |needle: &str| -> String {
        let start = printed
            .find(needle)
            .unwrap_or_else(|| panic!("no block for {needle} in:\n{printed}"));
        let rest = &printed[start..];
        let end = rest[needle.len()..]
            .find("File: ")
            .map(|offset| offset + needle.len())
            .unwrap_or(rest.len());
        rest[..end].to_string()
    };

    let header = block_for("File: include/linux/printk.h");
    assert!(header.contains("emit"), "{header}");
    assert!(!header.contains("fprintf"), "{header}");

    let host = block_for("File: arch/x86/tools/decoder_test.c");
    assert!(host.contains("fprintf"), "{host}");
    assert!(!host.contains("emit"), "{host}");
}

#[tokio::test]
async fn the_types_belong_to_the_definition_that_was_named() {
    // Third part of one answer, third place it was ranked: the types beside a
    // function were picked by a copy of the older ladder, so a report could
    // name one definition, list a second one's callees and a third one's
    // types. Nothing said they were about different functions.
    // Each definition has to name a DIFFERENT type, or the two answers are
    // both empty and the test passes whichever definition it read. The first
    // version of this test did exactly that.
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::create_dir_all(repo.join("arch/x86/tools")).unwrap();
    std::fs::create_dir_all(repo.join("include/linux")).unwrap();
    std::fs::write(
        repo.join("include/linux/printk.h"),
        "struct kdev { int id; };\n\
         static inline int report(struct kdev *dev)\n{\n\treturn dev->id;\n}\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("arch/x86/tools/decoder_test.c"),
        "struct host_ctx { int fd; };\n\
         int report(struct host_ctx *ctx)\n{\n\treturn ctx->fd;\n}\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "two definitions, two types"]);
    git_run(repo, &["branch", "-M", "main"]);
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
    let manifest = db.git_manifest_cached(&sha).await.unwrap();

    let chosen = db
        .find_function_git_aware_reporting("report", &sha)
        .await
        .unwrap()
        .unwrap();
    let types = db
        .get_function_types_with_manifest("report", &manifest)
        .await
        .unwrap();

    assert_eq!(chosen.function.file_path, "include/linux/printk.h");
    assert!(
        types.iter().any(|t| t == "kdev" || t == "struct kdev"),
        "named include/linux/printk.h and reported types {types:?}"
    );
    assert!(
        !types.iter().any(|t| t.contains("host_ctx")),
        "types came from the host tool's definition: {types:?}"
    );
}

#[tokio::test]
async fn a_use_of_the_name_is_not_an_answer_about_it() {
    // Some rows are neither a definition nor a declaration. In Linux,
    // arch/x86/xen/suspend_hvm.c:22 is `BUG_ON(xen_set_upcall_vector(cpu));`
    // -- a call stored under the name it calls -- and being a `.c` file in the
    // tree being audited it outranked every real definition, so `callers
    // BUG_ON` answered about a use of BUG_ON and counted nine definitions
    // where a callee query counted eight.
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::create_dir_all(repo.join("include/asm-generic")).unwrap();
    std::fs::write(
        repo.join("include/asm-generic/bug.h"),
        "#define CHECK(cond) do { if (cond) report(); } while (0)\n",
    )
    .unwrap();
    // The shape of the artefact: a statement that names CHECK, stored as a row
    // of its own, ending in a semicolon with no braces of its own.
    std::fs::write(
        repo.join("use.c"),
        "void start(void)\n{\n\tCHECK(ready());\n}\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "a macro and a use of it"]);
    git_run(repo, &["branch", "-M", "main"]);
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

    let chosen = db
        .find_function_git_aware_reporting("CHECK", &sha)
        .await
        .unwrap()
        .unwrap();
    // Whatever else is stored under this name, the answer is the definition.
    assert_eq!(
        chosen.function.file_path, "include/asm-generic/bug.h",
        "answered about {}:{}",
        chosen.function.file_path, chosen.function.line_start
    );
    // And the count matches what a callee query reports, because both now ask
    // the row's own text whether it defines the name.
    let definitions = db
        .get_function_callees_by_definition_git_aware("CHECK", &sha)
        .await
        .unwrap();
    let defining = definitions.iter().filter(|d| d.is_definition).count();
    assert_eq!(chosen.others.len() + 1, defining, "{definitions:?}");
}

#[tokio::test]
async fn two_languages_one_definition_each_is_not_a_majority() {
    // The boundary the majority rung has to get right and the only one the
    // languages this indexes can reach: C and Rust are the two groups a path
    // extension can fall into, so a skew short of a majority needs a third
    // language that is not parsed. One each is a tie, no majority, and the
    // lower rungs decide -- the same way twice, which is the property worth
    // pinning.
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::create_dir_all(repo.join("rust/kernel")).unwrap();
    std::fs::write(
        repo.join("driver.c"),
        "int solo(int level)\n{\n\treturn emit(level);\n}\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("rust/kernel/thing.rs"),
        "impl Thing {\n    pub fn solo(&self, level: i32) {\n        self.record(level);\n    }\n}\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "one each"]);
    git_run(repo, &["branch", "-M", "main"]);
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
    let extensions = ["c".to_string(), "h".to_string(), "rs".to_string()];
    semcode::git_range::process_git_tree(repo, &sha, &extensions, db.clone(), false, 1)
        .await
        .unwrap();

    let first = db
        .find_function_git_aware_reporting("solo", &sha)
        .await
        .unwrap()
        .unwrap();
    let again = db
        .find_function_git_aware_reporting("solo", &sha)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.function.file_path, again.function.file_path);
    assert_eq!(first.others.len(), 1, "{:?}", first.others);
    let note = first.ambiguity_note().unwrap();
    assert!(note.contains("defined 2 times"), "{note}");
}

/// A tree where one registrar name has two definitions, as `call_rcu` does.
async fn tree_with_two_registrars(
    second_member: &str,
) -> (tempfile::TempDir, Arc<DatabaseManager>, String) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::create_dir_all(repo.join("kernel/rcu")).unwrap();
    std::fs::write(
        repo.join("head.h"),
        "struct cb_head { void (*func)(struct cb_head *); struct cb_head *next; };\n\
         struct other_head { void (*other)(struct other_head *); };\n",
    )
    .unwrap();
    // One definition stores the parameter itself.
    std::fs::write(
        repo.join("kernel/rcu/tiny.c"),
        "#include \"head.h\"\nvoid queue_cb(struct cb_head *head, void (*func)(struct cb_head *))\n{\n\thead->func = func;\n}\n",
    )
    .unwrap();
    // The other hands it on, and the wrapper it hands it to stores it -- in
    // the same member, or in a different one, depending on the caller.
    std::fs::write(
        repo.join("kernel/rcu/tree.c"),
        format!(
            "#include \"head.h\"\n\
             static void common_queue(struct cb_head *head, void (*func)(struct cb_head *))\n{{\n\thead->{second_member} = func;\n}}\n\n\
             void queue_cb(struct cb_head *head, void (*func)(struct cb_head *))\n{{\n\tcommon_queue(head, func);\n}}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        repo.join("user.c"),
        "#include \"head.h\"\n\
         static void my_callback(struct cb_head *h)\n{\n\t(void)h;\n}\n\n\
         void start(struct cb_head *head)\n{\n\tqueue_cb(head, my_callback);\n}\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "two registrars"]);
    git_run(repo, &["branch", "-M", "main"]);
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

#[tokio::test]
async fn agreeing_definitions_of_a_registrar_are_one_claim() {
    // `call_rcu` has three definitions in Linux; two reach `rcu_head::func`,
    // one storing the parameter and one handing it to `__call_rcu_common`.
    // Walking a single silently-chosen definition reported one route as the
    // fact. Same member, two routes, so it is one claim -- and that two
    // definitions agree is worth saying, because it holds whichever is built.
    let (_dir, db, sha) = tree_with_two_registrars("func").await;

    let claims = db
        .follow_handed_parameter("queue_cb", 1, &sha)
        .await
        .unwrap();
    assert_eq!(claims.len(), 1, "{claims:?}");
    let (claim, agreeing) = &claims[0];
    assert_eq!(*agreeing, 2, "{claims:?}");
    match claim {
        semcode::Handover::StoredIn {
            container_type,
            member,
            path,
        } => {
            assert_eq!(member, "func", "{claim:?}");
            assert!(container_type.contains("cb_head"), "{claim:?}");
            // The route names the file it was read from, or the reader cannot
            // tell which of the two definitions produced it.
            assert!(
                path.iter().any(|hop| hop.contains("kernel/rcu/")),
                "{path:?}"
            );
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn definitions_that_disagree_are_both_reported() {
    // The case a single answer hid: two definitions of one registrar putting
    // the callback in different members. Picking either one states a fact
    // about a configuration the reader did not choose.
    let (_dir, db, sha) = tree_with_two_registrars("next").await;

    let claims = db
        .follow_handed_parameter("queue_cb", 1, &sha)
        .await
        .unwrap();
    let mut members: Vec<String> = claims
        .iter()
        .filter_map(|(claim, _)| match claim {
            semcode::Handover::StoredIn { member, .. } => Some(member.clone()),
            _ => None,
        })
        .collect();
    members.sort();
    assert_eq!(
        members,
        vec!["func".to_string(), "next".to_string()],
        "{claims:?}"
    );
}

#[tokio::test]
async fn a_hop_with_many_definitions_does_not_starve_the_rest_of_the_walk() {
    // Walking every definition of every name shared one budget with following
    // wrapper branches, so a hop with many definitions spent the whole budget
    // and the claim two hops further on stopped being found -- silently, and
    // the disagreement this reports would have gone with it.
    //
    // `noisy` here has 40 definitions, more than the 32 branches the walk will
    // follow. The claim is three hops past it.
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git_run(repo, &["init", "-q"]);
    std::fs::write(
        repo.join("head.h"),
        "struct cb_head { void (*func)(struct cb_head *); };\n",
    )
    .unwrap();
    // The intermediate, defined many times over, each definition handing the
    // parameter on to the same next wrapper.
    std::fs::create_dir_all(repo.join("drivers")).unwrap();
    for i in 0..40 {
        std::fs::write(
            repo.join(format!("drivers/d{i}.c")),
            "#include \"head.h\"\nstatic void deep_store(struct cb_head *, void (*)(struct cb_head *));\n\
             static void noisy(struct cb_head *head, void (*func)(struct cb_head *))\n{\n\tdeep_store(head, func);\n}\n",
        )
        .unwrap();
    }
    // The last hop, which actually stores it.
    std::fs::write(
        repo.join("store.c"),
        "#include \"head.h\"\nvoid deep_store(struct cb_head *head, void (*func)(struct cb_head *))\n{\n\thead->func = func;\n}\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("entry.c"),
        "#include \"head.h\"\n\
         static void noisy(struct cb_head *, void (*)(struct cb_head *));\n\
         void register_cb(struct cb_head *head, void (*func)(struct cb_head *))\n{\n\tnoisy(head, func);\n}\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "a noisy intermediate"]);
    git_run(repo, &["branch", "-M", "main"]);
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

    let claims = db
        .follow_handed_parameter("register_cb", 1, &sha)
        .await
        .unwrap();
    assert!(
        claims.iter().any(|(claim, _)| matches!(
            claim,
            semcode::Handover::StoredIn { member, .. } if member == "func"
        )),
        "the claim past the noisy hop was not found: {claims:?}"
    );
}

fn strip_colour(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        for escape in chars.by_ref() {
            if escape == 'm' {
                break;
            }
        }
    }
    out
}

#[test]
fn a_path_component_names_another_program_where_a_prefix_does_not() {
    use semcode::path_is_other_program;

    // The definition that made this necessary. Every directory named `tools`
    // in Linux holds a host program, including twelve under `arch/`.
    assert!(path_is_other_program("arch/x86/tools/insn_decoder_test.c"));
    assert!(path_is_other_program("tools/lib/bpf/relo_core.c"));
    assert!(path_is_other_program("samples/bpf/sockex1_kern.c"));
    assert!(path_is_other_program("Documentation/tools/whatever.c"));

    assert!(!path_is_other_program("include/linux/printk.h"));
    assert!(!path_is_other_program("kernel/fork.c"));
    // A name is not a component: this is kernel code.
    assert!(!path_is_other_program("drivers/tty/toolsomething.c"));
    assert!(!path_is_other_program("mm/mytools.c"));
}

#[tokio::test]
async fn the_three_commands_count_the_same_definitions() {
    // The note tells the reader to run `func` to see the definitions it set
    // aside, so the two have to agree about how many there are. They did not:
    // three predicates answered "does this row define the function" three
    // ways, and `kfree` was reported six times and listed five.
    let (_dir, db, sha) = tree_shaped_like_pr_warn().await;

    let chosen = db
        .find_function_git_aware_reporting("report", &sha)
        .await
        .unwrap()
        .unwrap();
    let listed = db
        .find_all_functions_git_aware("report", &sha)
        .await
        .unwrap();
    let by_callee_query = db
        .get_function_callees_by_definition_git_aware("report", &sha)
        .await
        .unwrap()
        .iter()
        .filter(|definition| definition.is_definition)
        .count();

    assert_eq!(chosen.others.len() + 1, listed.len(), "note vs listing");
    assert_eq!(listed.len(), by_callee_query, "listing vs callee query");
}
