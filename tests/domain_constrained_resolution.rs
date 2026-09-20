// SPDX-License-Identifier: MIT OR Apache-2.0
//
// A search may be constrained to the build it came from. This checks the
// three outcomes of resolving a name under a constraint, on a tree shaped
// like the case that motivated it: one name, one definition per
// architecture, and no generic one.
//
// A display path can only exercise the constraint it happens to pass, so
// these drive the resolver directly with each one.
use semcode::domain::{domain_of, Context};
use semcode::Resolution;
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

/// The shape of `pte_present`, reduced: one definition per architecture, in
/// headers, with nothing generic to fall back to.
async fn tree_with_one_definition_per_arch() -> (tempfile::TempDir, Arc<DatabaseManager>, String) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();

    git_run(repo, &["init", "-q"]);
    for arch in ["x86", "sparc", "arm64"] {
        std::fs::create_dir_all(repo.join(format!("arch/{arch}/include/asm"))).unwrap();
        std::fs::write(
            repo.join(format!("arch/{arch}/include/asm/pgtable.h")),
            format!("static inline int page_present(unsigned long pte)\n{{\n\treturn {arch}_present(pte);\n}}\n"),
        )
        .unwrap();
    }
    std::fs::create_dir_all(repo.join("mm")).unwrap();
    std::fs::write(
        repo.join("mm/memory.c"),
        "int handle_fault(unsigned long pte)\n{\n\treturn page_present(pte);\n}\n",
    )
    .unwrap();

    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "one definition per arch"]);
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
async fn an_unconstrained_search_still_chooses_and_reports() {
    let (_dir, db, sha) = tree_with_one_definition_per_arch().await;

    let resolution = db
        .find_function_git_aware_reporting("page_present", &sha, Context::Any)
        .await
        .unwrap();

    let chosen = match resolution {
        Resolution::Chosen(chosen) => chosen,
        other => panic!("unconstrained search should answer, got {other:?}"),
    };
    // Which of the three it picks is the chooser's business; that it says
    // there were three is the contract.
    assert_eq!(chosen.others.len(), 2);
    assert!(chosen.ambiguity_note().is_some());
}

#[tokio::test]
async fn a_constraint_picks_its_own_architecture() {
    let (_dir, db, sha) = tree_with_one_definition_per_arch().await;

    let caller = domain_of("arch/x86/mm/fault.c");
    let resolution = db
        .find_function_git_aware_reporting("page_present", &sha, Context::In(caller))
        .await
        .unwrap();

    let chosen = match resolution {
        Resolution::Chosen(chosen) => chosen,
        other => panic!("x86 should reach its own definition, got {other:?}"),
    };
    assert_eq!(chosen.function.file_path, "arch/x86/include/asm/pgtable.h");
    // The other two are not worse answers that lost a ranking; they were
    // never candidates, so there is no choice left to report.
    assert!(chosen.others.is_empty());
    assert!(chosen.ambiguity_note().is_none());
}

#[tokio::test]
async fn no_definition_in_this_build_names_the_ones_that_exist() {
    let (_dir, db, sha) = tree_with_one_definition_per_arch().await;

    // No powerpc definition exists. The honest answer is not "not found":
    // it is "not here, and here is where the other side lives".
    let caller = domain_of("arch/powerpc/mm/fault.c");
    let resolution = db
        .find_function_git_aware_reporting("page_present", &sha, Context::In(caller))
        .await
        .unwrap();

    match resolution {
        Resolution::NoneAdmitted { candidates } => {
            assert_eq!(candidates.len(), 3);
            let mut paths: Vec<&str> = candidates.iter().map(|c| c.file_path.as_str()).collect();
            paths.sort();
            assert_eq!(
                paths,
                vec![
                    "arch/arm64/include/asm/pgtable.h",
                    "arch/sparc/include/asm/pgtable.h",
                    "arch/x86/include/asm/pgtable.h",
                ]
            );
        }
        other => panic!("powerpc has no definition to reach, got {other:?}"),
    }
}

#[tokio::test]
async fn another_program_is_not_reachable_at_all() {
    let (_dir, db, sha) = tree_with_one_definition_per_arch().await;

    let caller = domain_of("tools/perf/builtin-stat.c");
    let resolution = db
        .find_function_git_aware_reporting("page_present", &sha, Context::In(caller))
        .await
        .unwrap();

    assert!(
        matches!(resolution, Resolution::NoneAdmitted { .. }),
        "a tools caller must not reach kernel definitions"
    );
}

#[tokio::test]
async fn a_name_that_does_not_exist_is_not_found_rather_than_unadmitted() {
    let (_dir, db, sha) = tree_with_one_definition_per_arch().await;

    let resolution = db
        .find_function_git_aware_reporting("no_such_function", &sha, Context::Any)
        .await
        .unwrap();

    assert!(
        matches!(resolution, Resolution::NotFound),
        "an absent name has no candidates to name, got {resolution:?}"
    );
}

#[tokio::test]
async fn a_caller_list_is_about_the_definition_not_the_name() {
    let (dir, db, sha) = tree_with_one_definition_per_arch().await;
    let repo = dir.path();

    // Two callers of the same name, one per architecture, plus a generic
    // one. Listing all three under either definition says the other
    // architecture's caller calls this definition, which it does not.
    std::fs::create_dir_all(repo.join("arch/x86/mm")).unwrap();
    std::fs::create_dir_all(repo.join("arch/sparc/mm")).unwrap();
    std::fs::write(
        repo.join("arch/x86/mm/fault.c"),
        "int x86_fault(unsigned long pte)\n{\n\treturn page_present(pte);\n}\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("arch/sparc/mm/fault.c"),
        "int sparc_fault(unsigned long pte)\n{\n\treturn page_present(pte);\n}\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "one caller per arch"]);
    let sha2 = git::get_git_sha(repo).unwrap().unwrap();
    let extensions = ["c".to_string(), "h".to_string()];
    semcode::git_range::process_git_tree(repo, &sha2, &extensions, db.clone(), false, 1)
        .await
        .unwrap();
    let _ = sha;

    let unconstrained = db
        .get_function_callers_in("page_present", &sha2, Context::Any)
        .await
        .unwrap();
    assert!(unconstrained.contains(&"x86_fault".to_string()));
    assert!(unconstrained.contains(&"sparc_fault".to_string()));
    assert!(unconstrained.contains(&"handle_fault".to_string()));

    let from_x86 = db
        .get_function_callers_in(
            "page_present",
            &sha2,
            Context::In(domain_of("arch/x86/include/asm/pgtable.h")),
        )
        .await
        .unwrap();
    assert!(from_x86.contains(&"x86_fault".to_string()));
    // Generic code calls whichever definition the build selects, so it is a
    // caller of this one.
    assert!(from_x86.contains(&"handle_fault".to_string()));
    // The sparc caller is not.
    assert!(
        !from_x86.contains(&"sparc_fault".to_string()),
        "sparc_fault calls sparc's definition, not x86's: {from_x86:?}"
    );
}

#[tokio::test]
async fn callees_come_from_one_definition_not_from_all_of_them() {
    let (dir, db, sha) = tree_with_one_definition_per_arch().await;
    let repo = dir.path();

    // Each architecture's page_present calls its own helper. Merging the
    // callees of all three gives a set that belongs to no build -- the
    // sparc leaves under an x86 root.
    for arch in ["x86", "sparc"] {
        std::fs::write(
            repo.join(format!("arch/{arch}/include/asm/pgtable.h")),
            format!(
                "static inline int page_present(unsigned long pte)\n{{\n\treturn {arch}_lookup(pte);\n}}\n"
            ),
        )
        .unwrap();
    }
    // A generic definition beside them, which an architecture's own
    // definition overrides the way asm/ overrides asm-generic/.
    std::fs::create_dir_all(repo.join("include/linux")).unwrap();
    std::fs::write(
        repo.join("include/linux/pgtable.h"),
        "static inline int page_present(unsigned long pte)\n{\n\treturn generic_lookup(pte);\n}\n",
    )
    .unwrap();
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "per-arch helpers"]);
    let sha2 = git::get_git_sha(repo).unwrap().unwrap();
    let extensions = ["c".to_string(), "h".to_string()];
    semcode::git_range::process_git_tree(repo, &sha2, &extensions, db.clone(), false, 1)
        .await
        .unwrap();
    let _ = sha;

    let from_x86 = db
        .get_function_callees_in(
            "page_present",
            &sha2,
            Context::In(domain_of("arch/x86/mm/fault.c")),
        )
        .await
        .unwrap();
    assert!(
        from_x86.contains(&"x86_lookup".to_string()),
        "x86's definition calls x86_lookup: {from_x86:?}"
    );
    assert!(
        !from_x86.contains(&"sparc_lookup".to_string()),
        "sparc's helper is not reachable from x86: {from_x86:?}"
    );
    // The generic definition is admitted but overridden: a build with an
    // x86 page_present does not also have the generic one.
    assert!(
        !from_x86.contains(&"generic_lookup".to_string()),
        "x86 overrides the generic definition: {from_x86:?}"
    );

    // A architecture with no definition of its own gets the generic one.
    let from_arm = db
        .get_function_callees_in(
            "page_present",
            &sha2,
            Context::In(domain_of("arch/arm/mm/fault.c")),
        )
        .await
        .unwrap();
    assert!(
        from_arm.contains(&"generic_lookup".to_string()),
        "arm has no page_present, so it reaches the generic one: {from_arm:?}"
    );

    // Unconstrained is unchanged, which is not the same as correct: the
    // existing query answers from one definition chosen without a reason,
    // so all that can be asserted is that it still answers and that this
    // patch did not change which one.
    let unconstrained = db
        .get_function_callees_in("page_present", &sha2, Context::Any)
        .await
        .unwrap();
    let existing = db
        .get_function_callees_git_aware("page_present", &sha2)
        .await
        .unwrap();
    assert_eq!(unconstrained, existing);
}
