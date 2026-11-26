// SPDX-License-Identifier: MIT OR Apache-2.0
//! `semcode-index --result-json`: the contract in docs/index-result.md.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A command that sees none of the caller's git environment or
/// configuration, as under a hook, `git rebase --exec`, or a CI runner
/// with no identity: git and semcode-index (through gix) both read only
/// what is set here.
fn clean_command(program: &str) -> Command {
    let mut command = Command::new(program);
    for (var, _) in std::env::vars_os() {
        if var.to_string_lossy().starts_with("GIT_") {
            command.env_remove(var);
        }
    }
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Semcode Test")
        .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
        .env("GIT_COMMITTER_NAME", "Semcode Test")
        .env("GIT_COMMITTER_EMAIL", "semcode@example.com");
    command
}

fn semcode_index() -> Command {
    clean_command(env!("CARGO_BIN_EXE_semcode-index"))
}

/// `http://127.0.0.1:PORT` on a listener this test process owns, which
/// closes every connection it accepts. Any request sent there fails at
/// once, whatever else runs on the host.
fn dead_end() -> &'static str {
    static URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    URL.get_or_init(|| {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                drop(stream);
            }
        });
        url
    })
}

/// Send every proxied request to the dead end, so a run that would
/// reach lore.kernel.org (a list name, the manifest check) fails at once.
fn offline(mut command: Command) -> Command {
    for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
        command.env(var, dead_end());
        command.env(var.to_lowercase(), dead_end());
    }
    command.env_remove("NO_PROXY").env_remove("no_proxy");
    command
}

fn git(repo: &Path, args: &[&str]) -> String {
    let output = clean_command("git")
        .args(args)
        .current_dir(repo)
        .output()
        .unwrap();
    assert!(output.status.success(), "git {args:?} failed");
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn commit_file(repo: &Path, name: &str, body: &str) -> String {
    std::fs::write(repo.join(name), body).unwrap();
    git(repo, &["add", name]);
    git(repo, &["commit", "-q", "-m", name]);
    git(repo, &["rev-parse", "HEAD"])
}

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    /// A repository with `main` and `dev`, both holding one C file.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let fixture = Self { dir };
        let repo = fixture.repo();
        std::fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-q", "--initial-branch=main"]);
        commit_file(&repo, "a.c", "int a(void)\n{\n\treturn 0;\n}\n");
        git(&repo, &["branch", "dev"]);
        fixture
    }

    fn repo(&self) -> PathBuf {
        self.dir.path().join("repo")
    }

    fn db(&self) -> PathBuf {
        self.dir.path().join("index.db")
    }

    fn report_path(&self) -> PathBuf {
        self.dir.path().join("result.json")
    }

    fn tip(&self, branch: &str) -> String {
        git(&self.repo(), &["rev-parse", branch])
    }

    fn index(&self, args: &[&str]) -> Output {
        offline(semcode_index())
            .arg("--source")
            .arg(self.repo())
            .arg("--database")
            .arg(self.db())
            .args(args)
            .output()
            .unwrap()
    }

    fn index_with_report(&self, args: &[&str]) -> Output {
        let path = self.report_path();
        let mut all = vec!["--result-json", path.to_str().unwrap()];
        all.extend_from_slice(args);
        self.index(&all)
    }

    fn report(&self) -> Value {
        serde_json::from_str(&std::fs::read_to_string(self.report_path()).unwrap()).unwrap()
    }

    fn recorded_tip(&self, branch: &str) -> Option<String> {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let db = semcode::DatabaseManager::new(
                self.db().to_str().unwrap(),
                self.repo().to_string_lossy().into_owned(),
            )
            .await
            .unwrap();
            db.get_branch_tip(branch).await.unwrap()
        })
    }

    /// No temporary report file is left beside the destination.
    fn assert_no_temp_files(&self) {
        for entry in std::fs::read_dir(self.dir.path()).unwrap() {
            let name = entry.unwrap().file_name();
            assert!(
                !name.to_string_lossy().starts_with(".semcode-result-"),
                "left behind {name:?}"
            );
        }
    }
}

fn entry(name: &str, outcome: &str, commit: &str) -> Value {
    json!({ "name": name, "outcome": outcome, "commit": commit })
}

#[test]
fn initial_index_rerun_and_moved_branch() {
    let f = Fixture::new();

    let out = f.index_with_report(&["--branches", "main,dev", "--update-branches"]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        f.report(),
        json!({ "version": 1, "branches": [
            entry("main", "indexed", &f.tip("main")),
            entry("dev", "indexed", &f.tip("dev")),
        ]})
    );

    let out = f.index_with_report(&["--branches", "main,dev", "--update-branches"]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        f.report(),
        json!({ "version": 1, "branches": [
            entry("main", "current", &f.tip("main")),
            entry("dev", "current", &f.tip("dev")),
        ]})
    );

    git(&f.repo(), &["checkout", "-q", "dev"]);
    let moved = commit_file(&f.repo(), "b.c", "int b(void)\n{\n\treturn 1;\n}\n");
    let out = f.index_with_report(&["--branch", "main", "--branch", "dev", "--update-branches"]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        f.report(),
        json!({ "version": 1, "branches": [
            entry("main", "current", &f.tip("main")),
            entry("dev", "indexed", &moved),
        ]})
    );
}

#[test]
fn a_missing_branch_fails_alone() {
    let f = Fixture::new();
    let out = f.index_with_report(&["--branch", "main", "--branch", "nope", "--branch", "main"]);
    assert!(!out.status.success());

    let report = f.report();
    let branches = report["branches"].as_array().unwrap();
    assert_eq!(branches.len(), 2, "one entry per distinct name: {report}");
    assert_eq!(branches[0], entry("main", "indexed", &f.tip("main")));
    assert_eq!(branches[1]["name"], "nope");
    assert_eq!(branches[1]["outcome"], "failed");
    assert_eq!(branches[1]["commit"], Value::Null);
    assert!(branches[1]["error"].as_str().unwrap().contains("nope"));
    f.assert_no_temp_files();
}

#[test]
fn without_the_flag_a_missing_branch_no_longer_stops_the_others() {
    let f = Fixture::new();
    let out = f.index(&["--branch", "nope", "--branch", "main"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("1 of 2 branch(es) failed: nope"));

    let out = f.index_with_report(&["--branch", "main", "--update-branches"]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(f.report()["branches"][0]["outcome"], "current");
}

/// An update that fails partway keeps the previous tip, the report says
/// so, and the other branches are still indexed.
#[test]
fn a_failed_update_reports_the_previous_tip() {
    let f = Fixture::new();
    let old = f.tip("main");
    assert!(f.index(&["--branch", "main"]).status.success());
    commit_file(&f.repo(), "b.c", "int b(void)\n{\n\treturn 1;\n}\n");
    // The new tip lists b.c, but its blob cannot be read.
    let blob = git(&f.repo(), &["rev-parse", "HEAD:b.c"]);
    std::fs::remove_file(
        f.repo()
            .join(".git/objects")
            .join(&blob[..2])
            .join(&blob[2..]),
    )
    .unwrap();

    let out = f.index_with_report(&["--branches", "main,dev"]);
    assert!(!out.status.success());
    let report = f.report();
    let main = &report["branches"][0];
    assert_eq!(main["outcome"], "failed", "{report}");
    assert_eq!(main["commit"], json!(old));
    assert!(main["error"]
        .as_str()
        .unwrap()
        .contains("could not be read"));
    assert_eq!(
        report["branches"][1],
        entry("dev", "indexed", &f.tip("dev"))
    );
    assert_eq!(f.recorded_tip("main"), Some(old));
    f.assert_no_temp_files();
}

/// Build options the recorded build does not hold refuse the whole run:
/// refusing the indexed branch but reading a new branch's tree under
/// those options would rewrite the record.
#[test]
fn foreign_build_options_refuse_the_whole_run() {
    let f = Fixture::new();
    assert!(f.index(&["--branch", "main"]).status.success());
    git(&f.repo(), &["checkout", "-q", "-b", "feat"]);
    commit_file(&f.repo(), "b.c", "int b(void)\n{\n\treturn 1;\n}\n");

    std::fs::write(f.report_path(), "stale").unwrap();
    let out = f.index_with_report(&["--branches", "main,feat", "--extensions", "c"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("recorded build"));
    assert!(
        !f.report_path().exists(),
        "a refused run publishes no report"
    );
    assert_eq!(f.recorded_tip("feat"), None, "feat must not be indexed");
    f.assert_no_temp_files();
}

/// --clear wipes the index before the first branch, so a name that does
/// not resolve refuses the run instead of leaving nothing behind.
#[test]
fn clear_with_an_unknown_branch_keeps_the_index() {
    let f = Fixture::new();
    assert!(f.index(&["--branch", "main"]).status.success());

    let out = f.index_with_report(&["--clear", "--branches", "main,mian"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("refusing --clear"));
    assert!(!f.report_path().exists());
    assert_eq!(f.recorded_tip("main"), Some(f.tip("main")));
}

#[test]
fn all_branches_follow_the_named_ones_without_repeats() {
    let f = Fixture::new();
    git(&f.repo(), &["branch", "zeta"]);
    let out = f.index_with_report(&["--branch", "zeta", "--all-branches"]);
    assert!(out.status.success(), "{out:?}");
    let names: Vec<String> = f.report()["branches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, ["zeta", "dev", "main"]);
}

/// A run that stops before any branch, here on a database that will not
/// open, leaves no report, not even the previous one.
#[test]
fn a_database_that_will_not_open_leaves_no_report() {
    let f = Fixture::new();
    std::fs::write(f.db(), "not a database").unwrap();
    std::fs::write(f.report_path(), "stale").unwrap();
    let out = f.index_with_report(&["--branch", "main"]);
    assert!(!out.status.success());
    assert!(!f.report_path().exists());
    f.assert_no_temp_files();
}

#[test]
fn rejected_combinations_remove_the_old_report_and_touch_nothing() {
    let f = Fixture::new();
    let tip = f.tip("main");
    for args in [
        vec!["--branch", "main", "--git", &format!("{tip}~0..{tip}")],
        vec!["--branch", "main", "--commits", "HEAD~0..HEAD"],
        vec!["--branch", "main", "--vectors"],
        vec!["--lore", "bpf", "--vectors"],
        vec!["--lore", "bpf", "--commits", "HEAD~0..HEAD"],
        vec!["--branch", "main", "--lore", "bpf"],
        vec![],
    ] {
        std::fs::write(f.report_path(), "stale").unwrap();
        let out = f.index_with_report(&args);
        assert!(!out.status.success(), "{args:?} must be rejected");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("--result-json") || stderr.contains("--lore cannot be used"),
            "{args:?}: {out:?}"
        );
        assert!(!f.report_path().exists(), "{args:?} left a stale report");
        assert!(!f.db().exists(), "{args:?} touched the database");
    }
}

#[test]
fn an_unusable_report_path_fails_before_indexing() {
    let f = Fixture::new();
    std::fs::create_dir(f.dir.path().join("taken")).unwrap();
    for path in ["missing/result.json", "result.json/", "taken"] {
        let path = f.dir.path().join(path);
        let out = f.index(&["--branch", "main", "--result-json", path.to_str().unwrap()]);
        assert!(!out.status.success(), "{path:?} must be refused");
        assert!(!f.db().exists(), "{path:?}: indexing must not start");
        assert!(!f.report_path().exists(), "{path:?}");
    }
    assert!(f.dir.path().join("taken").is_dir());
    f.assert_no_temp_files();
}

#[test]
fn a_relative_report_path_resolves_against_the_working_directory() {
    let f = Fixture::new();
    let out = semcode_index()
        .current_dir(f.dir.path())
        .args(["--source", "repo", "--database", "index.db"])
        .args(["--branch", "main", "--result-json", "result.json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(f.report()["branches"][0]["outcome"], "indexed");
}

#[test]
fn an_empty_inventory_is_a_successful_no_op() {
    let f = Fixture::new();
    let empty = f.dir.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    git(&empty, &["init", "-q", "--initial-branch=main"]);
    let out = semcode_index()
        .arg("--source")
        .arg(&empty)
        .arg("--database")
        .arg(f.db())
        .arg("--result-json")
        .arg(f.report_path())
        .arg("--all-branches")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(f.report(), json!({ "version": 1, "branches": [] }));
}

// ==================== Lore archives ====================

/// Run `semcode-index --result-json PATH --lore LORE...`.
fn index_lore(f: &Fixture, lore: &[&str]) -> Output {
    let mut args = vec!["--lore"];
    args.extend_from_slice(lore);
    f.index_with_report(&args)
}

/// Commit one email as file `m`, the layout of a lore archive.
fn commit_email(repo: &Path, message_id: &str) {
    std::fs::write(
        repo.join("m"),
        format!(
            "From: A U Thor <author@example.org>\n\
             Date: Mon, 2 Nov 2026 10:00:00 +0000\n\
             Message-ID: {message_id}\n\
             Subject: [PATCH] test\n\
             To: list@example.org\n\
             \n\
             body\n"
        ),
    )
    .unwrap();
    git(repo, &["add", "m"]);
    git(repo, &["commit", "-q", "-m", message_id]);
}

impl Fixture {
    /// An upstream archive holding one email, cloned where docs/lore.md
    /// says archives live (`<db>/lore/<name>`), with the upstream as its
    /// origin. Returns the upstream.
    fn lore_archive(&self, name: &str) -> PathBuf {
        let upstream = self.dir.path().join("upstream").join(name);
        std::fs::create_dir_all(&upstream).unwrap();
        git(&upstream, &["init", "-q", "--initial-branch=master"]);
        commit_email(&upstream, &format!("<1@{}>", name.replace('/', ".")));
        let clone = self.db().join("lore").join(name);
        std::fs::create_dir_all(clone.parent().unwrap()).unwrap();
        git(
            self.dir.path(),
            &[
                "clone",
                "-q",
                upstream.to_str().unwrap(),
                clone.to_str().unwrap(),
            ],
        );
        upstream
    }

    /// The archives of the report in report order.
    fn archives_in_order(&self) -> Vec<(String, String)> {
        let report = self.report();
        report["archives"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                let field = |k: &str| a[k].as_str().unwrap().to_string();
                (field("name"), field("outcome"))
            })
            .collect()
    }

    /// The archives of the report by name, ignoring discovery order.
    fn archive_outcomes(&self) -> Vec<(String, String)> {
        let report = self.report();
        assert_eq!(report["version"], 1);
        assert!(report.get("branches").is_none(), "{report}");
        let mut outcomes: Vec<(String, String)> = report["archives"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                let outcome = a["outcome"].as_str().unwrap().to_string();
                assert_eq!(a.get("error").is_some(), outcome == "failed", "{a}");
                (a["name"].as_str().unwrap().to_string(), outcome)
            })
            .collect();
        outcomes.sort();
        outcomes
    }
}

fn outcomes(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(n, o)| (n.to_string(), o.to_string()))
        .collect()
}

#[test]
fn a_lore_refresh_reports_every_archive_and_fails_if_one_does() {
    let f = Fixture::new();
    let good = f.lore_archive("good/0");
    let broken = f.lore_archive("broken/0");
    std::fs::remove_dir_all(&broken).unwrap();

    let out = index_lore(&f, &[]);
    assert!(!out.status.success(), "{out:?}");
    assert_eq!(
        f.archive_outcomes(),
        outcomes(&[("broken/0", "failed"), ("good/0", "indexed")])
    );
    f.assert_no_temp_files();

    std::fs::remove_dir_all(f.db().join("lore").join("broken")).unwrap();
    let out = index_lore(&f, &[]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(f.archive_outcomes(), outcomes(&[("good/0", "current")]));

    // New mail upstream: the next refresh indexes it.
    commit_email(&good, "<2@good.0>");
    let out = index_lore(&f, &[]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(f.archive_outcomes(), outcomes(&[("good/0", "indexed")]));
}

#[test]
fn a_lore_refresh_with_no_archives_reports_an_empty_list() {
    let f = Fixture::new();
    let out = index_lore(&f, &[]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(f.report(), json!({ "version": 1, "archives": [] }));
}

#[test]
fn a_requested_archive_that_cannot_be_cloned_is_reported_by_its_request() {
    let f = Fixture::new();
    std::fs::write(f.report_path(), "stale").unwrap();
    let url = format!("{}/bpf/0.git", dead_end());
    let url = url.as_str();
    let out = index_lore(&f, &[url]);
    assert!(!out.status.success(), "{out:?}");
    assert_eq!(f.archive_outcomes(), outcomes(&[(url, "failed")]));
}

/// A URL outside lore.kernel.org maps to `<db>/lore/<list>/<n>`; an
/// archive already there is updated from its own origin, so a requested
/// list runs offline.
#[test]
fn requested_archives_report_in_request_order_once_each() {
    let f = Fixture::new();
    let upstream = f.lore_archive("good/0");
    let good = format!("{}/good/0.git", dead_end());
    let bad = format!("{}/bad/0.git", dead_end());
    let (good, bad) = (good.as_str(), bad.as_str());

    let out = index_lore(&f, &[bad, good, bad]);
    assert!(!out.status.success(), "{out:?}");
    assert_eq!(
        f.archives_in_order(),
        outcomes(&[(bad, "failed"), (good, "indexed")])
    );

    let out = index_lore(&f, &[good]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(f.archives_in_order(), outcomes(&[(good, "current")]));

    commit_email(&upstream, "<2@good.0>");
    let out = index_lore(&f, &[good, good]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(f.archives_in_order(), outcomes(&[(good, "indexed")]));
}

#[test]
fn credentials_in_a_requested_url_stay_out_of_the_report() {
    let f = Fixture::new();
    let host = dead_end().trim_start_matches("http://");
    let url = format!("http://user:s3cret@{host}/bpf/0.git");
    let out = index_lore(&f, &[&url]);
    assert!(!out.status.success(), "{out:?}");
    let text = std::fs::read_to_string(f.report_path()).unwrap();
    assert!(!text.contains("s3cret"), "{text}");
    assert_eq!(
        f.archive_outcomes(),
        outcomes(&[(&format!("http://{host}/bpf/0.git"), "failed")])
    );
}
