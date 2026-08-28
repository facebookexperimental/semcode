// SPDX-License-Identifier: MIT OR Apache-2.0
//
// End to end: index a small tree, then ask the questions a user asks.
//
// The pieces are unit tested individually, but the thing that has to work is
// the whole path — extraction, storage, revision filtering and the join —
// and only indexing real files exercises it.
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use semcode::{git, DatabaseManager};

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

/// A tree shaped like the kernel's protocol dispatch: a handler installed in
/// a struct member by a compound literal inside a function, and a call site
/// that goes through that member inside an indirect-call macro.
fn write_fixture(repo: &Path) {
    std::fs::write(
        repo.join("proto.h"),
        "struct sk_buff;\n\
         struct net_protocol {\n\
         \tint (*handler)(struct sk_buff *skb);\n\
         \tint no_policy;\n\
         };\n\
         struct hotdata { struct net_protocol tcp_protocol; };\n\
         struct inet_stack { struct net_protocol *proto; };\n",
    )
    .unwrap();

    // A callback installed through a field of a declared object, which is
    // how every per-superblock, per-mount and per-pool shrinker is
    // registered. The container type is not in this file: `s_shrink` is
    // declared with struct super_block, in the header.
    std::fs::write(
        repo.join("shrinker.h"),
        "struct shrink_control;\n\
         struct shrinker {\n\
         \tunsigned long (*scan_objects)(struct shrinker *, struct shrink_control *);\n\
         };\n\
         struct super_block { struct shrinker *s_shrink; };\n",
    )
    .unwrap();

    std::fs::write(
        repo.join("super.c"),
        "#include \"shrinker.h\"\n\
         unsigned long super_cache_scan(struct shrinker *shrink,\n\
         \t\t\t       struct shrink_control *sc);\n\
         int alloc_super(struct super_block *s)\n\
         {\n\
         \ts->s_shrink->scan_objects = super_cache_scan;\n\
         \treturn 0;\n\
         }\n",
    )
    .unwrap();

    std::fs::write(
        repo.join("shrinker.c"),
        "#include \"shrinker.h\"\n\
         unsigned long do_shrink_slab(struct shrinker *shrinker,\n\
         \t\t\t     struct shrink_control *sc)\n\
         {\n\
         \treturn shrinker->scan_objects(shrinker, sc);\n\
         }\n\
         unsigned long shrink_slab_all(struct shrinker *shrinker,\n\
         \t\t\t      struct shrink_control *sc)\n\
         {\n\
         \treturn do_shrink_slab(shrinker, sc);\n\
         }\n",
    )
    .unwrap();

    // Four links: the container of the member is three field lookups from
    // the only name the calling file declares. Both the registration and the
    // dispatch have to walk the same path.
    std::fs::write(
        repo.join("deep.h"),
        "struct leaf_ops { int (*run)(void); };\n\
         struct level3 { struct leaf_ops *ops; };\n\
         struct level2 { struct level3 *l3; };\n\
         struct level1 { struct level2 *l2; };\n",
    )
    .unwrap();

    std::fs::write(
        repo.join("deep_install.c"),
        "#include \"deep.h\"\n\
         int deep_impl(void);\n\
         int install_deep(struct level1 *top)\n\
         {\n\
         \ttop->l2->l3->ops->run = deep_impl;\n\
         \treturn 0;\n\
         }\n",
    )
    .unwrap();

    std::fs::write(
        repo.join("deep_call.c"),
        "#include \"deep.h\"\n\
         int call_deep(struct level1 *top)\n\
         {\n\
         \treturn top->l2->l3->ops->run();\n\
         }\n",
    )
    .unwrap();

    std::fs::write(
        repo.join("tcp.c"),
        "#include \"proto.h\"\n\
         int tcp_v4_rcv(struct sk_buff *skb) { return 0; }\n",
    )
    .unwrap();

    // Installed in a member, and the only call through that member is on a
    // receiver nothing declares. There is no typed site to show, so the
    // question is what a section says when it has candidates and no answers.
    std::fs::write(
        repo.join("quirk.h"),
        "struct quirk_ops { void (*fixup)(void); };\n",
    )
    .unwrap();

    std::fs::write(
        repo.join("quirk_install.c"),
        "#include \"quirk.h\"\n\
         void quirk_impl(void) { }\n\
         static struct quirk_ops quirk_table = { .fixup = quirk_impl };\n",
    )
    .unwrap();

    std::fs::write(
        repo.join("quirk_call.c"),
        "#include \"quirk.h\"\n\
         void apply_quirk(void)\n\
         {\n\
         \tunknown_table->fixup();\n\
         }\n",
    )
    .unwrap();

    // The registration: a compound literal assigned to a member, inside a
    // function, which is how net/ipv4/af_inet.c writes it.
    std::fs::write(
        repo.join("af_inet.c"),
        "#include \"proto.h\"\n\
         int tcp_v4_rcv(struct sk_buff *skb);\n\
         static struct hotdata net_hotdata;\n\
         static int inet_init(void)\n\
         {\n\
         \tnet_hotdata.tcp_protocol = (struct net_protocol) {\n\
         \t\t.handler = tcp_v4_rcv,\n\
         \t\t.no_policy = 1,\n\
         \t};\n\
         \treturn 0;\n\
         }\n",
    )
    .unwrap();

    // The call site, wrapped in the macro the kernel uses to name its likely
    // targets.
    std::fs::write(
        repo.join("ip_input.c"),
        "#include \"proto.h\"\n\
         int tcp_v4_rcv(struct sk_buff *skb);\n\
         int udp_rcv(struct sk_buff *skb);\n\
         static void ip_protocol_deliver_rcu(const struct net_protocol *ipprot,\n\
         \t\t\t\t    struct sk_buff *skb)\n\
         {\n\
         \tINDIRECT_CALL_2(ipprot->handler, tcp_v4_rcv, udp_rcv, skb);\n\
         }\n\
         int deliver_plain(const struct net_protocol *ipprot, struct sk_buff *skb)\n\
         {\n\
         \treturn ipprot->handler(skb);\n\
         }\n\
         int deliver_untyped(struct sk_buff *skb)\n\
         {\n\
         \treturn proto_table->handler(skb);\n\
         }\n\
         int deliver_chained(struct inet_stack *stack, struct sk_buff *skb)\n\
         {\n\
         \treturn stack->proto->handler(skb);\n\
         }\n",
    )
    .unwrap();
}

async fn index_fixture(repo: &Path) -> (Arc<DatabaseManager>, String) {
    git_run(repo, &["init", "-q"]);
    write_fixture(repo);
    git_run(repo, &["add", "."]);
    git_run(repo, &["commit", "-q", "-m", "fixture"]);

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
    )
    .await
    .unwrap();

    (db, git_sha)
}

#[tokio::test]
async fn a_handler_reached_only_through_a_pointer_has_callers() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_fixture(dir.path()).await;

    // Nothing calls it by name: that is the complaint this work answers.
    let direct = db
        .get_function_callers_git_aware("tcp_v4_rcv", &git_sha)
        .await
        .unwrap();
    assert!(
        direct.is_empty(),
        "expected no direct callers, got {direct:?}"
    );

    let indirect = db
        .find_indirect_callers("tcp_v4_rcv", &git_sha)
        .await
        .unwrap();
    let named_at_site: Vec<_> = indirect
        .iter()
        .filter(|c| c.evidence.is_type_matched())
        .collect();

    // Two sites reach it on the evidence of a type: the macro names it, and
    // the plain member call is on a receiver this file declares as the
    // struct the function is installed in.
    let named: Vec<&str> = named_at_site
        .iter()
        .map(|caller| caller.caller_name.as_str())
        .collect();
    assert_eq!(
        named,
        vec![
            "deliver_chained",
            "deliver_plain",
            "ip_protocol_deliver_rcu"
        ],
        "expected every typed candidate, got {indirect:?}"
    );
    assert!(named_at_site
        .iter()
        .all(|caller| caller.site_file == "ip_input.c" && caller.member == "handler"));

    // The chained receiver `stack->proto` is typed by what the field is
    // declared as, which is in the header rather than in the calling file.
    assert!(
        named.contains(&"deliver_chained"),
        "field chain not resolved through the types table: {indirect:?}"
    );

    // The call on a receiver the file never declares matches by member name
    // alone; it stays weaker evidence, and says so rather than being dropped.
    let by_member: Vec<_> = indirect
        .iter()
        .filter(|c| !c.evidence.is_type_matched())
        .collect();
    assert!(
        by_member.iter().any(|c| c.caller_name == "deliver_untyped"),
        "member call missing from the weaker matches: {indirect:?}"
    );
}

#[tokio::test]
async fn the_registration_is_found_where_the_source_writes_it() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_fixture(dir.path()).await;

    let installed = db
        .find_registrations_of_git_aware("tcp_v4_rcv", &git_sha)
        .await
        .unwrap();

    assert_eq!(
        installed.len(),
        1,
        "expected one registration: {installed:?}"
    );
    assert_eq!(installed[0].container_type, "net_protocol");
    assert_eq!(installed[0].member, "handler");
    assert_eq!(installed[0].file_path, "af_inet.c");
    // Written inside a function, not at file scope.
    assert_eq!(installed[0].enclosing_function, "inet_init");

    let in_slot = db
        .find_registrations_for_slot_git_aware("net_protocol", "handler", &git_sha)
        .await
        .unwrap();
    assert_eq!(in_slot.len(), 1);
    assert_eq!(in_slot[0].target, "tcp_v4_rcv");
}

#[tokio::test]
async fn a_function_installed_nowhere_reports_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_fixture(dir.path()).await;

    // udp_rcv is declared and named by the macro, but never installed.
    let installed = db
        .find_registrations_of_git_aware("udp_rcv", &git_sha)
        .await
        .unwrap();
    assert!(
        installed.is_empty(),
        "registered without an initializer: {installed:?}"
    );

    // A function that does not exist at all answers nothing, rather than
    // everything.
    let missing = db
        .find_indirect_callers("no_such_function", &git_sha)
        .await
        .unwrap();
    assert!(missing.is_empty(), "invented callers: {missing:?}");
}

#[tokio::test]
async fn the_member_call_is_not_recorded_as_a_call_to_a_function() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_fixture(dir.path()).await;

    // `ipprot->handler(skb)` names a member, not a function. Recording it as
    // a callee is what made call chains resolve to whatever function happened
    // to share the name.
    let callees = db
        .get_function_callees_git_aware("deliver_plain", &git_sha)
        .await
        .unwrap();

    assert!(
        !callees.contains(&"handler".to_string()),
        "member name recorded as a callee: {callees:?}"
    );
}

#[tokio::test]
async fn a_callback_installed_through_a_field_has_callers() {
    // `s->s_shrink->scan_objects = super_cache_scan` names no container: what
    // `s_shrink` points at is declared with struct super_block, elsewhere. The
    // registration is recorded with the path and resolved at query time, or
    // the function appears to have no callers at all.
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_fixture(dir.path()).await;

    let registrations = db
        .find_registrations_of_git_aware("super_cache_scan", &git_sha)
        .await
        .unwrap();
    assert_eq!(registrations.len(), 1, "{registrations:?}");
    assert_eq!(registrations[0].container_type, "shrinker");
    assert_eq!(registrations[0].member, "scan_objects");

    let indirect = db
        .find_indirect_callers("super_cache_scan", &git_sha)
        .await
        .unwrap();
    let typed: Vec<&str> = indirect
        .iter()
        .filter(|c| c.evidence.is_type_matched())
        .map(|c| c.caller_name.as_str())
        .collect();
    assert!(
        typed.contains(&"do_shrink_slab"),
        "the dispatch that reaches it is missing: {indirect:?}"
    );

    let installed = db
        .find_registrations_for_slot_git_aware("shrinker", "scan_objects", &git_sha)
        .await
        .unwrap();
    assert!(
        installed.iter().any(|r| r.target == "super_cache_scan"),
        "implementors misses a registration made through a field: {installed:?}"
    );
}

#[tokio::test]
async fn a_path_of_three_fields_resolves_on_both_sides() {
    // `top->l2->l3->ops->run` is three lookups from the only declared name,
    // on the registration and on the dispatch. One hop was covered; the walk
    // itself was not.
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_fixture(dir.path()).await;

    let registrations = db
        .find_registrations_of_git_aware("deep_impl", &git_sha)
        .await
        .unwrap();
    assert_eq!(registrations.len(), 1, "{registrations:?}");
    assert_eq!(
        registrations[0].container_type, "leaf_ops",
        "the walk stopped short: {registrations:?}"
    );

    let indirect = db
        .find_indirect_callers("deep_impl", &git_sha)
        .await
        .unwrap();
    let typed: Vec<&str> = indirect
        .iter()
        .filter(|c| c.evidence.is_type_matched())
        .map(|c| c.caller_name.as_str())
        .collect();
    assert!(
        typed.contains(&"call_deep"),
        "a dispatch three fields deep was not matched: {indirect:?}"
    );
}

#[tokio::test]
async fn a_callback_reached_only_through_a_pointer_has_a_chain_above_it() {
    // A shrinker callback is called by nobody and reached by everybody. Built
    // from calls alone the reverse chain renders it as a root, so `callers`
    // named the dispatch while `callchain` reported none, from one index. The
    // chain continues above the dispatching function.
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_fixture(dir.path()).await;

    let mut rendered = Vec::new();
    let reach = semcode::callchain::write_indirect_reverse_chain(
        &db,
        "super_cache_scan",
        &git_sha,
        2,
        10,
        &mut rendered,
    )
    .await
    .unwrap();
    let text = String::from_utf8(rendered).unwrap();

    assert!(reach.shown >= 1, "no dispatching site shown: {text}");
    assert!(
        text.contains("do_shrink_slab"),
        "the dispatch is missing: {text}"
    );
    assert!(
        text.contains("shrink_slab_all"),
        "the chain above the dispatch is missing: {text}"
    );
}

#[tokio::test]
async fn a_function_with_ordinary_callers_gets_no_pointer_chain() {
    // The section is for what calls cannot show. A function called by name
    // has nothing to add here, and an empty heading is a wrong answer.
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_fixture(dir.path()).await;

    let mut rendered = Vec::new();
    let reach = semcode::callchain::write_indirect_reverse_chain(
        &db,
        "do_shrink_slab",
        &git_sha,
        2,
        10,
        &mut rendered,
    )
    .await
    .unwrap();

    assert!(reach.is_empty(), "{reach:?}");
    assert!(
        rendered.is_empty(),
        "{}",
        String::from_utf8_lossy(&rendered)
    );
}

#[tokio::test]
async fn a_member_name_match_does_not_crowd_out_a_typed_one() {
    // The section never applied the confidence filter the other commands do,
    // and the rows are ordered by the dispatching function's name. Any weak
    // row sorting early took a place from a real answer: can_rcv is installed
    // in packet_type::func, and the fifteen rows shown were bcache work items
    // and amdgpu register macros dispatching through some other ::func, with
    // every site that receives a CAN frame past the end of the list.
    //
    // Here `deliver_untyped` calls `proto_table->handler` on a receiver
    // nothing declares, and sorts ahead of the macro that names tcp_v4_rcv
    // outright.
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_fixture(dir.path()).await;

    let mut rendered = Vec::new();
    let reach = semcode::callchain::write_indirect_reverse_chain(
        &db,
        "tcp_v4_rcv",
        &git_sha,
        2,
        3,
        &mut rendered,
    )
    .await
    .unwrap();
    let text = String::from_utf8(rendered).unwrap();

    assert_eq!(reach.shown, 3, "{text}");
    for dispatching in [
        "deliver_chained",
        "deliver_plain",
        "ip_protocol_deliver_rcu",
    ] {
        assert!(text.contains(dispatching), "{dispatching} missing: {text}");
    }
    assert!(
        !text.contains("deliver_untyped"),
        "a member-name match took a row: {text}"
    );

    // Dropped from the list, not from the answer.
    assert!(reach.noted >= 1, "{reach:?}");
    assert!(
        text.contains("go through a member of the same name"),
        "the weaker matches were dropped silently: {text}"
    );
}

#[tokio::test]
async fn weak_evidence_alone_still_gets_a_heading() {
    // quirk_impl is installed in quirk_ops::fixup, and the one call through
    // `fixup` is on a receiver nothing declares. Nothing can be shown with a
    // chain above it, and saying nothing at all would claim the index knows of
    // no way in when it knows of one it cannot stand behind.
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_fixture(dir.path()).await;

    let mut rendered = Vec::new();
    let reach = semcode::callchain::write_indirect_reverse_chain(
        &db,
        "quirk_impl",
        &git_sha,
        2,
        10,
        &mut rendered,
    )
    .await
    .unwrap();
    let text = String::from_utf8(rendered).unwrap();

    assert_eq!(reach.shown, 0, "{text}");
    assert_eq!(reach.noted, 1, "{text}");
    assert!(!reach.is_empty(), "{reach:?}");
    assert!(text.contains("Reverse Chain"), "{text}");
    assert!(
        text.contains("1 call sites go through a member of the same name"),
        "the count claims something was listed above it: {text}"
    );
    assert!(
        !text.contains("apply_quirk"),
        "a member-name match was shown as an answer: {text}"
    );
}
