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

/// A handler that reaches the hardware only because a registrar was handed
/// its name, which is how every driver installs an interrupt handler. The
/// registrar is a wrapper, as it is in the kernel: request_irq stores nothing
/// itself, it hands its parameter to request_threaded_irq.
fn write_argument_fixture(repo: &Path) {
    std::fs::write(
        repo.join("irq.h"),
        "typedef int (*irq_handler_t)(int irq, void *dev);\n\
         struct irqaction { irq_handler_t handler; };\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("irq.c"),
        "#include \"irq.h\"\n\
         int request_threaded_irq(unsigned int irq, irq_handler_t handler)\n\
         {\n\
         \tstruct irqaction *action = alloc_action();\n\
         \taction->handler = handler;\n\
         \treturn 0;\n\
         }\n\
         int request_irq(unsigned int irq, irq_handler_t handler)\n\
         {\n\
         \treturn request_threaded_irq(irq, handler);\n\
         }\n",
    )
    .unwrap();
    // An ops table declared in a header and dispatched from a file that
    // includes it: the calling file cannot type the receiver.
    std::fs::write(
        repo.join("delay.h"),
        "struct arm_delay_ops { void (*delay)(unsigned long); };\n\
         extern struct arm_delay_ops arm_delay_ops;\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("delay.c"),
        "#include \"delay.h\"\n\
         static void loop_delay(unsigned long n) { }\n\
         struct arm_delay_ops arm_delay_ops = { .delay = loop_delay };\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("use_delay.c"),
        "#include \"delay.h\"\n\
         void spin(unsigned long n)\n\
         {\n\
         \tarm_delay_ops.delay(n);\n\
         }\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("rcu.c"),
        "struct rcu_head { void (*func)(struct rcu_head *head); };\n\
         struct inode { int i_state; struct rcu_head i_rcu; };\n\
         static void i_callback(struct rcu_head *head) { }\n\
         void call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *))\n\
         {\n\
         \thead->func = func;\n\
         }\n\
         static void destroy_inode(struct inode *inode)\n\
         {\n\
         \tcall_rcu(&inode->i_rcu, i_callback);\n\
         }\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("nic.c"),
        "#include \"irq.h\"\n\
         static int nic_intr(int irq, void *dev) { return 0; }\n\
         static int nic_open(void *dev)\n\
         {\n\
         \tunsigned long flags = 0;\n\
         \treturn request_irq(16, nic_intr);\n\
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

async fn index_argument_fixture(repo: &Path) -> (Arc<DatabaseManager>, String) {
    git_run(repo, &["init", "-q"]);
    write_argument_fixture(repo);
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
async fn a_function_handed_to_a_call_is_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_argument_fixture(dir.path()).await;

    let handed = db.find_argument_functions_of("nic_intr").await.unwrap();
    assert_eq!(
        handed.len(),
        1,
        "expected one call handed nic_intr, got {handed:?}"
    );
    assert_eq!(handed[0].callee, "request_irq");
    assert_eq!(handed[0].argument_index, 1);
    assert_eq!(handed[0].enclosing_function, "nic_open");
    assert!(!handed[0].taken_address);

    // `flags` is a local, so naming it is not handing over a function, even
    // where some other tree defines a function of that name.
    let local = db.find_argument_functions_of("flags").await.unwrap();
    assert!(local.is_empty(), "a local was recorded: {local:?}");

    // An RCU callback is attached to the object holding the head, which is
    // the only place that says which type the callback frees.
    let rcu = db.find_argument_functions_of("i_callback").await.unwrap();
    assert_eq!(rcu.len(), 1, "{rcu:?}");
    assert_eq!(
        rcu[0].subject_type.as_deref(),
        Some("inode"),
        "{:?}",
        rcu[0]
    );
    assert_eq!(
        rcu[0].subject_member.as_deref(),
        Some("i_rcu"),
        "{:?}",
        rcu[0]
    );

    // The identifier has to name a function: an enum constant in the same
    // argument position does not.
    let constant = db
        .find_argument_functions_of_git_aware("16", &git_sha)
        .await
        .unwrap();
    assert!(constant.is_empty(), "a constant was reported: {constant:?}");

    let mut output = Vec::new();
    semcode::callchain::show_registrations_to_writer(&db, "nic_intr", &mut output, &git_sha)
        .await
        .unwrap();
    let output = plain(&String::from_utf8(output).unwrap());
    assert!(
        output.contains("request_irq") && output.contains("nic_open"),
        "registrations did not report the handover:\n{output}"
    );

    // The wrapper installs nothing itself, so saying where the handler ends
    // up means following it into request_threaded_irq.
    assert!(
        output.contains("irqaction::handler"),
        "the handover was not followed to a member:\n{output}"
    );

    // Both hops stay visible: a two-hop claim that reads like a one-hop fact
    // is worse than no answer. Each hop names the file and line its body was
    // read from, because a name can have several definitions and a route
    // through one of them is only checkable if it says which.
    assert!(
        output.contains(
            "request_irq(handler) at irq.c:8 -> request_threaded_irq(handler) at irq.c:2"
        ),
        "the route was not reported with the definitions it was read from:\n{output}"
    );

    // Installing is not calling: the handler runs when an interrupt arrives,
    // and a reader reasoning about a race needs that said out loud.
    assert!(
        output.contains("called later"),
        "the timing was not reported:\n{output}"
    );

    // The call passes `netdev->name` too, and the handler has nothing to do
    // with it: only an object holding what the callee stored is the subject.
    assert!(
        !output.contains("attached to"),
        "an unrelated argument was reported as the subject:\n{output}"
    );

    let mut output = Vec::new();
    semcode::callchain::show_registrations_to_writer(&db, "i_callback", &mut output, &git_sha)
        .await
        .unwrap();
    let output = plain(&String::from_utf8(output).unwrap());
    assert!(
        output.contains("attached to inode::i_rcu"),
        "the rcu_head's owner was not reported:\n{output}"
    );
}

#[tokio::test]
async fn a_receiver_declared_in_a_header_is_typed() {
    let dir = tempfile::tempdir().unwrap();
    let (db, git_sha) = index_argument_fixture(dir.path()).await;

    // `arm_delay_ops.delay(n)` is written where only the header declares the
    // variable, so the type comes from the index rather than the file.
    let callers = db
        .find_indirect_callers("loop_delay", &git_sha)
        .await
        .unwrap();
    let matched: Vec<_> = callers
        .iter()
        .filter(|c| c.evidence.is_type_matched())
        .collect();
    assert_eq!(
        matched.len(),
        1,
        "expected the header-declared receiver to match: {callers:?}"
    );
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
    let shown = semcode::callchain::write_indirect_reverse_chain(
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

    assert!(shown >= 1, "no dispatching site shown: {text}");
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
    let shown = semcode::callchain::write_indirect_reverse_chain(
        &db,
        "do_shrink_slab",
        &git_sha,
        2,
        10,
        &mut rendered,
    )
    .await
    .unwrap();

    assert_eq!(shown, 0);
    assert!(
        rendered.is_empty(),
        "{}",
        String::from_utf8_lossy(&rendered)
    );
}

#[tokio::test]
async fn the_subject_survives_a_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let db = DatabaseManager::new(
        dir.path().join(".semcode.db").to_str().unwrap(),
        dir.path().to_string_lossy().into_owned(),
    )
    .await
    .unwrap();
    db.create_tables().await.unwrap();

    db.insert_argument_functions(vec![semcode::ArgumentFunction {
        target: "i_callback".to_string(),
        callee: "call_rcu".to_string(),
        argument_index: 1,
        taken_address: false,
        subject_type: Some("inode".to_string()),
        subject_member: Some("i_rcu".to_string()),
        file_path: "rcu.c".to_string(),
        git_file_hash: "hash".to_string(),
        byte_start: 178,
        line: 5,
        enclosing_function: "destroy_inode".to_string(),
    }])
    .await
    .unwrap();

    let back = db.find_argument_functions_of("i_callback").await.unwrap();
    assert_eq!(back.len(), 1, "{back:?}");
    assert_eq!(
        back[0].subject_type.as_deref(),
        Some("inode"),
        "{:?}",
        back[0]
    );
}
