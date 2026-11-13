// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Thread walks over the lore table: which emails count as replies, and how
// many lookups a walk costs.
//
// A reply names its parent in In-Reply-To or References. Those headers are
// stored as they arrived, so a message-id is matched literally and as a whole
// id: `+` and `.` in it are ordinary characters, and `<a@x>` is not named by
// `<a@x.y>`. Each lookup scans the `references` column of the whole table, so
// a walk asks for one thread level at a time.
use semcode::lore_writers::{collect_thread_descendants, collect_thread_descendants_with};
use semcode::text_utils::header_names_message_id;
use semcode::{DatabaseManager, LoreEmailInfo};
use std::cell::Cell;

async fn database() -> (tempfile::TempDir, DatabaseManager) {
    let dir = tempfile::tempdir().unwrap();
    let db = DatabaseManager::new(
        dir.path().join(".semcode.db").to_str().unwrap(),
        dir.path().to_string_lossy().into_owned(),
    )
    .await
    .unwrap();
    db.create_tables().await.unwrap();
    (dir, db)
}

async fn insert(db: &DatabaseManager, emails: &[LoreEmailInfo]) {
    let known_ids = std::sync::Mutex::new(db.get_lore_message_ids().await.unwrap());
    let failed = db.insert_lore_emails(emails, &known_ids).await.unwrap();
    assert!(failed.is_empty(), "emails not stored: {failed:?}");
}

fn email(message_id: &str, in_reply_to: Option<&str>, references: Option<&str>) -> LoreEmailInfo {
    LoreEmailInfo {
        git_commit_sha: format!("sha-{message_id}"),
        from: "Someone <someone@example.org>".to_string(),
        date: "Wed, 11 Nov 2026 12:00:00 +0000".to_string(),
        date_timestamp: 1_794_398_400,
        message_id: message_id.to_string(),
        in_reply_to: in_reply_to.map(str::to_string),
        subject: format!("subject of {message_id}"),
        references: references.map(str::to_string),
        recipients: String::new(),
        body: String::new(),
        symbols: Vec::new(),
    }
}

fn ids(emails: &[LoreEmailInfo]) -> Vec<&str> {
    emails.iter().map(|e| e.message_id.as_str()).collect()
}

fn sorted(mut ids: Vec<&str>) -> Vec<&str> {
    ids.sort_unstable();
    ids
}

async fn root(db: &DatabaseManager, message_id: &str) -> LoreEmailInfo {
    db.get_lore_email_by_message_id(message_id)
        .await
        .unwrap()
        .expect("root is stored")
}

#[tokio::test]
async fn plus_and_dot_in_a_message_id_are_literal() {
    let (_dir, db) = database().await;
    let root_id = "<20261111.1+abc@x>";
    insert(
        &db,
        &[
            email(root_id, None, None),
            // Names the root only in References.
            email("<reply@x>", None, Some(root_id)),
            email("<grandchild@x>", Some("<reply@x>"), None),
            // What the root's id means as a regex: `.` any character, `1+`
            // one or more 1s. Not the root.
            email("<decoy@x>", None, Some("<20261111.1abc@x>")),
        ],
    )
    .await;

    let thread = collect_thread_descendants(&db, root(&db, root_id).await)
        .await
        .unwrap();
    assert_eq!(ids(&thread), [root_id, "<reply@x>", "<grandchild@x>"]);
}

#[tokio::test]
async fn a_dot_matches_only_a_dot() {
    let (_dir, db) = database().await;
    insert(
        &db,
        &[
            email("<a.b@x>", None, None),
            email("<unrelated@x>", Some("<axb@x>"), Some("<axb@x>")),
        ],
    )
    .await;

    let replies = db
        .get_lore_emails_referencing_any(&["<a.b@x>".to_string()])
        .await
        .unwrap();
    assert!(replies.is_empty(), "matched: {:?}", ids(&replies));

    let thread = collect_thread_descendants(&db, root(&db, "<a.b@x>").await)
        .await
        .unwrap();
    assert_eq!(ids(&thread), ["<a.b@x>"]);
}

#[tokio::test]
async fn a_walk_makes_one_lookup_per_level() {
    let (_dir, db) = database().await;
    let mut emails = vec![
        email("<root@x>", None, None),
        email("<level1@x>", Some("<root@x>"), Some("<root@x>")),
    ];
    let level2: Vec<String> = (0..40).map(|i| format!("<level2.{i}@x>")).collect();
    for id in &level2 {
        // Real replies usually list the root in References too, which puts
        // them a level up; these name only their parent.
        emails.push(email(id, Some("<level1@x>"), Some("<level1@x>")));
    }
    insert(&db, &emails).await;

    let lookups = Cell::new(0);
    let thread =
        collect_thread_descendants_with(root(&db, "<root@x>").await, async |ids: &[String]| {
            lookups.set(lookups.get() + 1);
            db.get_lore_emails_referencing_any(ids).await
        })
        .await
        .unwrap();

    // Level 1, level 2, and the empty level below it.
    assert_eq!(lookups.get(), 3);
    assert_eq!(thread.len(), 42);
    assert_eq!(ids(&thread[..2]), ["<root@x>", "<level1@x>"]);
    let mut expected: Vec<&str> = level2.iter().map(String::as_str).collect();
    expected.sort_unstable();
    assert_eq!(sorted(ids(&thread[2..])), expected);
}

#[tokio::test]
async fn quotes_and_backslashes_in_a_message_id_match() {
    let (_dir, db) = database().await;
    let root_id = r"<it's\here@x>";
    insert(
        &db,
        &[
            email(root_id, None, None),
            email("<by-in-reply-to@x>", Some(root_id), None),
            email("<by-references@x>", None, Some(root_id)),
        ],
    )
    .await;

    let thread = collect_thread_descendants(&db, root(&db, root_id).await)
        .await
        .unwrap();
    assert_eq!(
        sorted(ids(&thread)),
        ["<by-in-reply-to@x>", "<by-references@x>", root_id]
    );
}

#[tokio::test]
async fn headers_match_as_they_were_stored() {
    let (_dir, db) = database().await;
    // A Message-ID header folded onto its own line keeps the space.
    let folded = email(" <folded@x>", None, None);
    insert(
        &db,
        &[
            folded.clone(),
            email("<bare-in-reply-to@x>", Some("<folded@x>"), None),
            email("<folded-in-reply-to@x>", Some(" <folded@x>"), None),
            email("<commas@x>", None, Some("<other@x>, <folded@x>")),
            email("<glued@x>", None, Some("<other@x><folded@x>")),
            // A longer id that starts with the root's.
            email("<longer@x>", None, Some("<folded@x.y> <other@x>")),
        ],
    )
    .await;

    let thread = collect_thread_descendants(&db, folded).await.unwrap();
    assert_eq!(
        sorted(ids(&thread)),
        [
            " <folded@x>",
            "<bare-in-reply-to@x>",
            "<commas@x>",
            "<folded-in-reply-to@x>",
            "<glued@x>",
        ]
    );
}

#[tokio::test]
async fn a_lookup_of_many_ids_returns_each_reply_once() {
    let (_dir, db) = database().await;
    // More ids than one query takes, so the lookup splits them.
    let parents: Vec<String> = (0..130).map(|i| format!("<parent.{i}@x>")).collect();
    let mut emails: Vec<LoreEmailInfo> = parents
        .iter()
        .enumerate()
        .map(|(i, parent)| email(&format!("<reply.{i}@x>"), Some(parent), None))
        .collect();
    // Answers parents that land in different queries.
    emails.push(email(
        "<both@x>",
        Some("<parent.0@x>"),
        Some("<parent.0@x> <parent.129@x>"),
    ));
    insert(&db, &emails).await;

    let replies = db.get_lore_emails_referencing_any(&parents).await.unwrap();
    assert_eq!(replies.len(), 131);
    let mut expected: Vec<&str> = emails.iter().map(|e| e.message_id.as_str()).collect();
    expected.sort_unstable();
    assert_eq!(sorted(ids(&replies)), expected);
}

#[tokio::test]
async fn a_level_lists_in_reply_to_answers_before_references_ones() {
    let (_dir, db) = database().await;
    insert(
        &db,
        &[
            email("<root@x>", None, None),
            email("<first@x>", Some("<root@x>"), Some("<root@x>")),
            email("<by-references@x>", None, Some("<root@x> <first@x>")),
            email("<second@x>", Some("<root@x>"), Some("<root@x>")),
            email("<under-first@x>", Some("<first@x>"), Some("<first@x>")),
        ],
    )
    .await;

    // `<by-references@x>` names the root in References, so it belongs to
    // level 1, after the root's In-Reply-To answers.
    let thread = collect_thread_descendants(&db, root(&db, "<root@x>").await)
        .await
        .unwrap();
    assert_eq!(
        ids(&thread),
        [
            "<root@x>",
            "<first@x>",
            "<second@x>",
            "<by-references@x>",
            "<under-first@x>",
        ]
    );
}

#[tokio::test]
async fn an_email_answering_two_messages_of_a_level_is_placed_under_the_first() {
    let (_dir, db) = database().await;
    insert(
        &db,
        &[
            email("<root@x>", None, None),
            email("<a@x>", Some("<root@x>"), Some("<root@x>")),
            email("<b@x>", Some("<root@x>"), Some("<root@x>")),
            // Stored in an order that neither table order nor "In-Reply-To
            // answers of every parent first" reproduces.
            email("<under-b@x>", Some("<b@x>"), Some("<b@x>")),
            // Answers `<b@x>` by In-Reply-To and `<a@x>` by References.
            email("<both@x>", Some("<b@x>"), Some("<a@x>")),
            email("<under-a@x>", Some("<a@x>"), Some("<a@x>")),
        ],
    )
    .await;

    // Level 2 follows level 1's order, `<a@x>` then `<b@x>`: under `<a@x>`
    // its In-Reply-To answer, then `<both@x>` by References; under `<b@x>`
    // only what is left.
    let thread = collect_thread_descendants(&db, root(&db, "<root@x>").await)
        .await
        .unwrap();
    assert_eq!(
        ids(&thread),
        [
            "<root@x>",
            "<a@x>",
            "<b@x>",
            "<under-a@x>",
            "<both@x>",
            "<under-b@x>",
        ]
    );
}

#[test]
fn header_names_only_whole_message_ids() {
    let names = header_names_message_id;
    assert!(names("<a@x>", "<a@x>"));
    assert!(names("<a@x>", " <a@x> "));
    assert!(names(
        "<a@x> (Someone's message of \"Wed, 11 Nov 2026\")",
        "<a@x>"
    ));
    assert!(names("<b@x>\t<a@x>", "<a@x>"));
    assert!(!names("<a@x.y>", "<a@x>"));
    assert!(!names("<za@x>", "a@x>"));
    // Ids without angle brackets still need a separator on each side.
    assert!(names("a@x.y a@x", "a@x"));
    assert!(!names("a@x.y", "a@x"));
    assert!(!names("<a@x>", ""));
    assert!(!names("<a@x>", "   "));
}
