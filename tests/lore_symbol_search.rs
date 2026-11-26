// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Field-filtered lore search over the symbols an email's patch touches.
//
// A symbols pattern is one more field filter: it selects the emails whose
// extracted symbols match, and it is ANDed with the other fields like any of
// them. It must reach the query, or a symbols-only search finds nothing and a
// combined search answers as though only the other fields had been asked.
use semcode::{DatabaseManager, LoreEmailInfo};

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
    let outcome = db.insert_lore_emails(emails, &known_ids).await.unwrap();
    assert!(outcome.is_complete(), "emails not stored: {outcome:?}");
    db.create_lore_fts_indices().await.unwrap();
}

fn email(message_id: &str, subject: &str, symbols: &[&str]) -> LoreEmailInfo {
    let body = symbols
        .iter()
        .map(|s| format!("@@ -1,3 +1,4 @@ {s}(void)\n"))
        .collect::<String>();
    LoreEmailInfo {
        git_commit_sha: format!("sha-{message_id}"),
        from: "Someone <someone@example.org>".to_string(),
        date: "Wed, 11 Nov 2026 12:00:00 +0000".to_string(),
        date_timestamp: 1_794_398_400,
        message_id: message_id.to_string(),
        in_reply_to: None,
        subject: subject.to_string(),
        references: None,
        recipients: String::new(),
        body,
        symbols: symbols.iter().map(|s| s.to_string()).collect(),
    }
}

/// Four emails: a networking patch touching netif_receive_skb, a
/// networking patch touching something else, an unrelated patch touching
/// netif_receive_skb, and a networking reply that names netif_receive_skb
/// in its text but carries no patch, so has no symbols.
async fn populated() -> (tempfile::TempDir, DatabaseManager) {
    let (dir, db) = database().await;
    insert(
        &db,
        &[
            email(
                "<net-rx@x>",
                "[PATCH] networking: fix rx path",
                &["netif_receive_skb", "napi_poll"],
            ),
            email(
                "<net-tx@x>",
                "[PATCH] networking: fix tx path",
                &["dev_queue_xmit"],
            ),
            email(
                "<mm@x>",
                "[PATCH] mm: unrelated change",
                &["netif_receive_skb"],
            ),
            LoreEmailInfo {
                body: "Does this still hold for netif_receive_skb?\n".to_string(),
                ..email("<net-reply@x>", "Re: [PATCH] networking: fix rx path", &[])
            },
        ],
    )
    .await;
    (dir, db)
}

async fn search(db: &DatabaseManager, fields: Vec<(&str, &str)>) -> Vec<String> {
    let mut ids: Vec<String> = db
        .search_lore_emails_multi_field(fields, 0, None, None)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.message_id)
        .collect();
    ids.sort_unstable();
    ids
}

#[tokio::test]
async fn a_symbols_only_search_finds_the_emails_touching_the_symbol() {
    let (_dir, db) = populated().await;
    assert_eq!(
        search(&db, vec![("symbols", "netif_receive_skb")]).await,
        ["<mm@x>", "<net-rx@x>"]
    );
}

#[tokio::test]
async fn subject_and_symbols_must_both_match() {
    let (_dir, db) = populated().await;
    assert_eq!(
        search(
            &db,
            vec![("subject", "networking"), ("symbols", "netif_receive_skb")]
        )
        .await,
        ["<net-rx@x>"]
    );
}

#[tokio::test]
async fn emails_without_the_symbol_are_excluded() {
    let (_dir, db) = populated().await;
    // The reply mentions netif_receive_skb in its body and matches the
    // subject, but the symbol is not among its symbols.
    assert_eq!(
        search(
            &db,
            vec![("subject", "networking"), ("symbols", "netif_receive_skb")]
        )
        .await,
        ["<net-rx@x>"]
    );
    assert_eq!(
        search(&db, vec![("symbols", "dev_queue_xmit")]).await,
        ["<net-tx@x>"]
    );
    assert!(search(&db, vec![("symbols", "no_such_symbol")])
        .await
        .is_empty());
}
