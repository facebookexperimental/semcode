// SPDX-License-Identifier: MIT OR Apache-2.0
//! Writer-based functions for lore email output
//! These are shared between the CLI (with file output) and MCP (with string buffers)

use anyhow::Result;
use std::collections::{HashSet, VecDeque};
use std::io::Write;

use crate::DatabaseManager;

/// Sort emails by date (oldest first) using RFC 2822 date parsing
pub fn sort_emails_by_date(emails: &mut [crate::types::LoreEmailInfo]) {
    emails.sort_by(|a, b| {
        use chrono::DateTime;
        let a_parsed = DateTime::parse_from_rfc2822(&a.date);
        let b_parsed = DateTime::parse_from_rfc2822(&b.date);

        match (a_parsed, b_parsed) {
            (Ok(a_time), Ok(b_time)) => a_time.cmp(&b_time),
            // If parsing fails, fall back to string comparison
            _ => a.date.cmp(&b.date),
        }
    });
}

/// Show full email thread for a given message_id (writer version)
pub async fn lore_show_thread_to_writer(
    db: &DatabaseManager,
    message_id: &str,
    verbose: usize,
    writer: &mut dyn Write,
) -> Result<()> {
    writeln!(writer, "Finding thread root for message: {}", message_id)?;

    // Step 1: Walk up the in_reply_to chain to find the root message
    let mut current_email = match db.get_lore_email_by_message_id(message_id).await? {
        Some(email) => email,
        None => {
            writeln!(
                writer,
                "Error: Email not found with message_id: {}",
                message_id
            )?;
            return Ok(());
        }
    };

    let mut seen_during_walk_up = HashSet::new();
    seen_during_walk_up.insert(current_email.message_id.clone());

    // Walk up the reply chain until we find the root (no in_reply_to)
    while let Some(ref in_reply_to) = current_email.in_reply_to {
        // Avoid infinite loops in case of circular references
        if seen_during_walk_up.contains(in_reply_to) {
            break;
        }

        match db.get_lore_email_by_message_id(in_reply_to).await? {
            Some(parent_email) => {
                seen_during_walk_up.insert(parent_email.message_id.clone());
                current_email = parent_email;
            }
            None => {
                // Parent message not found in database, use current as root
                break;
            }
        }
    }

    let root_message_id = current_email.message_id.clone();
    writeln!(writer, "Found thread root: {}\n", root_message_id)?;

    // Step 2: Now walk down from root to collect all messages in thread
    let mut all_emails = Vec::new();
    let mut seen_message_ids = HashSet::new();
    let mut to_process = VecDeque::new();

    // Add root email to seen set and processing queue
    seen_message_ids.insert(current_email.message_id.clone());
    to_process.push_back(current_email.message_id.clone());
    all_emails.push(current_email);

    // Recursively find all messages that reply to messages in this thread
    while let Some(current_message_id) = to_process.pop_front() {
        // Find all emails that reference this message
        let referencing_emails = db.get_lore_emails_referencing(&current_message_id).await?;

        for email in referencing_emails {
            // Add to seen set immediately to avoid duplicate processing
            if !seen_message_ids.insert(email.message_id.clone()) {
                // Already seen this message, skip it
                continue;
            }

            // Add to processing queue and results
            to_process.push_back(email.message_id.clone());
            all_emails.push(email);
        }
    }

    // Sort emails in thread order (respecting reply structure, then by date)
    let sorted_emails = crate::search::sort_emails_by_thread_order(&all_emails);

    writeln!(
        writer,
        "Thread: Found {} message(s) in thread:\n",
        all_emails.len()
    )?;

    // Display all emails in the thread
    for (idx, email) in sorted_emails.iter().enumerate() {
        writeln!(writer, "{}. {} - {}", idx + 1, email.date, email.subject)?;

        // Always show database column headers
        writeln!(writer, "   From: {}", email.from)?;
        writeln!(writer, "   Message-ID: {}", email.message_id)?;

        if let Some(ref in_reply_to) = email.in_reply_to {
            writeln!(writer, "   In-Reply-To: {}", in_reply_to)?;
        }

        if let Some(ref references) = email.references {
            writeln!(writer, "   References: {}", references)?;
        }

        if !email.recipients.is_empty() {
            writeln!(writer, "   Recipients: {}", email.recipients)?;
        }

        if verbose >= 1 {
            writeln!(writer, "\n   --- Message Body ---")?;
            for line in email.body.lines() {
                writeln!(writer, "   {}", line)?;
            }
            writeln!(writer, "   --- End Message ---")?;
        }

        writeln!(writer)?;
    }

    Ok(())
}

/// Show all replies/subthreads under a given message (writer version)
pub async fn lore_show_replies_to_writer(
    db: &DatabaseManager,
    message_id: &str,
    verbose: usize,
    writer: &mut dyn Write,
) -> Result<()> {
    use std::collections::{HashSet, VecDeque};

    writeln!(writer, "Finding all replies to message: {}", message_id)?;

    // Get the starting message
    let root_email = match db.get_lore_email_by_message_id(message_id).await? {
        Some(email) => email,
        None => {
            writeln!(
                writer,
                "Error: Email not found with message_id: {}",
                message_id
            )?;
            return Ok(());
        }
    };

    // Collect all descendants (messages that reply to this message or its descendants)
    let mut all_emails = Vec::new();
    let mut seen_message_ids = HashSet::new();
    let mut to_process = VecDeque::new();

    // Start with the root message
    seen_message_ids.insert(root_email.message_id.clone());
    to_process.push_back(root_email.message_id.clone());
    all_emails.push(root_email);

    // Recursively find all messages that reply to messages in this subthread
    while let Some(current_message_id) = to_process.pop_front() {
        // Find all emails that reference this message
        let referencing_emails = db.get_lore_emails_referencing(&current_message_id).await?;

        for email in referencing_emails {
            // Add to seen set immediately to avoid duplicate processing
            if !seen_message_ids.insert(email.message_id.clone()) {
                // Already seen this message, skip it
                continue;
            }

            // Add to processing queue and results
            to_process.push_back(email.message_id.clone());
            all_emails.push(email);
        }
    }

    if all_emails.len() == 1 {
        // Only the root message, no replies
        writeln!(writer, "\nInfo: No replies found")?;
        return Ok(());
    }

    // Sort emails in thread order (respecting reply structure, then by date)
    let sorted_emails = crate::search::sort_emails_by_thread_order(&all_emails);

    writeln!(
        writer,
        "\nReplies: Found {} message(s) (including root):\n",
        all_emails.len()
    )?;

    // Display all emails in the subthread
    for (idx, email) in sorted_emails.iter().enumerate() {
        writeln!(writer, "{}. {} - {}", idx + 1, email.date, email.subject)?;

        // Always show database column headers
        writeln!(writer, "   From: {}", email.from)?;
        writeln!(writer, "   Message-ID: {}", email.message_id)?;

        if let Some(ref in_reply_to) = email.in_reply_to {
            writeln!(writer, "   In-Reply-To: {}", in_reply_to)?;
        }

        // Show full message body only when verbose
        if verbose >= 1 {
            writeln!(writer, "\n   --- Message Body ---")?;
            for line in email.body.lines() {
                writeln!(writer, "   {}", line)?;
            }
            writeln!(writer, "   --- End Message ---\n")?;
        } else {
            writeln!(writer)?; // Empty line between messages
        }
    }

    Ok(())
}

/// Get email by message_id (writer version)
pub async fn lore_get_by_message_id_to_writer(
    db: &DatabaseManager,
    message_id: &str,
    verbose: usize,
    show_thread: bool,
    show_replies: bool,
    writer: &mut dyn Write,
) -> Result<()> {
    writeln!(writer, "Looking up email with message_id: {}\n", message_id)?;

    let email_opt = db.get_lore_email_by_message_id(message_id).await?;

    match email_opt {
        Some(email) => {
            if show_thread {
                // Show the full thread for this message
                lore_show_thread_to_writer(db, &email.message_id, verbose, writer).await?;
            } else if show_replies {
                // Show only replies/descendants
                lore_show_replies_to_writer(db, &email.message_id, verbose, writer).await?;
            } else {
                // Show just this single message
                writeln!(writer, "Email found:\n")?;
                writeln!(writer, "{} - {}", email.date, email.subject)?;
                writeln!(writer, "   From: {}", email.from)?;
                writeln!(writer, "   Message-ID: {}", email.message_id)?;

                if let Some(ref in_reply_to) = email.in_reply_to {
                    writeln!(writer, "   In-Reply-To: {}", in_reply_to)?;
                }

                if let Some(ref references) = email.references {
                    writeln!(writer, "   References: {}", references)?;
                }

                if !email.recipients.is_empty() {
                    writeln!(writer, "   Recipients: {}", email.recipients)?;
                }

                if verbose >= 1 {
                    writeln!(writer, "\n{}", "   --- Message Body ---")?;
                    for line in email.body.lines() {
                        writeln!(writer, "   {}", line)?;
                    }
                    writeln!(writer, "{}", "   --- End Message ---")?;
                }
            }
        }
        None => {
            writeln!(
                writer,
                "Info: Email not found with message_id: {}",
                message_id
            )?;
        }
    }

    Ok(())
}

/// Search lore emails with single field filter (writer version)
pub async fn lore_search_with_thread_to_writer(
    db: &DatabaseManager,
    field: &str,
    pattern: &str,
    limit: usize,
    verbose: usize,
    show_thread: bool,
    show_replies: bool,
    since_date: Option<&str>,
    until_date: Option<&str>,
    writer: &mut dyn Write,
) -> Result<()> {
    writeln!(
        writer,
        "Searching lore emails where {} matches pattern: {}",
        field, pattern
    )?;

    let mut emails = db
        .search_lore_emails(field, pattern, limit, since_date, until_date)
        .await?;

    if emails.is_empty() {
        writeln!(writer, "Info: No matching emails found")?;
        return Ok(());
    }

    // Sort by date (oldest first)
    sort_emails_by_date(&mut emails);

    if show_thread {
        // Show full threads for all matching emails
        writeln!(
            writer,
            "\n{} matches found, showing threads:\n",
            emails.len()
        )?;

        for (idx, email) in emails.iter().enumerate() {
            if idx > 0 {
                writeln!(writer, "\n{}\n", "=".repeat(80))?;
            }
            writeln!(writer, "===> Thread {} of {}:", idx + 1, emails.len())?;
            lore_show_thread_to_writer(db, &email.message_id, verbose, writer).await?;
        }
        return Ok(());
    }

    if show_replies {
        // Show replies for all matching emails
        writeln!(
            writer,
            "\n{} matches found, showing replies:\n",
            emails.len()
        )?;

        for (idx, email) in emails.iter().enumerate() {
            if idx > 0 {
                writeln!(writer, "\n{}\n", "=".repeat(80))?;
            }
            writeln!(writer, "===> Replies {} of {}:", idx + 1, emails.len())?;
            lore_show_replies_to_writer(db, &email.message_id, verbose, writer).await?;
        }
        return Ok(());
    }

    writeln!(writer, "\n{} matches found:\n", emails.len())?;

    for (idx, email) in emails.iter().enumerate() {
        writeln!(writer, "{}. {} - {}", idx + 1, email.date, email.subject)?;

        // Always show database column headers
        writeln!(writer, "   From: {}", email.from)?;
        writeln!(writer, "   Message-ID: {}", email.message_id)?;

        if let Some(ref in_reply_to) = email.in_reply_to {
            writeln!(writer, "   In-Reply-To: {}", in_reply_to)?;
        }

        if let Some(ref references) = email.references {
            writeln!(writer, "   References: {}", references)?;
        }

        if !email.recipients.is_empty() {
            writeln!(writer, "   Recipients: {}", email.recipients)?;
        }

        // Show full message body only when verbose
        if verbose >= 1 {
            writeln!(writer, "\n   --- Message Body ---")?;
            // Body is already separated from headers
            for line in email.body.lines() {
                writeln!(writer, "   {}", line)?;
            }
            writeln!(writer, "   --- End Message ---")?;
        }

        writeln!(writer)?;
    }

    if limit > 0 && emails.len() >= limit {
        writeln!(
            writer,
            "Note: Result limit of {} reached. There may be more matches.",
            limit
        )?;
    }

    Ok(())
}

/// Search lore emails with multiple field filters (writer version)
pub async fn lore_search_multi_field_to_writer(
    db: &DatabaseManager,
    field_patterns: Vec<(&str, &str)>,
    limit: usize,
    verbose: usize,
    show_thread: bool,
    show_replies: bool,
    since_date: Option<&str>,
    until_date: Option<&str>,
    writer: &mut dyn Write,
) -> Result<()> {
    writeln!(writer, "Searching lore emails with multiple filters:")?;
    for (field, pattern) in &field_patterns {
        writeln!(writer, "  {} matches pattern: {}", field, pattern)?;
    }

    let mut emails = db
        .search_lore_emails_multi_field(field_patterns, limit, since_date, until_date)
        .await?;

    if emails.is_empty() {
        writeln!(writer, "Info: No matching emails found")?;
        return Ok(());
    }

    // Sort by date (oldest first)
    sort_emails_by_date(&mut emails);

    if show_thread {
        // Show full threads for all matching emails
        writeln!(
            writer,
            "\n{} matches found, showing threads:\n",
            emails.len()
        )?;

        for (idx, email) in emails.iter().enumerate() {
            if idx > 0 {
                writeln!(writer, "\n{}\n", "=".repeat(80))?;
            }
            writeln!(writer, "===> Thread {} of {}:", idx + 1, emails.len())?;
            lore_show_thread_to_writer(db, &email.message_id, verbose, writer).await?;
        }
        return Ok(());
    }

    if show_replies {
        // Show replies for all matching emails
        writeln!(
            writer,
            "\n{} matches found, showing replies:\n",
            emails.len()
        )?;

        for (idx, email) in emails.iter().enumerate() {
            if idx > 0 {
                writeln!(writer, "\n{}\n", "=".repeat(80))?;
            }
            writeln!(writer, "===> Replies {} of {}:", idx + 1, emails.len())?;
            lore_show_replies_to_writer(db, &email.message_id, verbose, writer).await?;
        }
        return Ok(());
    }

    writeln!(writer, "\n{} matches found:\n", emails.len())?;

    for (idx, email) in emails.iter().enumerate() {
        writeln!(writer, "{}. {} - {}", idx + 1, email.date, email.subject)?;

        // Always show database column headers
        writeln!(writer, "   From: {}", email.from)?;
        writeln!(writer, "   Message-ID: {}", email.message_id)?;

        if let Some(ref in_reply_to) = email.in_reply_to {
            writeln!(writer, "   In-Reply-To: {}", in_reply_to)?;
        }

        if let Some(ref references) = email.references {
            writeln!(writer, "   References: {}", references)?;
        }

        if !email.recipients.is_empty() {
            writeln!(writer, "   Recipients: {}", email.recipients)?;
        }

        // Show full message body only when verbose
        if verbose >= 1 {
            writeln!(writer, "\n   --- Message Body ---")?;
            // Body is already separated from headers
            for line in email.body.lines() {
                writeln!(writer, "   {}", line)?;
            }
            writeln!(writer, "   --- End Message ---")?;
        }

        writeln!(writer)?;
    }

    if limit > 0 && emails.len() >= limit {
        writeln!(
            writer,
            "Note: Result limit of {} reached. There may be more matches.",
            limit
        )?;
    }

    Ok(())
}

/// Search for lore emails related to a git commit (dig command) - writer version
/// Takes a commit from the main git repo, extracts its subject, and searches lore emails
pub async fn dig_lore_by_commit_to_writer(
    db: &DatabaseManager,
    commit_ish: &str,
    git_repo_path: &str,
    verbose: usize,
    show_all: bool,
    show_thread: bool,
    show_replies: bool,
    since_date: Option<&str>,
    until_date: Option<&str>,
    writer: &mut dyn Write,
) -> Result<()> {
    use crate::git;

    writeln!(
        writer,
        "Searching for lore emails related to git commit: {}",
        commit_ish
    )?;
    if show_all {
        writeln!(writer, "  (showing all matches)")?;
    } else {
        writeln!(writer, "  (showing most recent match only)")?;
    }
    if show_thread {
        writeln!(writer, "  (with full threads)")?;
    }
    if show_replies {
        writeln!(writer, "  (with all replies)")?;
    }

    // Resolve git commit-ish to full SHA and get commit info (reuse git resolution logic)
    let (git_sha, subject) = match gix::discover(git_repo_path) {
        Ok(repo) => match git::resolve_to_commit(&repo, commit_ish) {
            Ok(commit) => {
                let sha = commit.id().to_string();
                let message = commit.message_raw().ok().and_then(|msg| {
                    std::str::from_utf8(msg.as_ref())
                        .ok()
                        .map(|s| s.to_string())
                });
                let subject = message
                    .as_ref()
                    .and_then(|m| m.lines().next())
                    .unwrap_or("")
                    .to_string();
                (sha, subject)
            }
            Err(e) => {
                writeln!(
                    writer,
                    "Error: Failed to resolve git reference '{}': {}",
                    commit_ish, e
                )?;
                return Ok(());
            }
        },
        Err(e) => {
            writeln!(writer, "Error: Not in a git repository: {}", e)?;
            return Ok(());
        }
    };

    if subject.is_empty() {
        writeln!(
            writer,
            "Error: Commit {} has no subject line",
            &git_sha[..12]
        )?;
        return Ok(());
    }

    writeln!(
        writer,
        "Looking up commit: {} ({})",
        commit_ish,
        &git_sha[..12]
    )?;
    writeln!(writer, "  Commit subject: {}\n", subject)?;

    // Search lore emails by exact subject match (reuse database function)
    let emails = db
        .search_lore_emails_by_subject(&subject, 100, since_date, until_date)
        .await?;

    if emails.is_empty() {
        writeln!(writer, "Info: No matching emails found")?;
        return Ok(());
    }

    // Sort by date (newest first)
    let mut sorted_emails = emails;
    sorted_emails.sort_by(|a, b| b.date.cmp(&a.date));

    writeln!(
        writer,
        "Searching lore emails where subject matches pattern: {}",
        subject
    )?;

    if show_all {
        // Show all matching emails
        writeln!(
            writer,
            "\nResults: Found {} matching email(s):\n",
            sorted_emails.len()
        )?;

        if show_thread {
            // Show full threads
            for (idx, email) in sorted_emails.iter().enumerate() {
                if idx > 0 {
                    writeln!(writer, "\n{}\n", "=".repeat(80))?;
                }
                writeln!(
                    writer,
                    "===> Thread {} of {} ({}):",
                    idx + 1,
                    sorted_emails.len(),
                    email.date
                )?;
                lore_show_thread_to_writer(db, &email.message_id, verbose, writer).await?;
            }
        } else if show_replies {
            // Show all replies
            for (idx, email) in sorted_emails.iter().enumerate() {
                if idx > 0 {
                    writeln!(writer, "\n{}\n", "=".repeat(80))?;
                }
                writeln!(
                    writer,
                    "===> Replies {} of {} ({}):",
                    idx + 1,
                    sorted_emails.len(),
                    email.date
                )?;
                lore_show_replies_to_writer(db, &email.message_id, verbose, writer).await?;
            }
        } else {
            // Show summary of all matching emails
            for (idx, email) in sorted_emails.iter().enumerate() {
                writeln!(writer, "{}. {} - {}", idx + 1, email.date, email.subject)?;
                writeln!(writer, "   From: {}", email.from)?;
                writeln!(writer, "   Message-ID: {}", email.message_id)?;

                if verbose >= 1 {
                    writeln!(writer, "\n   --- Message Body ---")?;
                    for line in email.body.lines() {
                        writeln!(writer, "   {}", line)?;
                    }
                    writeln!(writer, "   --- End Message ---")?;
                }
                writeln!(writer)?;
            }
        }
    } else {
        // Show only most recent match
        if let Some(most_recent) = sorted_emails.first() {
            writeln!(
                writer,
                "\nResults: Found {} matching email(s), showing most recent:\n",
                sorted_emails.len()
            )?;

            if show_thread {
                writeln!(writer, "===> Most Recent Thread:")?;
                lore_show_thread_to_writer(db, &most_recent.message_id, verbose, writer).await?;
            } else if show_replies {
                writeln!(writer, "===> Replies to Most Recent:")?;
                lore_show_replies_to_writer(db, &most_recent.message_id, verbose, writer).await?;
            } else {
                writeln!(writer, "1. {} - {}", most_recent.date, most_recent.subject)?;
                writeln!(writer, "   From: {}", most_recent.from)?;
                writeln!(writer, "   Message-ID: {}", most_recent.message_id)?;

                if verbose >= 1 {
                    writeln!(writer, "\n   --- Message Body ---")?;
                    for line in most_recent.body.lines() {
                        writeln!(writer, "   {}", line)?;
                    }
                    writeln!(writer, "   --- End Message ---")?;
                }
            }

            if sorted_emails.len() > 1 {
                writeln!(
                    writer,
                    "\nNote: {} older match(es) not shown. Use -a flag to see all.",
                    sorted_emails.len() - 1
                )?;
            }
        }
    }

    Ok(())
}
