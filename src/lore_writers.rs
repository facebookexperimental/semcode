// SPDX-License-Identifier: MIT OR Apache-2.0
//! Writer-based functions for lore email output
//! These are shared between the CLI (with file output) and MCP (with string buffers)

use anyhow::Result;
use std::collections::{HashSet, VecDeque};
use std::io::Write;

use crate::DatabaseManager;

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

/// Get email by message_id (writer version)
pub async fn lore_get_by_message_id_to_writer(
    db: &DatabaseManager,
    message_id: &str,
    verbose: usize,
    show_thread: bool,
    writer: &mut dyn Write,
) -> Result<()> {
    writeln!(writer, "Looking up email with message_id: {}\n", message_id)?;

    let email_opt = db.get_lore_email_by_message_id(message_id).await?;

    match email_opt {
        Some(email) => {
            if show_thread {
                // Show the full thread for this message
                lore_show_thread_to_writer(db, &email.message_id, verbose, writer).await?;
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
    writer: &mut dyn Write,
) -> Result<()> {
    writeln!(
        writer,
        "Searching lore emails where {} matches pattern: {}",
        field, pattern
    )?;

    let emails = db.search_lore_emails(field, pattern, limit).await?;

    if emails.is_empty() {
        writeln!(writer, "Info: No matching emails found")?;
        return Ok(());
    }

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
    writer: &mut dyn Write,
) -> Result<()> {
    writeln!(writer, "Searching lore emails with multiple filters:")?;
    for (field, pattern) in &field_patterns {
        writeln!(writer, "  {} matches pattern: {}", field, pattern)?;
    }

    let emails = db
        .search_lore_emails_multi_field(field_patterns, limit)
        .await?;

    if emails.is_empty() {
        writeln!(writer, "Info: No matching emails found")?;
        return Ok(());
    }

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
