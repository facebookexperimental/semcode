// SPDX-License-Identifier: MIT OR Apache-2.0
//! Writer-based functions for lore email output
//! These are shared between the CLI (with file output) and MCP (with string buffers)

use anyhow::Result;
use std::collections::{HashSet, VecDeque};
use std::io::Write;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use crate::search::LoreSearchOptions;
use crate::types::LoreEmailInfo;
use crate::DatabaseManager;

/// Detect base64-encoded email bodies by content inspection.
/// Base64 email bodies have lines wrapped at exactly 76 characters using
/// only the base64 alphabet [A-Za-z0-9+/=].
fn looks_like_base64(body: &str) -> bool {
    let mut full_lines = 0;
    let mut total_lines = 0;

    for line in body.lines() {
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        total_lines += 1;
        if !trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        {
            return false;
        }
        if trimmed.len() == 76 {
            full_lines += 1;
        }
    }

    // Need at least a few full-length lines to be confident
    total_lines >= 3 && full_lines >= 2
}

/// Decode an email body from base64 to UTF-8 if the body looks base64-encoded.
/// Returns the decoded body, or the original body if not base64 or on decode error.
pub fn decode_email_body(email: &LoreEmailInfo) -> std::borrow::Cow<'_, str> {
    if !looks_like_base64(&email.body) {
        return std::borrow::Cow::Borrowed(&email.body);
    }

    // Strip whitespace (base64 in emails is typically line-wrapped)
    let cleaned: String = email
        .body
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();

    match BASE64.decode(cleaned.as_bytes()) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(decoded) => std::borrow::Cow::Owned(decoded),
            Err(_) => std::borrow::Cow::Borrowed(&email.body),
        },
        Err(_) => std::borrow::Cow::Borrowed(&email.body),
    }
}

/// Reconstruct RFC 5322 headers from individual fields.
/// When `snip` is true, only essential headers are emitted.
fn reconstruct_headers(email: &LoreEmailInfo, snip: bool) -> String {
    let mut result = String::new();

    result.push_str(&format!("From: {}\n", email.from));
    result.push_str(&format!("Subject: {}\n", email.subject));
    result.push_str(&format!("Date: {}\n", email.date));
    result.push_str(&format!("Message-ID: {}\n", email.message_id));

    if !snip {
        if let Some(ref in_reply_to) = email.in_reply_to {
            result.push_str(&format!("In-Reply-To: {}\n", in_reply_to));
        }
        if let Some(ref references) = email.references {
            result.push_str(&format!("References: {}\n", references));
        }
    }

    if !email.recipients.is_empty() {
        result.push_str(&format!("To: {}\n", email.recipients));
    }

    result
}

/// Check if a line looks like a reply starter (e.g., "On ... wrote:", "X writes:")
fn is_reply_starter(line: &str) -> bool {
    let trimmed = line.trim();

    // Common patterns:
    // "On DATE, NAME wrote:"
    // "On DATE at TIME, NAME wrote:"
    // "NAME <email> writes:"
    // "NAME <email> wrote:"

    // Check for lines ending with "wrote:" or "writes:"
    if trimmed.ends_with("wrote:") || trimmed.ends_with("writes:") {
        return true;
    }

    // Check for "On ... wrote:" pattern (starter might be on previous line)
    if trimmed.starts_with("On ") && trimmed.contains("wrote:") {
        return true;
    }

    false
}

/// Check if a line continues a reply starter (for multi-line starters)
fn continues_reply_starter(line: &str, prev_line: &str) -> bool {
    let trimmed = line.trim();
    let prev_trimmed = prev_line.trim();

    // If previous line started with "On " but didn't end with "wrote:"
    // and this line ends with "wrote:" or "writes:", it's a continuation
    if prev_trimmed.starts_with("On ")
        && !prev_trimmed.ends_with("wrote:")
        && (trimmed.ends_with("wrote:") || trimmed.ends_with("writes:"))
    {
        return true;
    }

    // Handle "> On Fri, 27 Jun 2025 17:00:54 -0400" followed by "> Aaron Conole <...> wrote:"
    if (prev_trimmed.starts_with("> On ") || prev_trimmed.starts_with(">> On "))
        && (trimmed.ends_with("wrote:") || trimmed.ends_with("writes:"))
    {
        return true;
    }

    false
}

/// Check if a line is a quote line (starts with > after stripping whitespace)
fn is_quote_line(line: &str) -> bool {
    line.trim_start().starts_with('>')
}

/// Check if a line is a snip marker (e.g., "[...]", "[ ... ]", "[snip]")
/// These shouldn't trigger context inclusion - they're meta-markers
fn is_snip_marker(line: &str) -> bool {
    let trimmed = line.trim();
    // Match patterns like [...], [ ... ], [snip], etc.
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = &trimmed[1..trimmed.len() - 1].trim();
        // Common snip markers
        if inner.is_empty()
            || *inner == "..."
            || *inner == "…"
            || inner.to_lowercase() == "snip"
            || inner.chars().all(|c| c == '.' || c == ' ')
        {
            return true;
        }
    }
    false
}

/// Check if a line is "real" new content (non-quoted, non-snip-marker, non-empty)
fn is_real_new_content(line: &str) -> bool {
    !is_quote_line(line) && !is_snip_marker(line) && !line.trim().is_empty()
}

/// Snip quoted content in email body, keeping only 6 lines of context
/// around new (non-quoted) content.
///
/// The algorithm:
/// 1. Identify reply starter blocks (preserved entirely)
/// 2. Find contiguous blocks of real new content
/// 3. Keep 6 lines of quoted context before and after each block
/// 4. Replace snipped sections with "[...]"
pub fn snip_quoted_body(body: &str, context_lines: usize) -> String {
    let lines: Vec<&str> = body.lines().collect();
    if lines.is_empty() {
        return String::new();
    }

    // Track which lines to include (true = include, false = snip)
    let mut include: Vec<bool> = vec![false; lines.len()];

    // First pass: mark reply starters, real new content, and snip markers
    for (i, line) in lines.iter().enumerate() {
        // Reply starters are always included
        if is_reply_starter(line) {
            include[i] = true;
            continue;
        }

        // Multi-line starter continuation
        if i > 0 && continues_reply_starter(line, lines[i - 1]) {
            include[i] = true;
            continue;
        }

        // Non-quoted lines are included (but snip markers don't trigger context)
        if !is_quote_line(line) {
            include[i] = true;
        }
    }

    // Second pass: find blocks of real new content and mark context
    // A "block" is a contiguous run of included non-quoted lines with real content
    let mut i = 0;
    while i < lines.len() {
        // Find start of a block of real new content
        if include[i] && is_real_new_content(lines[i]) {
            let block_start = i;

            // Find end of this block (contiguous real new content or blanks between)
            while i < lines.len() && include[i] && !is_quote_line(lines[i]) {
                i += 1;
            }
            let block_end = i;

            // Mark context BEFORE this block (only quoted lines)
            let ctx_start = block_start.saturating_sub(context_lines);
            for j in ctx_start..block_start {
                if is_quote_line(lines[j]) {
                    include[j] = true;
                }
            }

            // Mark context AFTER this block (only quoted lines)
            let ctx_end = (block_end + context_lines).min(lines.len());
            for j in block_end..ctx_end {
                if is_quote_line(lines[j]) {
                    include[j] = true;
                }
            }
        } else {
            i += 1;
        }
    }

    // Third pass: build output with [...] markers for snipped sections
    let mut result = String::new();
    let mut in_snipped_section = false;

    for (i, &line) in lines.iter().enumerate() {
        if include[i] {
            if in_snipped_section {
                // End of snipped section - add marker
                result.push_str("[...]\n");
                in_snipped_section = false;
            }
            result.push_str(line);
            result.push('\n');
        } else {
            // This line is being snipped
            if !in_snipped_section && is_quote_line(line) {
                in_snipped_section = true;
            }
        }
    }

    // Handle trailing snipped section
    if in_snipped_section {
        result.push_str("[...]\n");
    }

    result
}

/// Apply snipping to an email (headers and body)
pub fn snip_email(email: &LoreEmailInfo) -> (String, String) {
    let snipped_headers = reconstruct_headers(email, true);
    let body = decode_email_body(email);
    let snipped_body = snip_quoted_body(&body, 6);
    (snipped_headers, snipped_body)
}

/// Get the email body for display, decoding base64 if needed and applying snipping if requested
fn get_display_body<'a>(
    email: &'a LoreEmailInfo,
    options: &LoreSearchOptions<'_>,
) -> std::borrow::Cow<'a, str> {
    let body = decode_email_body(email);
    if options.snip_output {
        std::borrow::Cow::Owned(snip_quoted_body(&body, 6))
    } else {
        body
    }
}

/// Write email body to writer with proper indentation
fn write_email_body(
    email: &LoreEmailInfo,
    options: &LoreSearchOptions<'_>,
    writer: &mut dyn Write,
    indent: &str,
) -> Result<()> {
    let body = get_display_body(email, options);
    writeln!(writer, "\n{}--- Message Body ---", indent)?;
    for line in body.lines() {
        writeln!(writer, "{}{}", indent, line)?;
    }
    writeln!(writer, "{}--- End Message ---", indent)?;
    Ok(())
}

/// Format a lore email in MBOX format and write it to the writer
///
/// MBOX format:
/// - "From " separator line with sender and date in asctime format
/// - Full RFC 5322 headers
/// - Blank line
/// - Message body
/// - Final blank line
pub fn write_email_as_mbox(email: &LoreEmailInfo, writer: &mut dyn Write) -> Result<()> {
    write_email_as_mbox_with_options(email, writer, false)
}

/// Format a lore email in MBOX format with optional snipping
pub fn write_email_as_mbox_with_options(
    email: &LoreEmailInfo,
    writer: &mut dyn Write,
    snip: bool,
) -> Result<()> {
    // Extract sender email for the From line
    // The from field is typically "Name <email@example.com>" or just "email@example.com"
    let sender = extract_email_address(&email.from);

    // Convert RFC 2822 date to asctime format (24 chars, e.g., "Thu Jan  1 00:00:00 1970")
    let asctime_date = convert_to_asctime(&email.date);

    // Write the "From " separator line
    writeln!(writer, "From {} {}", sender, asctime_date)?;

    // Write the headers (snipped or full)
    write!(writer, "{}", reconstruct_headers(email, snip))?;
    writeln!(writer)?;

    // Write the body (decode base64 if needed, then snip if requested)
    let decoded_body = decode_email_body(email);
    let body = if snip {
        snip_quoted_body(&decoded_body, 6)
    } else {
        decoded_body.into_owned()
    };
    write!(writer, "{}", body)?;

    // Ensure the message ends with a newline
    if !body.ends_with('\n') {
        writeln!(writer)?;
    }

    // Write the blank line that terminates the message
    writeln!(writer)?;

    Ok(())
}

/// Extract email address from a "Name <email@example.com>" string
fn extract_email_address(from: &str) -> String {
    // Look for email in angle brackets
    if let Some(start) = from.find('<') {
        if let Some(end) = from.find('>') {
            if end > start {
                return from[start + 1..end].to_string();
            }
        }
    }
    // No angle brackets, assume the whole string is the email
    // Remove any surrounding whitespace
    from.trim().to_string()
}

/// Convert RFC 2822 date to asctime format
/// Input: "Thu, 01 Jan 1970 00:00:00 +0000"
/// Output: "Thu Jan  1 00:00:00 1970"
fn convert_to_asctime(rfc2822_date: &str) -> String {
    use chrono::DateTime;

    match DateTime::parse_from_rfc2822(rfc2822_date) {
        Ok(dt) => {
            // Format as asctime: "Thu Jan  1 00:00:00 1970"
            dt.format("%a %b %e %H:%M:%S %Y").to_string()
        }
        Err(_) => {
            // If parsing fails, return a default date
            "Thu Jan  1 00:00:00 1970".to_string()
        }
    }
}

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
    options: &LoreSearchOptions<'_>,
    writer: &mut dyn Write,
) -> Result<()> {
    if !options.mbox_output {
        writeln!(writer, "Finding thread root for message: {}", message_id)?;
    }

    // Step 1: Walk up the in_reply_to chain to find the root message
    let mut current_email = match db.get_lore_email_by_message_id(message_id).await? {
        Some(email) => email,
        None => {
            if !options.mbox_output {
                writeln!(
                    writer,
                    "Error: Email not found with message_id: {}",
                    message_id
                )?;
            }
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
    if !options.mbox_output {
        writeln!(writer, "Found thread root: {}\n", root_message_id)?;
    }

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

    // Handle MBOX output format
    if options.mbox_output {
        for email in &sorted_emails {
            write_email_as_mbox_with_options(email, writer, options.snip_output)?;
        }
        return Ok(());
    }

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

        if options.verbose >= 1 || options.snip_output {
            write_email_body(email, options, writer, "   ")?;
        }

        writeln!(writer)?;
    }

    Ok(())
}

/// Show all replies/subthreads under a given message (writer version)
pub async fn lore_show_replies_to_writer(
    db: &DatabaseManager,
    message_id: &str,
    options: &LoreSearchOptions<'_>,
    writer: &mut dyn Write,
) -> Result<()> {
    #[allow(unused)] // verbose is used in conditional compilation
    use std::collections::{HashSet, VecDeque};

    if !options.mbox_output {
        writeln!(writer, "Finding all replies to message: {}", message_id)?;
    }

    // Get the starting message
    let root_email = match db.get_lore_email_by_message_id(message_id).await? {
        Some(email) => email,
        None => {
            if !options.mbox_output {
                writeln!(
                    writer,
                    "Error: Email not found with message_id: {}",
                    message_id
                )?;
            }
            return Ok(());
        }
    };

    // Collect all descendants (messages that reply to this message or its descendants)
    let mut all_emails = Vec::new();
    let mut seen_message_ids = HashSet::new();
    let mut to_process = VecDeque::new();

    // Start with the root message
    let root_message_id = root_email.message_id.clone();
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
        if options.replies_only {
            // In replies_only mode, nothing to output if there are no replies
            return Ok(());
        }
        if !options.mbox_output {
            writeln!(writer, "\nInfo: No replies found")?;
        }
        // For mbox, still output the root message
        if options.mbox_output {
            write_email_as_mbox_with_options(&all_emails[0], writer, options.snip_output)?;
        }
        return Ok(());
    }

    // Sort emails in thread order (respecting reply structure, then by date)
    let sorted_emails = crate::search::sort_emails_by_thread_order(&all_emails);

    // Filter out root email if replies_only mode
    let emails_to_output: Vec<_> = if options.replies_only {
        sorted_emails
            .iter()
            .filter(|e| e.message_id != root_message_id)
            .collect()
    } else {
        sorted_emails.iter().collect()
    };

    if options.replies_only && emails_to_output.is_empty() {
        // No replies to output
        return Ok(());
    }

    // Handle MBOX output format
    if options.mbox_output {
        for email in &emails_to_output {
            write_email_as_mbox_with_options(email, writer, options.snip_output)?;
        }
        return Ok(());
    }

    if options.replies_only {
        writeln!(
            writer,
            "\nReplies: Found {} reply message(s):\n",
            emails_to_output.len()
        )?;
    } else {
        writeln!(
            writer,
            "\nReplies: Found {} message(s) (including root):\n",
            all_emails.len()
        )?;
    }

    // Display all emails in the subthread
    for (idx, email) in emails_to_output.iter().enumerate() {
        writeln!(writer, "{}. {} - {}", idx + 1, email.date, email.subject)?;

        // Always show database column headers
        writeln!(writer, "   From: {}", email.from)?;
        writeln!(writer, "   Message-ID: {}", email.message_id)?;

        if let Some(ref in_reply_to) = email.in_reply_to {
            writeln!(writer, "   In-Reply-To: {}", in_reply_to)?;
        }

        // Show full message body when verbose or snipping
        if options.verbose >= 1 || options.snip_output {
            write_email_body(email, options, writer, "   ")?;
            writeln!(writer)?;
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
    options: &LoreSearchOptions<'_>,
    writer: &mut dyn Write,
) -> Result<()> {
    if !options.mbox_output {
        writeln!(writer, "Looking up email with message_id: {}\n", message_id)?;
    }

    let email_opt = db.get_lore_email_by_message_id(message_id).await?;

    match email_opt {
        Some(email) => {
            if options.show_thread {
                // Show the full thread for this message
                lore_show_thread_to_writer(db, &email.message_id, options, writer).await?;
            } else if options.show_replies {
                // Show only replies/descendants
                lore_show_replies_to_writer(db, &email.message_id, options, writer).await?;
            } else if options.mbox_output {
                // Output single message in mbox format
                write_email_as_mbox_with_options(&email, writer, options.snip_output)?;
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

                if options.verbose >= 1 || options.snip_output {
                    write_email_body(&email, options, writer, "   ")?;
                }
            }
        }
        None => {
            if !options.mbox_output {
                writeln!(
                    writer,
                    "Info: Email not found with message_id: {}",
                    message_id
                )?;
            }
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
    options: &LoreSearchOptions<'_>,
    writer: &mut dyn Write,
) -> Result<()> {
    if !options.mbox_output {
        writeln!(
            writer,
            "Searching lore emails where {} matches pattern: {}",
            field, pattern
        )?;
    }

    let mut emails = db
        .search_lore_emails(
            field,
            pattern,
            limit,
            options.since_date,
            options.until_date,
        )
        .await?;

    if emails.is_empty() {
        if !options.mbox_output {
            writeln!(writer, "Info: No matching emails found")?;
        }
        return Ok(());
    }

    // Sort by date (oldest first)
    sort_emails_by_date(&mut emails);

    // Handle show_thread first - lore_show_thread_to_writer handles mbox_output internally
    if options.show_thread {
        // Show full threads for all matching emails
        if !options.mbox_output {
            writeln!(
                writer,
                "\n{} matches found, showing threads:\n",
                emails.len()
            )?;
        }

        for (idx, email) in emails.iter().enumerate() {
            if !options.mbox_output && idx > 0 {
                writeln!(writer, "\n{}\n", "=".repeat(80))?;
            }
            if !options.mbox_output {
                writeln!(writer, "===> Thread {} of {}:", idx + 1, emails.len())?;
            }
            lore_show_thread_to_writer(db, &email.message_id, options, writer).await?;
        }
        return Ok(());
    }

    // Handle show_replies - lore_show_replies_to_writer handles mbox_output internally
    if options.show_replies {
        // Show replies for all matching emails
        if !options.mbox_output {
            writeln!(
                writer,
                "\n{} matches found, showing replies:\n",
                emails.len()
            )?;
        }

        for (idx, email) in emails.iter().enumerate() {
            if !options.mbox_output && idx > 0 {
                writeln!(writer, "\n{}\n", "=".repeat(80))?;
            }
            if !options.mbox_output {
                writeln!(writer, "===> Replies {} of {}:", idx + 1, emails.len())?;
            }
            lore_show_replies_to_writer(db, &email.message_id, options, writer).await?;
        }
        return Ok(());
    }

    // Handle MBOX output format (without show_thread/show_replies)
    if options.mbox_output {
        for email in &emails {
            write_email_as_mbox_with_options(email, writer, options.snip_output)?;
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

        // Show full message body when verbose or snipping
        if options.verbose >= 1 || options.snip_output {
            write_email_body(email, options, writer, "   ")?;
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
    options: &LoreSearchOptions<'_>,
    writer: &mut dyn Write,
) -> Result<()> {
    if !options.mbox_output {
        writeln!(writer, "Searching lore emails with multiple filters:")?;
        for (field, pattern) in &field_patterns {
            writeln!(writer, "  {} matches pattern: {}", field, pattern)?;
        }
    }

    let mut emails = db
        .search_lore_emails_multi_field(
            field_patterns,
            limit,
            options.since_date,
            options.until_date,
        )
        .await?;

    if emails.is_empty() {
        if !options.mbox_output {
            writeln!(writer, "Info: No matching emails found")?;
        }
        return Ok(());
    }

    // Sort by date (oldest first)
    sort_emails_by_date(&mut emails);

    // Handle show_thread first - lore_show_thread_to_writer handles mbox_output internally
    if options.show_thread {
        // Show full threads for all matching emails
        if !options.mbox_output {
            writeln!(
                writer,
                "\n{} matches found, showing threads:\n",
                emails.len()
            )?;
        }

        for (idx, email) in emails.iter().enumerate() {
            if !options.mbox_output && idx > 0 {
                writeln!(writer, "\n{}\n", "=".repeat(80))?;
            }
            if !options.mbox_output {
                writeln!(writer, "===> Thread {} of {}:", idx + 1, emails.len())?;
            }
            lore_show_thread_to_writer(db, &email.message_id, options, writer).await?;
        }
        return Ok(());
    }

    // Handle show_replies - lore_show_replies_to_writer handles mbox_output internally
    if options.show_replies {
        // Show replies for all matching emails
        if !options.mbox_output {
            writeln!(
                writer,
                "\n{} matches found, showing replies:\n",
                emails.len()
            )?;
        }

        for (idx, email) in emails.iter().enumerate() {
            if !options.mbox_output && idx > 0 {
                writeln!(writer, "\n{}\n", "=".repeat(80))?;
            }
            if !options.mbox_output {
                writeln!(writer, "===> Replies {} of {}:", idx + 1, emails.len())?;
            }
            lore_show_replies_to_writer(db, &email.message_id, options, writer).await?;
        }
        return Ok(());
    }

    // Handle MBOX output format (without show_thread/show_replies)
    if options.mbox_output {
        for email in &emails {
            write_email_as_mbox_with_options(email, writer, options.snip_output)?;
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

        // Show full message body when verbose or snipping
        if options.verbose >= 1 || options.snip_output {
            write_email_body(email, options, writer, "   ")?;
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
    show_all: bool,
    options: &LoreSearchOptions<'_>,
    writer: &mut dyn Write,
) -> Result<()> {
    use crate::git;

    if !options.mbox_output {
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
        if options.show_thread {
            writeln!(writer, "  (with full threads)")?;
        }
        if options.show_replies {
            writeln!(writer, "  (with all replies)")?;
        }
        if options.replies_only {
            writeln!(writer, "  (showing only replies, not original patches)")?;
        }
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
        if !options.mbox_output {
            writeln!(
                writer,
                "Error: Commit {} has no subject line",
                &git_sha[..12]
            )?;
        }
        return Ok(());
    }

    if !options.mbox_output {
        writeln!(
            writer,
            "Looking up commit: {} ({})",
            commit_ish,
            &git_sha[..12]
        )?;
        writeln!(writer, "  Commit subject: {}\n", subject)?;
    }

    // Search lore emails by exact subject match (reuse database function)
    let emails = db
        .search_lore_emails_by_subject(&subject, 100, options.since_date, options.until_date)
        .await?;

    if emails.is_empty() {
        if !options.mbox_output {
            writeln!(writer, "Info: No matching emails found")?;
        }
        return Ok(());
    }

    // Sort by date (newest first)
    let mut sorted_emails = emails;
    sorted_emails.sort_by(|a, b| {
        // Parse RFC 2822 dates for proper chronological comparison
        let a_date = chrono::DateTime::parse_from_rfc2822(&a.date).ok();
        let b_date = chrono::DateTime::parse_from_rfc2822(&b.date).ok();

        match (b_date, a_date) {
            (Some(b_dt), Some(a_dt)) => b_dt.cmp(&a_dt), // Descending order (newest first)
            (Some(_), None) => std::cmp::Ordering::Less, // b is valid, a is not - b comes first
            (None, Some(_)) => std::cmp::Ordering::Greater, // a is valid, b is not - a comes first
            (None, None) => b.date.cmp(&a.date), // Both invalid - fall back to string comparison
        }
    });

    // Handle MBOX output format (only for simple case without thread/replies/replies_only)
    if options.mbox_output && !options.show_thread && !options.show_replies && !options.replies_only
    {
        // For mbox, sort by date (oldest first) for proper chronological order in mailbox
        sort_emails_by_date(&mut sorted_emails);

        let emails_to_output = if show_all {
            &sorted_emails[..]
        } else {
            // Just the most recent (which is now at the end after sorting oldest first)
            if sorted_emails.is_empty() {
                &[]
            } else {
                &sorted_emails[sorted_emails.len() - 1..]
            }
        };

        for email in emails_to_output {
            write_email_as_mbox_with_options(email, writer, options.snip_output)?;
        }
        return Ok(());
    }

    if !options.mbox_output {
        writeln!(
            writer,
            "Searching lore emails where subject matches pattern: {}",
            subject
        )?;
    }

    if show_all {
        // Show all matching emails
        if !options.mbox_output {
            writeln!(
                writer,
                "\nResults: Found {} matching email(s):\n",
                sorted_emails.len()
            )?;
        }

        if options.show_thread {
            // Show full threads
            for (idx, email) in sorted_emails.iter().enumerate() {
                if !options.mbox_output {
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
                }
                lore_show_thread_to_writer(db, &email.message_id, options, writer).await?;
            }
        } else if options.show_replies || options.replies_only {
            // Filter to only original patches (not "Re:" replies) so we show replies
            // for each version of the patch (v1, v2, RFC, etc.) but not replies to replies
            let original_patches: Vec<_> = sorted_emails
                .iter()
                .filter(|e| !e.subject.trim_start().to_lowercase().starts_with("re:"))
                .collect();

            if original_patches.is_empty() {
                if !options.mbox_output {
                    writeln!(
                        writer,
                        "Info: No original patch emails found (only replies)"
                    )?;
                }
            } else {
                if !options.mbox_output {
                    writeln!(
                        writer,
                        "Found {} patch version(s):\n",
                        original_patches.len()
                    )?;
                }

                for (idx, email) in original_patches.iter().enumerate() {
                    if !options.mbox_output && !options.replies_only {
                        if idx > 0 {
                            writeln!(writer, "\n{}\n", "=".repeat(80))?;
                        }
                        writeln!(
                            writer,
                            "===> Patch version {} of {} ({}):",
                            idx + 1,
                            original_patches.len(),
                            email.date
                        )?;
                        writeln!(writer, "     Subject: {}", email.subject)?;
                        writeln!(writer, "     From: {}", email.from)?;
                    }
                    lore_show_replies_to_writer(db, &email.message_id, options, writer).await?;
                }
            }
        } else {
            // Show summary of all matching emails
            for (idx, email) in sorted_emails.iter().enumerate() {
                writeln!(writer, "{}. {} - {}", idx + 1, email.date, email.subject)?;
                writeln!(writer, "   From: {}", email.from)?;
                writeln!(writer, "   Message-ID: {}", email.message_id)?;

                if options.verbose >= 1 || options.snip_output {
                    write_email_body(email, options, writer, "   ")?;
                }
                writeln!(writer)?;
            }
        }
    } else {
        // Show only most recent match
        // For --replies/--replies-only, find the most recent original patch (not a "Re:" reply)
        let target_email = if options.show_replies || options.replies_only {
            sorted_emails
                .iter()
                .find(|e| !e.subject.trim_start().to_lowercase().starts_with("re:"))
        } else {
            sorted_emails.first()
        };

        if let Some(most_recent) = target_email {
            if !options.mbox_output && !options.replies_only {
                writeln!(
                    writer,
                    "\nResults: Found {} matching email(s), showing most recent:\n",
                    sorted_emails.len()
                )?;
            }

            if options.show_thread {
                if !options.mbox_output {
                    writeln!(writer, "===> Most Recent Thread:")?;
                }
                lore_show_thread_to_writer(db, &most_recent.message_id, options, writer).await?;
            } else if options.show_replies || options.replies_only {
                if !options.mbox_output && !options.replies_only {
                    writeln!(writer, "===> Replies to Most Recent Patch:")?;
                    writeln!(writer, "     Subject: {}", most_recent.subject)?;
                    writeln!(writer, "     From: {}", most_recent.from)?;
                }
                lore_show_replies_to_writer(db, &most_recent.message_id, options, writer).await?;
            } else {
                writeln!(writer, "1. {} - {}", most_recent.date, most_recent.subject)?;
                writeln!(writer, "   From: {}", most_recent.from)?;
                writeln!(writer, "   Message-ID: {}", most_recent.message_id)?;

                if options.verbose >= 1 || options.snip_output {
                    write_email_body(most_recent, options, writer, "   ")?;
                }
            }

            if !options.mbox_output && sorted_emails.len() > 1 {
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
