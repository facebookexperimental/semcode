// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{CodeVectorizer, DatabaseManager};
use anstream::stdout;
use anyhow::Result;
use owo_colors::OwoColorize as _;
use std::fs::File;
use std::io::Write;

use crate::display::{
    display_function_to_writer_with_options, display_type_to_writer, display_typedef_to_writer,
};

/// Options for displaying call relationships
#[derive(Debug, Clone)]
pub struct DisplayCallOptions {
    pub truncate: bool,
    pub verbose: bool,
    pub show_calls: bool,
    pub show_callers: bool,
}

/// Options for lore email search and display
#[derive(Debug, Clone)]
pub struct LoreSearchOptions<'a> {
    pub verbose: usize,
    pub show_thread: bool,
    pub show_replies: bool,
    pub since_date: Option<&'a str>,
    pub until_date: Option<&'a str>,
    pub mbox_output: bool,
}

/// Get functions called by the given function name - git-aware version
async fn get_function_calls_git_aware(
    db: &DatabaseManager,
    function_name: &str,
    git_sha: &str,
) -> Result<Vec<String>> {
    // Get callees from functions table using git-aware method (includes macros stored as functions)
    db.get_function_callees_git_aware(function_name, git_sha)
        .await
        .or_else(|_| Ok(vec![]))
}

/// Get functions that call the given function name
async fn get_function_callers(db: &DatabaseManager, function_name: &str) -> Result<Vec<String>> {
    db.get_function_callers(function_name).await
}

/// Display call relationships for a function with truncation control
/// Display call relationships for a function with full control over what to show
fn display_call_relationships_with_options(
    _function_name: &str,
    calls: &[String],
    called_by: &[String],
    writer: &mut dyn Write,
    options: &DisplayCallOptions,
) -> Result<()> {
    const TRUNCATE_LIMIT: usize = 25;

    if options.show_calls && !calls.is_empty() {
        writeln!(writer, "\nCalls: {}", calls.len())?;

        let should_truncate = options.truncate && !options.verbose && calls.len() > TRUNCATE_LIMIT;
        let display_calls = if should_truncate {
            &calls[..TRUNCATE_LIMIT]
        } else {
            calls
        };

        for call in display_calls.iter() {
            writeln!(writer, "  → {}", call.cyan())?;
        }

        if should_truncate {
            writeln!(
                writer,
                "  {} ... ({} more calls, use -v to show all)",
                "...".bright_black(),
                calls.len() - TRUNCATE_LIMIT
            )?;
        }
    }

    if options.show_callers && !called_by.is_empty() {
        writeln!(writer, "\nCalled By: {}", called_by.len())?;

        let should_truncate =
            options.truncate && !options.verbose && called_by.len() > TRUNCATE_LIMIT;
        let display_callers = if should_truncate {
            &called_by[..TRUNCATE_LIMIT]
        } else {
            called_by
        };

        for caller in display_callers.iter() {
            writeln!(writer, "  ← {}", caller.cyan())?;
        }

        if should_truncate {
            writeln!(
                writer,
                "  {} ... ({} more callers, use -v to show all)",
                "...".bright_black(),
                called_by.len() - TRUNCATE_LIMIT
            )?;
        }
    }

    Ok(())
}

pub async fn query_function_or_macro(
    db: &DatabaseManager,
    name: &str,
    git_sha: &str,
) -> Result<()> {
    query_function_or_macro_to_writer(db, name, git_sha, &mut stdout()).await
}

pub async fn query_function_or_macro_verbose(
    db: &DatabaseManager,
    name: &str,
    git_sha: &str,
    verbose: bool,
) -> Result<()> {
    query_function_or_macro_to_writer_verbose(db, name, git_sha, &mut stdout(), verbose).await
}

pub async fn query_type_or_typedef(db: &DatabaseManager, name: &str, git_sha: &str) -> Result<()> {
    query_type_or_typedef_to_writer(db, name, git_sha, &mut stdout()).await
}

pub async fn query_similar(
    db: &DatabaseManager,
    vectorizer: &CodeVectorizer,
    code: &str,
) -> Result<()> {
    println!("Searching for functions similar to: {}", code.cyan());
    println!("Generating vector...");

    // Generate vector for the query code
    let query_vector = match vectorizer.vectorize_code(code) {
        Ok(vec) => vec,
        Err(e) => {
            println!("{} Failed to generate vector: {}", "Error:".red(), e);
            return Ok(());
        }
    };

    // Search for similar functions
    match db.search_similar_functions(&query_vector, 10, None).await? {
        functions if functions.is_empty() => {
            println!("{} No similar functions found", "Error:".red());
        }
        functions => {
            println!("\n{}", "=== Similar Functions ===".bold().green());
            for (i, func) in functions.iter().enumerate() {
                println!(
                    "\n{}. {} in {}",
                    (i + 1).to_string().yellow(),
                    func.name.bold(),
                    func.file_path.cyan()
                );
                println!("   Lines: {}-{}", func.line_start, func.line_end);

                // Show preview of the function
                let preview: String = func.body.lines().take(3).collect::<Vec<_>>().join("\n   ");

                if !preview.is_empty() {
                    println!("   {}", preview.bright_black());
                    if func.body.lines().count() > 3 {
                        println!("   ...");
                    }
                }
            }
        }
    }

    Ok(())
}

pub async fn query_similar_by_name(
    db: &DatabaseManager,
    vectorizer: &CodeVectorizer,
    name: &str,
) -> Result<()> {
    println!("Searching for functions similar to name: {}", name.cyan());
    println!("Generating vector...");

    match db.search_similar_by_name(vectorizer, name, 10).await? {
        functions if functions.is_empty() => {
            println!("{} No similar functions found", "Error:".red());
        }
        functions => {
            println!("\n{}", "=== Similar Functions ===".bold().green());
            for (i, func) in functions.iter().enumerate() {
                println!(
                    "\n{}. {} in {}",
                    (i + 1).to_string().yellow(),
                    func.name.bold(),
                    func.file_path.cyan()
                );
                println!("   Lines: {}-{}", func.line_start, func.line_end);
                println!("   Return: {}", func.return_type.magenta());
            }
        }
    }

    Ok(())
}

pub async fn list_functions_and_macros(
    db: &DatabaseManager,
    pattern: &str,
    git_sha: &str,
) -> Result<()> {
    list_functions_and_macros_to_writer(db, pattern, git_sha, &mut stdout()).await
}

pub async fn list_types_and_typedefs(
    db: &DatabaseManager,
    pattern: &str,
    git_sha: &str,
) -> Result<()> {
    list_types_and_typedefs_to_writer(db, pattern, git_sha, &mut stdout()).await
}

pub async fn show_tables(db: &DatabaseManager) -> Result<()> {
    show_tables_to_writer(db, &mut stdout()).await
}

pub async fn dump_functions(db: &DatabaseManager, output_file: &str) -> Result<()> {
    println!("Dumping all functions to {}...", output_file.cyan());

    let functions = db.get_all_functions_metadata_only().await?;
    let json = serde_json::to_string_pretty(&functions)?;

    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    println!(
        "{} Dumped {} functions to {}",
        "Success:".green(),
        functions.len(),
        output_file.cyan()
    );

    Ok(())
}

pub async fn dump_types(db: &DatabaseManager, output_file: &str) -> Result<()> {
    println!("Dumping all types to {}...", output_file.cyan());

    let types = db.get_all_types_metadata_only().await?;
    let json = serde_json::to_string_pretty(&types)?;

    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    println!(
        "{} Dumped {} types to {}",
        "Success:".green(),
        types.len(),
        output_file.cyan()
    );

    Ok(())
}

pub async fn dump_typedefs(db: &DatabaseManager, output_file: &str) -> Result<()> {
    println!("Dumping all typedefs to {}...", output_file.cyan());

    let typedefs = db.get_all_typedefs().await?;
    let json = serde_json::to_string_pretty(&typedefs)?;

    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    println!(
        "{} Dumped {} typedefs to {}",
        "Success:".green(),
        typedefs.len(),
        output_file.cyan()
    );

    Ok(())
}

pub async fn dump_macros(_db: &DatabaseManager, _output_file: &str) -> Result<()> {
    println!("{} dump-macros command is deprecated", "Note:".yellow());
    println!("Macros are now stored as functions in the functions table.");
    println!("Use dump-functions instead to export all functions.");

    Ok(())
}

pub async fn dump_calls(db: &DatabaseManager, output_file: &str) -> Result<()> {
    println!(
        "Dumping all call relationships to {}...",
        output_file.cyan()
    );

    let calls = db.get_all_call_relationships().await?;

    // Convert to JSON-serializable format with hex strings
    #[derive(serde::Serialize)]
    struct CallRelationshipJson {
        caller: String,
        callee: String,
        caller_git_file_hash: String, // Converted from Vec<u8> to hex string
        callee_git_file_hash: Option<String>, // Converted from Option<Vec<u8>> to hex string
    }

    let json_calls: Vec<CallRelationshipJson> = calls
        .into_iter()
        .map(|call| CallRelationshipJson {
            caller: call.caller,
            callee: call.callee,
            caller_git_file_hash: hex::encode(&call.caller_git_file_hash),
            callee_git_file_hash: call.callee_git_file_hash.map(|hash| hex::encode(&hash)),
        })
        .collect();

    let json = serde_json::to_string_pretty(&json_calls)?;

    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    println!(
        "{} Dumped {} call relationships to {}",
        "Success:".green(),
        json_calls.len(),
        output_file.cyan()
    );

    Ok(())
}

pub async fn dump_processed_files(db: &DatabaseManager, output_file: &str) -> Result<()> {
    println!("Dumping all processed files to {}...", output_file.cyan());

    let processed_files = db.get_all_processed_files().await?;

    // Convert to JSON-serializable format with hex strings
    let json_records: Vec<crate::database::processed_files::ProcessedFileRecordJson> =
        processed_files
            .into_iter()
            .map(|record| record.into())
            .collect();

    let json = serde_json::to_string_pretty(&json_records)?;

    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    println!(
        "{} Dumped {} processed files to {}",
        "Success:".green(),
        json_records.len(),
        output_file.cyan()
    );

    Ok(())
}

pub async fn dump_content(db: &DatabaseManager, output_file: &str) -> Result<()> {
    println!("Dumping all content to {}...", output_file.cyan());

    let content_items = db.get_all_content().await?;

    // Convert to JSON-serializable format with hex strings
    let json_records: Vec<crate::database::content::ContentInfoJson> = content_items
        .into_iter()
        .map(|content| content.into())
        .collect();

    let json = serde_json::to_string_pretty(&json_records)?;

    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    println!(
        "{} Dumped {} content entries to {}",
        "Success:".green(),
        json_records.len(),
        output_file.cyan()
    );

    Ok(())
}

pub async fn dump_symbol_filename(db: &DatabaseManager, output_file: &str) -> Result<()> {
    println!(
        "Dumping all symbol-filename pairs to {}...",
        output_file.cyan()
    );

    let pairs = db.get_all_symbol_filename_pairs().await?;

    // Convert to JSON-serializable format
    #[derive(serde::Serialize)]
    struct SymbolFilenamePair {
        symbol: String,
        filename: String,
    }

    let json_records: Vec<SymbolFilenamePair> = pairs
        .into_iter()
        .map(|(symbol, filename)| SymbolFilenamePair { symbol, filename })
        .collect();

    let json = serde_json::to_string_pretty(&json_records)?;

    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    println!(
        "{} Dumped {} symbol-filename pairs to {}",
        "Success:".green(),
        json_records.len(),
        output_file.cyan()
    );

    Ok(())
}

pub async fn dump_git_commits(db: &DatabaseManager, output_file: &str) -> Result<()> {
    println!("Dumping all git commits to {}...", output_file.cyan());

    let commits = db.get_all_git_commits().await?;
    let json = serde_json::to_string_pretty(&commits)?;

    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    println!(
        "{} Dumped {} git commits to {}",
        "Success:".green(),
        commits.len(),
        output_file.cyan()
    );

    Ok(())
}

pub async fn dump_lore(db: &DatabaseManager, output_file: &str) -> Result<()> {
    println!("Dumping all lore emails to {}...", output_file.cyan());

    let emails = db.get_all_lore_emails().await?;
    let json = serde_json::to_string_pretty(&emails)?;

    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    println!(
        "{} Dumped {} lore emails to {}",
        "Success:".green(),
        emails.len(),
        output_file.cyan()
    );

    Ok(())
}

pub async fn lore_search(
    db: &DatabaseManager,
    field: &str,
    pattern: &str,
    limit: usize,
    verbose: usize,
) -> Result<()> {
    let options = LoreSearchOptions {
        verbose,
        show_thread: false,
        show_replies: false,
        since_date: None,
        until_date: None,
        mbox_output: false,
    };
    lore_search_with_thread(db, field, pattern, limit, &options).await
}

pub async fn lore_search_multi_field(
    db: &DatabaseManager,
    field_patterns: Vec<(&str, &str)>,
    limit: usize,
    options: &LoreSearchOptions<'_>,
) -> Result<()> {
    // Build description of the search
    use std::collections::HashMap;
    let mut field_map: HashMap<&str, Vec<&str>> = HashMap::new();
    for (field, pattern) in &field_patterns {
        field_map.entry(field).or_default().push(pattern);
    }

    if !options.mbox_output {
        println!("Searching lore emails with conditions:");
        for (field, patterns) in &field_map {
            if patterns.len() == 1 {
                println!("  {} matches: {}", field.cyan(), patterns[0].yellow());
            } else {
                println!(
                    "  {} matches (OR): {}",
                    field.cyan(),
                    patterns.join(" OR ").yellow()
                );
            }
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
            println!("{} No matching emails found", "Info:".yellow());
        }
        return Ok(());
    }

    // Sort by date (oldest first)
    crate::lore_writers::sort_emails_by_date(&mut emails);

    // Handle MBOX output format
    if options.mbox_output {
        let mut stdout = std::io::stdout();
        for email in &emails {
            crate::lore_writers::write_email_as_mbox(email, &mut stdout)?;
        }
        return Ok(());
    }

    if options.show_thread {
        // Show full threads for all matching emails
        println!(
            "\n{} matches found, showing threads:\n",
            emails.len().to_string().green()
        );

        for (idx, email) in emails.iter().enumerate() {
            if idx > 0 {
                println!("\n{}\n", "=".repeat(80).bright_black());
            }
            lore_show_thread(db, &email.message_id, options.verbose).await?;
        }
        return Ok(());
    }

    if options.show_replies {
        // Show replies for all matching emails
        println!(
            "\n{} matches found, showing replies:\n",
            emails.len().to_string().green()
        );

        for (idx, email) in emails.iter().enumerate() {
            if idx > 0 {
                println!("\n{}\n", "=".repeat(80).bright_black());
            }
            println!(
                "{} Replies {} of {}:",
                "===>".bold().cyan(),
                idx + 1,
                emails.len()
            );
            lore_show_replies(db, &email.message_id, options.verbose).await?;
        }
        return Ok(());
    }

    println!("\n{} matches found:\n", emails.len().to_string().green());

    for (idx, email) in emails.iter().enumerate() {
        println!(
            "{}. {} - {}",
            (idx + 1).to_string().bright_black(),
            email.date.bright_black(),
            email.subject.cyan()
        );
        println!("   From: {}", email.from.yellow());
        println!("   Message-ID: {}", email.message_id.bright_black());

        if let Some(ref in_reply_to) = email.in_reply_to {
            println!("   In-Reply-To: {}", in_reply_to.bright_black());
        }

        // Show full message body only when verbose
        if options.verbose >= 1 {
            println!("\n{}", "   --- Message Body ---".bright_black());
            // Body is already separated from headers
            for line in email.body.lines() {
                println!("   {}", line);
            }
            println!("{}", "   --- End Message ---".bright_black());
        }

        println!();
    }

    Ok(())
}

pub async fn lore_search_with_thread(
    db: &DatabaseManager,
    field: &str,
    pattern: &str,
    limit: usize,
    options: &LoreSearchOptions<'_>,
) -> Result<()> {
    if !options.mbox_output {
        println!(
            "Searching lore emails where {} matches pattern: {}",
            field.cyan(),
            pattern.yellow()
        );
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
            println!("{} No matching emails found", "Info:".yellow());
        }
        return Ok(());
    }

    // Sort by date (oldest first)
    crate::lore_writers::sort_emails_by_date(&mut emails);

    // Handle MBOX output format
    if options.mbox_output {
        let mut stdout = std::io::stdout();
        for email in &emails {
            crate::lore_writers::write_email_as_mbox(email, &mut stdout)?;
        }
        return Ok(());
    }

    if options.show_thread {
        // Show full threads for all matching emails
        println!(
            "\n{} matches found, showing threads:\n",
            emails.len().to_string().green()
        );

        for (idx, email) in emails.iter().enumerate() {
            if idx > 0 {
                println!("\n{}\n", "=".repeat(80).bright_black());
            }
            println!(
                "{} Thread {} of {}:",
                "===>".bold().cyan(),
                idx + 1,
                emails.len()
            );
            lore_show_thread(db, &email.message_id, options.verbose).await?;
        }
        return Ok(());
    }

    if options.show_replies {
        // Show replies for all matching emails
        println!(
            "\n{} matches found, showing replies:\n",
            emails.len().to_string().green()
        );

        for (idx, email) in emails.iter().enumerate() {
            if idx > 0 {
                println!("\n{}\n", "=".repeat(80).bright_black());
            }
            println!(
                "{} Replies {} of {}:",
                "===>".bold().cyan(),
                idx + 1,
                emails.len()
            );
            lore_show_replies(db, &email.message_id, options.verbose).await?;
        }
        return Ok(());
    }

    println!("\n{} matches found:\n", emails.len().to_string().green());

    for (idx, email) in emails.iter().enumerate() {
        println!(
            "{}. {} - {}",
            (idx + 1).to_string().bright_black(),
            email.date.bright_black(),
            email.subject.cyan()
        );

        // Always show database column headers
        println!("   From: {}", email.from.yellow());
        println!("   Message-ID: {}", email.message_id.bright_black());

        if let Some(ref in_reply_to) = email.in_reply_to {
            println!("   In-Reply-To: {}", in_reply_to.bright_black());
        }

        if let Some(ref references) = email.references {
            println!("   References: {}", references.bright_black());
        }

        if !email.recipients.is_empty() {
            println!("   Recipients: {}", email.recipients.bright_black());
        }

        // Show full message body only when verbose
        if options.verbose >= 1 {
            println!("\n{}", "   --- Message Body ---".bright_black());
            // Body is already separated from headers
            for line in email.body.lines() {
                println!("   {}", line);
            }
            println!("{}", "   --- End Message ---".bright_black());
        }

        println!();
    }

    if limit > 0 && emails.len() >= limit {
        println!(
            "{} Result limit of {} reached. There may be more matches.",
            "Note:".yellow(),
            limit
        );
    }

    Ok(())
}

pub async fn lore_get_by_message_id(
    db: &DatabaseManager,
    message_id: &str,
    verbose: usize,
    show_thread: bool,
    show_replies: bool,
) -> Result<()> {
    println!("Looking up email with message_id: {}", message_id.cyan());

    let email_opt = db.get_lore_email_by_message_id(message_id).await?;

    match email_opt {
        Some(email) => {
            if show_thread {
                // Show the full thread for this message
                println!();
                lore_show_thread(db, &email.message_id, verbose).await?;
            } else if show_replies {
                // Show only replies/descendants
                println!();
                lore_show_replies(db, &email.message_id, verbose).await?;
            } else {
                // Show just this single message
                println!("\n{}\n", "Email found:".green());
                println!("{} - {}", email.date.bright_black(), email.subject.cyan());

                // Always show database column headers
                println!("   From: {}", email.from.yellow());
                println!("   Message-ID: {}", email.message_id.bright_black());

                if let Some(ref in_reply_to) = email.in_reply_to {
                    println!("   In-Reply-To: {}", in_reply_to.bright_black());
                }

                if let Some(ref references) = email.references {
                    println!("   References: {}", references.bright_black());
                }

                if !email.recipients.is_empty() {
                    println!("   Recipients: {}", email.recipients.bright_black());
                }

                // Show full message body only when verbose
                if verbose >= 1 {
                    println!("\n{}", "   --- Message Body ---".bright_black());
                    // Body is already separated from headers
                    for line in email.body.lines() {
                        println!("   {}", line);
                    }
                    println!("{}", "   --- End Message ---".bright_black());
                }

                println!();
            }
        }
        None => {
            println!(
                "{} Email not found with message_id: {}",
                "Info:".yellow(),
                message_id
            );
        }
    }

    Ok(())
}

/// Get a lore email by message_id with full options support (including mbox output)
pub async fn lore_get_by_message_id_with_options(
    db: &DatabaseManager,
    message_id: &str,
    options: &LoreSearchOptions<'_>,
) -> Result<()> {
    if !options.mbox_output {
        println!("Looking up email with message_id: {}", message_id.cyan());
    }

    let email_opt = db.get_lore_email_by_message_id(message_id).await?;

    match email_opt {
        Some(email) => {
            if options.mbox_output {
                // Output in MBOX format
                let mut stdout = std::io::stdout();
                crate::lore_writers::write_email_as_mbox(&email, &mut stdout)?;
            } else if options.show_thread {
                // Show the full thread for this message
                println!();
                lore_show_thread(db, &email.message_id, options.verbose).await?;
            } else if options.show_replies {
                // Show only replies/descendants
                println!();
                lore_show_replies(db, &email.message_id, options.verbose).await?;
            } else {
                // Show just this single message
                println!("\n{}\n", "Email found:".green());
                println!("{} - {}", email.date.bright_black(), email.subject.cyan());

                // Always show database column headers
                println!("   From: {}", email.from.yellow());
                println!("   Message-ID: {}", email.message_id.bright_black());

                if let Some(ref in_reply_to) = email.in_reply_to {
                    println!("   In-Reply-To: {}", in_reply_to.bright_black());
                }

                if let Some(ref references) = email.references {
                    println!("   References: {}", references.bright_black());
                }

                if !email.recipients.is_empty() {
                    println!("   Recipients: {}", email.recipients.bright_black());
                }

                // Show full message body only when verbose
                if options.verbose >= 1 {
                    println!("\n{}", "   --- Message Body ---".bright_black());
                    // Body is already separated from headers
                    for line in email.body.lines() {
                        println!("   {}", line);
                    }
                    println!("{}", "   --- End Message ---".bright_black());
                }

                println!();
            }
        }
        None => {
            println!(
                "{} Email not found with message_id: {}",
                "Info:".yellow(),
                message_id
            );
        }
    }

    Ok(())
}

/// Sort emails in thread order: first by reply structure, then by date within each level
pub fn sort_emails_by_thread_order(
    emails: &[crate::types::LoreEmailInfo],
) -> Vec<crate::types::LoreEmailInfo> {
    use std::collections::HashMap;

    if emails.is_empty() {
        return Vec::new();
    }

    // Build a map of message_id -> email for quick lookup
    let email_map: HashMap<String, &crate::types::LoreEmailInfo> =
        emails.iter().map(|e| (e.message_id.clone(), e)).collect();

    // Build a map of parent message_id -> list of children (sorted by date)
    let mut children_map: HashMap<Option<String>, Vec<&crate::types::LoreEmailInfo>> =
        HashMap::new();

    for email in emails {
        let parent_key = email.in_reply_to.clone();
        children_map.entry(parent_key).or_default().push(email);
    }

    // Sort children by date within each parent
    for children in children_map.values_mut() {
        children.sort_by(|a, b| a.date.cmp(&b.date));
    }

    // Perform depth-first traversal starting from root messages (no parent)
    let mut result = Vec::new();
    let mut stack = Vec::new();

    // Find root messages (those with no in_reply_to or whose parent is not in our set)
    for email in emails {
        let is_root = match &email.in_reply_to {
            None => true,
            Some(parent_id) => !email_map.contains_key(parent_id),
        };

        if is_root {
            stack.push(email);
        }
    }

    // Sort root messages by date
    stack.sort_by(|a, b| b.date.cmp(&a.date)); // Reverse for stack (pop gives oldest first)

    // DFS traversal
    while let Some(email) = stack.pop() {
        result.push(email.clone());

        // Add children in reverse order (so oldest is processed first when popped)
        if let Some(children) = children_map.get(&Some(email.message_id.clone())) {
            for child in children.iter().rev() {
                stack.push(child);
            }
        }
    }

    result
}

pub async fn lore_show_thread(
    db: &DatabaseManager,
    message_id: &str,
    verbose: usize,
) -> Result<()> {
    use std::collections::{HashSet, VecDeque};

    println!("Finding thread root for message: {}", message_id.cyan());

    // Step 1: Walk up the in_reply_to chain to find the root message
    let mut current_email = match db.get_lore_email_by_message_id(message_id).await? {
        Some(email) => email,
        None => {
            println!(
                "{} Email not found with message_id: {}",
                "Error:".red(),
                message_id
            );
            return Ok(());
        }
    };

    let mut seen_during_walk_up = HashSet::new();
    seen_during_walk_up.insert(current_email.message_id.clone());

    // Walk up the reply chain until we find the root (no in_reply_to)
    while let Some(ref in_reply_to) = current_email.in_reply_to {
        // Avoid infinite loops in case of circular references
        if seen_during_walk_up.contains(in_reply_to) {
            tracing::warn!("Circular in_reply_to reference detected, stopping walk up");
            break;
        }

        match db.get_lore_email_by_message_id(in_reply_to).await? {
            Some(parent_email) => {
                seen_during_walk_up.insert(parent_email.message_id.clone());
                current_email = parent_email;
            }
            None => {
                // Parent message not found in database, use current as root
                tracing::debug!(
                    "Parent message {} not found, using current as root",
                    in_reply_to
                );
                break;
            }
        }
    }

    let root_message_id = current_email.message_id.clone();
    println!("Found thread root: {}", root_message_id.bright_black());

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
    // This uses a topological sort based on in_reply_to relationships
    let sorted_emails = sort_emails_by_thread_order(&all_emails);

    println!(
        "\n{} Found {} message(s) in thread:\n",
        "Thread:".bold().green(),
        all_emails.len()
    );

    // Display all emails in the thread
    for (idx, email) in sorted_emails.iter().enumerate() {
        println!(
            "{}. {} - {}",
            (idx + 1).to_string().bright_black(),
            email.date.bright_black(),
            email.subject.cyan()
        );

        // Always show database column headers
        println!("   From: {}", email.from.yellow());
        println!("   Message-ID: {}", email.message_id.bright_black());

        if let Some(ref in_reply_to) = email.in_reply_to {
            println!("   In-Reply-To: {}", in_reply_to.bright_black());
        }

        if let Some(ref references) = email.references {
            println!("   References: {}", references.bright_black());
        }

        if !email.recipients.is_empty() {
            println!("   Recipients: {}", email.recipients.bright_black());
        }

        // Show full message body only when verbose
        if verbose >= 1 {
            println!("\n{}", "   --- Message Body ---".bright_black());
            // Body is already separated from headers
            for line in email.body.lines() {
                println!("   {}", line);
            }
            println!("{}", "   --- End Message ---".bright_black());
        }

        println!();
    }

    Ok(())
}

/// Show all replies/subthreads under a given message (descendants only, not ancestors)
pub async fn lore_show_replies(
    db: &DatabaseManager,
    message_id: &str,
    verbose: usize,
) -> Result<()> {
    use std::collections::{HashSet, VecDeque};

    println!("Finding all replies to message: {}", message_id.cyan());

    // Get the starting message
    let root_email = match db.get_lore_email_by_message_id(message_id).await? {
        Some(email) => email,
        None => {
            println!(
                "{} Email not found with message_id: {}",
                "Error:".red(),
                message_id
            );
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
        println!("\n{} No replies found", "Info:".yellow());
        return Ok(());
    }

    // Sort emails in thread order (respecting reply structure, then by date)
    let sorted_emails = sort_emails_by_thread_order(&all_emails);

    println!(
        "\n{} Found {} message(s) (including root):\n",
        "Replies:".bold().green(),
        all_emails.len()
    );

    // Display all emails in the subthread
    for (idx, email) in sorted_emails.iter().enumerate() {
        println!(
            "{}. {} - {}",
            (idx + 1).to_string().bright_black(),
            email.date.bright_black(),
            email.subject.cyan()
        );

        // Always show database column headers
        println!("   From: {}", email.from.yellow());
        println!("   Message-ID: {}", email.message_id.bright_black());

        if let Some(ref in_reply_to) = email.in_reply_to {
            println!("   In-Reply-To: {}", in_reply_to.bright_black());
        }

        // Show full message body only when verbose
        if verbose >= 1 {
            println!("\n{}", "   --- Message Body ---".bright_black());
            for line in email.body.lines() {
                println!("   {}", line);
            }
            println!("{}\n", "   --- End Message ---".bright_black());
        } else {
            println!(); // Empty line between messages
        }
    }

    Ok(())
}

/// Search lore emails by git commit SHA, ordered by date (newest first)
/// Takes a commit from the main git repo, extracts its subject, and searches lore emails
pub async fn lore_search_by_commit(
    db: &DatabaseManager,
    git_commit_ish: &str,
    git_repo_path: &str,
    show_all: bool,
    options: &LoreSearchOptions<'_>,
) -> Result<()> {
    use anstream::stdout;

    // Use shared writer function for consistent behavior with MCP
    crate::lore_writers::dig_lore_by_commit_to_writer(
        db,
        git_commit_ish,
        git_repo_path,
        show_all,
        options,
        &mut stdout(),
    )
    .await
}

// Writer-based versions of search functions for both CLI and MCP usage

pub async fn query_function_or_macro_to_writer(
    db: &DatabaseManager,
    name: &str,
    git_sha: &str,
    writer: &mut dyn Write,
) -> Result<()> {
    query_function_or_macro_to_writer_with_options(db, name, git_sha, writer, false).await
}

pub async fn query_function_or_macro_to_writer_verbose(
    db: &DatabaseManager,
    name: &str,
    git_sha: &str,
    writer: &mut dyn Write,
    verbose: bool,
) -> Result<()> {
    query_function_or_macro_to_writer_with_options(db, name, git_sha, writer, verbose).await
}

/// Check if a function is actually a definition (has implementation) vs just a declaration
pub fn is_function_definition(func: &crate::FunctionInfo) -> bool {
    if func.body.is_empty() {
        return false; // Empty body is definitely a declaration
    }

    // Macros have empty return_type and are always definitions (never just declarations)
    if func.return_type.is_empty() {
        return true;
    }

    let body = func.body.trim();

    // If body ends with just a semicolon, it's a declaration
    if body.ends_with(';') && !body.contains('{') {
        return false;
    }

    // If it contains braces, it's likely a definition
    if body.contains('{') && body.contains('}') {
        return true;
    }

    // Header files typically contain declarations
    if func.file_path.ends_with(".h") || func.file_path.ends_with(".hpp") {
        // In header files, be more strict - require braces for definitions
        return body.contains('{') && body.contains('}');
    }

    // For .c/.cpp files, if it's not just a semicolon-terminated line, assume it's a definition
    !body.ends_with(';')
}

async fn query_function_or_macro_to_writer_with_options(
    db: &DatabaseManager,
    name: &str,
    git_sha: &str,
    writer: &mut dyn Write,
    verbose: bool,
) -> Result<()> {
    let search_msg = format!(
        "Searching for function: {} (git SHA: {})",
        name.cyan(),
        git_sha.yellow()
    );
    writeln!(writer, "{search_msg}")?;

    // Find all functions at the specific git SHA (includes macros stored as functions)
    let func_results = db.find_all_functions_git_aware(name, git_sha).await?;

    match func_results.is_empty() {
        false => {
            // Found functions only - filter out declarations and display only definitions
            let definitions: Vec<_> = func_results
                .iter()
                .filter(|func| is_function_definition(func))
                .collect();

            if definitions.len() > 1 {
                writeln!(
                    writer,
                    "\n{} Found {} function definitions with name '{}' at git SHA {}:",
                    "Note:".yellow(),
                    definitions.len(),
                    name,
                    git_sha.yellow()
                )?;
            }

            // Display each function definition with its outgoing calls
            for (i, func) in definitions.iter().enumerate() {
                if definitions.len() > 1 {
                    writeln!(
                        writer,
                        "\n{} Function {} of {}:",
                        "==>".bold().blue(),
                        i + 1,
                        definitions.len()
                    )?;
                }
                display_function_to_writer_with_options(func, writer, true)?;
                // Get and display calls (outgoing) for each function definition
                let calls = db
                    .get_function_callees_git_aware(&func.name, git_sha)
                    .await?;
                display_call_relationships_with_options(
                    &func.name,
                    &calls,
                    &[],
                    writer,
                    &DisplayCallOptions {
                        truncate: true,
                        verbose,
                        show_calls: true,
                        show_callers: false,
                    },
                )?;
            }

            // If there are multiple definitions, display callers once at the end
            if definitions.len() > 1 {
                let called_by = db.get_function_callers_git_aware(name, git_sha).await?;
                if !called_by.is_empty() {
                    writeln!(
                        writer,
                        "\n{} Callers to all '{}' functions:",
                        "==>".bold().blue(),
                        name
                    )?;
                    display_call_relationships_with_options(
                        name,
                        &[],
                        &called_by,
                        writer,
                        &DisplayCallOptions {
                            truncate: true,
                            verbose,
                            show_calls: false,
                            show_callers: true,
                        },
                    )?;
                }
            } else if definitions.len() == 1 {
                // For single definition, show callers normally (maintain existing behavior)
                let called_by = db.get_function_callers_git_aware(name, git_sha).await?;
                display_call_relationships_with_options(
                    name,
                    &[],
                    &called_by,
                    writer,
                    &DisplayCallOptions {
                        truncate: true,
                        verbose,
                        show_calls: false,
                        show_callers: true,
                    },
                )?;
            } else {
                // No definitions found, only declarations
                writeln!(
                    writer,
                    "\n{} Found function declarations but no definitions for '{}' at git SHA {}",
                    "Info:".yellow(),
                    name,
                    git_sha.yellow()
                )?;
            }
            // Early return - we found exact matches (even if only declarations)
            return Ok(());
        }
        true => {
            // No exact match found, try regex search
            let regex_functions = db.search_functions_regex_git_aware(name, git_sha).await?;

            match regex_functions.is_empty() {
                false => {
                    // Found functions with regex
                    writeln!(writer, "\n{} No exact match found for '{}' at git SHA {}, but found functions using it as a regex pattern:", "Info:".yellow(), name, git_sha.yellow())?;

                    writeln!(
                        writer,
                        "\n{}",
                        "=== Functions (regex matches) ===".bold().green()
                    )?;
                    // Filter out declarations and show only definitions
                    let regex_definitions: Vec<_> = regex_functions
                        .iter()
                        .filter(|func| is_function_definition(func))
                        .collect();
                    for func in &regex_definitions {
                        display_function_to_writer_with_options(func, writer, true)?;
                        // Get and display calls (outgoing) for each function definition
                        let calls = get_function_calls_git_aware(db, &func.name, git_sha).await?;
                        display_call_relationships_with_options(
                            &func.name,
                            &calls,
                            &[],
                            writer,
                            &DisplayCallOptions {
                                truncate: true,
                                verbose,
                                show_calls: true,
                                show_callers: false,
                            },
                        )?;
                    }

                    // Collect and display callers for all matched function definitions
                    let mut all_callers = std::collections::HashSet::new();
                    for func in &regex_definitions {
                        let func_callers = get_function_callers(db, &func.name).await?;
                        all_callers.extend(func_callers);
                    }
                    if !all_callers.is_empty() {
                        let callers: Vec<String> = all_callers.into_iter().collect();
                        writeln!(
                            writer,
                            "\n{} Callers to all matched functions:",
                            "==>".bold().blue()
                        )?;
                        display_call_relationships_with_options(
                            "",
                            &[],
                            &callers,
                            writer,
                            &DisplayCallOptions {
                                truncate: true,
                                verbose,
                                show_calls: false,
                                show_callers: true,
                            },
                        )?;
                    }
                }
                true => {
                    // No regex matches either, show fuzzy suggestions
                    let error_msg = format!(
                        "{} No function '{}' found at git SHA {}",
                        "Error:".red(),
                        name,
                        git_sha.yellow()
                    );
                    writeln!(writer, "{error_msg}")?;

                    // Try git-aware fuzzy search for suggestions
                    let func_suggestions =
                        db.search_functions_fuzzy_git_aware(name, git_sha).await?;

                    if !func_suggestions.is_empty() {
                        writeln!(writer, "\nDid you mean:")?;
                        for func in func_suggestions.iter().take(3) {
                            writeln!(
                                writer,
                                "  - {} {} (function at git SHA {})",
                                "func --git".yellow(),
                                func.name,
                                git_sha.yellow()
                            )?;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

pub async fn show_tables_to_writer(db: &DatabaseManager, writer: &mut dyn Write) -> Result<()> {
    // Get counts using efficient count methods (no table scans)
    let function_count = db.count_functions().await?;
    let type_count = db.count_types().await?;
    let typedef_count = db.count_typedefs().await?;

    writeln!(writer, "{}", "=== Database Tables ===".bold().green())?;

    writeln!(
        writer,
        "{}: {}",
        "Functions".bold(),
        function_count.to_string().cyan()
    )?;
    writeln!(
        writer,
        "{}: {}",
        "Types".bold(),
        type_count.to_string().cyan()
    )?;
    writeln!(
        writer,
        "{}: {}",
        "Typedefs".bold(),
        typedef_count.to_string().cyan()
    )?;

    let total = function_count + type_count + typedef_count;
    writeln!(writer, "{}: {}", "Total".bold(), total.to_string().cyan())?;
    writeln!(writer, "\nNote: Macros are stored in the functions table")?;

    Ok(())
}

pub async fn query_type_or_typedef_to_writer(
    db: &DatabaseManager,
    name: &str,
    git_sha: &str,
    writer: &mut dyn Write,
) -> Result<()> {
    // Handle "struct", "union", "enum" prefixes
    let clean_name = name
        .trim_start_matches("struct ")
        .trim_start_matches("union ")
        .trim_start_matches("enum ");

    let search_msg = format!(
        "Searching for type or typedef: {} (git SHA: {})",
        clean_name.cyan(),
        git_sha.yellow()
    );
    writeln!(writer, "{search_msg}")?;

    // First try to find a type at the specific git SHA
    let type_result = db.find_type_git_aware(clean_name, git_sha).await?;
    // Then try to find a typedef at the specific git SHA
    let typedef_result = db.find_typedef_git_aware(clean_name, git_sha).await?;

    match (type_result, typedef_result) {
        (Some(type_info), Some(typedef_info)) => {
            // Found both - display both
            let note = format!(
                "\n{} Found both a type and a typedef with this name at git SHA {}!",
                "Note:".yellow(),
                git_sha.yellow()
            );
            writeln!(writer, "{note}")?;
            display_type_to_writer(&type_info, writer)?;
            display_typedef_to_writer(&typedef_info, writer)?;
        }
        (Some(type_info), None) => {
            display_type_to_writer(&type_info, writer)?;
        }
        (None, Some(typedef_info)) => {
            display_typedef_to_writer(&typedef_info, writer)?;
        }
        (None, None) => {
            // No exact match found, try regex search
            let regex_types = db.search_types_regex_git_aware(clean_name, git_sha).await?;
            let regex_typedefs = db
                .search_typedefs_regex_git_aware(clean_name, git_sha)
                .await?;

            match (regex_types.is_empty(), regex_typedefs.is_empty()) {
                (false, false) => {
                    // Found both types and typedefs with regex
                    writeln!(writer, "\n{} No exact match found for '{}' at git SHA {}, but found matches using it as a regex pattern:", "Info:".yellow(), clean_name, git_sha.yellow())?;

                    writeln!(
                        writer,
                        "\n{}",
                        "=== Types (regex matches) ===".bold().green()
                    )?;
                    for type_info in &regex_types {
                        display_type_to_writer(type_info, writer)?;
                    }

                    writeln!(
                        writer,
                        "\n{}",
                        "=== Typedefs (regex matches) ===".bold().green()
                    )?;
                    for typedef_info in &regex_typedefs {
                        display_typedef_to_writer(typedef_info, writer)?;
                    }
                }
                (false, true) => {
                    // Found only types with regex
                    writeln!(writer, "\n{} No exact match found for '{}' at git SHA {}, but found types using it as a regex pattern:", "Info:".yellow(), clean_name, git_sha.yellow())?;
                    for type_info in &regex_types {
                        display_type_to_writer(type_info, writer)?;
                    }
                }
                (true, false) => {
                    // Found only typedefs with regex
                    writeln!(writer, "\n{} No exact match found for '{}' at git SHA {}, but found typedefs using it as a regex pattern:", "Info:".yellow(), clean_name, git_sha.yellow())?;
                    for typedef_info in &regex_typedefs {
                        display_typedef_to_writer(typedef_info, writer)?;
                    }
                }
                (true, true) => {
                    // No regex matches either, show fuzzy suggestions
                    let error_msg = format!(
                        "{} No type or typedef '{}' found at git SHA {}",
                        "Error:".red(),
                        clean_name,
                        git_sha.yellow()
                    );
                    writeln!(writer, "{error_msg}")?;

                    // Try git-aware fuzzy search for suggestions
                    let type_suggestions =
                        db.search_types_fuzzy_git_aware(clean_name, git_sha).await?;
                    let typedef_suggestions = db
                        .search_typedefs_fuzzy_git_aware(clean_name, git_sha)
                        .await?;

                    if !type_suggestions.is_empty() || !typedef_suggestions.is_empty() {
                        writeln!(writer, "\nDid you mean:")?;
                        for typ in type_suggestions.iter().take(3) {
                            writeln!(
                                writer,
                                "  - {} {} {} (at git SHA {})",
                                "type --git".yellow(),
                                typ.kind,
                                typ.name,
                                git_sha.yellow()
                            )?;
                        }
                        for typedef in typedef_suggestions.iter().take(3) {
                            writeln!(
                                writer,
                                "  - {} {} (at git SHA {})",
                                "typedef --git".yellow(),
                                typedef.name,
                                git_sha.yellow()
                            )?;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

pub async fn list_functions_and_macros_to_writer(
    db: &DatabaseManager,
    pattern: &str,
    git_sha: &str,
    writer: &mut dyn Write,
) -> Result<()> {
    writeln!(
        writer,
        "Searching for functions and macros matching: {} (git SHA: {})",
        pattern.cyan(),
        git_sha.yellow()
    )?;

    let functions = db
        .search_functions_fuzzy_git_aware(pattern, git_sha)
        .await?;

    if !functions.is_empty() {
        writeln!(writer, "\n{}", "=== Functions ===".bold().green())?;

        for (i, func) in functions.iter().enumerate() {
            writeln!(
                writer,
                "  {}. {} ({}:{})",
                (i + 1).to_string().yellow(),
                func.name.cyan(),
                func.file_path.bright_black(),
                func.line_start
            )?;
        }
    }

    if functions.is_empty() {
        writeln!(
            writer,
            "{} No matches found for pattern '{}' at git SHA {}",
            "Info:".yellow(),
            pattern,
            git_sha.yellow()
        )?;
    } else {
        writeln!(
            writer,
            "\n{} Found {} functions (including macros) at git SHA {}",
            "Summary:".bold().cyan(),
            functions.len(),
            git_sha.yellow()
        )?;
    }

    Ok(())
}

pub async fn list_types_and_typedefs_to_writer(
    db: &DatabaseManager,
    pattern: &str,
    git_sha: &str,
    writer: &mut dyn Write,
) -> Result<()> {
    writeln!(
        writer,
        "Searching for types and typedefs matching: {} (git SHA: {})",
        pattern.cyan(),
        git_sha.yellow()
    )?;

    let types = db.search_types_fuzzy_git_aware(pattern, git_sha).await?;
    let typedefs = db.search_typedefs_fuzzy_git_aware(pattern, git_sha).await?;

    if !types.is_empty() {
        writeln!(writer, "\n{}", "=== Types ===".bold().green())?;

        for (i, typ) in types.iter().enumerate() {
            writeln!(
                writer,
                "  {}. {} {} ({}:{})",
                (i + 1).to_string().yellow(),
                typ.kind.magenta(),
                typ.name.cyan(),
                typ.file_path.bright_black(),
                typ.line_start
            )?;
        }
    }

    if !typedefs.is_empty() {
        writeln!(writer, "\n{}", "=== Typedefs ===".bold().green())?;

        for (i, typedef) in typedefs.iter().enumerate() {
            writeln!(
                writer,
                "  {}. {} -> {} ({}:{})",
                (i + 1).to_string().yellow(),
                typedef.name.cyan(),
                typedef.underlying_type.magenta(),
                typedef.file_path.bright_black(),
                typedef.line_start
            )?;
        }
    }

    if types.is_empty() && typedefs.is_empty() {
        writeln!(
            writer,
            "{} No matches found for pattern '{}' at git SHA {}",
            "Info:".yellow(),
            pattern,
            git_sha.yellow()
        )?;
    } else {
        writeln!(
            writer,
            "\n{} Found {} types, {} typedefs at git SHA {}",
            "Summary:".bold().cyan(),
            types.len(),
            typedefs.len(),
            git_sha.yellow()
        )?;
    }

    Ok(())
}
