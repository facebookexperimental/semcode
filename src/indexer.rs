// SPDX-License-Identifier: MIT OR Apache-2.0
//! Indexing functionality shared across binaries
//!
//! This module provides reusable indexing functions for git commits and files
//! that can be called from different binaries (semcode-index, semcode, semcode-mcp, etc.)

use anyhow::Result;
use gix::revision::walk::Sorting;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use tracing::{debug, error, info, warn};

use crate::git::resolve_to_commit;
use crate::{DatabaseManager, GitCommitInfo, LoreIdState};

/// Perform periodic optimization check during indexing operations
/// Returns true if optimization was performed, false otherwise
pub async fn check_and_optimize_if_needed(
    db_manager: &DatabaseManager,
    inserter_id: usize,
    total_batches: usize,
    optimization_check_timer: &Arc<std::sync::Mutex<std::time::Instant>>,
) -> bool {
    use owo_colors::OwoColorize;

    // Periodic optimization check (only inserter 0, every 300 batches total, at most once per 15 minutes)
    // Don't check until we've done at least 300 batches (skip the very first check)
    if inserter_id != 0 || total_batches <= 300 || !total_batches.is_multiple_of(300) {
        return false;
    }

    // Check if we should run optimization (must drop lock before await)
    let should_optimize = {
        // Try to acquire lock without blocking - if another thread is checking, skip
        if let Ok(last_check) = optimization_check_timer.try_lock() {
            let elapsed = last_check.elapsed();
            // Only check if it's been at least 15 minutes since last check
            elapsed.as_secs() >= 900
        } else {
            false
        }
    };

    if !should_optimize {
        return false;
    }

    // Quick health check (lock is dropped, safe to await)
    match db_manager.check_optimization_health().await {
        Ok((needs_optimization, message)) => {
            if needs_optimization {
                info!("{}", message);
                info!(
                    "\n{} Fragment threshold exceeded during indexing, running optimization...",
                    "⚠️".yellow()
                );
                match db_manager.optimize_database().await {
                    Ok(_) => {
                        info!("{} In-progress optimization completed", "✓".green());
                    }
                    Err(e) => {
                        warn!("In-progress optimization failed: {}", e);
                    }
                }
            } else {
                debug!(
                    "Optimization health check passed at batch {}",
                    total_batches
                );
            }
        }
        Err(e) => {
            warn!("Failed to check optimization health: {}", e);
        }
    }

    // Update last check time
    if let Ok(mut last_check) = optimization_check_timer.lock() {
        *last_check = std::time::Instant::now();
    }

    true
}

/// Parse git range and get all commit SHAs in the range.
///
/// List commit SHAs in a range using gitoxide's rev_walk.
///
/// Supports two formats:
/// 1. "A..B" - commits reachable from B but not from A
/// 2. "REF" (no ..) - all commits reachable from REF (for initial indexing)
pub fn list_shas_in_range(repo: &gix::Repository, range: &str) -> Result<Vec<String>> {
    let (from_spec, to_spec) = if range.contains("..") {
        let parts: Vec<&str> = range.split("..").collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid range format '{}'", range));
        }
        (parts[0], parts[1])
    } else {
        ("", range)
    };

    let to_commit = resolve_to_commit(repo, to_spec)?;
    let to_id = to_commit.id().detach();

    let walk = if from_spec.is_empty() {
        repo.rev_walk([to_id])
            .sorting(Sorting::ByCommitTime(Default::default()))
            .all()?
    } else {
        match resolve_to_commit(repo, from_spec) {
            Ok(from_commit) => {
                let from_id = from_commit.id().detach();
                repo.rev_walk([to_id])
                    .with_hidden([from_id])
                    .sorting(Sorting::ByCommitTime(Default::default()))
                    .all()?
            }
            Err(e) => {
                info!(
                    "Could not resolve '{}' ({}); falling back to single-commit indexing",
                    from_spec, e
                );
                return Ok(vec![to_id.to_string()]);
            }
        }
    };

    let mut shas = Vec::new();
    const MAX_COMMITS: usize = 10000000;

    for info in walk {
        let info = info?;

        if shas.len() > MAX_COMMITS {
            return Err(anyhow::anyhow!(
                "Commit range {} is too large (>{} commits)",
                range,
                MAX_COMMITS
            ));
        }

        shas.push(info.id().to_string());
    }

    // Reverse to get chronological order (oldest first)
    shas.reverse();

    Ok(shas)
}

/// Parse tags from commit message (e.g., Signed-off-by:, Reported-by:, etc.)
fn parse_commit_message_tags(message: &str) -> std::collections::HashMap<String, Vec<String>> {
    use std::collections::HashMap;

    let mut tags: HashMap<String, Vec<String>> = HashMap::new();

    for line in message.lines() {
        let line = line.trim();

        // Look for tag pattern: "Tag-Name: value"
        if let Some(colon_pos) = line.find(':') {
            let tag_name = line[..colon_pos].trim();
            let tag_value = line[colon_pos + 1..].trim();

            // Check if this looks like a tag (capitalized words with dashes)
            if tag_name.chars().all(|c| c.is_alphanumeric() || c == '-')
                && tag_name.contains(|c: char| c.is_uppercase())
                && !tag_value.is_empty()
            {
                tags.entry(tag_name.to_string())
                    .or_default()
                    .push(tag_value.to_string());
            }
        }
    }

    tags
}

/// Extract commit metadata from git repository
pub fn extract_commit_metadata(repo: &gix::Repository, commit_sha: &str) -> Result<GitCommitInfo> {
    // Resolve commit
    let commit = resolve_to_commit(repo, commit_sha)?;

    // Get commit metadata
    let git_sha = commit.id().to_string();

    // Get parent commits
    let parent_sha: Vec<String> = commit.parent_ids().map(|id| id.to_string()).collect();

    // Get author
    let author_sig = commit.author()?;
    let author = format!("{} <{}>", author_sig.name, author_sig.email);

    // Get commit message
    let message_bytes = commit.message_raw()?;
    let message = String::from_utf8_lossy(message_bytes).to_string();

    // Extract subject (first line of message)
    let subject = message.lines().next().unwrap_or("").to_string();

    // Parse tags from message
    let tags = parse_commit_message_tags(&message);

    // Generate unified diff for commits with exactly one parent
    let (diff, symbols, files) = if parent_sha.len() == 1 {
        match generate_commit_diff(repo, &parent_sha[0], &git_sha) {
            Ok((d, s, f)) => (d, s, f),
            Err(e) => {
                tracing::warn!("Failed to generate diff for commit {}: {}", git_sha, e);
                (String::new(), Vec::new(), Vec::new())
            }
        }
    } else {
        // Skip diff for merge commits (multiple parents) or root commits (no parents)
        (String::new(), Vec::new(), Vec::new())
    };

    Ok(GitCommitInfo {
        git_sha,
        parent_sha,
        author,
        subject,
        message,
        tags,
        diff,
        symbols,
        files,
    })
}

/// Generate a unified diff between two commits using gitoxide
/// Returns the diff string, a vector of symbols (functions, types, macros) that were modified, and a vector of changed files
fn generate_commit_diff(
    repo: &gix::Repository,
    from_sha: &str,
    to_sha: &str,
) -> Result<(String, Vec<String>, Vec<String>)> {
    use crate::git;
    use std::fmt::Write as _;

    tracing::info!(
        "generate_commit_diff: generating diff {} -> {} using gitoxide",
        from_sha,
        to_sha
    );

    let from_commit = resolve_to_commit(repo, from_sha)?;
    let to_commit = resolve_to_commit(repo, to_sha)?;

    let from_tree = from_commit.tree()?;
    let to_tree = to_commit.tree()?;

    let mut diff_output = String::new();
    let mut all_symbols = Vec::new();
    let mut changed_files = Vec::new();

    // Use gitoxide's diff functionality
    from_tree
        .changes()?
        .for_each_to_obtain_tree(&to_tree, |change| {
            use gix::object::tree::diff::Action;

            match change {
                gix::object::tree::diff::Change::Modification {
                    previous_entry_mode,
                    previous_id,
                    entry_mode,
                    id,
                    location,
                    ..
                } => {
                    // Skip non-blob modifications
                    if !previous_entry_mode.is_blob() || !entry_mode.is_blob() {
                        return Ok::<_, anyhow::Error>(Action::Continue(()));
                    }

                    let path = location.to_string();
                    changed_files.push(path.clone());

                    // Write diff header
                    let _ = writeln!(diff_output, "diff --git a/{} b/{}", path, path);
                    let _ = writeln!(diff_output, "--- a/{}", path);
                    let _ = writeln!(diff_output, "+++ b/{}", path);

                    // Get file contents
                    if let (Ok(old_obj), Ok(new_obj)) =
                        (repo.find_object(previous_id), repo.find_object(id))
                    {
                        if let (Ok(old_blob), Ok(new_blob)) =
                            (old_obj.try_into_blob(), new_obj.try_into_blob())
                        {
                            let old_content = String::from_utf8_lossy(old_blob.data.as_slice());
                            let new_content = String::from_utf8_lossy(new_blob.data.as_slice());

                            // Generate diff and extract symbols using walk-back algorithm
                            let (write_result, file_symbols) = git::write_diff_and_extract_symbols(
                                &mut diff_output,
                                &old_content,
                                &new_content,
                                &path,
                            );
                            let _ = write_result;
                            all_symbols.extend(file_symbols);
                        }
                    }

                    Ok(Action::Continue(()))
                }
                gix::object::tree::diff::Change::Addition {
                    entry_mode,
                    id,
                    location,
                    ..
                } => {
                    if !entry_mode.is_blob() {
                        return Ok(Action::Continue(()));
                    }

                    let path = location.to_string();
                    changed_files.push(path.clone());
                    let _ = writeln!(diff_output, "diff --git a/{} b/{}", path, path);
                    let _ = writeln!(diff_output, "--- /dev/null");
                    let _ = writeln!(diff_output, "+++ b/{}", path);

                    if let Ok(obj) = repo.find_object(id) {
                        if let Ok(blob) = obj.try_into_blob() {
                            let content = String::from_utf8_lossy(blob.data.as_slice());
                            let _ =
                                writeln!(diff_output, "@@ -0,0 +1,{} @@", content.lines().count());
                            for line in content.lines() {
                                let _ = writeln!(diff_output, "+{}", line);
                            }
                        }
                    }

                    Ok(Action::Continue(()))
                }
                gix::object::tree::diff::Change::Deletion {
                    entry_mode,
                    id,
                    location,
                    ..
                } => {
                    if !entry_mode.is_blob() {
                        return Ok(Action::Continue(()));
                    }

                    let path = location.to_string();
                    changed_files.push(path.clone());
                    let _ = writeln!(diff_output, "diff --git a/{} b/{}", path, path);
                    let _ = writeln!(diff_output, "--- a/{}", path);
                    let _ = writeln!(diff_output, "+++ /dev/null");

                    if let Ok(obj) = repo.find_object(id) {
                        if let Ok(blob) = obj.try_into_blob() {
                            let content = String::from_utf8_lossy(blob.data.as_slice());
                            let _ =
                                writeln!(diff_output, "@@ -1,{} +0,0 @@", content.lines().count());
                            for line in content.lines() {
                                let _ = writeln!(diff_output, "-{}", line);
                            }
                        }
                    }

                    Ok(Action::Continue(()))
                }
                gix::object::tree::diff::Change::Rewrite { .. } => {
                    // Rewrite represents a complete file replacement - rare in practice
                    // Skip for now as it's complex to handle properly
                    Ok::<_, anyhow::Error>(Action::Continue(()))
                }
            }
        })?;

    tracing::info!(
        "generate_commit_diff: generated {} bytes of diff with {} symbols and {} files",
        diff_output.len(),
        all_symbols.len(),
        changed_files.len()
    );

    Ok((diff_output, all_symbols, changed_files))
}

/// Parse RFC 2822 date string to Unix timestamp
/// Returns 0 if parsing fails (fallback for malformed dates)
fn parse_rfc2822_to_timestamp(date_str: &str) -> i64 {
    chrono::DateTime::parse_from_rfc2822(date_str)
        .map(|dt| dt.timestamp())
        .unwrap_or_else(|e| {
            tracing::warn!("Failed to parse RFC 2822 date '{}': {}", date_str, e);
            0
        })
}

/// Parse email from a lore commit's 'm' file
/// Extracts headers and body from an email message
pub fn parse_email_from_commit(
    repo: &gix::Repository,
    commit_sha: &str,
) -> Result<crate::LoreEmailInfo> {
    // Resolve commit
    let commit = resolve_to_commit(repo, commit_sha)?;

    // Get the tree
    let tree = commit.tree()?;

    // Find the 'm' file in the tree
    let m_entry = tree
        .find_entry("m")
        .ok_or_else(|| anyhow::anyhow!("Commit {} does not contain file 'm'", commit_sha))?;

    // Read the file content
    let object = m_entry.object()?;
    let blob = object.try_into_blob()?;
    let email_content = String::from_utf8_lossy(blob.data.as_slice()).to_string();

    // Parse email headers
    let mut headers = EmailHeaders::new();

    // Split headers and body
    let mut lines = email_content.lines();
    let mut in_headers = true;
    let mut body_lines = Vec::new();
    let mut current_header: Option<(String, String)> = None;

    for line in lines.by_ref() {
        if in_headers {
            if line.is_empty() {
                // Empty line marks end of headers
                if let Some((name, value)) = current_header.take() {
                    headers.process_header(&name, &value);
                }
                in_headers = false;
                continue;
            }

            // Check if this is a continuation line (starts with whitespace)
            if line.starts_with(' ') || line.starts_with('\t') {
                if let Some((_, ref mut value)) = current_header {
                    value.push(' ');
                    value.push_str(line.trim());
                }
            } else {
                // New header
                if let Some((name, value)) = current_header.take() {
                    headers.process_header(&name, &value);
                }

                if let Some(colon_pos) = line.find(':') {
                    let header_name = line[..colon_pos].trim().to_lowercase();
                    let header_value = line[colon_pos + 1..].trim().to_string();
                    current_header = Some((header_name, header_value));
                }
            }
        } else {
            // Body content
            body_lines.push(line);
        }
    }

    // Process any remaining header
    if let Some((name, value)) = current_header {
        headers.process_header(&name, &value);
    }

    let recipients = headers.recipients_list.join(", ");
    let body = body_lines.join("\n");

    // Extract symbols from any diffs found in the email body
    let symbols = extract_symbols_from_email_body(&body);

    // Parse date to Unix timestamp for efficient database filtering
    let date_timestamp = parse_rfc2822_to_timestamp(&headers.date);

    Ok(crate::LoreEmailInfo {
        git_commit_sha: commit_sha.to_string(),
        from: headers.from,
        date: headers.date,
        date_timestamp,
        message_id: headers.message_id,
        in_reply_to: headers.in_reply_to,
        subject: headers.subject,
        references: headers.references,
        recipients,
        body,
        symbols,
    })
}

/// Email header fields
struct EmailHeaders {
    from: String,
    date: String,
    message_id: String,
    in_reply_to: Option<String>,
    subject: String,
    references: Option<String>,
    recipients_list: Vec<String>,
}

impl EmailHeaders {
    fn new() -> Self {
        Self {
            from: String::new(),
            date: String::new(),
            message_id: String::new(),
            in_reply_to: None,
            subject: String::new(),
            references: None,
            recipients_list: Vec::new(),
        }
    }

    fn process_header(&mut self, name: &str, value: &str) {
        match name {
            "from" => self.from = value.to_string(),
            "date" => self.date = value.to_string(),
            "message-id" => self.message_id = value.to_string(),
            "in-reply-to" => self.in_reply_to = Some(value.to_string()),
            "subject" => self.subject = value.to_string(),
            "references" => self.references = Some(value.to_string()),
            "to" | "cc" => self.recipients_list.push(value.to_string()),
            _ => {}
        }
    }
}

/// Extract symbols from unified diffs found in email body
/// Detects diff headers starting at column 0 (to avoid quoted replies)
fn extract_symbols_from_email_body(body: &str) -> Vec<String> {
    use std::collections::HashSet;

    // Check if body contains unified diff markers starting at column 0
    let has_diff = body.lines().any(|line| {
        // Look for unified diff headers that start at column 0
        line.starts_with("--- a/") || line.starts_with("+++ b/") || line.starts_with("diff --git")
    });

    if !has_diff {
        return Vec::new();
    }

    // Try to parse the diff and extract symbols
    match crate::diffdump::parse_unified_diff(body) {
        Ok(result) => {
            // Collect all symbols into a deduplicated set
            let mut all_symbols = HashSet::new();

            // Add modified functions with file:function() format
            for func in result.modified_functions {
                all_symbols.insert(func);
            }

            // Add called functions
            for func in result.called_functions {
                all_symbols.insert(func);
            }

            // Add modified types
            for type_name in result.modified_types {
                all_symbols.insert(type_name);
            }

            // Add modified macros
            for macro_name in result.modified_macros {
                all_symbols.insert(macro_name);
            }

            // Convert to sorted vector for consistent output
            let mut symbols: Vec<String> = all_symbols.into_iter().collect();
            symbols.sort();
            symbols
        }
        Err(e) => {
            // Log error but don't fail the entire email parsing
            tracing::debug!("Failed to parse diff in email body: {}", e);
            Vec::new()
        }
    }
}

/// Extract metadata for each commit SHA received from `commit_rx` until it
/// closes, sending it to `result_tx` in batches of `batch_size`. `repo` is
/// the pipeline's one object store, shared by every worker.
fn commit_metadata_worker(
    worker_id: usize,
    repo: gix::ThreadSafeRepository,
    commit_rx: Arc<std::sync::Mutex<mpsc::Receiver<String>>>,
    result_tx: mpsc::SyncSender<Vec<GitCommitInfo>>,
    processed: Arc<AtomicUsize>,
    batch_size: usize,
) {
    let repo = repo.to_thread_local();
    let mut batch = Vec::new();

    loop {
        // Get next commit SHA
        let commit_sha = {
            match commit_rx.lock() {
                Ok(rx) => rx.recv(),
                Err(e) => {
                    tracing::error!("Worker {} failed to lock receiver: {}", worker_id, e);
                    break;
                }
            }
        };

        match commit_sha {
            Ok(sha) => {
                match extract_commit_metadata(&repo, &sha) {
                    Ok(metadata) => {
                        batch.push(metadata);
                        processed.fetch_add(1, Ordering::Relaxed);

                        // Send batch when it reaches batch_size
                        if batch.len() >= batch_size {
                            if result_tx.send(batch.clone()).is_err() {
                                break;
                            }
                            batch.clear();
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Worker {} failed to extract metadata for {}: {}",
                            worker_id, sha, e
                        );
                        processed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Err(_) => {
                // Channel closed, send remaining batch
                if !batch.is_empty() {
                    let _ = result_tx.send(batch);
                }
                break;
            }
        }
    }
}

/// Process commits using a streaming pipeline
pub async fn process_commits_pipeline(
    repo_path: &std::path::Path,
    commit_shas: Vec<String>,
    db_manager: Arc<DatabaseManager>,
    batch_size: usize,
    num_workers: usize,
    existing_commits: HashSet<String>,
    num_inserters: usize,
) -> Result<()> {
    use indicatif::{ProgressBar, ProgressStyle};
    use std::sync::Mutex;

    // One object store for every worker. Each store maps the pack files on
    // its own and `VmRSS` counts a mapped page once per mapping, so a store
    // per worker counts the repository's packs once per worker.
    let shared_repo = gix::discover(repo_path)
        .map_err(|e| anyhow::anyhow!("Not in a git repository: {}", e))?
        .into_sync();

    // Create progress bar
    let pb = ProgressBar::new(commit_shas.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} commits ({per_sec}) - {msg}"
        )
        .unwrap()
        .progress_chars("█▓▒░  ")
    );

    // Create channels for streaming
    // Use unbounded channel for commit SHAs (small strings, no memory concern)
    let (commit_tx, commit_rx) = mpsc::channel::<String>();
    // Use bounded channel for commit metadata (large diffs) to prevent memory explosion
    // Bound of 10 batches = max ~1000 commits in memory = ~50-100MB instead of 170GB
    let (result_tx, result_rx) = mpsc::sync_channel::<Vec<GitCommitInfo>>(10);

    // Wrap receiver for shared access
    let shared_commit_rx = Arc::new(Mutex::new(commit_rx));

    // Shared counters
    let processed_count = Arc::new(AtomicUsize::new(0));
    let inserted_count = Arc::new(AtomicUsize::new(0));

    // Spawn progress updater thread
    let pb_clone = pb.clone();
    let processed_clone = processed_count.clone();
    let progress_thread = std::thread::spawn(move || loop {
        let count = processed_clone.load(Ordering::Relaxed);
        pb_clone.set_position(count as u64);
        if pb_clone.is_finished() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    });

    // Spawn worker threads to extract commit metadata
    let mut worker_handles = Vec::new();
    for worker_id in 0..num_workers {
        let worker_commit_rx = shared_commit_rx.clone();
        let worker_result_tx = result_tx.clone();
        let worker_repo = shared_repo.clone();
        let worker_processed = processed_count.clone();

        let handle = thread::spawn(move || {
            commit_metadata_worker(
                worker_id,
                worker_repo,
                worker_commit_rx,
                worker_result_tx,
                worker_processed,
                batch_size,
            )
        });
        worker_handles.push(handle);
    }

    // Spawn producer thread to feed commit SHAs
    let producer_handle = thread::spawn(move || {
        for commit_sha in commit_shas {
            if commit_tx.send(commit_sha).is_err() {
                break;
            }
        }
    });

    // Close original senders
    drop(result_tx);

    // Wrap result receiver for shared access across multiple inserter tasks
    let shared_result_rx = Arc::new(Mutex::new(result_rx));

    // Spawn multiple database inserter tasks for parallel insertion
    // Initialize with existing commits from database and track new inserts
    let seen_commits = Arc::new(Mutex::new(existing_commits));

    // Use specified number of inserter tasks for parallel database insertion
    // Balance between parallelism (faster insertion) and lock contention
    let mut inserter_handles = Vec::new();

    for inserter_id in 0..num_inserters {
        let db_manager_clone = Arc::clone(&db_manager);
        let inserted_clone = inserted_count.clone();
        let pb_clone = pb.clone();
        let seen_commits_clone = seen_commits.clone();
        let result_rx_clone = shared_result_rx.clone();

        let handle = tokio::spawn(async move {
            loop {
                // Get next batch from shared receiver
                let batch = {
                    let rx = result_rx_clone.lock().unwrap();
                    rx.recv()
                };

                match batch {
                    Ok(batch) => {
                        // Filter out commits we've already seen (in DB or inserted this run)
                        let filtered_batch: Vec<_> = {
                            let mut seen = seen_commits_clone.lock().unwrap();
                            batch
                                .into_iter()
                                .filter(|commit| {
                                    // Try to insert the git_sha; if it's already present, filter it out
                                    seen.insert(commit.git_sha.clone())
                                })
                                .collect()
                        };

                        if !filtered_batch.is_empty() {
                            let batch_len = filtered_batch.len();
                            if let Err(e) =
                                db_manager_clone.insert_git_commits(filtered_batch).await
                            {
                                error!(
                                    "Inserter {} failed to insert commit batch: {}",
                                    inserter_id, e
                                );
                            } else {
                                let total = inserted_clone.fetch_add(batch_len, Ordering::Relaxed)
                                    + batch_len;
                                pb_clone.set_message(format!("{} inserted", total));
                            }
                        }
                    }
                    Err(_) => break, // Channel closed, exit task
                }
            }
        });

        inserter_handles.push(handle);
    }

    // Wait for producer to finish
    if let Err(e) = producer_handle.join() {
        tracing::error!("Producer thread panicked: {:?}", e);
    }

    // Wait for workers to finish
    for (worker_id, handle) in worker_handles.into_iter().enumerate() {
        if let Err(e) = handle.join() {
            tracing::error!("Worker {} thread panicked: {:?}", worker_id, e);
        }
    }

    // Wait for all inserter tasks to finish
    for (inserter_id, handle) in inserter_handles.into_iter().enumerate() {
        if let Err(e) = handle.await {
            tracing::error!("Inserter {} task failed: {:?}", inserter_id, e);
        }
    }

    // Finish progress bar
    pb.finish_with_message(format!(
        "Complete: {} commits processed",
        processed_count.load(Ordering::Relaxed)
    ));
    progress_thread.join().unwrap();

    Ok(())
}

/// The duplicate check the lore inserters share: message_id to its state.
pub type LoreIdMap = Arc<std::sync::Mutex<HashMap<String, LoreIdState>>>;

/// message_ids already in the lore table, shared by every archive of one
/// lore run and loaded when the first archive with new mail needs them.
/// Between pipelines every entry is `LoreIdState::Stored`: inserters mark
/// what they stored and remove what failed before they exit.  The
/// exception is an inserter that panics between claiming ids and marking
/// them.  Its ids stay `Pending` for the rest of the run, so later
/// archives defer those emails and the next run retries them; debug
/// builds fail an assertion at the end of the pipeline instead.
#[derive(Default)]
pub struct KnownLoreIds(tokio::sync::OnceCell<LoreIdMap>);

impl KnownLoreIds {
    pub fn new() -> Self {
        Self::default()
    }

    /// The shared map, scanning the lore table's message_ids on the first
    /// call only.  A failed scan leaves it unloaded, so the next call
    /// retries.
    pub async fn get(&self, db: &DatabaseManager) -> Result<LoreIdMap> {
        let ids = self
            .0
            .get_or_try_init(|| async {
                let ids = db.get_lore_message_ids().await?;
                info!("Loaded {} existing lore message_ids", ids.len());
                Ok::<_, anyhow::Error>(Arc::new(std::sync::Mutex::new(ids)))
            })
            .await?;
        Ok(Arc::clone(ids))
    }
}

/// Process lore commits using a streaming pipeline
/// Similar to process_commits_pipeline but parses email from 'm' file
///
/// `known_ids` is the duplicate check for crossposts and partially failed
/// runs; pass the same one for every archive of a run.
pub async fn process_lore_commits_pipeline(
    repo_path: &std::path::Path,
    commit_shas: Vec<String>,
    db_manager: Arc<DatabaseManager>,
    batch_size: usize,
    num_workers: usize,
    num_inserters: usize,
    known_ids: &KnownLoreIds,
) -> Result<()> {
    use indicatif::{ProgressBar, ProgressStyle};
    use std::sync::Mutex;

    let known_ids = known_ids.get(&db_manager).await?;

    // Create progress bar
    let pb = ProgressBar::new(commit_shas.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} emails ({per_sec}) - {msg}"
        )
        .unwrap()
        .progress_chars("█▓▒░  ")
    );

    // Create channels for streaming
    let (commit_tx, commit_rx) = mpsc::channel::<String>();
    let (result_tx, result_rx) = mpsc::sync_channel::<Vec<crate::LoreEmailInfo>>(10);

    // Wrap receiver for shared access
    let shared_commit_rx = Arc::new(Mutex::new(commit_rx));

    // Shared counters
    let processed_count = Arc::new(AtomicUsize::new(0));
    let inserted_count = Arc::new(AtomicUsize::new(0));

    // Spawn progress updater thread
    let pb_clone = pb.clone();
    let processed_clone = processed_count.clone();
    let progress_thread = std::thread::spawn(move || loop {
        let count = processed_clone.load(Ordering::Relaxed);
        pb_clone.set_position(count as u64);
        if pb_clone.is_finished() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    });

    // Spawn worker threads to parse email metadata
    let mut worker_handles = Vec::new();
    for worker_id in 0..num_workers {
        let worker_commit_rx = shared_commit_rx.clone();
        let worker_result_tx = result_tx.clone();
        let worker_repo_path = repo_path.to_path_buf();
        let worker_processed = processed_count.clone();

        let handle = thread::spawn(move || {
            // Open repository ONCE per worker thread
            let thread_repo = match gix::discover(&worker_repo_path) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("Worker {} failed to open repository: {}", worker_id, e);
                    return;
                }
            };

            let mut batch = Vec::new();

            loop {
                // Get next commit SHA
                let commit_sha = {
                    match worker_commit_rx.lock() {
                        Ok(rx) => rx.recv(),
                        Err(e) => {
                            tracing::error!("Worker {} failed to lock receiver: {}", worker_id, e);
                            break;
                        }
                    }
                };

                match commit_sha {
                    Ok(sha) => {
                        match parse_email_from_commit(&thread_repo, &sha) {
                            Ok(email_info) => {
                                batch.push(email_info);
                                worker_processed.fetch_add(1, Ordering::Relaxed);

                                // Send batch when it reaches batch_size
                                if batch.len() >= batch_size {
                                    if worker_result_tx.send(batch.clone()).is_err() {
                                        break;
                                    }
                                    batch.clear();
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "Worker {} failed to parse email for {}: {}",
                                    worker_id, sha, e
                                );
                                worker_processed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(_) => {
                        // Channel closed, send remaining batch
                        if !batch.is_empty() {
                            let _ = worker_result_tx.send(batch);
                        }
                        break;
                    }
                }
            }
        });
        worker_handles.push(handle);
    }

    // Spawn producer thread to feed commit SHAs
    let producer_handle = thread::spawn(move || {
        for commit_sha in commit_shas {
            if commit_tx.send(commit_sha).is_err() {
                break;
            }
        }
    });

    // Close original senders
    drop(result_tx);

    // Wrap result receiver for shared access
    let shared_result_rx = Arc::new(Mutex::new(result_rx));

    // Shared flag to coordinate periodic optimization checks
    // Only one inserter should check at a time to avoid redundant checks
    let last_optimization_check = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
    let batches_inserted = Arc::new(AtomicUsize::new(0));

    // Spawn multiple database inserter tasks
    let mut inserter_handles = Vec::new();

    for inserter_id in 0..num_inserters {
        let db_manager_clone = Arc::clone(&db_manager);
        let inserted_clone = inserted_count.clone();
        let pb_clone = pb.clone();
        let result_rx_clone = shared_result_rx.clone();
        let batches_counter = batches_inserted.clone();
        let optimization_check_timer = last_optimization_check.clone();
        let known_ids = known_ids.clone();

        let handle = tokio::spawn(async move {
            loop {
                // Get next batch from shared receiver.  A parser only
                // sends a short batch when its input has run out, so
                // keep receiving until the batch holds at least
                // batch_size emails or every parser has finished.
                // Otherwise each parser's last partial batch becomes
                // its own small append, dozens of tiny fragments per
                // archive on a refresh.
                let batch = {
                    match result_rx_clone.lock() {
                        Ok(rx) => rx.recv().map(|mut emails| {
                            while emails.len() < batch_size {
                                match rx.recv() {
                                    Ok(more) => emails.extend(more),
                                    Err(_) => break,
                                }
                            }
                            emails
                        }),
                        Err(e) => {
                            error!("Inserter {} failed to lock receiver: {}", inserter_id, e);
                            break;
                        }
                    }
                };

                match batch {
                    Ok(emails) => {
                        // Insert batch into database
                        match db_manager_clone
                            .insert_lore_emails(&emails, &known_ids)
                            .await
                        {
                            Err(e) => {
                                error!("Inserter {} failed to insert batch: {}", inserter_id, e);
                            }
                            Ok(failed_indices) => {
                                let failed_set: std::collections::HashSet<usize> =
                                    failed_indices.into_iter().collect();
                                let success_count = emails.len() - failed_set.len();

                                // Record commit SHAs only for emails that
                                // were actually stored, so that failed
                                // emails are retried on the next run.
                                let shas: Vec<String> = emails
                                    .iter()
                                    .enumerate()
                                    .filter(|(i, _)| !failed_set.contains(i))
                                    .map(|(_, e)| e.git_commit_sha.as_str())
                                    .collect::<std::collections::HashSet<_>>()
                                    .into_iter()
                                    .map(String::from)
                                    .collect();
                                if !shas.is_empty() {
                                    if let Err(e) =
                                        db_manager_clone.insert_lore_indexed_commits(&shas).await
                                    {
                                        error!(
                                            "Inserter {} failed to record indexed commits: {}",
                                            inserter_id, e
                                        );
                                    }
                                }

                                let count =
                                    inserted_clone.fetch_add(success_count, Ordering::Relaxed);
                                pb_clone.set_message(format!(
                                    "Inserted {} emails",
                                    count + success_count
                                ));

                                // Track successful batch insertions and check for periodic optimization
                                let total_batches =
                                    batches_counter.fetch_add(1, Ordering::Relaxed) + 1;
                                check_and_optimize_if_needed(
                                    &db_manager_clone,
                                    inserter_id,
                                    total_batches,
                                    &optimization_check_timer,
                                )
                                .await;
                            }
                        }
                    }
                    Err(_) => {
                        // Channel closed
                        break;
                    }
                }
            }
        });
        inserter_handles.push(handle);
    }

    // Wait for all workers to finish
    for handle in worker_handles {
        let _ = handle.join();
    }

    // Wait for producer
    let _ = producer_handle.join();

    // Wait for all inserters to finish
    for handle in inserter_handles {
        let _ = handle.await;
    }

    debug_assert!(
        known_ids
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .all(|state| *state == LoreIdState::Stored),
        "lore message_id map holds pending ids after every inserter finished"
    );

    pb.finish_with_message(format!(
        "Processed {} emails, inserted {}",
        processed_count.load(Ordering::Relaxed),
        inserted_count.load(Ordering::Relaxed)
    ));

    // Wait for progress thread
    progress_thread.join().unwrap();

    Ok(())
}

/// Index commits in a git range
pub async fn index_git_commits(
    repo_path: &PathBuf,
    git_range: &str,
    db_manager: Arc<DatabaseManager>,
    db_threads: usize,
) -> Result<usize> {
    info!("Starting commit indexing for range: {}", git_range);

    // Open repository and get list of commits in range
    let repo =
        gix::discover(repo_path).map_err(|e| anyhow::anyhow!("Not in a git repository: {}", e))?;
    let commit_shas = list_shas_in_range(&repo, git_range)?;
    let commit_count = commit_shas.len();

    if commit_shas.is_empty() {
        info!("No commits found in range: {}", git_range);
        return Ok(0);
    }

    info!(
        "Checking for {} commits already in database...",
        commit_count
    );

    // Get existing commits from database to avoid reprocessing
    let existing_commits: HashSet<String> = {
        let all_commits = db_manager.get_all_git_commits().await?;
        all_commits.into_iter().map(|c| c.git_sha).collect()
    };

    // Filter out commits that are already in the database
    let new_commit_shas: Vec<String> = commit_shas
        .into_iter()
        .filter(|sha| !existing_commits.contains(sha))
        .collect();

    let already_indexed = commit_count - new_commit_shas.len();
    if already_indexed > 0 {
        info!(
            "{} commits already indexed, processing {} new commits",
            already_indexed,
            new_commit_shas.len()
        );
    } else {
        info!("Processing all {} new commits", new_commit_shas.len());
    }

    if new_commit_shas.is_empty() {
        info!("All commits in range are already indexed!");
        return Ok(commit_count);
    }

    let start_time = std::time::Instant::now();

    // Process commits using streaming pipeline
    let batch_size = 100;
    let num_workers = num_cpus::get();

    process_commits_pipeline(
        repo_path,
        new_commit_shas,
        db_manager.clone(),
        batch_size,
        num_workers,
        existing_commits,
        db_threads,
    )
    .await?;

    let total_time = start_time.elapsed();

    info!("\n=== Commit Indexing Complete ===");
    info!("Total time: {:.1}s", total_time.as_secs_f64());
    info!("Commits indexed: {}", commit_count);

    Ok(commit_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: run a git command in a directory, panic on failure.
    fn git(repo: &std::path::Path, args: &[&str]) -> String {
        crate::git::test_git(repo, args)
    }

    /// The metadata workers read through the store they are handed. A
    /// worker that opened a store of its own would map the repository's
    /// packs again, and the handed store's pack would stay unopened.
    #[test]
    fn commit_metadata_workers_read_through_the_store_they_are_handed() {
        let (dir, commits) = crate::git::packed_test_repo();
        let repo = gix::discover(dir.path()).unwrap().into_sync();
        assert_eq!(repo.objects.metrics().open_reachable_packs, 0);

        let (commit_tx, commit_rx) = mpsc::channel();
        for commit in &commits {
            commit_tx.send(commit.clone()).unwrap();
        }
        drop(commit_tx);
        let commit_rx = Arc::new(std::sync::Mutex::new(commit_rx));
        let (result_tx, result_rx) = mpsc::sync_channel(16);
        let processed = Arc::new(AtomicUsize::new(0));
        let workers: Vec<_> = (0..4)
            .map(|worker_id| {
                let (repo, commit_rx, result_tx, processed) = (
                    repo.clone(),
                    commit_rx.clone(),
                    result_tx.clone(),
                    processed.clone(),
                );
                thread::spawn(move || {
                    commit_metadata_worker(worker_id, repo, commit_rx, result_tx, processed, 1)
                })
            })
            .collect();
        drop(result_tx);
        for worker in workers {
            worker.join().unwrap();
        }

        let mut extracted: Vec<String> = result_rx.iter().flatten().map(|c| c.git_sha).collect();
        extracted.sort();
        let mut expected = commits.clone();
        expected.sort();
        assert_eq!(extracted, expected);
        assert_eq!(processed.load(Ordering::Relaxed), 2);
        assert_eq!(repo.objects.metrics().open_reachable_packs, 1);
    }

    /// Build a repo with merge topology and a tag on the side branch:
    ///
    ///   A -- B -- M -- D   (main)
    ///         \      /
    ///          C ---       (tagged "v1")
    ///
    /// Returns (tempdir, repo, sha_a, sha_b, sha_c, sha_m, sha_d).
    fn create_merge_repo() -> (
        tempfile::TempDir,
        gix::Repository,
        String,
        String,
        String,
        String,
        String,
    ) {
        let tmpdir = tempfile::tempdir().unwrap();
        let p = tmpdir.path();

        git(p, &["init", "-b", "main"]);

        // Commit A
        std::fs::write(p.join("a.txt"), "a").unwrap();
        git(p, &["add", "a.txt"]);
        git(p, &["commit", "-m", "A"]);
        let sha_a = git(p, &["rev-parse", "HEAD"]);

        // Commit B
        std::fs::write(p.join("b.txt"), "b").unwrap();
        git(p, &["add", "b.txt"]);
        git(p, &["commit", "-m", "B"]);
        let sha_b = git(p, &["rev-parse", "HEAD"]);

        // Side branch with commit C, tagged "v1"
        git(p, &["checkout", "-b", "side"]);
        std::fs::write(p.join("c.txt"), "c").unwrap();
        git(p, &["add", "c.txt"]);
        git(p, &["commit", "-m", "C"]);
        let sha_c = git(p, &["rev-parse", "HEAD"]);
        git(p, &["tag", "v1"]);

        // Back to main, merge side → creates merge commit M
        git(p, &["checkout", "main"]);
        git(p, &["merge", "side", "--no-ff", "-m", "M"]);
        let sha_m = git(p, &["rev-parse", "HEAD"]);

        // Commit D on top
        std::fs::write(p.join("d.txt"), "d").unwrap();
        git(p, &["add", "d.txt"]);
        git(p, &["commit", "-m", "D"]);
        let sha_d = git(p, &["rev-parse", "HEAD"]);

        let repo = gix::open(p).unwrap();
        (tmpdir, repo, sha_a, sha_b, sha_c, sha_m, sha_d)
    }

    /// Regression test: a tag on a side branch (not on the first-parent
    /// chain) must still correctly bound the range.  A first-parent-only
    /// walk would miss it and traverse the entire history.
    #[test]
    fn test_list_shas_tag_on_side_branch() {
        let (_tmp, repo, _sha_a, _sha_b, _sha_c, sha_m, sha_d) = create_merge_repo();

        let shas = list_shas_in_range(&repo, "v1..HEAD").unwrap();

        // v1 points at C (on the side branch).  The range v1..HEAD
        // should include M and D only — NOT A, B, or C.
        assert!(
            shas.contains(&sha_m),
            "merge commit M should be in v1..HEAD"
        );
        assert!(shas.contains(&sha_d), "commit D should be in v1..HEAD");
        assert_eq!(
            shas.len(),
            2,
            "v1..HEAD should contain exactly 2 commits (M, D), got {}: {:?}",
            shas.len(),
            shas
        );
    }

    /// Range where the start IS on the first-parent chain works too.
    #[test]
    fn test_list_shas_first_parent_boundary() {
        let (_tmp, repo, sha_a, sha_b, sha_c, sha_m, sha_d) = create_merge_repo();

        let shas = list_shas_in_range(&repo, &format!("{sha_a}..HEAD")).unwrap();

        // A..HEAD should include B, C, M, D (everything after A).
        let expected: std::collections::HashSet<&str> = [
            sha_b.as_str(),
            sha_c.as_str(),
            sha_m.as_str(),
            sha_d.as_str(),
        ]
        .into_iter()
        .collect();
        let got: std::collections::HashSet<&str> = shas.iter().map(|s| s.as_str()).collect();

        assert_eq!(expected, got, "A..HEAD should be {{B, C, M, D}}");
    }

    /// No range separator — returns all reachable commits.
    #[test]
    fn test_list_shas_no_range() {
        let (_tmp, repo, sha_a, sha_b, sha_c, sha_m, sha_d) = create_merge_repo();

        let shas = list_shas_in_range(&repo, "HEAD").unwrap();

        let expected: std::collections::HashSet<&str> = [
            sha_a.as_str(),
            sha_b.as_str(),
            sha_c.as_str(),
            sha_m.as_str(),
            sha_d.as_str(),
        ]
        .into_iter()
        .collect();
        let got: std::collections::HashSet<&str> = shas.iter().map(|s| s.as_str()).collect();

        assert_eq!(expected, got, "HEAD (no range) should return all 5 commits");
    }

    async fn lore_database() -> (tempfile::TempDir, Arc<DatabaseManager>) {
        let dir = tempfile::tempdir().unwrap();
        let db = DatabaseManager::new(
            dir.path().join(".semcode.db").to_str().unwrap(),
            dir.path().to_string_lossy().into_owned(),
        )
        .await
        .unwrap();
        db.create_tables().await.unwrap();
        (dir, Arc::new(db))
    }

    fn lore_email(git_commit_sha: &str, message_id: &str) -> crate::LoreEmailInfo {
        crate::LoreEmailInfo {
            git_commit_sha: git_commit_sha.to_string(),
            from: "A U Thor <author@example.org>".to_string(),
            date: "Mon, 2 Nov 2026 10:00:00 +0000".to_string(),
            date_timestamp: 1_793_613_600,
            message_id: message_id.to_string(),
            in_reply_to: None,
            subject: "[PATCH] test".to_string(),
            references: None,
            recipients: "list@example.org".to_string(),
            body: "body".to_string(),
            symbols: Vec::new(),
        }
    }

    async fn lore_rows(db: &DatabaseManager, filter: Option<String>) -> usize {
        db.connection()
            .open_table("lore")
            .execute()
            .await
            .unwrap()
            .count_rows(filter)
            .await
            .unwrap()
    }

    /// The map is scanned once: a second get() returns the same map and
    /// does not see a row stored behind its back.
    #[tokio::test]
    async fn known_lore_ids_loads_once() {
        let (_dir, db) = lore_database().await;
        let side_map = std::sync::Mutex::new(std::collections::HashMap::new());
        let failed = db
            .insert_lore_emails(
                &[lore_email("1111", "<one@x>"), lore_email("2222", "<two@x>")],
                &side_map,
            )
            .await
            .unwrap();
        assert!(failed.is_empty());

        let known = KnownLoreIds::new();
        let first = known.get(&db).await.unwrap();
        {
            let ids = first.lock().unwrap();
            assert_eq!(ids.len(), 2);
            assert_eq!(ids.get("<one@x>"), Some(&LoreIdState::Stored));
            assert_eq!(ids.get("<two@x>"), Some(&LoreIdState::Stored));
        }

        let failed = db
            .insert_lore_emails(&[lore_email("3333", "<three@x>")], &side_map)
            .await
            .unwrap();
        assert!(failed.is_empty());

        let second = known.get(&db).await.unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(!second.lock().unwrap().contains_key("<three@x>"));

        // The row is in the table: a fresh map loads it.
        let fresh = KnownLoreIds::new().get(&db).await.unwrap();
        assert!(fresh.lock().unwrap().contains_key("<three@x>"));
    }

    /// A batch holding an id that another batch has pending defers that
    /// email: its index is returned as not stored, no row is written for
    /// it, and the other batch's claim is left alone.  The rest of the
    /// batch is stored.
    #[tokio::test]
    async fn pending_id_is_deferred() {
        let (_dir, db) = lore_database().await;
        let map = std::sync::Mutex::new(HashMap::from([(
            "<held@x>".to_string(),
            LoreIdState::Pending,
        )]));

        let failed = db
            .insert_lore_emails(
                &[
                    lore_email("4444", "<held@x>"),
                    lore_email("5555", "<new@x>"),
                ],
                &map,
            )
            .await
            .unwrap();

        assert_eq!(failed, vec![0]);
        assert_eq!(
            lore_rows(&db, Some("message_id = '<held@x>'".to_string())).await,
            0
        );
        assert_eq!(
            lore_rows(&db, Some("message_id = '<new@x>'".to_string())).await,
            1
        );
        let map = map.lock().unwrap();
        assert_eq!(map.get("<held@x>"), Some(&LoreIdState::Pending));
        assert_eq!(map.get("<new@x>"), Some(&LoreIdState::Stored));
    }

    /// A failed scan leaves the map unloaded: the next get() scans again.
    #[tokio::test]
    async fn known_lore_ids_retries_after_failed_load() {
        let dir = tempfile::tempdir().unwrap();
        let db = DatabaseManager::new(
            dir.path().join(".semcode.db").to_str().unwrap(),
            dir.path().to_string_lossy().into_owned(),
        )
        .await
        .unwrap();
        let known = KnownLoreIds::new();

        // No lore table yet.
        assert!(known.get(&db).await.is_err());

        db.create_tables().await.unwrap();
        let side_map = std::sync::Mutex::new(HashMap::new());
        let failed = db
            .insert_lore_emails(&[lore_email("6666", "<late@x>")], &side_map)
            .await
            .unwrap();
        assert!(failed.is_empty());

        let ids = known.get(&db).await.unwrap();
        assert_eq!(
            ids.lock().unwrap().get("<late@x>"),
            Some(&LoreIdState::Stored)
        );
    }

    /// Commit one RFC 2822 message as file `m`, the layout of a lore
    /// archive, and return the commit's SHA.
    fn commit_lore_message(
        repo: &std::path::Path,
        message_id: &str,
        commit_message: &str,
    ) -> String {
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
        git(repo, &["commit", "-q", "-m", commit_message]);
        git(repo, &["rev-parse", "HEAD"])
    }

    /// A crosspost appears in two archives of one run.  The second
    /// archive's pipeline must see the id the first one stored, store no
    /// second row, and still record its commit as indexed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn crossposted_email_is_stored_once_across_archives() {
        let (_dir, db) = lore_database().await;

        let archive_a = tempfile::tempdir().unwrap();
        git(archive_a.path(), &["init", "-q", "-b", "master"]);
        let cross_a = commit_lore_message(archive_a.path(), "<cross@x>", "list a");

        let archive_b = tempfile::tempdir().unwrap();
        git(archive_b.path(), &["init", "-q", "-b", "master"]);
        let cross_b = commit_lore_message(archive_b.path(), "<cross@x>", "list b");
        let only_b = commit_lore_message(archive_b.path(), "<only-b@x>", "list b only");
        assert_ne!(cross_a, cross_b);

        let known = KnownLoreIds::new();
        process_lore_commits_pipeline(
            archive_a.path(),
            vec![cross_a.clone()],
            db.clone(),
            1024,
            1,
            1,
            &known,
        )
        .await
        .unwrap();
        process_lore_commits_pipeline(
            archive_b.path(),
            vec![cross_b.clone(), only_b.clone()],
            db.clone(),
            1024,
            1,
            1,
            &known,
        )
        .await
        .unwrap();

        assert_eq!(
            lore_rows(&db, Some("message_id = '<cross@x>'".to_string())).await,
            1
        );
        assert_eq!(lore_rows(&db, None).await, 2);

        let indexed = db.get_indexed_lore_commits().await.unwrap();
        for sha in [&cross_a, &cross_b, &only_b] {
            assert!(indexed.contains(sha), "{sha} not recorded as indexed");
        }
    }
}
