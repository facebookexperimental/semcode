// SPDX-License-Identifier: MIT OR Apache-2.0
//! Indexing functionality shared across binaries
//!
//! This module provides reusable indexing functions for git commits and files
//! that can be called from different binaries (semcode-index, semcode, semcode-mcp, etc.)

use anyhow::{Context, Result};
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

pub(crate) fn join_failed<T>(
    kind: &str,
    handles: impl IntoIterator<Item = thread::JoinHandle<Result<T>>>,
) -> usize {
    let mut failed = 0;
    for (id, handle) in handles.into_iter().enumerate() {
        match handle.join() {
            Ok(Ok(_)) => continue,
            Ok(Err(e)) => error!("{kind} {id} failed: {e:#}"),
            Err(panic) => error!("{kind} {id} thread panicked: {panic:?}"),
        }
        failed += 1;
    }
    failed
}

/// Receive from a std channel shared by several inserter tasks without
/// holding a tokio worker while waiting.
///
/// `f` runs on the blocking pool with the receiver locked, so a task waiting
/// for a batch, or for another task to release the receiver, occupies a
/// blocking-pool thread instead of a runtime worker. Returns `None` if the
/// receiver's lock is poisoned, or if the runtime shut down before `f` ran.
/// A panic in `f` is resumed in the caller. Dropping the returned future
/// does not stop `f`; anything it received is lost.
pub(crate) async fn recv_shared<T, R>(
    rx: &Arc<std::sync::Mutex<mpsc::Receiver<T>>>,
    f: impl FnOnce(&mpsc::Receiver<T>) -> R + Send + 'static,
) -> Option<R>
where
    T: Send + 'static,
    R: Send + 'static,
{
    let rx = Arc::clone(rx);
    match tokio::task::spawn_blocking(move || rx.lock().ok().map(|rx| f(&rx))).await {
        Ok(result) => result,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(_) => None,
    }
}

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
                        return Ok(Action::Continue(()));
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
                    Ok(Action::Continue(()))
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
///
/// `Ok(None)` is a commit that holds no message: public-inbox records a
/// removed message as a commit with a 'd' file and no 'm'.  Reading it
/// again gives the same answer.  An error means the commit could not be
/// read -- a missing object, say -- and a later run may succeed.
pub fn parse_email_from_commit(
    repo: &gix::Repository,
    commit_sha: &str,
) -> Result<Option<crate::LoreEmailInfo>> {
    // Resolve commit
    let commit = resolve_to_commit(repo, commit_sha)?;

    // Get the tree
    let tree = commit.tree()?;

    // Find the 'm' file in the tree.  Tree::find_entry() drops decoding
    // errors, which would make a malformed tree look like a removed
    // message and get its commit recorded as indexed.
    let mut m_entry = None;
    for entry in tree.iter() {
        let entry =
            entry.with_context(|| format!("Failed to decode the tree of commit {commit_sha}"))?;
        if entry.filename() == "m" {
            m_entry = Some(entry);
            break;
        }
    }
    let Some(m_entry) = m_entry else {
        return Ok(None);
    };

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

    Ok(Some(crate::LoreEmailInfo {
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
    }))
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
                let batch = recv_shared(&result_rx_clone, |rx| rx.recv())
                    .await
                    .expect("commit inserter receiver lock poisoned");

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

/// Pluralize `n` with `one` or `many`, for failure summaries.
pub(crate) fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

pub(crate) fn counted_problem(count: usize, one: &str, many: &str, detail: &str) -> Option<String> {
    (count > 0).then(|| format!("{} {detail}", plural(count, one, many)))
}

/// The error of a lore pipeline that finished without indexing every
/// commit it was given.
///
/// Whatever the run did store stays stored and recorded.  Every commit
/// counted here is left out of lore_indexed_commits, so the next run over
/// the archive reads it again.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LoreIndexIncomplete {
    /// Emails this run stored or found already stored.
    pub stored: usize,
    /// Of `stored`, the rows this run appended to the lore table.
    pub appended: usize,
    /// Parser, producer, and inserter threads that failed or panicked.
    /// The commits such a thread held are counted nowhere else.
    pub failed_threads: usize,
    /// Commits whose message could not be read.
    pub unread_commits: usize,
    /// Emails that were read but could not be stored.
    pub unstored_emails: usize,
    /// Commits whose email was stored, or that hold no email, but that
    /// could not be recorded as indexed.
    pub unrecorded_commits: usize,
}

impl LoreIndexIncomplete {
    fn has_failures(&self) -> bool {
        self.failed_threads > 0
            || self.unread_commits > 0
            || self.unstored_emails > 0
            || self.unrecorded_commits > 0
    }
}

impl std::fmt::Display for LoreIndexIncomplete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let problems: Vec<_> = [
            counted_problem(
                self.failed_threads,
                "pipeline thread",
                "pipeline threads",
                "failed",
            ),
            counted_problem(self.unread_commits, "email", "emails", "could not be read"),
            counted_problem(
                self.unstored_emails,
                "email",
                "emails",
                "could not be stored",
            ),
            counted_problem(
                self.unrecorded_commits,
                "commit",
                "commits",
                "could not be recorded as indexed",
            ),
        ]
        .into_iter()
        .flatten()
        .collect();
        write!(
            f,
            "lore indexing incomplete: {}; indexing again retries them ({} stored)",
            problems.join(", "),
            plural(self.stored, "email", "emails")
        )
    }
}

impl std::error::Error for LoreIndexIncomplete {}

/// Failure counts the threads of one lore pipeline add to.
#[derive(Default)]
struct LoreFailureCounts {
    unread_commits: AtomicUsize,
    unstored_emails: AtomicUsize,
    unrecorded_commits: AtomicUsize,
}

/// Store one batch and record the commits of the emails now in the table.
/// Returns how many of the batch's emails are stored, how many rows were
/// appended for them, and the emails that were deferred because another
/// batch holds their message_id; failures are added to `counts`.
async fn store_lore_batch(
    db: &DatabaseManager,
    emails: Vec<crate::LoreEmailInfo>,
    known_ids: &std::sync::Mutex<HashMap<String, LoreIdState>>,
    counts: &LoreFailureCounts,
    inserter: &str,
) -> (usize, usize, Vec<crate::LoreEmailInfo>) {
    let outcome = match db.insert_lore_emails(&emails, known_ids).await {
        Ok(outcome) => outcome,
        Err(e) => {
            error!(
                "{} failed to insert batch of {} emails: {:#}",
                inserter,
                emails.len(),
                e
            );
            counts
                .unstored_emails
                .fetch_add(emails.len(), Ordering::Relaxed);
            return (0, 0, Vec::new());
        }
    };
    counts
        .unstored_emails
        .fetch_add(outcome.failed.len(), Ordering::Relaxed);

    // Record commit SHAs only for emails that are in the table, so that
    // the rest are read again on the next run.
    let not_stored: HashSet<usize> = outcome.not_stored().collect();
    let shas: Vec<String> = emails
        .iter()
        .enumerate()
        .filter(|(i, _)| !not_stored.contains(i))
        .map(|(_, e)| e.git_commit_sha.as_str())
        .collect::<HashSet<_>>()
        .into_iter()
        .map(String::from)
        .collect();
    if !shas.is_empty() {
        if let Err(e) = db.insert_lore_indexed_commits(&shas).await {
            error!(
                "{} failed to record {} indexed commits: {:#}",
                inserter,
                shas.len(),
                e
            );
            counts
                .unrecorded_commits
                .fetch_add(shas.len(), Ordering::Relaxed);
        }
    }

    let stored = emails.len() - not_stored.len();
    let deferred_set: HashSet<usize> = outcome.deferred.into_iter().collect();
    let deferred = emails
        .into_iter()
        .enumerate()
        .filter(|(i, _)| deferred_set.contains(i))
        .map(|(_, e)| e)
        .collect();
    (stored, outcome.appended, deferred)
}

/// Process lore commits using a streaming pipeline
/// Similar to process_commits_pipeline but parses email from 'm' file
///
/// `known_ids` is the duplicate check for crossposts and partially failed
/// runs; pass the same one for every archive of a run.
///
/// Returns `Ok` with the rows appended to the lore table only when every
/// commit is recorded in lore_indexed_commits.  Emails found already
/// stored, such as crossposts, and commits that hold no message add no
/// rows.  Otherwise the error is a [`LoreIndexIncomplete`] counting what
/// was left undone, rows appended included; the emails that were stored
/// stay stored and recorded, and the rest are read again by the next run.
pub async fn process_lore_commits_pipeline(
    repo_path: &std::path::Path,
    commit_shas: Vec<String>,
    db_manager: Arc<DatabaseManager>,
    batch_size: usize,
    num_workers: usize,
    num_inserters: usize,
    known_ids: &KnownLoreIds,
) -> Result<usize> {
    use indicatif::{ProgressBar, ProgressStyle};
    use std::sync::{Mutex, PoisonError};

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
    // Of those, the rows appended to the lore table.
    let appended_count = Arc::new(AtomicUsize::new(0));
    let counts = Arc::new(LoreFailureCounts::default());
    // Commits that hold no message, recorded as indexed at the end.
    let no_message_commits = Arc::new(Mutex::new(Vec::<String>::new()));

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

    // Spawn worker threads to parse email metadata.  A commit that cannot
    // be read is counted and the worker goes on; an error means the worker
    // stopped, and the caller fails the run.  The receiver lock guards
    // nothing a panic can leave half-written, so a poisoned one is taken
    // anyway: the panic already fails the run.
    let mut worker_handles = Vec::new();
    for worker_id in 0..num_workers {
        let worker_commit_rx = shared_commit_rx.clone();
        let worker_result_tx = result_tx.clone();
        let worker_repo_path = repo_path.to_path_buf();
        let worker_processed = processed_count.clone();
        let counts = counts.clone();
        let no_message_commits = no_message_commits.clone();

        let handle = thread::spawn(move || -> Result<()> {
            // Open repository ONCE per worker thread
            let thread_repo = gix::discover(&worker_repo_path).map_err(|e| {
                anyhow::anyhow!(
                    "failed to open repository {}: {}",
                    worker_repo_path.display(),
                    e
                )
            })?;

            let send = |batch: Vec<crate::LoreEmailInfo>| {
                let len = batch.len();
                worker_result_tx.send(batch).map_err(|_| {
                    anyhow::anyhow!("every inserter stopped; {len} parsed emails were not sent")
                })
            };

            let mut batch = Vec::new();
            loop {
                let commit_sha = worker_commit_rx
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .recv();
                // Channel closed: every commit has been handed out.
                let Ok(sha) = commit_sha else { break };

                match parse_email_from_commit(&thread_repo, &sha) {
                    Ok(Some(email_info)) => {
                        batch.push(email_info);
                        // Send batch when it reaches batch_size
                        if batch.len() >= batch_size {
                            send(std::mem::take(&mut batch))?;
                        }
                    }
                    Ok(None) => {
                        info!("Commit {} holds no message, recording it as indexed", sha);
                        no_message_commits
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push(sha);
                    }
                    Err(e) => {
                        error!(
                            "Worker {} failed to read email for {}: {:#}",
                            worker_id, sha, e
                        );
                        counts.unread_commits.fetch_add(1, Ordering::Relaxed);
                    }
                }
                worker_processed.fetch_add(1, Ordering::Relaxed);
            }
            if !batch.is_empty() {
                send(batch)?;
            }
            Ok(())
        });
        worker_handles.push(handle);
    }
    // Only the workers hold the receiver now, so the producer stops if
    // every worker has.
    drop(shared_commit_rx);

    // Spawn producer thread to feed commit SHAs
    let producer_handle = thread::spawn(move || -> Result<()> {
        for commit_sha in commit_shas {
            if commit_tx.send(commit_sha).is_err() {
                break;
            }
        }
        Ok(())
    });

    // Close original senders
    drop(result_tx);

    // Wrap result receiver for shared access
    let shared_result_rx = Arc::new(Mutex::new(result_rx));

    // Shared flag to coordinate periodic optimization checks
    // Only one inserter should check at a time to avoid redundant checks
    let last_optimization_check = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
    let batches_inserted = Arc::new(AtomicUsize::new(0));

    // Spawn multiple database inserter tasks.  Each returns the emails it
    // deferred, to be stored once every inserter has finished.
    let mut inserter_handles = Vec::new();

    for inserter_id in 0..num_inserters {
        let db_manager_clone = Arc::clone(&db_manager);
        let inserted_clone = inserted_count.clone();
        let appended_clone = appended_count.clone();
        let pb_clone = pb.clone();
        let result_rx_clone = shared_result_rx.clone();
        let batches_counter = batches_inserted.clone();
        let optimization_check_timer = last_optimization_check.clone();
        let known_ids = known_ids.clone();
        let counts = counts.clone();

        let handle = tokio::spawn(async move {
            let name = format!("Inserter {inserter_id}");
            let mut deferred = Vec::new();
            loop {
                // Get next batch from shared receiver.  A parser only
                // sends a short batch when its input has run out, so
                // keep receiving until the batch holds at least
                // batch_size emails or every parser has finished.
                // Otherwise each parser's last partial batch becomes
                // its own small append, dozens of tiny fragments per
                // archive on a refresh.
                let batch = recv_shared(&result_rx_clone, move |rx| {
                    rx.recv().map(|mut emails| {
                        while emails.len() < batch_size {
                            match rx.recv() {
                                Ok(more) => emails.extend(more),
                                Err(_) => break,
                            }
                        }
                        emails
                    })
                })
                .await;

                let emails = match batch {
                    Some(Ok(emails)) => emails,
                    // Channel closed: every parser has finished.
                    Some(Err(_)) => break,
                    None => anyhow::bail!("{name} failed to lock receiver"),
                };

                let (stored, appended, mut batch_deferred) =
                    store_lore_batch(&db_manager_clone, emails, &known_ids, &counts, &name).await;
                deferred.append(&mut batch_deferred);
                appended_clone.fetch_add(appended, Ordering::Relaxed);

                let count = inserted_clone.fetch_add(stored, Ordering::Relaxed);
                pb_clone.set_message(format!("Inserted {} emails", count + stored));

                // Track batch insertions and check for periodic optimization
                let total_batches = batches_counter.fetch_add(1, Ordering::Relaxed) + 1;
                check_and_optimize_if_needed(
                    &db_manager_clone,
                    inserter_id,
                    total_batches,
                    &optimization_check_timer,
                )
                .await;
            }
            Ok::<_, anyhow::Error>(deferred)
        });
        inserter_handles.push(handle);
    }
    // Only the inserters hold the receiver now, so a parser's send fails,
    // rather than blocking forever, if every inserter has stopped.
    drop(shared_result_rx);

    let mut failed_threads =
        join_failed("Worker", worker_handles) + join_failed("Producer", [producer_handle]);

    // Wait for all inserters to finish
    let mut deferred = Vec::new();
    for (id, handle) in inserter_handles.into_iter().enumerate() {
        match handle.await {
            Ok(Ok(mut emails)) => deferred.append(&mut emails),
            Ok(Err(e)) => {
                error!("Inserter {id} failed: {e:#}");
                failed_threads += 1;
            }
            Err(e) => {
                error!("Inserter {id} failed: {e}");
                failed_threads += 1;
            }
        }
    }

    // Every inserter has finished, so no batch holds an id pending (short
    // of a panicked one).  A deferred email's id is now stored, and the
    // email is skipped and its commit recorded, or was released by a
    // failed append, and the email is stored here.
    if !deferred.is_empty() {
        info!("Storing {} deferred emails", deferred.len());
        let (stored, appended, still_deferred) =
            store_lore_batch(&db_manager, deferred, &known_ids, &counts, "Final pass").await;
        inserted_count.fetch_add(stored, Ordering::Relaxed);
        appended_count.fetch_add(appended, Ordering::Relaxed);
        if !still_deferred.is_empty() {
            error!(
                "{} emails are still held by an inserter that did not finish",
                still_deferred.len()
            );
            counts
                .unstored_emails
                .fetch_add(still_deferred.len(), Ordering::Relaxed);
        }
    }

    let no_message_commits = std::mem::take(
        &mut *no_message_commits
            .lock()
            .unwrap_or_else(PoisonError::into_inner),
    );
    if let Err(e) = db_manager
        .insert_lore_indexed_commits(&no_message_commits)
        .await
    {
        error!(
            "Failed to record {} commits without a message: {:#}",
            no_message_commits.len(),
            e
        );
        counts
            .unrecorded_commits
            .fetch_add(no_message_commits.len(), Ordering::Relaxed);
    }

    // A failed inserter can leave the ids of its batch pending; the
    // emails it held are already counted as not stored.
    debug_assert!(
        failed_threads > 0
            || known_ids
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .all(|state| *state == LoreIdState::Stored),
        "lore message_id map holds pending ids after every inserter finished"
    );

    let outcome = LoreIndexIncomplete {
        stored: inserted_count.load(Ordering::Relaxed),
        appended: appended_count.load(Ordering::Relaxed),
        failed_threads,
        unread_commits: counts.unread_commits.load(Ordering::Relaxed),
        unstored_emails: counts.unstored_emails.load(Ordering::Relaxed),
        unrecorded_commits: counts.unrecorded_commits.load(Ordering::Relaxed),
    };

    pb.finish_with_message(format!(
        "Processed {} emails, inserted {}",
        processed_count.load(Ordering::Relaxed),
        outcome.stored
    ));

    // Wait for progress thread
    progress_thread.join().unwrap();

    if outcome.has_failures() {
        return Err(outcome.into());
    }
    Ok(outcome.appended)
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

    /// Two inserter-style tasks waiting on a shared receiver whose sender
    /// stays alive must leave the runtime's two workers free for other work.
    /// The test body runs on the `block_on` thread, not on a worker, and
    /// waits with std primitives, so it still fails (rather than hangs) if
    /// the waiters do occupy both workers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recv_shared_does_not_hold_workers() {
        let (tx, rx) = mpsc::channel::<u32>();
        let rx = Arc::new(std::sync::Mutex::new(rx));
        let entered = Arc::new(AtomicUsize::new(0));

        let waiters: Vec<_> = (0..2)
            .map(|_| {
                let rx = Arc::clone(&rx);
                let entered = Arc::clone(&entered);
                tokio::spawn(async move {
                    entered.fetch_add(1, Ordering::SeqCst);
                    recv_shared(&rx, |rx| rx.recv()).await
                })
            })
            .collect();

        // Each waiter increments `entered` on a worker right before it
        // starts waiting.  Once both have, waiters that block their workers
        // would now hold both.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while entered.load(Ordering::SeqCst) < 2 {
            assert!(
                std::time::Instant::now() < deadline,
                "waiters never started"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        let (done_tx, done_rx) = mpsc::channel();
        tokio::spawn(async move {
            let _ = done_tx.send(7);
        });
        assert_eq!(
            done_rx.recv_timeout(std::time::Duration::from_secs(10)),
            Ok(7),
            "a task spawned while two receivers wait never ran"
        );

        drop(tx);
        for waiter in waiters {
            assert_eq!(waiter.await.unwrap(), Some(Err(mpsc::RecvError)));
        }
    }

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
        let outcome = db
            .insert_lore_emails(
                &[lore_email("1111", "<one@x>"), lore_email("2222", "<two@x>")],
                &side_map,
            )
            .await
            .unwrap();
        assert!(outcome.is_complete());

        let known = KnownLoreIds::new();
        let first = known.get(&db).await.unwrap();
        {
            let ids = first.lock().unwrap();
            assert_eq!(ids.len(), 2);
            assert_eq!(ids.get("<one@x>"), Some(&LoreIdState::Stored));
            assert_eq!(ids.get("<two@x>"), Some(&LoreIdState::Stored));
        }

        let outcome = db
            .insert_lore_emails(&[lore_email("3333", "<three@x>")], &side_map)
            .await
            .unwrap();
        assert!(outcome.is_complete());

        let second = known.get(&db).await.unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(!second.lock().unwrap().contains_key("<three@x>"));

        // The row is in the table: a fresh map loads it.
        let fresh = KnownLoreIds::new().get(&db).await.unwrap();
        assert!(fresh.lock().unwrap().contains_key("<three@x>"));
    }

    /// A batch holding an id that another batch has pending defers that
    /// email: its index is returned as deferred, no row is written for
    /// it, and the other batch's claim is left alone.  The rest of the
    /// batch is stored.
    #[tokio::test]
    async fn pending_id_is_deferred() {
        let (_dir, db) = lore_database().await;
        let map = std::sync::Mutex::new(HashMap::from([(
            "<held@x>".to_string(),
            LoreIdState::Pending,
        )]));

        let outcome = db
            .insert_lore_emails(
                &[
                    lore_email("4444", "<held@x>"),
                    lore_email("5555", "<new@x>"),
                ],
                &map,
            )
            .await
            .unwrap();

        assert_eq!(
            outcome,
            crate::LoreInsertOutcome {
                failed: Vec::new(),
                deferred: vec![0],
                appended: 1,
            }
        );
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

    /// Every copy of a deferred message_id in the batch is deferred, not
    /// only the one copy the batch tried, so that no copy's commit is
    /// recorded as indexed while its message is not stored.
    #[tokio::test]
    async fn every_copy_of_a_pending_id_is_deferred() {
        let (_dir, db) = lore_database().await;
        let map = std::sync::Mutex::new(HashMap::from([(
            "<held@x>".to_string(),
            LoreIdState::Pending,
        )]));

        let outcome = db
            .insert_lore_emails(
                &[
                    lore_email("1111", "<held@x>"),
                    lore_email("2222", "<new@x>"),
                    lore_email("3333", "<held@x>"),
                    lore_email("4444", "<new@x>"),
                ],
                &map,
            )
            .await
            .unwrap();

        assert_eq!(
            outcome,
            crate::LoreInsertOutcome {
                failed: Vec::new(),
                deferred: vec![0, 2],
                appended: 1,
            }
        );
        assert_eq!(lore_rows(&db, None).await, 1);
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
        let outcome = db
            .insert_lore_emails(&[lore_email("6666", "<late@x>")], &side_map)
            .await
            .unwrap();
        assert!(outcome.is_complete());

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
        let appended = process_lore_commits_pipeline(
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
        assert_eq!(appended, 1, "the crosspost was counted as a new row");

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

    /// A lore archive of one commit per message id, oldest first.
    fn lore_archive(message_ids: &[&str]) -> (tempfile::TempDir, Vec<String>) {
        let archive = tempfile::tempdir().unwrap();
        git(archive.path(), &["init", "-q", "-b", "master"]);
        let shas = message_ids
            .iter()
            .map(|id| commit_lore_message(archive.path(), id, id))
            .collect();
        (archive, shas)
    }

    /// Run the pipeline as `semcode-index --lore` does: a fresh duplicate
    /// check, two parsers and two inserters, over the commits not yet
    /// recorded as indexed.  Fails rather than hangs if the pipeline does
    /// not finish.
    async fn index_lore_run(
        db: &Arc<DatabaseManager>,
        archive: &std::path::Path,
        commits: &[String],
    ) -> Result<usize> {
        let indexed = db.get_indexed_lore_commits().await.unwrap();
        let pending = commits
            .iter()
            .filter(|sha| !indexed.contains(*sha))
            .cloned()
            .collect();
        index_lore_commits(db, archive, pending, &KnownLoreIds::new()).await
    }

    async fn index_lore_commits(
        db: &Arc<DatabaseManager>,
        archive: &std::path::Path,
        commits: Vec<String>,
        known: &KnownLoreIds,
    ) -> Result<usize> {
        tokio::time::timeout(
            std::time::Duration::from_secs(120),
            process_lore_commits_pipeline(archive, commits, db.clone(), 1, 2, 2, known),
        )
        .await
        .expect("lore pipeline did not finish")
    }

    fn incomplete(result: Result<usize>) -> LoreIndexIncomplete {
        let e = result.expect_err("a run that left commits unindexed reported success");
        e.downcast_ref::<LoreIndexIncomplete>()
            .unwrap_or_else(|| panic!("not a LoreIndexIncomplete: {e:#}"))
            .clone()
    }

    async fn assert_all_recorded(db: &DatabaseManager, commits: &[String]) {
        let indexed = db.get_indexed_lore_commits().await.unwrap();
        for sha in commits {
            assert!(indexed.contains(sha), "{sha} not recorded as indexed");
        }
    }

    /// A commit whose message cannot be read fails the run.  The emails
    /// read beside it stay stored and recorded, and the unread commit is
    /// left unrecorded, so the next run reads it and completes the
    /// archive.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unreadable_email_fails_the_run_and_is_retried() {
        let (_dir, db) = lore_database().await;
        let (archive, commits) = lore_archive(&["<a@x>", "<b@x>", "<c@x>"]);

        // Delete the loose blob of the middle commit's message.
        let blob = git(archive.path(), &["rev-parse", &format!("{}:m", commits[1])]);
        let blob_path = archive
            .path()
            .join(".git/objects")
            .join(&blob[..2])
            .join(&blob[2..]);
        let blob_bytes = std::fs::read(&blob_path).unwrap();
        std::fs::remove_file(&blob_path).unwrap();

        let outcome = incomplete(index_lore_run(&db, archive.path(), &commits).await);
        assert_eq!(
            outcome,
            LoreIndexIncomplete {
                stored: 2,
                appended: 2,
                unread_commits: 1,
                ..Default::default()
            }
        );
        let message = outcome.to_string();
        assert!(
            message.contains("1 email could not be read"),
            "unexpected summary: {message}"
        );
        assert_eq!(lore_rows(&db, None).await, 2);
        let indexed = db.get_indexed_lore_commits().await.unwrap();
        assert!(indexed.contains(&commits[0]));
        assert!(!indexed.contains(&commits[1]));
        assert!(indexed.contains(&commits[2]));

        std::fs::write(&blob_path, blob_bytes).unwrap();
        assert_eq!(
            index_lore_run(&db, archive.path(), &commits).await.unwrap(),
            1
        );
        assert_eq!(lore_rows(&db, None).await, 3);
        assert_all_recorded(&db, &commits).await;
    }

    /// Emails that cannot be stored fail the run and leave their commits
    /// unrecorded, so the next run stores them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unstored_emails_fail_the_run_and_are_retried() {
        let (_dir, db) = lore_database().await;
        let (archive, commits) = lore_archive(&["<a@x>", "<b@x>"]);

        // Load the duplicate check, then take the table away from the
        // inserters.
        let known = KnownLoreIds::new();
        known.get(&db).await.unwrap();
        db.connection().drop_table("lore", &[]).await.unwrap();

        let outcome =
            incomplete(index_lore_commits(&db, archive.path(), commits.clone(), &known).await);
        assert_eq!(
            outcome,
            LoreIndexIncomplete {
                unstored_emails: 2,
                ..Default::default()
            }
        );
        assert!(db.get_indexed_lore_commits().await.unwrap().is_empty());

        db.create_tables().await.unwrap();
        assert_eq!(
            index_lore_run(&db, archive.path(), &commits).await.unwrap(),
            2
        );
        assert_eq!(lore_rows(&db, None).await, 2);
        assert_all_recorded(&db, &commits).await;
    }

    /// A failed run that found its only readable email already stored
    /// appended nothing, so it reports no new rows for maintenance.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn already_stored_email_is_not_counted_as_appended() {
        let (_dir, db) = lore_database().await;
        let (archive, commits) = lore_archive(&["<a@x>", "<b@x>"]);

        // Store <a@x> as another archive's crosspost would, without
        // recording this archive's commit.
        let side_map = std::sync::Mutex::new(HashMap::new());
        db.insert_lore_emails(&[lore_email("9999", "<a@x>")], &side_map)
            .await
            .unwrap();

        let blob = git(archive.path(), &["rev-parse", &format!("{}:m", commits[1])]);
        std::fs::remove_file(
            archive
                .path()
                .join(".git/objects")
                .join(&blob[..2])
                .join(&blob[2..]),
        )
        .unwrap();

        let outcome = incomplete(index_lore_run(&db, archive.path(), &commits).await);
        assert_eq!(
            outcome,
            LoreIndexIncomplete {
                stored: 1,
                appended: 0,
                unread_commits: 1,
                ..Default::default()
            }
        );
        assert_eq!(lore_rows(&db, None).await, 1);
    }

    /// A commit whose tree cannot be decoded is unread, not taken for a
    /// removed message: it fails the run and is left unrecorded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn malformed_tree_is_not_recorded() {
        let (_dir, db) = lore_database().await;
        let (archive, mut commits) = lore_archive(&["<a@x>"]);

        let bad_tree = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(bad_tree.path(), b"100644 no-nul-or-object-id").unwrap();
        let tree = git(
            archive.path(),
            &[
                "hash-object",
                "-t",
                "tree",
                "--literally",
                "-w",
                bad_tree.path().to_str().unwrap(),
            ],
        );
        let commit = git(
            archive.path(),
            &["commit-tree", &tree, "-p", &commits[0], "-m", "bad tree"],
        );
        commits.push(commit.clone());

        let outcome = incomplete(index_lore_run(&db, archive.path(), &commits).await);
        assert_eq!(
            outcome,
            LoreIndexIncomplete {
                stored: 1,
                appended: 1,
                unread_commits: 1,
                ..Default::default()
            }
        );
        let indexed = db.get_indexed_lore_commits().await.unwrap();
        assert!(indexed.contains(&commits[0]));
        assert!(!indexed.contains(&commit));
    }

    /// Stored emails whose commits cannot be recorded fail the run.  The
    /// next run reads them again, finds them stored, and records them
    /// without storing a second copy.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unrecorded_commits_fail_the_run_and_are_retried() {
        let (_dir, db) = lore_database().await;
        let (archive, commits) = lore_archive(&["<a@x>", "<b@x>"]);
        db.connection()
            .drop_table("lore_indexed_commits", &[])
            .await
            .unwrap();

        let outcome = incomplete(index_lore_run(&db, archive.path(), &commits).await);
        assert_eq!(
            outcome,
            LoreIndexIncomplete {
                stored: 2,
                appended: 2,
                unrecorded_commits: 2,
                ..Default::default()
            }
        );
        assert_eq!(lore_rows(&db, None).await, 2);

        db.create_tables().await.unwrap();
        assert_eq!(
            index_lore_run(&db, archive.path(), &commits).await.unwrap(),
            0
        );
        assert_eq!(lore_rows(&db, None).await, 2);
        assert_all_recorded(&db, &commits).await;
    }

    /// Parsers that cannot open the archive fail the run instead of
    /// leaving every commit unread and reporting success.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_parsers_fail_the_run() {
        let (_dir, db) = lore_database().await;
        let (_archive, commits) = lore_archive(&["<a@x>"]);
        let not_a_repo = tempfile::tempdir().unwrap();

        let outcome = incomplete(index_lore_run(&db, not_a_repo.path(), &commits).await);
        assert_eq!(
            outcome,
            LoreIndexIncomplete {
                failed_threads: 2,
                ..Default::default()
            }
        );
        assert!(db.get_indexed_lore_commits().await.unwrap().is_empty());
    }

    /// public-inbox records a removed message as a commit with a 'd' file
    /// and no 'm'.  Such a commit holds nothing to store: it does not fail
    /// the run and is recorded, so later runs do not read it again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn commit_without_a_message_is_recorded() {
        let (_dir, db) = lore_database().await;
        let (archive, mut commits) = lore_archive(&["<a@x>"]);
        git(archive.path(), &["rm", "-q", "m"]);
        std::fs::write(archive.path().join("d"), "removed\n").unwrap();
        git(archive.path(), &["add", "d"]);
        git(archive.path(), &["commit", "-q", "-m", "remove"]);
        commits.push(git(archive.path(), &["rev-parse", "HEAD"]));

        assert_eq!(
            index_lore_run(&db, archive.path(), &commits).await.unwrap(),
            1
        );
        assert_eq!(lore_rows(&db, None).await, 1);
        assert_all_recorded(&db, &commits).await;
    }

    /// One message id in several commits of an archive, spread over
    /// batches that two inserters store at once.  Whichever batch defers
    /// the id to another, the run stores one copy and records every
    /// commit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplicate_message_ids_are_stored_once_and_recorded() {
        let (_dir, db) = lore_database().await;
        let (archive, commits) = lore_archive(&[
            "<dup@x>", "<a@x>", "<dup@x>", "<b@x>", "<dup@x>", "<c@x>", "<dup@x>",
        ]);

        assert_eq!(
            index_lore_run(&db, archive.path(), &commits).await.unwrap(),
            4
        );
        assert_eq!(
            lore_rows(&db, Some("message_id = '<dup@x>'".to_string())).await,
            1
        );
        assert_eq!(lore_rows(&db, None).await, 4);
        assert_all_recorded(&db, &commits).await;
    }

    /// The summary names each kind of failure, and the stored count.
    #[test]
    fn incomplete_summary_lists_each_failure() {
        let outcome = LoreIndexIncomplete {
            stored: 900,
            appended: 800,
            failed_threads: 1,
            unread_commits: 2,
            unstored_emails: 100,
            unrecorded_commits: 1,
        };
        assert_eq!(
            outcome.to_string(),
            "lore indexing incomplete: 1 pipeline thread failed, \
             2 emails could not be read, 100 emails could not be stored, \
             1 commit could not be recorded as indexed; \
             indexing again retries them (900 emails stored)"
        );
    }
}
