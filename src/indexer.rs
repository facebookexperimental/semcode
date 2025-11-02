// SPDX-License-Identifier: MIT OR Apache-2.0
//! Indexing functionality shared across binaries
//!
//! This module provides reusable indexing functions for git commits and files
//! that can be called from different binaries (semcode-index, semcode, semcode-mcp, etc.)

use anyhow::Result;
use gix::revision::walk::Sorting;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use tracing::{error, info, warn};

use crate::git::resolve_to_commit;
use crate::{DatabaseManager, GitCommitInfo};

/// Parse git range and get all commit SHAs in the range
/// Uses gitoxide's built-in rev-spec parsing for proper A..B semantics
pub fn list_shas_in_range(repo: &gix::Repository, range: &str) -> Result<Vec<String>> {
    // For simplicity, let's just handle the common A..B case manually for now
    // and use gitoxide's rev_walk properly
    if !range.contains("..") {
        return Err(anyhow::anyhow!(
            "Only range format (A..B) is supported, got: '{}'",
            range
        ));
    }

    // Parse A..B manually
    let parts: Vec<&str> = range.split("..").collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!("Invalid range format '{}'", range));
    }

    let from_spec = parts[0];
    let to_spec = parts[1];

    // Resolve the commit IDs
    let from_commit = resolve_to_commit(repo, from_spec)?;
    let to_commit = resolve_to_commit(repo, to_spec)?;
    let from_id = from_commit.id().detach();
    let to_id = to_commit.id().detach();

    // Use rev_walk with proper include/exclude
    let walk = repo
        .rev_walk([to_id])
        .with_hidden([from_id])
        .sorting(Sorting::ByCommitTime(Default::default()))
        .all()?;

    let mut shas = Vec::new();
    let mut commit_count = 0;
    const MAX_COMMITS: usize = 10000000; // Safety limit

    // Iterate commits in the set "reachable from B but not from A"
    for info in walk {
        let info = info?;
        commit_count += 1;

        // Safety check to prevent runaway processing
        if commit_count > MAX_COMMITS {
            return Err(anyhow::anyhow!(
                "Commit range {} is too large (>{} commits). This may indicate a problem with the repository.",
                range, MAX_COMMITS
            ));
        }

        let commit_id = info.id();
        let commit_sha = commit_id.to_string();
        shas.push(commit_sha);
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
                    .or_insert_with(Vec::new)
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
    let message = String::from_utf8_lossy(&message_bytes).to_string();

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
                        return Ok::<_, anyhow::Error>(Action::Continue);
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

                    Ok(Action::Continue)
                }
                gix::object::tree::diff::Change::Addition {
                    entry_mode,
                    id,
                    location,
                    ..
                } => {
                    if !entry_mode.is_blob() {
                        return Ok(Action::Continue);
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

                    Ok(Action::Continue)
                }
                gix::object::tree::diff::Change::Deletion {
                    entry_mode,
                    id,
                    location,
                    ..
                } => {
                    if !entry_mode.is_blob() {
                        return Ok(Action::Continue);
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

                    Ok(Action::Continue)
                }
                gix::object::tree::diff::Change::Rewrite { .. } => {
                    // Rewrite represents a complete file replacement - rare in practice
                    // Skip for now as it's complex to handle properly
                    Ok::<_, anyhow::Error>(Action::Continue)
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
        let worker_repo_path = repo_path.to_path_buf();
        let worker_processed = processed_count.clone();

        let handle = thread::spawn(move || {
            // Open repository ONCE per worker thread, reuse for all commits
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
                        match extract_commit_metadata(&thread_repo, &sha) {
                            Ok(metadata) => {
                                batch.push(metadata);
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
                                    "Worker {} failed to extract metadata for {}: {}",
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
        println!("No commits found in range: {}", git_range);
        return Ok(0);
    }

    println!(
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
        println!(
            "{} commits already indexed, processing {} new commits",
            already_indexed,
            new_commit_shas.len()
        );
    } else {
        println!("Processing all {} new commits", new_commit_shas.len());
    }

    if new_commit_shas.is_empty() {
        println!("All commits in range are already indexed!");
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

    println!("\n=== Commit Indexing Complete ===");
    println!("Total time: {:.1}s", total_time.as_secs_f64());
    println!("Commits indexed: {}", commit_count);

    Ok(commit_count)
}
