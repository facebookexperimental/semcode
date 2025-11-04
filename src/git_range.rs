// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::git::walk_tree_at_commit_with_repo;
use crate::indexer::{list_shas_in_range, process_commits_pipeline};
use crate::{
    DatabaseManager, FunctionInfo, GitFileEntry, GitFileManifestEntry, ProcessedFileRecord,
    TreeSitterAnalyzer, TypeInfo,
};
use anyhow::Result;
use dashmap::DashSet;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use tracing::{error, info};

struct GitFileTuple {
    file_path: PathBuf,
    file_sha: String,
    object_id: gix::ObjectId,
}

/// Results from processing git file tuples (for database insertion batches)
#[derive(Debug, Default, Clone)]
struct GitTupleResults {
    functions: Vec<FunctionInfo>,
    types: Vec<TypeInfo>,
    processed_files: Vec<ProcessedFileRecord>,
    files_processed: usize,
}

impl GitTupleResults {
    fn merge(&mut self, other: GitTupleResults) {
        self.functions.extend(other.functions);
        self.types.extend(other.types);
        self.processed_files.extend(other.processed_files);
        self.files_processed += other.files_processed;
    }
}

/// Statistics from processing git file tuples (lightweight, no accumulated data)
#[derive(Debug, Default, Clone)]
struct GitTupleStats {
    files_processed: usize,
    functions_count: usize,
    types_count: usize,
}

/// Get manifest of files from a specific git commit with a reused repository reference
/// This version avoids repeated repository discovery for better performance
fn get_git_commit_manifest_with_repo(
    repo: &gix::Repository,
    git_sha: &str,
    extensions: &[String],
) -> Result<Vec<GitFileManifestEntry>> {
    let mut manifest = Vec::new();

    // Use shared tree traversal utility with extension filtering (with repo reuse)
    walk_tree_at_commit_with_repo(repo, git_sha, |relative_path, object_id| {
        // Check if file has one of the target extensions
        if let Some(ext) = std::path::Path::new(relative_path).extension() {
            if extensions.contains(&ext.to_string_lossy().to_string()) {
                manifest.push(GitFileManifestEntry {
                    relative_path: relative_path.into(),
                    object_id: *object_id,
                });
            }
        }
        Ok(())
    })?;

    Ok(manifest)
}

/// Load a specific file from git using its object ID and write to a temporary file
fn load_git_file_to_temp(
    repo: &gix::Repository,
    object_id: gix::ObjectId,
    file_stem: &str,
) -> Result<PathBuf> {
    let object = repo.find_object(object_id)?;
    let mut blob = object.try_into_blob()?;
    let blob_data = blob.take_data();

    // Create temp file with a meaningful prefix
    let temp_file = tempfile::Builder::new()
        .prefix(&format!("semcode_git_{file_stem}_"))
        .tempfile()?;

    // Write blob content to temp file
    let (mut temp_file, temp_path) = temp_file.keep()?;
    temp_file.write_all(&blob_data)?;
    temp_file.flush()?;

    Ok(temp_path)
}

/// Stream git file tuples to a channel from a subset of commits (producer)
fn stream_git_file_tuples_batch(
    generator_id: usize,
    repo_path: PathBuf,
    commit_batch: Vec<String>,
    extensions: Vec<String>,
    tuple_tx: mpsc::Sender<GitFileTuple>,
    processed_files: Arc<HashSet<String>>,
    sent_in_this_run: Arc<DashSet<String>>,
) -> Result<()> {
    // Open repository ONCE per generator thread and reuse for all commits
    let repo = gix::discover(&repo_path)?;

    let mut total_files = 0;
    let mut sent_files = 0;
    let mut filtered_already_processed = 0;
    let mut filtered_already_sent = 0;

    for commit_sha in commit_batch.iter() {
        // Get all files from this commit using reused repo handle
        let manifest = get_git_commit_manifest_with_repo(&repo, commit_sha, &extensions)?;

        for manifest_entry in manifest {
            let file_sha = manifest_entry.object_id.to_string();
            total_files += 1;

            // Filter out files already processed in database
            if processed_files.contains(&file_sha) {
                filtered_already_processed += 1;
                continue;
            }

            // Filter out files already sent in this run (lock-free with DashSet)
            if !sent_in_this_run.insert(file_sha.clone()) {
                // File already sent by another generator
                filtered_already_sent += 1;
                continue;
            }

            let tuple = GitFileTuple {
                file_path: manifest_entry.relative_path.clone(),
                file_sha: file_sha.clone(),
                object_id: manifest_entry.object_id,
            };

            // Send tuple to channel - if channel is closed, workers are done
            if tuple_tx.send(tuple).is_err() {
                break;
            }
            sent_files += 1;
        }
    }

    tracing::info!(
        "Generator {} finished: {} total files, {} sent, {} filtered (already processed), {} filtered (duplicate)",
        generator_id,
        total_files,
        sent_files,
        filtered_already_processed,
        filtered_already_sent
    );

    Ok(())
}

// Mapping extraction functions removed - now using embedded calls/types columns

/// Process a single git file tuple and extract functions/types/macros (with repo reuse)
fn process_git_file_tuple_with_repo(
    tuple: &GitFileTuple,
    repo: &gix::Repository,
    source_root: &std::path::Path,
    no_macros: bool,
) -> Result<GitTupleResults> {
    // Load git file content to temp file using the reused repo
    let file_stem = tuple
        .file_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("gitfile");

    let temp_path = load_git_file_to_temp(repo, tuple.object_id, file_stem)?;

    // Create temp GitFileEntry for cleanup
    let git_file = GitFileEntry {
        relative_path: tuple.file_path.clone(),
        blob_id: tuple.file_sha.clone(),
        temp_file_path: temp_path,
    };

    // Read source code and analyze
    let source_code = std::fs::read_to_string(&git_file.temp_file_path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read temp file {}: {}",
            git_file.temp_file_path.display(),
            e
        )
    })?;

    // Each thread needs its own TreeSitter analyzer
    let mut ts_analyzer = TreeSitterAnalyzer::new()
        .map_err(|e| anyhow::anyhow!("Failed to create TreeSitter analyzer: {}", e))?;

    let analysis_result = ts_analyzer.analyze_source_with_metadata(
        &source_code,
        &tuple.file_path,
        &tuple.file_sha,
        Some(source_root),
    );

    // Cleanup temp file before checking results
    if let Err(e) = git_file.cleanup() {
        tracing::warn!(
            "Failed to cleanup temp file {}: {}",
            git_file.temp_file_path.display(),
            e
        );
    }

    // Check analysis results
    let (mut functions, types, macros) = analysis_result?;

    // Macros are now stored as functions - combine them
    if !no_macros {
        functions.extend(macros);
    }

    // Function-type and type-type mapping extraction removed - now using embedded columns
    // Call relationships are now embedded in function/macro JSON columns

    // Track this file as processed
    let processed_file_record = ProcessedFileRecord {
        file: tuple.file_path.to_string_lossy().to_string(),
        git_sha: None, // Will be set by caller if available
        git_file_sha: tuple.file_sha.clone(),
    };

    let results = GitTupleResults {
        functions,
        types,
        processed_files: vec![processed_file_record],
        files_processed: 1,
    };

    Ok(results)
}

/// Worker function that processes tuples from a shared channel and sends batches to inserters
fn tuple_worker_shared(
    worker_id: usize,
    shared_tuple_rx: Arc<std::sync::Mutex<mpsc::Receiver<GitFileTuple>>>,
    result_tx: mpsc::SyncSender<GitTupleResults>,
    repo_path: PathBuf,
    source_root: PathBuf,
    no_macros: bool,
    processed_count: Arc<AtomicUsize>,
    batches_sent: Arc<AtomicUsize>,
    accumulate_lock: Arc<std::sync::Mutex<()>>,
) {
    // Open repository ONCE per worker thread and reuse for all tuples
    let thread_repo = match gix::discover(&repo_path) {
        Ok(repo) => repo,
        Err(e) => {
            tracing::error!("Worker {} failed to open repository: {}", worker_id, e);
            return;
        }
    };

    const DB_BATCH_SIZE: usize = 2048; // Number of files required before processing begins

    loop {
        // Step 1: Acquire lock to ensure only one worker accumulates at a time
        let _guard = match accumulate_lock.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!("Worker {} failed to acquire accumulate lock", worker_id);
                return;
            }
        };

        // Step 2: Accumulate tuples until we have DB_BATCH_SIZE files
        let mut tuples_to_process = Vec::new();

        'accumulate: loop {
            // Keep accumulating until we have DB_BATCH_SIZE files
            if tuples_to_process.len() >= DB_BATCH_SIZE {
                break 'accumulate;
            }

            // Get next tuple with blocking receive
            let tuple = {
                let rx = match shared_tuple_rx.lock() {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!("Worker {} failed to lock receiver: {}", worker_id, e);
                        return;
                    }
                };

                // Blocking receive - wait for work
                rx.recv()
            };

            match tuple {
                Ok(t) => {
                    tuples_to_process.push(t);
                }
                Err(_) => {
                    // Channel closed
                    if tuples_to_process.is_empty() {
                        // No files at all - exit worker
                        tracing::debug!(
                            "Worker {} exiting: channel closed, no files accumulated",
                            worker_id
                        );
                        return;
                    }
                    // Have some files - process them even if < DB_BATCH_SIZE
                    tracing::info!(
                        "Worker {} processing final batch: {} files (channel closed)",
                        worker_id,
                        tuples_to_process.len()
                    );
                    break 'accumulate;
                }
            }
        }

        // Step 3: Release lock so next worker can start accumulating
        drop(_guard);

        // Step 2: Process exactly DB_BATCH_SIZE files
        let mut batch = GitTupleResults::default();
        let tuples_to_process_now: Vec<_> = tuples_to_process
            .drain(..DB_BATCH_SIZE.min(tuples_to_process.len()))
            .collect();

        for tuple in tuples_to_process_now {
            match process_git_file_tuple_with_repo(&tuple, &thread_repo, &source_root, no_macros) {
                Ok(tuple_result) => {
                    batch.merge(tuple_result);
                    processed_count.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    tracing::warn!(
                        "Worker {} failed to process tuple {}: {}",
                        worker_id,
                        tuple.file_path.display(),
                        e
                    );
                }
            }
        }

        // Step 3: Send the batch (always exactly DB_BATCH_SIZE files)
        if batch.files_processed > 0 {
            batches_sent.fetch_add(1, Ordering::Relaxed);
            if result_tx.send(batch).is_err() {
                tracing::warn!("Worker {} failed to send batch (channel closed)", worker_id);
                return;
            }
        }
    }
}

/// Process git file tuples using streaming pipeline with database inserters
async fn process_git_tuples_streaming(
    repo_path: PathBuf,
    git_range: String,
    extensions: Vec<String>,
    source_root: PathBuf,
    no_macros: bool,
    processed_files: Arc<HashSet<String>>,
    num_workers: usize,
    db_manager: Arc<DatabaseManager>,
    num_inserters: usize,
) -> Result<GitTupleStats> {
    use std::sync::Mutex;

    // First, get all commits in the range
    let repo =
        gix::discover(&repo_path).map_err(|e| anyhow::anyhow!("Not in a git repository: {}", e))?;
    let commit_shas = list_shas_in_range(&repo, &git_range)?;

    // Handle empty commit range early - return empty stats
    if commit_shas.is_empty() {
        return Ok(GitTupleStats {
            files_processed: 0,
            functions_count: 0,
            types_count: 0,
        });
    }

    // Determine number of generator threads (up to 32, but not more than commits)
    let max_generators = std::cmp::min(num_cpus::get(), 32);
    let num_generators = std::cmp::min(max_generators, commit_shas.len()).max(1);

    // Split commits into chunks for each generator
    let chunk_size = commit_shas.len().div_ceil(num_generators);
    let commit_chunks: Vec<Vec<String>> = commit_shas
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect();

    // Create progress bar for file processing (indeterminate since we don't know total files)
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] Processing git commits: {pos} files processed - {msg}"
        ).unwrap()
        .progress_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
    );
    pb.set_message(format!(
        "{} commits, {} generators, {} workers",
        commit_shas.len(),
        num_generators,
        num_workers
    ));

    // Create channels with backpressure
    let (tuple_tx, tuple_rx) = mpsc::channel::<GitFileTuple>();
    // Scale result channel size with number of workers to prevent blocking
    // Allow 2 batches per worker in flight, with minimum of 4 and maximum of 64
    // Each batch ~= 2048 files, so this provides buffering without excessive memory use
    let result_channel_size = (num_workers * 2).clamp(4, 64);
    let (result_tx, result_rx) = mpsc::sync_channel::<GitTupleResults>(result_channel_size);
    tracing::info!(
        "Result channel size: {} (scaled with {} workers)",
        result_channel_size,
        num_workers
    );

    // Wrap receivers for shared access
    let shared_tuple_rx = Arc::new(Mutex::new(tuple_rx));
    let shared_result_rx = Arc::new(Mutex::new(result_rx));

    // Shared progress counters
    let processed_count = Arc::new(AtomicUsize::new(0));
    let inserted_functions = Arc::new(AtomicUsize::new(0));
    let inserted_types = Arc::new(AtomicUsize::new(0));
    let batches_sent = Arc::new(AtomicUsize::new(0));
    let batches_inserted = Arc::new(AtomicUsize::new(0));

    // Shared deduplication set across all generators (lock-free)
    let sent_in_this_run = Arc::new(DashSet::new());

    // Spawn progress updater thread
    let pb_clone = pb.clone();
    let processed_clone = processed_count.clone();
    let functions_clone = inserted_functions.clone();
    let types_clone = inserted_types.clone();
    let batches_sent_clone = batches_sent.clone();
    let batches_inserted_clone = batches_inserted.clone();
    let progress_thread = std::thread::spawn(move || {
        loop {
            let files = processed_clone.load(Ordering::Relaxed);
            let funcs = functions_clone.load(Ordering::Relaxed);
            let types = types_clone.load(Ordering::Relaxed);
            let sent = batches_sent_clone.load(Ordering::Relaxed);
            let inserted = batches_inserted_clone.load(Ordering::Relaxed);
            let pending = sent.saturating_sub(inserted);

            pb_clone.set_position(files as u64);
            pb_clone.set_message(format!(
                "{} funcs, {} types | {} batches pending",
                funcs, types, pending
            ));

            // Check if we should exit
            if pb_clone.is_finished() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    });

    // Spawn generator threads
    let mut generator_handles = Vec::new();
    for (generator_id, commit_chunk) in commit_chunks.into_iter().enumerate() {
        let generator_repo_path = repo_path.clone();
        let generator_extensions = extensions.clone();
        let generator_tuple_tx = tuple_tx.clone();
        let generator_processed_files = processed_files.clone();
        let generator_sent_in_run = sent_in_this_run.clone();

        let handle = thread::spawn(move || {
            if let Err(e) = stream_git_file_tuples_batch(
                generator_id,
                generator_repo_path,
                commit_chunk,
                generator_extensions,
                generator_tuple_tx,
                generator_processed_files,
                generator_sent_in_run,
            ) {
                tracing::error!("Generator {} failed: {}", generator_id, e);
            }
        });
        generator_handles.push(handle);
    }

    // Close the original tuple sender (generators have clones)
    drop(tuple_tx);

    // Use a mutex as a simple semaphore to control worker batch filling
    // Only one worker can accumulate files at a time to ensure sequential batches
    let accumulate_lock = Arc::new(std::sync::Mutex::new(()));

    // Spawn worker threads
    let mut worker_handles = Vec::new();
    for worker_id in 0..num_workers {
        let worker_tuple_rx = shared_tuple_rx.clone();
        let worker_result_tx = result_tx.clone();
        let worker_repo_path = repo_path.clone();
        let worker_source_root = source_root.clone();
        let worker_processed_count = processed_count.clone();
        let worker_batches_sent = batches_sent.clone();
        let worker_accumulate_lock = accumulate_lock.clone();

        let handle = thread::spawn(move || {
            tuple_worker_shared(
                worker_id,
                worker_tuple_rx,
                worker_result_tx,
                worker_repo_path,
                worker_source_root,
                no_macros,
                worker_processed_count,
                worker_batches_sent,
                worker_accumulate_lock,
            );
        });
        worker_handles.push(handle);
    }

    // Close the original result sender (workers have clones)
    drop(result_tx);

    // Spawn database inserter tasks (configurable via --db-threads)
    let mut inserter_handles = Vec::new();

    // Shared flag to coordinate periodic optimization checks
    // Only one inserter should check at a time to avoid redundant checks
    let last_optimization_check = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));

    for inserter_id in 0..num_inserters {
        let db_manager_clone = Arc::clone(&db_manager);
        let result_rx_clone = shared_result_rx.clone();
        let functions_counter = inserted_functions.clone();
        let types_counter = inserted_types.clone();
        let batches_inserted_counter = batches_inserted.clone();
        let optimization_check_timer = last_optimization_check.clone();

        let handle = tokio::spawn(async move {
            loop {
                // Get next batch from shared receiver
                let batch = {
                    let rx = result_rx_clone.lock().unwrap();
                    rx.recv()
                };

                match batch {
                    Ok(batch) => {
                        let func_count = batch.functions.len();
                        let type_count = batch.types.len();

                        // Insert all three types in parallel
                        let (func_result, type_result, processed_files_result) = tokio::join!(
                            async {
                                if !batch.functions.is_empty() {
                                    db_manager_clone.insert_functions(batch.functions).await
                                } else {
                                    Ok(())
                                }
                            },
                            async {
                                if !batch.types.is_empty() {
                                    db_manager_clone.insert_types(batch.types).await
                                } else {
                                    Ok(())
                                }
                            },
                            async {
                                if !batch.processed_files.is_empty() {
                                    db_manager_clone
                                        .mark_files_processed(batch.processed_files)
                                        .await
                                } else {
                                    Ok(())
                                }
                            }
                        );

                        // Check results and update counters
                        let mut insertion_successful = true;
                        if let Err(e) = func_result {
                            error!("Inserter {} failed to insert functions: {}", inserter_id, e);
                            insertion_successful = false;
                        } else {
                            functions_counter.fetch_add(func_count, Ordering::Relaxed);
                        }
                        if let Err(e) = type_result {
                            error!("Inserter {} failed to insert types: {}", inserter_id, e);
                            insertion_successful = false;
                        } else {
                            types_counter.fetch_add(type_count, Ordering::Relaxed);
                        }
                        if let Err(e) = processed_files_result {
                            error!(
                                "Inserter {} failed to insert processed_files: {}",
                                inserter_id, e
                            );
                            insertion_successful = false;
                        }
                        // Note: not tracking processed_files_count in a counter since it's not displayed

                        // Only increment batches_inserted if insertion was successful
                        if insertion_successful {
                            let total_batches =
                                batches_inserted_counter.fetch_add(1, Ordering::Relaxed) + 1;

                            // Periodic optimization check using shared function
                            crate::indexer::check_and_optimize_if_needed(
                                &db_manager_clone,
                                inserter_id,
                                total_batches,
                                &optimization_check_timer,
                            )
                            .await;
                        }
                    }
                    Err(_) => break, // Channel closed, exit task
                }
            }
        });

        inserter_handles.push(handle);
    }

    // Wait for all generators to complete
    for (generator_id, handle) in generator_handles.into_iter().enumerate() {
        if let Err(e) = handle.join() {
            tracing::error!("Generator {} thread panicked: {:?}", generator_id, e);
        }
    }

    // Wait for all workers to complete
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

    // Collect final statistics
    let stats = GitTupleStats {
        files_processed: processed_count.load(Ordering::Relaxed),
        functions_count: inserted_functions.load(Ordering::Relaxed),
        types_count: inserted_types.load(Ordering::Relaxed),
    };

    // Finish progress bar
    pb.finish_with_message(format!(
        "Complete: {} files, {} functions, {} types",
        stats.files_processed, stats.functions_count, stats.types_count
    ));
    progress_thread.join().unwrap();

    Ok(stats)
}

/// Parse tags from commit message (e.g., Signed-off-by:, Reported-by:, etc.)

/// Process git range using streaming file tuple pipeline
/// This is the shared implementation used by semcode-index, query, and MCP tools
pub async fn process_git_range(
    repo_path: &PathBuf,
    git_range: &str,
    extensions: &[String],
    db_manager: Arc<DatabaseManager>,
    no_macros: bool,
    db_threads: usize,
) -> Result<()> {
    info!(
        "Processing git range {} using streaming file tuple pipeline",
        git_range
    );

    let start_time = std::time::Instant::now();

    // Step 1: Get already processed files from database for deduplication
    info!("Loading processed files from database for deduplication");
    let processed_files_records = db_manager.get_all_processed_files().await?;
    let processed_files: HashSet<String> = processed_files_records
        .into_iter()
        .map(|record| record.git_file_sha)
        .collect();

    info!(
        "Found {} already processed files in database",
        processed_files.len()
    );
    let processed_files = Arc::new(processed_files);

    // Step 1.5: Extract and store git commit metadata using optimized streaming pipeline
    info!("Extracting git commit metadata for range: {}", git_range);
    let commit_extraction_start = std::time::Instant::now();

    // Open repository and get list of commits in range
    let repo =
        gix::discover(repo_path).map_err(|e| anyhow::anyhow!("Not in a git repository: {}", e))?;
    let commit_shas = list_shas_in_range(&repo, git_range)?;
    let commit_count = commit_shas.len();

    if !commit_shas.is_empty() {
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

        if !new_commit_shas.is_empty() {
            // Use the optimized streaming pipeline from --commits mode
            // This provides: pre-filtering, streaming, parallel workers, parallel DB insertion
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

            info!(
                "Total commit metadata extraction time: {:.1}s",
                commit_extraction_start.elapsed().as_secs_f64()
            );
        } else {
            println!("All commits in range are already indexed!");
        }
    } else {
        info!("No commits found in range");
    }

    // Step 2: Determine number of workers
    // Since generators are I/O bound and workers are CPU bound, use a balanced approach
    let num_workers = (num_cpus::get() / 2).max(1);
    info!(
        "Starting streaming pipeline with up to 32 generator threads and {} worker threads",
        num_workers
    );

    // Step 3: Process tuples using streaming pipeline with database inserters
    let processing_start = std::time::Instant::now();
    let stats = process_git_tuples_streaming(
        repo_path.clone(),
        git_range.to_string(),
        extensions.to_vec(),
        repo_path.clone(),
        no_macros,
        processed_files,
        num_workers,
        db_manager.clone(),
        db_threads,
    )
    .await?;

    let processing_time = processing_start.elapsed();

    info!(
        "Streaming pipeline completed in {:.1}s: {} files, {} functions, {} types (inserted throughout processing)",
        processing_time.as_secs_f64(),
        stats.files_processed,
        stats.functions_count,
        stats.types_count
    );

    // Database insertion happened throughout processing via streaming inserters
    // No batch insertion needed here!

    let total_time = start_time.elapsed();

    println!("\n=== Git Range Pipeline Complete ===");
    println!("Total time: {:.1}s", total_time.as_secs_f64());
    println!("Commits indexed: {commit_count}");
    println!("Files processed: {}", stats.files_processed);
    println!("Functions indexed: {}", stats.functions_count);
    println!("Types indexed: {}", stats.types_count);

    // Check if optimization is needed after git range indexing
    match db_manager.check_optimization_health().await {
        Ok((needs_optimization, message)) => {
            if needs_optimization {
                println!("\n{}", message);
                match db_manager.optimize_database().await {
                    Ok(_) => println!("Database optimization completed successfully"),
                    Err(e) => error!("Failed to optimize database: {}", e),
                }
            } else {
                println!("\n{}", message);
            }
        }
        Err(e) => {
            error!("Failed to check database health: {}", e);
        }
    }

    Ok(())
}
