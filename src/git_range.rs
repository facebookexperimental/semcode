// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::git::walk_tree_at_commit_with_repo;
use crate::indexer::{list_shas_in_range, process_commits_pipeline};
use crate::types::{ArgumentFunction, GlobalVariable};
use crate::{
    DatabaseManager, DispatchSite, FunctionInfo, GitFileEntry, GitFileManifestEntry,
    ProcessedFileRecord, Registration, TreeSitterAnalyzer, TypeInfo,
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
    /// The commit this file was read from. Recorded with the file, because it
    /// is the only place that knows: a range run reads many commits, and a
    /// row cannot say which tree it belongs to afterwards.
    commit_sha: String,
}

/// Results from processing git file tuples (for database insertion batches)
#[derive(Debug, Default, Clone)]
struct GitTupleResults {
    functions: Vec<FunctionInfo>,
    types: Vec<TypeInfo>,
    dispatch_sites: Vec<DispatchSite>,
    registrations: Vec<Registration>,
    argument_functions: Vec<ArgumentFunction>,
    unresolved_edges: Vec<crate::types::UnresolvedEdge>,
    globals: Vec<GlobalVariable>,
    processed_files: Vec<ProcessedFileRecord>,
    files_processed: usize,
}

impl GitTupleResults {
    fn merge(&mut self, other: GitTupleResults) {
        // Destructured, not field-by-field: a new fact table that nobody
        // extends here is data silently dropped, so it must fail to compile.
        let GitTupleResults {
            functions,
            types,
            dispatch_sites,
            registrations,
            argument_functions,
            unresolved_edges,
            globals,
            processed_files,
            files_processed,
        } = other;
        self.functions.extend(functions);
        self.types.extend(types);
        self.dispatch_sites.extend(dispatch_sites);
        self.registrations.extend(registrations);
        self.argument_functions.extend(argument_functions);
        self.unresolved_edges.extend(unresolved_edges);
        self.globals.extend(globals);
        self.processed_files.extend(processed_files);
        self.files_processed += files_processed;
    }
}

/// Context for tuple worker threads
struct TupleWorkerContext {
    worker_id: usize,
    shared_tuple_rx: Arc<std::sync::Mutex<mpsc::Receiver<GitFileTuple>>>,
    result_tx: mpsc::SyncSender<GitTupleResults>,
    repo_path: PathBuf,
    source_root: PathBuf,
    no_macros: bool,
    processed_count: Arc<AtomicUsize>,
    batches_sent: Arc<AtomicUsize>,
    accumulate_lock: Arc<std::sync::Mutex<()>>,
}

/// Configuration for streaming git tuples processing
struct StreamingConfig {
    repo_path: PathBuf,
    git_range: String,
    extensions: Vec<String>,
    source_root: PathBuf,
    no_macros: bool,
    processed_files: Arc<HashSet<String>>,
    num_workers: usize,
    db_manager: Arc<DatabaseManager>,
    num_inserters: usize,
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
                commit_sha: commit_sha.to_string(),
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
    let analysis = analysis_result?;
    let (
        mut functions,
        types,
        dispatch_sites,
        registrations,
        argument_functions,
        unresolved_edges,
        globals,
    ) = (
        analysis.functions,
        analysis.types,
        analysis.dispatch_sites,
        analysis.registrations,
        analysis.argument_functions,
        analysis.unresolved_edges,
        analysis.globals,
    );
    let macros = analysis.macros;

    // Macros are now stored as functions - combine them
    if !no_macros {
        functions.extend(macros);
    }

    // Function-type and type-type mapping extraction removed - now using embedded columns
    // Call relationships are now embedded in function/macro JSON columns

    // Track this file as processed
    let processed_file_record = ProcessedFileRecord {
        file: tuple.file_path.to_string_lossy().to_string(),
        git_sha: Some(tuple.commit_sha.clone()),
        git_file_sha: tuple.file_sha.clone(),
        extractor_version: Some(crate::SCHEMA_VERSION),
    };

    let results = GitTupleResults {
        functions,
        types,
        dispatch_sites,
        registrations,
        argument_functions,
        unresolved_edges,
        globals,
        processed_files: vec![processed_file_record],
        files_processed: 1,
    };

    Ok(results)
}

/// Worker function that processes tuples from a shared channel and sends batches to inserters
fn tuple_worker_shared(ctx: TupleWorkerContext) {
    // Open repository ONCE per worker and convert to thread-safe version for sharing across rayon threads
    let thread_safe_repo = match gix::discover(&ctx.repo_path) {
        Ok(repo) => repo.into_sync(),
        Err(e) => {
            tracing::error!("Worker {} failed to open repository: {}", ctx.worker_id, e);
            return;
        }
    };

    const DB_BATCH_SIZE: usize = 2048; // Number of files required before processing begins

    loop {
        // Step 1: Acquire lock to ensure only one worker accumulates at a time
        let _guard = match ctx.accumulate_lock.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!("Worker {} failed to acquire accumulate lock", ctx.worker_id);
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
                let rx = match ctx.shared_tuple_rx.lock() {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!("Worker {} failed to lock receiver: {}", ctx.worker_id, e);
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
                            ctx.worker_id
                        );
                        return;
                    }
                    // Have some files - process them even if < DB_BATCH_SIZE
                    tracing::info!(
                        "Worker {} processing final batch: {} files (channel closed)",
                        ctx.worker_id,
                        tuples_to_process.len()
                    );
                    break 'accumulate;
                }
            }
        }

        // Step 3: Release lock so next worker can start accumulating
        drop(_guard);

        // Step 4: Process exactly DB_BATCH_SIZE files IN PARALLEL using rayon
        // Share the thread-safe repository across all Rayon threads
        let mut batch = GitTupleResults::default();
        let tuples_to_process_now: Vec<_> = tuples_to_process
            .drain(..DB_BATCH_SIZE.min(tuples_to_process.len()))
            .collect();

        // Process files in parallel using rayon with shared thread-safe repo
        // Each Rayon worker thread converts it to a thread-local handle once
        use rayon::prelude::*;

        let processed_count_clone = ctx.processed_count.clone();
        let results: Vec<Result<GitTupleResults>> = tuples_to_process_now
            .par_iter()
            .map_init(
                || {
                    // Initialize: convert thread-safe repo to thread-local once per Rayon worker thread
                    thread_safe_repo.to_thread_local()
                },
                |thread_local_repo, tuple| {
                    // Process each file using the thread-local repo handle
                    let result = process_git_file_tuple_with_repo(
                        tuple,
                        thread_local_repo,
                        &ctx.source_root,
                        ctx.no_macros,
                    );

                    // Update progress counter immediately after processing each file
                    if result.is_ok() {
                        processed_count_clone.fetch_add(1, Ordering::Relaxed);
                    }

                    result
                },
            )
            .collect();

        // Merge all successful results
        for result in results {
            match result {
                Ok(tuple_result) => {
                    batch.merge(tuple_result);
                }
                Err(e) => {
                    tracing::warn!("Worker {} failed to process tuple: {}", ctx.worker_id, e);
                }
            }
        }

        // Step 3: Send the batch (always exactly DB_BATCH_SIZE files)
        if batch.files_processed > 0 {
            ctx.batches_sent.fetch_add(1, Ordering::Relaxed);
            if ctx.result_tx.send(batch).is_err() {
                tracing::warn!(
                    "Worker {} failed to send batch (channel closed)",
                    ctx.worker_id
                );
                return;
            }
        }
    }
}

/// Insert one batch of facts, then mark its files processed.
///
/// Both streaming inserters commit through here, so exactly one place
/// decides when a file counts as read. The mark goes last, and only if
/// every fact table accepted its rows: a file marked processed is never
/// read again, so a mark written beside a failed insert is facts the index
/// silently lacks. Every fact store merges on its key, so leaving a
/// half-inserted batch unmarked heals where the next run re-reads the same
/// blob at the same path and the failure does not repeat: the merge then
/// completes what the failed run wrote. Three shapes escape that -- a blob
/// read at a new path, a failure that fails the same way every run, a run
/// whose input never contains the blob -- and those stay holes until the
/// run learns to retry per file and to account for unmarked files.
///
/// A failed mark is the same shape: the facts are in, the file is not
/// marked, the next run re-reads it and the merges change nothing.
async fn insert_batch_and_mark(
    db: &DatabaseManager,
    batch: GitTupleResults,
    inserter_id: usize,
    functions_counter: &AtomicUsize,
    types_counter: &AtomicUsize,
    batches_inserted_counter: &AtomicUsize,
    optimization_check_timer: &Arc<std::sync::Mutex<std::time::Instant>>,
) {
    // Exhaustive: a new fact table must be inserted and checked here, not
    // silently left out of the batch the mark commits.
    let GitTupleResults {
        functions,
        types,
        dispatch_sites,
        registrations,
        argument_functions,
        unresolved_edges,
        globals,
        processed_files,
        files_processed: _,
    } = batch;
    let func_count = functions.len();
    let type_count = types.len();

    // Every fact table in parallel. processed_files is not among them: the
    // mark is the batch's commit record, and a commit record written beside
    // a failed insert is how a file gets skipped with its facts missing.
    let (
        func_result,
        type_result,
        dispatch_result,
        registration_result,
        argument_function_result,
        unresolved_edge_result,
        global_result,
    ) = tokio::join!(
        async {
            if !functions.is_empty() {
                db.insert_functions(functions).await
            } else {
                Ok(())
            }
        },
        async {
            if !types.is_empty() {
                db.insert_types(types).await
            } else {
                Ok(())
            }
        },
        async {
            if !dispatch_sites.is_empty() {
                db.insert_dispatch_sites(dispatch_sites).await
            } else {
                Ok(())
            }
        },
        async {
            if !registrations.is_empty() {
                db.insert_registrations(registrations).await
            } else {
                Ok(())
            }
        },
        async {
            if !argument_functions.is_empty() {
                db.insert_argument_functions(argument_functions).await
            } else {
                Ok(())
            }
        },
        async {
            if !unresolved_edges.is_empty() {
                db.insert_unresolved_edges(unresolved_edges).await
            } else {
                Ok(())
            }
        },
        async {
            if !globals.is_empty() {
                db.insert_globals(globals).await
            } else {
                Ok(())
            }
        },
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
    if let Err(e) = dispatch_result {
        error!(
            "Inserter {} failed to insert dispatch sites: {}",
            inserter_id, e
        );
        insertion_successful = false;
    }
    if let Err(e) = registration_result {
        error!(
            "Inserter {} failed to insert registrations: {}",
            inserter_id, e
        );
        insertion_successful = false;
    }
    if let Err(e) = argument_function_result {
        error!(
            "Inserter {} failed to insert argument functions: {}",
            inserter_id, e
        );
        insertion_successful = false;
    }
    if let Err(e) = unresolved_edge_result {
        error!(
            "Inserter {} failed to insert unresolved edges: {}",
            inserter_id, e
        );
        insertion_successful = false;
    }
    if let Err(e) = global_result {
        error!("Inserter {} failed to insert globals: {}", inserter_id, e);
        insertion_successful = false;
    }

    // Only a batch whose facts all landed may claim its files. A file left
    // unmarked is re-read next run; a file marked beside missing facts is
    // skipped with the hole in place.
    if insertion_successful && !processed_files.is_empty() {
        if let Err(e) = db.mark_files_processed(processed_files).await {
            error!(
                "Inserter {} failed to insert processed_files: {}",
                inserter_id, e
            );
            insertion_successful = false;
        }
    }
    // Note: not tracking processed_files_count in a counter since it's not displayed

    // Only increment batches_inserted if insertion was successful
    if insertion_successful {
        let total_batches = batches_inserted_counter.fetch_add(1, Ordering::Relaxed) + 1;

        // Periodic optimization check using shared function
        crate::indexer::check_and_optimize_if_needed(
            db,
            inserter_id,
            total_batches,
            optimization_check_timer,
        )
        .await;
    }
}

/// Process git file tuples using streaming pipeline with database inserters
async fn process_git_tuples_streaming(config: StreamingConfig) -> Result<GitTupleStats> {
    use std::sync::Mutex;

    // First, get all commits in the range
    let repo = gix::discover(&config.repo_path)
        .map_err(|e| anyhow::anyhow!("Not in a git repository: {}", e))?;
    let commit_shas = list_shas_in_range(&repo, &config.git_range)?;

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
        config.num_workers
    ));

    // Create channels with backpressure
    let (tuple_tx, tuple_rx) = mpsc::channel::<GitFileTuple>();
    // Scale result channel size with number of workers to prevent blocking
    // Allow 2 batches per worker in flight, with minimum of 4 and maximum of 64
    // Each batch ~= 2048 files, so this provides buffering without excessive memory use
    let result_channel_size = (config.num_workers * 2).clamp(4, 64);
    let (result_tx, result_rx) = mpsc::sync_channel::<GitTupleResults>(result_channel_size);
    tracing::info!(
        "Result channel size: {} (scaled with {} workers)",
        result_channel_size,
        config.num_workers
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
        let generator_repo_path = config.repo_path.clone();
        let generator_extensions = config.extensions.clone();
        let generator_tuple_tx = tuple_tx.clone();
        let generator_processed_files = config.processed_files.clone();
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
    for worker_id in 0..config.num_workers {
        let ctx = TupleWorkerContext {
            worker_id,
            shared_tuple_rx: shared_tuple_rx.clone(),
            result_tx: result_tx.clone(),
            repo_path: config.repo_path.clone(),
            source_root: config.source_root.clone(),
            no_macros: config.no_macros,
            processed_count: processed_count.clone(),
            batches_sent: batches_sent.clone(),
            accumulate_lock: accumulate_lock.clone(),
        };

        let handle = thread::spawn(move || {
            tuple_worker_shared(ctx);
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

    for inserter_id in 0..config.num_inserters {
        let db_manager_clone = Arc::clone(&config.db_manager);
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
                        insert_batch_and_mark(
                            &db_manager_clone,
                            batch,
                            inserter_id,
                            &functions_counter,
                            &types_counter,
                            &batches_inserted_counter,
                            &optimization_check_timer,
                        )
                        .await;
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

/// Configuration for streaming tree-based processing (single commit snapshot)
struct TreeStreamingConfig {
    repo_path: PathBuf,
    commit_sha: String,
    extensions: Vec<String>,
    source_root: PathBuf,
    no_macros: bool,
    processed_files: Arc<HashSet<String>>,
    num_workers: usize,
    db_manager: Arc<DatabaseManager>,
    num_inserters: usize,
}

/// Stream git file tuples from a tree at a specific commit (producer for tree-based indexing)
fn stream_tree_file_tuples(
    repo_path: PathBuf,
    commit_sha: String,
    extensions: Vec<String>,
    tuple_tx: mpsc::Sender<GitFileTuple>,
    processed_files: Arc<HashSet<String>>,
) -> Result<usize> {
    use crate::git::walk_tree_at_commit;

    let mut sent_files = 0;
    let mut filtered_already_processed = 0;

    // Walk the tree at the commit and send tuples for matching files
    walk_tree_at_commit(&repo_path, &commit_sha, |relative_path, object_id| {
        // Check if file has one of the target extensions
        let path = std::path::Path::new(relative_path);
        let ext_matches = path
            .extension()
            .map(|ext| extensions.contains(&ext.to_string_lossy().to_string()))
            .unwrap_or(false);

        if !ext_matches {
            return Ok(());
        }

        let file_sha = object_id.to_string();

        // Filter out files already processed in database
        if processed_files.contains(&file_sha) {
            filtered_already_processed += 1;
            return Ok(());
        }

        let tuple = GitFileTuple {
            file_path: PathBuf::from(relative_path),
            file_sha,
            object_id: *object_id,
            commit_sha: commit_sha.clone(),
        };

        // Send tuple to channel - if channel is closed, workers are done
        if tuple_tx.send(tuple).is_ok() {
            sent_files += 1;
        }

        Ok(())
    })?;

    tracing::info!(
        "Tree walk complete: {} files sent, {} filtered (already processed)",
        sent_files,
        filtered_already_processed
    );

    Ok(sent_files)
}

/// Process git tree at a specific commit using streaming pipeline
/// Unlike process_git_range which walks commits, this walks the tree snapshot
async fn process_git_tree_streaming(config: TreeStreamingConfig) -> Result<GitTupleStats> {
    use std::sync::Mutex;

    // Create progress bar for file processing
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] Processing tree: {pos} files processed - {msg}",
        )
        .unwrap()
        .progress_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
    );
    pb.set_message(format!("{} workers", config.num_workers));

    // Create channels with backpressure
    let (tuple_tx, tuple_rx) = mpsc::channel::<GitFileTuple>();
    let result_channel_size = (config.num_workers * 2).clamp(4, 64);
    let (result_tx, result_rx) = mpsc::sync_channel::<GitTupleResults>(result_channel_size);

    // Wrap receivers for shared access
    let shared_tuple_rx = Arc::new(Mutex::new(tuple_rx));
    let shared_result_rx = Arc::new(Mutex::new(result_rx));

    // Shared progress counters
    let processed_count = Arc::new(AtomicUsize::new(0));
    let inserted_functions = Arc::new(AtomicUsize::new(0));
    let inserted_types = Arc::new(AtomicUsize::new(0));
    let batches_sent = Arc::new(AtomicUsize::new(0));
    let batches_inserted = Arc::new(AtomicUsize::new(0));

    // Spawn progress updater thread
    let pb_clone = pb.clone();
    let processed_clone = processed_count.clone();
    let functions_clone = inserted_functions.clone();
    let types_clone = inserted_types.clone();
    let batches_sent_clone = batches_sent.clone();
    let batches_inserted_clone = batches_inserted.clone();
    let progress_thread = std::thread::spawn(move || loop {
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

        if pb_clone.is_finished() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    });

    // Spawn single generator thread that walks the tree
    let generator_repo_path = config.repo_path.clone();
    let generator_commit_sha = config.commit_sha.clone();
    let generator_extensions = config.extensions.clone();
    let generator_processed_files = config.processed_files.clone();

    let generator_handle = thread::spawn(move || {
        if let Err(e) = stream_tree_file_tuples(
            generator_repo_path,
            generator_commit_sha,
            generator_extensions,
            tuple_tx,
            generator_processed_files,
        ) {
            tracing::error!("Tree generator failed: {}", e);
        }
    });

    // Use a mutex as a simple semaphore to control worker batch filling
    let accumulate_lock = Arc::new(std::sync::Mutex::new(()));

    // Spawn worker threads (reuse existing tuple_worker_shared)
    let mut worker_handles = Vec::new();
    for worker_id in 0..config.num_workers {
        let ctx = TupleWorkerContext {
            worker_id,
            shared_tuple_rx: shared_tuple_rx.clone(),
            result_tx: result_tx.clone(),
            repo_path: config.repo_path.clone(),
            source_root: config.source_root.clone(),
            no_macros: config.no_macros,
            processed_count: processed_count.clone(),
            batches_sent: batches_sent.clone(),
            accumulate_lock: accumulate_lock.clone(),
        };

        let handle = thread::spawn(move || {
            tuple_worker_shared(ctx);
        });
        worker_handles.push(handle);
    }

    // Close the original result sender (workers have clones)
    drop(result_tx);

    // Spawn database inserter tasks
    let mut inserter_handles = Vec::new();
    let last_optimization_check = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));

    for inserter_id in 0..config.num_inserters {
        let db_manager_clone = Arc::clone(&config.db_manager);
        let result_rx_clone = shared_result_rx.clone();
        let functions_counter = inserted_functions.clone();
        let types_counter = inserted_types.clone();
        let batches_inserted_counter = batches_inserted.clone();
        let optimization_check_timer = last_optimization_check.clone();

        let handle = tokio::spawn(async move {
            loop {
                let batch = {
                    let rx = result_rx_clone.lock().unwrap();
                    rx.recv()
                };

                match batch {
                    Ok(batch) => {
                        insert_batch_and_mark(
                            &db_manager_clone,
                            batch,
                            inserter_id,
                            &functions_counter,
                            &types_counter,
                            &batches_inserted_counter,
                            &optimization_check_timer,
                        )
                        .await;
                    }
                    Err(_) => break,
                }
            }
        });

        inserter_handles.push(handle);
    }

    // Wait for generator to complete
    if let Err(e) = generator_handle.join() {
        tracing::error!("Tree generator thread panicked: {:?}", e);
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

    pb.finish_with_message(format!(
        "Complete: {} files, {} functions, {} types",
        stats.files_processed, stats.functions_count, stats.types_count
    ));
    progress_thread.join().unwrap();

    Ok(stats)
}

/// Process git tree at a specific commit (snapshot-based indexing)
/// This indexes all files at the commit without walking commit history.
/// Use this for initial branch indexing instead of process_git_range.
pub async fn process_git_tree(
    repo_path: &std::path::Path,
    commit_sha: &str,
    extensions: &[String],
    db_manager: Arc<DatabaseManager>,
    no_macros: bool,
    db_threads: usize,
) -> Result<()> {
    info!(
        "Processing git tree at {} using streaming pipeline",
        &commit_sha[..8.min(commit_sha.len())]
    );

    let start_time = std::time::Instant::now();

    // Get already processed files from database for deduplication. A row
    // written by an older extractor does not qualify: the file has not
    // changed, the reading of it has, so it is absent from this set and gets
    // read again on its own account.
    info!("Loading processed files from database for deduplication");
    let processed_files: HashSet<String> = db_manager.processed_by_this_extractor().await?;

    info!(
        "Found {} already processed files in database",
        processed_files.len()
    );
    let processed_files = Arc::new(processed_files);

    // Determine number of workers
    let num_workers = num_cpus::get().max(1);
    info!(
        "Starting tree streaming pipeline with {} worker threads",
        num_workers
    );

    // Process tree using streaming pipeline
    let processing_start = std::time::Instant::now();
    let config = TreeStreamingConfig {
        repo_path: repo_path.to_path_buf(),
        commit_sha: commit_sha.to_string(),
        extensions: extensions.to_vec(),
        source_root: repo_path.to_path_buf(),
        no_macros,
        processed_files,
        num_workers,
        db_manager: db_manager.clone(),
        num_inserters: db_threads,
    };
    let stats = process_git_tree_streaming(config).await?;

    let processing_time = processing_start.elapsed();

    info!(
        "Tree pipeline completed in {:.1}s: {} files, {} functions, {} types",
        processing_time.as_secs_f64(),
        stats.files_processed,
        stats.functions_count,
        stats.types_count
    );

    let total_time = start_time.elapsed();

    println!("\n=== Git Tree Indexing Complete ===");
    println!("Total time: {:.1}s", total_time.as_secs_f64());
    println!("Files processed: {}", stats.files_processed);
    println!("Functions indexed: {}", stats.functions_count);
    println!("Types indexed: {}", stats.types_count);

    // Check if optimization is needed
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

    // The whole tree has been read with this build, so a file still recorded
    // against an older extractor is content the tree no longer holds. Left in
    // place it keeps the index answering "older than this build" for ever, so
    // re-indexing never clears the refusal it is meant to clear.
    match db_manager.forget_older_processed_files().await {
        Ok(0) => {}
        Ok(forgotten) => info!("Forgot {forgotten} files read by an older extractor"),
        Err(e) => error!("Failed to forget files read by an older extractor: {e}"),
    }

    // The index now holds what this version writes, for the extensions it was
    // told to read. Recorded last: an interrupted run leaves the older version
    // in place and is re-read next time.
    db_manager.record_index_build(extensions, no_macros).await?;

    // The whole tree at this commit has been read, so record which commit it
    // was. Written last, after record_index_build, so an interrupted run
    // cannot claim coverage it did not finish.
    let tree_sha = gix::discover(repo_path)
        .ok()
        .and_then(|repo| {
            crate::git::resolve_to_commit(&repo, commit_sha)
                .ok()
                .map(|c| c.id().to_string())
        })
        .unwrap_or_else(|| commit_sha.to_string());
    if let Err(e) = db_manager.record_tree_sha(&tree_sha).await {
        tracing::warn!("Failed to record index:tree_sha {}: {}", tree_sha, e);
    }

    Ok(())
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

    // Step 1: Get already processed files from database for deduplication. As
    // in the tree path, a row written by an older extractor does not count as
    // processed: the file has not changed, the reading of it has.
    info!("Loading processed files from database for deduplication");
    let processed_files: HashSet<String> = db_manager.processed_by_this_extractor().await?;

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
            info!("All commits in range are already indexed!");
        }
    } else {
        info!("No commits found in range");
    }

    // Step 2: Determine number of workers
    // Since generators are I/O bound and workers are CPU bound, use a balanced approach
    let num_workers = (num_cpus::get()).max(1);
    info!(
        "Starting streaming pipeline with up to 32 generator threads and {} worker threads",
        num_workers
    );

    // Step 3: Process tuples using streaming pipeline with database inserters
    let processing_start = std::time::Instant::now();
    let config = StreamingConfig {
        repo_path: repo_path.clone(),
        git_range: git_range.to_string(),
        extensions: extensions.to_vec(),
        source_root: repo_path.clone(),
        no_macros,
        processed_files,
        num_workers,
        db_manager: db_manager.clone(),
        num_inserters: db_threads,
    };
    let stats = process_git_tuples_streaming(config).await?;

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

    info!("\n=== Git Range Pipeline Complete ===");
    info!("Total time: {:.1}s", total_time.as_secs_f64());
    info!("Commits indexed: {commit_count}");
    info!("Files processed: {}", stats.files_processed);
    info!("Functions indexed: {}", stats.functions_count);
    info!("Types indexed: {}", stats.types_count);

    // Check if optimization is needed after git range indexing
    match db_manager.check_optimization_health().await {
        Ok((needs_optimization, message)) => {
            if needs_optimization {
                info!("\n{}", message);
                match db_manager.optimize_database().await {
                    Ok(_) => info!("Database optimization completed successfully"),
                    Err(e) => error!("Failed to optimize database: {}", e),
                }
            } else {
                info!("\n{}", message);
            }
        }
        Err(e) => {
            error!("Failed to check database health: {}", e);
        }
    }

    // Do not write a database version. Part of the database was updated here,
    // but other parts could have been written by an older version of semcode.

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_batch() -> GitTupleResults {
        GitTupleResults {
            functions: vec![FunctionInfo {
                name: "marked_only_on_success".to_string(),
                file_path: "a.c".to_string(),
                git_file_hash: "abc123".to_string(),
                line_start: 1,
                line_end: 3,
                return_type: "int".to_string(),
                parameters: Vec::new(),
                body: "int marked_only_on_success(void) { return 0; }".to_string(),
                calls: None,
                types: None,
                guard: None,
                qualifier: None,
            }],
            types: vec![TypeInfo {
                name: "a_struct".to_string(),
                file_path: "a.c".to_string(),
                git_file_hash: "abc123".to_string(),
                line_start: 5,
                kind: "struct".to_string(),
                size: None,
                members: Vec::new(),
                definition: "struct a_struct { int x; };".to_string(),
                types: None,
            }],
            dispatch_sites: vec![DispatchSite {
                caller_name: "marked_only_on_success".to_string(),
                file_path: "a.c".to_string(),
                git_file_hash: "abc123".to_string(),
                byte_start: 10,
                line: 2,
                member: "read".to_string(),
                receiver_expr: Some("fop".to_string()),
                receiver_type: None,
                receiver_base_type: None,
                receiver_field: None,
                kind: crate::types::DispatchKind::MemberArrow,
                target: None,
            }],
            registrations: vec![Registration {
                container_type: "file_operations".to_string(),
                member: "read".to_string(),
                target: "marked_only_on_success".to_string(),
                file_path: "a.c".to_string(),
                git_file_hash: "abc123".to_string(),
                byte_start: 40,
                line: 8,
                enclosing_function: String::new(),
                kind: crate::types::RegistrationKind::DesignatedInit,
                container_base_type: None,
                container_field: None,
            }],
            argument_functions: vec![ArgumentFunction {
                target: "marked_only_on_success".to_string(),
                callee: "register".to_string(),
                argument_index: 0,
                taken_address: false,
                subject_type: None,
                subject_member: None,
                file_path: "a.c".to_string(),
                git_file_hash: "abc123".to_string(),
                byte_start: 60,
                line: 10,
                enclosing_function: "setup".to_string(),
            }],
            unresolved_edges: vec![crate::types::UnresolvedEdge {
                name: "marked_only_on_success".to_string(),
                direction: "out".to_string(),
                kind: "c:macro_parameter_call".to_string(),
                evidence: "CALLBACK".to_string(),
                locations: vec![crate::types::EdgeLocation {
                    role: "invocation".to_string(),
                    file_path: "a.c".to_string(),
                    line: 12,
                }],
                file_path: "a.c".to_string(),
                git_file_hash: "abc123".to_string(),
                line: 12,
            }],
            globals: vec![GlobalVariable {
                name: "a_global".to_string(),
                type_name: "a_struct".to_string(),
                file_path: "a.c".to_string(),
                git_file_hash: "abc123".to_string(),
                line: 4,
            }],
            processed_files: vec![ProcessedFileRecord {
                file: "a.c".to_string(),
                git_sha: None,
                git_file_sha: "abc123".to_string(),
                extractor_version: Some(crate::SCHEMA_VERSION),
            }],
            files_processed: 1,
        }
    }

    fn test_counters() -> (
        AtomicUsize,
        AtomicUsize,
        AtomicUsize,
        Arc<std::sync::Mutex<std::time::Instant>>,
    ) {
        (
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            Arc::new(std::sync::Mutex::new(std::time::Instant::now())),
        )
    }

    async fn test_db() -> (tempfile::TempDir, DatabaseManager) {
        let temp_dir = tempfile::tempdir().unwrap();
        let db = DatabaseManager::new(
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_string_lossy().into_owned(),
        )
        .await
        .unwrap();
        db.create_tables().await.unwrap();
        (temp_dir, db)
    }

    /// A batch whose facts did not all land must not mark its files: a
    /// marked file is never read again, so the mark used to run beside the
    /// fact inserts and a failed insert left a hole the next run skipped.
    /// Every fact table takes a turn being the broken one, so each table's
    /// result check is exercised and none can be dropped silently.
    #[tokio::test]
    async fn a_failed_fact_table_leaves_its_files_unmarked() {
        for table in [
            "functions",
            "types",
            "dispatch_sites",
            "registrations",
            "argument_functions",
            "unresolved_edges",
            "globals",
        ] {
            let (_dir, db) = test_db().await;
            db.connection().drop_table(table, &[]).await.unwrap();

            let (functions, types_count, batches, timer) = test_counters();
            insert_batch_and_mark(
                &db,
                test_batch(),
                0,
                &functions,
                &types_count,
                &batches,
                &timer,
            )
            .await;
            assert!(
                !db.is_file_processed("abc123").await.unwrap(),
                "{table} failing must leave the file unmarked"
            );
            assert_eq!(batches.load(Ordering::Relaxed), 0);

            db.create_tables().await.unwrap();
            insert_batch_and_mark(
                &db,
                test_batch(),
                0,
                &functions,
                &types_count,
                &batches,
                &timer,
            )
            .await;
            assert!(
                db.is_file_processed("abc123").await.unwrap(),
                "{table} healed must mark the file"
            );
            assert_eq!(batches.load(Ordering::Relaxed), 1);
        }
    }

    /// The retry a failed batch leaves behind merges onto the landed rows
    /// instead of doubling them.
    #[tokio::test]
    async fn a_retried_batch_merges_onto_its_rows() {
        let (_dir, db) = test_db().await;
        let (functions, types_count, batches, timer) = test_counters();
        for _ in 0..2 {
            insert_batch_and_mark(
                &db,
                test_batch(),
                0,
                &functions,
                &types_count,
                &batches,
                &timer,
            )
            .await;
        }
        let found = db.get_all_functions_metadata_only().await.unwrap();
        assert_eq!(found.len(), 1);
        let landed_types = db.get_all_types_metadata_only().await.unwrap();
        assert_eq!(landed_types.len(), 1);
    }
}
