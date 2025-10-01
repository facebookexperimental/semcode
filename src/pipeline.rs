// SPDX-License-Identifier: MIT OR Apache-2.0
//
// ==============================================================================
//                           SEMCODE PROCESSING PIPELINE
// ==============================================================================
//
// This module implements a high-performance, multi-stage pipeline for processing
// C codebases. The pipeline is designed for optimal CPU utilization, minimal
// memory usage, and git SHA-based incremental processing.
//
// ## ARCHITECTURE OVERVIEW
//
// The pipeline consists of 4 distinct stages connected by bounded channels:
//
//   [Git Manifest] -> [File Feeder] -> [Parallel Parsers] -> [Batch Processor] -> [DB Inserter]
//         │                │                 │                      │                  │
//   Pre-processing   Single Thread     Multi-Thread          Single Thread      Multi-Threaded
//   (SHA filtering)   (Producer)       (CPU-bound)          (Batching)        (I/O-bound + N-core)
//
// ## STAGE BREAKDOWN
//
// ### Stage 0: Git Manifest & SHA Pre-filtering
// - **Purpose**: Load git manifest and filter against processed files in database
// - **Threading**: Async (part of main thread)
// - **Key Operations**:
//   1. Load git manifest of current commit (all files with their git file SHAs)
//   2. Load processed file lookup set from database (file_path, git_file_sha) pairs
//   3. Filter manifest against database - only files with new SHAs proceed to processing
// - **Key Insight**: Git file SHA uniquely identifies file content, so if (file_path, git_file_sha)
//   exists in database, that file version is already fully processed
//
// ### Stage 1: File Feeder
// - **Purpose**: Stream pre-filtered files into the pipeline at controlled rate
// - **Threading**: Single dedicated thread
// - **Channel**: `file_tx` -> `file_rx` (bounded: ~filtered_files.len()/10, max 10k)
// - **Input**: Vector of (file_path, git_file_sha) pairs that need processing
// - **Behavior**:
//   - Streams only files that passed SHA pre-filtering
//   - Progress logging every 1000 files
//   - Closes channel when complete to signal downstream completion
//
// ### Stage 2: Parallel Parsing (TreeSitter)
// - **Purpose**: Parse C files using TreeSitter for AST analysis
// - **Threading**: Multi-threaded (num_cpus threads, 8MB stack each)
// - **Channel**: `parsed_tx` -> `parsed_rx` (bounded: num_threads * 50)
// - **Key Features**:
//   - Each thread maintains its own TreeSitter analyzer instance (thread-local)
//   - Extracts functions, types, macros with embedded JSON relationships
//   - Handles both regular files and git commit mode (reads from temp files)
//   - TreeSitter provides intra-file deduplication automatically
//   - Git file SHA passed through for database storage
// - **Output**: ParsedFile structs with all extracted code elements
//
// ### Stage 3: Batching
// - **Purpose**: Accumulate parsed data into efficient batches for database insertion
// - **Threading**: Single thread (lightweight batching logic)
// - **Channel**: `processed_tx` -> `processed_rx` (bounded: 100)
// - **Batching Logic**:
//   - Adaptive batch sizing (2000-8000 items, adjusts based on processing speed)
//   - Time-based flushing (every 2 seconds maximum)
//   - No deduplication needed (git SHA pre-filtering ensures uniqueness)
//   - Creates ProcessedFileRecord entries for database tracking
// - **Performance Tuning**: Batch size adapts to maintain optimal throughput
//
// ### Stage 4: Database Insertion
// - **Purpose**: Asynchronously insert batched data into LanceDB
// - **Threading**: Single thread with multi-threaded Tokio runtime (num_cpus workers)
// - **Parallel Operations**: Uses tokio::join! for concurrent insertion:
//   1. Mark files as processed (processed_files table)
//   2. Combined insertion of functions, types, macros with shared content deduplication
// - **Error Handling**: Logs errors but continues processing other batches
// - **Monitoring**: Warns about slow batches (>1s) for performance tuning
//
// ## CHANNEL FLOW & BACKPRESSURE
//
// The pipeline uses bounded channels to prevent memory bloat and provide backpressure:
//
// ```
// GitManifest -> FileFeeder --[file_channel]-> ParsingThreads --[parsed_channel]->
//                                                                                   |
// DatabaseInserter <--[processed_channel]-- BatchProcessor <--------------------/
// ```
//
// Channel sizes are dynamically calculated based on workload:
// - File channel: (filtered_files.len().min(10000) / 10).max(100)
// - Parsed channel: num_threads * 50 (keeps all parser threads busy)
// - Processed channel: 100 (sufficient buffering for database thread)
//
// ## KEY DESIGN PRINCIPLES
//
// 1. **Git SHA-based Incremental Processing**: Each file version is uniquely identified
//    by (file_path, git_file_sha). If this pair exists in database, file is already processed.
//
// 2. **Upfront Filtering**: Load git manifest and database state once, then filter
//    completely before any parsing begins. This eliminates need for complex downstream logic.
//
// 3. **Embedded Relationships**: Functions, types, and macros store their call/type
//    relationships as embedded JSON arrays rather than separate mapping tables.
//
// 4. **Content Deduplication**: Uses Blake3 content hashing in database layer to
//    deduplicate function bodies and other content across files efficiently.
//
// 5. **No Runtime Deduplication**: Pipeline focuses on throughput - all deduplication
//    is handled either upfront (git SHA) or in database layer (content hashing).
//
// ## MEMORY & PERFORMANCE OPTIMIZATIONS
//
// 1. **Git Manifest Pre-loading**: Builds complete git file manifest to avoid repeated
//    git operations and lock contention during multi-threaded processing
// 2. **Streaming Database Lookup**: Uses optimized database query to load only needed
//    columns (file_path, git_file_sha) for memory-efficient filtering
// 3. **Thread-local Parsers**: Each parsing thread reuses its TreeSitter analyzer
//    instance to avoid repeated initialization overhead
// 4. **Adaptive Batching**: Batch processor adjusts batch sizes based on database
//    insertion speed to maintain optimal throughput
// 5. **Parallel Database Operations**: Uses tokio::join! to insert different data
//    types concurrently, maximizing database throughput
// 6. **Stack Tuning**: 8MB stacks for parser threads to handle deeply nested ASTs
//    without stack overflow
//
// ## SUPPORTED MODES
//
// 1. **Regular Mode**: Process working directory files, filter against existing database
// 2. **Git Commit Mode**: Process specific commit using temporary files, supports
//    indexing historical commits or branches
// 3. **Force Reprocess Mode**: Skip some filtering for incremental rebuilds
// 4. **Full Tree Incremental**: Process all relationships with database-level deduplication
//
// ## ERROR HANDLING & RESILIENCE
//
// - File reading errors: Logged and skipped, pipeline continues with other files
// - Parse errors: Logged and skipped, TreeSitter is fault-tolerant
// - Database errors: Logged but batch processing continues for other data
// - Channel disconnections: Trigger graceful shutdown cascade through all stages
// - Slow operations: Logged with timing for performance monitoring and tuning
// - Final batch guarantees: Always processes remaining data even on early termination
//
// ## MONITORING & OBSERVABILITY
//
// Comprehensive logging and metrics throughout the pipeline:
// - **Pre-filtering**: Files skipped vs. files requiring processing
// - **Progress tracking**: Files/second rates for each stage with periodic updates
// - **Performance warnings**: Operations taking >1s (parsing, database batches)
// - **Adaptive tuning**: Batch size adjustments logged for optimization visibility
// - **Completion statistics**: Final timing summaries and throughput metrics
// - **Thread monitoring**: Per-thread completion statistics and performance rates
//
// ==============================================================================
use anyhow::Result;
use crossbeam_channel::bounded;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use crate::{
    git, measure, types::GitFileEntry, DatabaseManager, FunctionInfo, MacroInfo,
    TreeSitterAnalyzer, TypeInfo,
};

#[derive(Debug)]
struct ParsedFile {
    path: PathBuf,
    functions: Vec<FunctionInfo>,
    types: Vec<TypeInfo>,
    macros: Vec<MacroInfo>,
    git_file_sha: String, // Git file hash for tracking (hex string)
}

#[derive(Debug)]
struct ProcessedBatch {
    functions: Vec<FunctionInfo>,
    types: Vec<TypeInfo>, // Now includes typedefs with kind="typedef"
    macros: Vec<MacroInfo>,
    processed_files: Vec<crate::database::processed_files::ProcessedFileRecord>, // Files to mark as processed
}

pub struct PipelineBuilder {
    db_manager: Arc<DatabaseManager>,
    source_root: PathBuf,

    // Stats
    pub processed_files: Arc<AtomicUsize>,
    pub new_functions: Arc<AtomicUsize>,
    pub new_types: Arc<AtomicUsize>, // Now includes typedefs with kind="typedef"
    pub new_macros: Arc<AtomicUsize>,

    // Tracking for incremental processing
    pub newly_processed_files: Arc<Mutex<HashSet<String>>>, // git_sha:filename pairs
    pub git_sha: Option<String>,                            // Current git SHA for the source root

    // Force reprocessing mode for incremental scans
    pub force_reprocess: bool,

    // Full-tree incremental mode: scan all relationships, deduplicate at DB level
    pub full_tree_incremental: bool,
}

impl PipelineBuilder {
    pub fn new(db_manager: Arc<DatabaseManager>, source_root: PathBuf) -> Self {
        Self::new_with_mode(db_manager, source_root, false, false)
    }

    pub fn new_for_git_commit(
        db_manager: Arc<DatabaseManager>,
        source_root: PathBuf,
        git_sha: String,
    ) -> Self {
        Self::new_with_git_commit(db_manager, source_root, git_sha)
    }

    fn new_with_mode(
        db_manager: Arc<DatabaseManager>,
        source_root: PathBuf,
        force_reprocess: bool,
        full_tree_incremental: bool,
    ) -> Self {
        // Get current git SHA for the source root
        let git_sha = git::get_git_sha_for_workdir(&source_root).unwrap_or_else(|e| {
            tracing::warn!("Failed to get git SHA for {}: {}", source_root.display(), e);
            None
        });

        if let Some(ref sha) = git_sha {
            tracing::info!("Git SHA for source root: {}", sha);
        } else {
            tracing::info!("Source root is not in a git repository or has no commits");
        }

        if force_reprocess {
            if full_tree_incremental {
                tracing::info!("Pipeline configured for full-tree incremental scan (all relationships, DB-level deduplication)");
            } else {
                tracing::info!(
                    "Pipeline configured for commit-based incremental scan (force reprocess mode)"
                );
            }
        }

        Self {
            db_manager,
            source_root,
            processed_files: Arc::new(AtomicUsize::new(0)),
            new_functions: Arc::new(AtomicUsize::new(0)),
            new_types: Arc::new(AtomicUsize::new(0)), // Now includes typedefs with kind="typedef"
            new_macros: Arc::new(AtomicUsize::new(0)),
            newly_processed_files: Arc::new(Mutex::new(HashSet::new())),
            git_sha,
            force_reprocess,
            full_tree_incremental,
        }
    }

    fn new_with_git_commit(
        db_manager: Arc<DatabaseManager>,
        source_root: PathBuf,
        git_sha: String,
    ) -> Self {
        tracing::info!("Pipeline configured for git commit indexing mode");
        tracing::info!("Git SHA for commit indexing: {}", git_sha);

        Self {
            db_manager,
            source_root,
            processed_files: Arc::new(AtomicUsize::new(0)),
            new_functions: Arc::new(AtomicUsize::new(0)),
            new_types: Arc::new(AtomicUsize::new(0)),
            new_macros: Arc::new(AtomicUsize::new(0)),
            newly_processed_files: Arc::new(Mutex::new(HashSet::new())),
            git_sha: Some(git_sha),
            force_reprocess: true,       // Always reprocess for git commit mode
            full_tree_incremental: true, // Use incremental processing with deduplication
        }
    }

    pub async fn build_and_run(self, files: Vec<PathBuf>) -> Result<()> {
        self.build_and_run_with_git_files(files, None).await
    }

    pub async fn build_and_run_with_git_files(
        self,
        _files: Vec<PathBuf>,
        git_files: Option<std::collections::HashMap<PathBuf, GitFileEntry>>,
    ) -> Result<()> {
        let num_threads = num_cpus::get();
        tracing::info!("=== PIPELINE START: {} threads available ===", num_threads);

        // Step 1: Load git manifest of current commit (lightweight)
        tracing::info!("Loading git manifest for current commit...");
        let git_manifest = self.load_git_manifest().await?;
        tracing::info!("Loaded git manifest with {} files", git_manifest.len());

        // Step 2: Load processed file SHAs from database
        tracing::info!("Loading processed file SHAs from database...");
        let processed_files_set = self.load_processed_files_set().await?;
        tracing::info!(
            "Loaded {} processed file SHAs from database",
            processed_files_set.len()
        );

        // Step 3: Filter files - only process files with SHAs not in database
        tracing::info!("Filtering files against database SHAs...");
        let files_to_process =
            self.filter_files_by_manifest(&git_manifest, &processed_files_set)?;
        tracing::info!(
            "After filtering: {} files need processing",
            files_to_process.len()
        );

        // Early exit if no files to process
        if files_to_process.is_empty() {
            tracing::info!("No files to process - all files already in database");
            println!("All files are already processed - no work needed");
            return Ok(());
        }

        // Build git manifest at startup to avoid lock contention during threaded processing
        tracing::info!("Building git file manifest to avoid lock contention...");
        if let Err(e) = crate::git::build_git_manifest(&self.source_root) {
            tracing::warn!("Failed to build git manifest: {}", e);
        } else {
            tracing::info!("Git manifest built successfully");
        }

        // Dynamic channel sizes based on number of filtered files and available memory
        let file_channel_size = (files_to_process.len().min(10000) / 10).max(100);
        let parsed_channel_size = num_threads * 50; // Allow backpressure but keep threads busy
        let processed_channel_size = 100; // Larger buffer to prevent backpressure from DB thread

        // Create channels with bounded capacity to prevent memory bloat
        let (file_tx, file_rx) = bounded::<(PathBuf, String)>(file_channel_size);
        let (parsed_tx, parsed_rx) = bounded::<ParsedFile>(parsed_channel_size);
        let (processed_tx, processed_rx) = bounded::<ProcessedBatch>(processed_channel_size);

        tracing::info!(
            "Pipeline configuration: {} threads, channel sizes: files={}, parsed={}, processed={}",
            num_threads,
            file_channel_size,
            parsed_channel_size,
            processed_channel_size
        );

        // Create progress bar
        let pb = ProgressBar::new(files_to_process.len() as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} files {msg}"
            ).unwrap()
            .progress_chars("##-")
        );
        pb.set_message("Processing files...");

        // Stage 1: File feeder (runs in main thread)
        let file_feeder = {
            let file_tx = file_tx.clone();
            let total_files = files_to_process.len();
            thread::spawn(move || {
                let start = Instant::now();
                for (idx, (file_path, git_file_sha)) in files_to_process.into_iter().enumerate() {
                    if file_tx.send((file_path, git_file_sha)).is_err() {
                        break;
                    }

                    // Log progress periodically
                    if idx % 1000 == 0 && idx > 0 {
                        let elapsed = start.elapsed().as_secs_f64();
                        let rate = idx as f64 / elapsed;
                        tracing::debug!(
                            "File feeder: {}/{} files queued ({:.1} files/sec)",
                            idx,
                            total_files,
                            rate
                        );
                    }
                }
                drop(file_tx); // Signal completion
                tracing::info!("File feeder completed");
            })
        };

        // Stage 2: Parallel parsing (multiple threads)
        let git_files_shared = Arc::new(git_files);
        let pb_shared = Arc::new(pb);
        let parsing_threads: Vec<_> = (0..num_threads)
            .map(|thread_id| {
                let file_rx = file_rx.clone();
                let parsed_tx = parsed_tx.clone();
                let processed = self.processed_files.clone();
                let source_root = self.source_root.clone();
                let git_files_map = git_files_shared.clone();
                let pb_clone = pb_shared.clone();

                thread::Builder::new()
                    .name(format!("parser-{thread_id}"))
                    .stack_size(8 * 1024 * 1024) // 8MB stack for complex ASTs
                    .spawn(move || {
                        let thread_start = Instant::now();
                        let mut files_parsed = 0;

                        // Create one TreeSitter analyzer per thread and reuse it
                        let mut ts_analyzer = match TreeSitterAnalyzer::new() {
                            Ok(analyzer) => analyzer,
                            Err(e) => {
                                tracing::error!(
                                    "Failed to create TreeSitter analyzer for thread {}: {}",
                                    thread_id,
                                    e
                                );
                                return;
                            }
                        };

                        while let Ok((file_path, git_file_sha)) = file_rx.recv() {
                            let parse_start = Instant::now();

                            // Always use TreeSitter analyzer (reuse the thread-local analyzer)
                            // TreeSitter now handles intra-file deduplication automatically
                            let result = measure!("treesitter_parse", {
                                if let Some(ref git_files_hash_map) = git_files_map.as_ref() {
                                    // Git commit mode: read from temp file
                                    if let Some(git_file_entry) = git_files_hash_map.get(&file_path)
                                    {
                                        match std::fs::read_to_string(
                                            &git_file_entry.temp_file_path,
                                        ) {
                                            Ok(source_code) => {
                                                let git_hash = &git_file_entry.blob_id;
                                                ts_analyzer.analyze_source_with_metadata(
                                                    &source_code,
                                                    &file_path,
                                                    git_hash,
                                                    Some(&source_root),
                                                )
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    "Failed to read git temp file {}: {}",
                                                    git_file_entry.temp_file_path.display(),
                                                    e
                                                );
                                                // Return empty result to skip this file
                                                Ok((Vec::new(), Vec::new(), Vec::new()))
                                            }
                                        }
                                    } else {
                                        tracing::warn!(
                                            "Git file not found in pre-loaded content: {}",
                                            file_path.display()
                                        );
                                        // Fallback to regular file reading with git SHA
                                        let git_hash_hex = git_file_sha.clone();
                                        match std::fs::read_to_string(&file_path) {
                                            Ok(source_code) => ts_analyzer
                                                .analyze_source_with_metadata(
                                                    &source_code,
                                                    &file_path,
                                                    &git_hash_hex,
                                                    Some(&source_root),
                                                ),
                                            Err(e) => {
                                                tracing::warn!(
                                                    "Failed to read file {}: {}",
                                                    file_path.display(),
                                                    e
                                                );
                                                Ok((Vec::new(), Vec::new(), Vec::new()))
                                            }
                                        }
                                    }
                                } else {
                                    // Regular mode: read from working directory with git SHA
                                    let git_hash_hex = git_file_sha.clone();
                                    match std::fs::read_to_string(&file_path) {
                                        Ok(source_code) => ts_analyzer
                                            .analyze_source_with_metadata(
                                                &source_code,
                                                &file_path,
                                                &git_hash_hex,
                                                Some(&source_root),
                                            ),
                                        Err(e) => {
                                            tracing::warn!(
                                                "Failed to read file {}: {}",
                                                file_path.display(),
                                                e
                                            );
                                            Ok((Vec::new(), Vec::new(), Vec::new()))
                                        }
                                    }
                                }
                            });

                            if let Ok((functions, types, macros)) = result {
                                let parsed = ParsedFile {
                                    path: file_path.clone(),
                                    functions,
                                    types,
                                    macros,
                                    git_file_sha,
                                };

                                if parsed_tx.send(parsed).is_err() {
                                    break;
                                }

                                processed.fetch_add(1, Ordering::Relaxed);
                                files_parsed += 1;
                                pb_clone.inc(1);

                                // Log slow parses
                                let parse_time = parse_start.elapsed();
                                if parse_time > Duration::from_secs(1) {
                                    tracing::warn!(
                                        "Slow parse: {} took {:.1}s",
                                        file_path.display(),
                                        parse_time.as_secs_f64()
                                    );
                                }
                            } else {
                                tracing::warn!("Failed to parse: {}", file_path.display());
                            }
                        }

                        let elapsed = thread_start.elapsed().as_secs_f64();
                        let rate = files_parsed as f64 / elapsed;
                        tracing::info!(
                            "Parser thread {} completed: {} files in {:.1}s ({:.1} files/sec)",
                            thread_id,
                            files_parsed,
                            elapsed,
                            rate
                        );

                        drop(parsed_tx); // Signal completion
                    })
                    .expect("Failed to spawn parser thread")
            })
            .collect();

        // Stage 3: Simple batching (no deduplication needed since git SHA pre-filtering ensures uniqueness)
        let batch_thread = {
            let parsed_rx = parsed_rx.clone();
            let processed_tx = processed_tx.clone();
            let new_functions = self.new_functions.clone();
            let new_types = self.new_types.clone();
            let new_macros = self.new_macros.clone();

            thread::Builder::new()
                .name("batch-processor".to_string())
                .spawn(move || {
                    let start = Instant::now();
                    let mut total_processed = 0;

                    let mut batch = ProcessedBatch {
                        functions: Vec::new(),
                        types: Vec::new(),
                        macros: Vec::new(),
                        processed_files: Vec::new(),
                    };

                    let mut batch_size = 2000;
                    let mut last_batch_time = Instant::now();

                    loop {
                        match parsed_rx.recv() {
                            Ok(parsed) => {
                                total_processed += 1;

                                // Count items before adding to batch
                                let func_count = parsed.functions.len();
                                let type_count = parsed.types.len();
                                let macro_count = parsed.macros.len();

                                // Add all parsed data directly (no deduplication needed)
                                batch.functions.extend(parsed.functions);
                                batch.types.extend(parsed.types);
                                batch.macros.extend(parsed.macros);

                                // Create processed file record
                                let file_path_str = {
                                    let raw_path = parsed.path.to_string_lossy().to_string();
                                    if raw_path.starts_with("./") {
                                        raw_path.strip_prefix("./").unwrap().to_string()
                                    } else {
                                        raw_path
                                    }
                                };

                                batch.processed_files.push(
                                    crate::database::processed_files::ProcessedFileRecord {
                                        file: file_path_str,
                                        git_sha: None, // TODO: Add git SHA if needed
                                        git_file_sha: parsed.git_file_sha,
                                    },
                                );

                                // Update counters with items just added
                                new_functions.fetch_add(func_count, Ordering::Relaxed);
                                new_types.fetch_add(type_count, Ordering::Relaxed);
                                new_macros.fetch_add(macro_count, Ordering::Relaxed);

                                // Check if batch is ready to send
                                let batch_has_content = !batch.functions.is_empty()
                                    || !batch.types.is_empty()
                                    || !batch.macros.is_empty();

                                let should_send = batch_has_content
                                    && (batch.functions.len() >= batch_size
                                        || batch.types.len() >= batch_size
                                        || last_batch_time.elapsed() > Duration::from_secs(2));

                                if should_send {
                                    // Adaptive batch sizing
                                    let batch_time = last_batch_time.elapsed();
                                    if batch_time < Duration::from_millis(300) && batch_size < 8000
                                    {
                                        batch_size = (batch_size * 2).min(8000);
                                    } else if batch_time > Duration::from_secs(3)
                                        && batch_size > 500
                                    {
                                        batch_size = (batch_size * 3 / 4).max(500);
                                    }

                                    let batch_to_send = std::mem::replace(
                                        &mut batch,
                                        ProcessedBatch {
                                            functions: Vec::new(),
                                            types: Vec::new(),
                                            macros: Vec::new(),
                                            processed_files: Vec::new(),
                                        },
                                    );

                                    if processed_tx.send(batch_to_send).is_err() {
                                        break;
                                    }

                                    last_batch_time = Instant::now();
                                }

                                if total_processed % 1000 == 0 {
                                    let elapsed = start.elapsed().as_secs_f64();
                                    let rate = total_processed as f64 / elapsed;
                                    tracing::debug!(
                                        "Batch processor: {} files processed ({:.1} files/sec)",
                                        total_processed,
                                        rate
                                    );
                                }
                            }
                            Err(_) => {
                                // Send final batch and exit
                                let has_content = !batch.functions.is_empty()
                                    || !batch.types.is_empty()
                                    || !batch.macros.is_empty();

                                if has_content {
                                    let _ = processed_tx.send(batch);
                                }
                                break;
                            }
                        }
                    }

                    let elapsed = start.elapsed().as_secs_f64();
                    tracing::info!(
                        "Batch processor completed: {} files in {:.1}s ({:.1} files/sec)",
                        total_processed,
                        elapsed,
                        total_processed as f64 / elapsed
                    );

                    drop(processed_tx);
                })
                .expect("Failed to spawn batch processor thread")
        };

        // Stage 4: Database insertion (async in tokio runtime)
        let db_thread = {
            let processed_rx = processed_rx.clone();
            let db_manager = self.db_manager.clone();

            thread::Builder::new()
                .name("db-inserter".to_string())
                .spawn(move || {
                    let runtime = tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(num_cpus::get()) // Use all available CPU cores
                        .thread_name("db-worker")
                        .enable_all()
                        .build()
                        .expect("Failed to create tokio runtime");

                    runtime.block_on(async move {
                        let start = Instant::now();
                        let mut batches_processed = 0;
                        let mut total_functions = 0;
                        let mut total_types = 0;
                        let mut total_macros = 0;

                        while let Ok(batch) = processed_rx.recv() {
                            let batch_start = Instant::now();
                            let func_count = batch.functions.len();
                            let type_count = batch.types.len();
                            let macro_count = batch.macros.len();

                            // Insert processed files and all data in parallel using combined content insertion
                            let (file_result, combined_result) = measure!("database_batch_insert", {
                                tokio::join!(
                                    async {
                                        if !batch.processed_files.is_empty() {
                                            measure!("db_mark_files_processed", {
                                                db_manager.mark_files_processed(batch.processed_files).await
                                            })
                                        } else {
                                            Ok::<(), anyhow::Error>(())
                                        }
                                    },
                                    async {
                                        measure!("db_insert_combined", {
                                            db_manager.insert_batch_combined(
                                                batch.functions,
                                                batch.types,
                                                batch.macros
                                            ).await
                                        })
                                    }
                                )
                            });

                            // Log any errors but continue processing
                            if let Err(e) = file_result {
                                tracing::error!("Failed to mark files as processed: {}", e);
                            }
                            if let Err(e) = combined_result {
                                tracing::error!("Failed to insert combined data (functions/types/macros): {}", e);
                            }

                            batches_processed += 1;
                            total_functions += func_count;
                            total_types += type_count;
                            total_macros += macro_count;

                            let batch_time = batch_start.elapsed();
                            if batch_time > Duration::from_secs(1) {
                                tracing::warn!("Slow DB batch (combined content+metadata): {} functions, {} types, {} macros took {:.1}s",
                                             func_count, type_count, macro_count, batch_time.as_secs_f64());
                            }
                        }

                        let elapsed = start.elapsed().as_secs_f64();
                        tracing::info!("DB inserter completed: {} batches, {} functions, {} types, {} macros in {:.1}s",
                                      batches_processed, total_functions, total_types, total_macros, elapsed);
                    })
                })
                .expect("Failed to spawn db thread")
        };

        // Drop original senders to signal pipeline start
        drop(file_tx);
        drop(parsed_tx);
        drop(processed_tx);

        // Wait for all stages to complete
        file_feeder.join().unwrap();

        for thread in parsing_threads.into_iter() {
            thread.join().unwrap();
        }

        batch_thread.join().unwrap();
        db_thread.join().unwrap();

        // Finish progress bar
        pb_shared.finish_with_message("Processing complete");

        tracing::info!("Pipeline processing complete (no additional resolution needed with git SHA pre-filtering)");

        Ok::<(), anyhow::Error>(())
    }

    /// Pre-load all processed files for fast in-memory lookup (optimized streaming version)
    async fn load_processed_files_set(&self) -> Result<Arc<HashSet<(String, String)>>> {
        // Use optimized method that only loads needed columns and streams the results
        // This prevents memory issues with large repositories
        let lookup_set = self.db_manager.get_processed_file_pairs().await?;

        Ok(Arc::new(lookup_set))
    }

    /// Load git manifest of current commit - returns (file_path, git_file_sha) for all files
    async fn load_git_manifest(&self) -> Result<std::collections::HashMap<PathBuf, String>> {
        // Get current commit SHA
        let repo = gix::discover(&self.source_root)
            .map_err(|e| anyhow::anyhow!("Not in a git repository: {}", e))?;

        let commit = repo
            .head_commit()
            .map_err(|e| anyhow::anyhow!("Failed to get HEAD commit: {}", e))?;

        let tree = commit
            .tree()
            .map_err(|e| anyhow::anyhow!("Failed to get tree for HEAD commit: {}", e))?;

        let mut manifest = std::collections::HashMap::new();

        // Walk the entire git tree
        use gix::traverse::tree::Recorder;
        let mut recorder = Recorder::default();
        tree.traverse().breadthfirst(&mut recorder)?;

        for entry in recorder.records {
            if entry.mode.is_blob() {
                let relative_path = entry.filepath.to_string();
                let path_buf = PathBuf::from(relative_path);
                let git_file_sha = hex::encode(entry.oid.as_bytes());

                manifest.insert(path_buf, git_file_sha);
            }
        }

        Ok(manifest)
    }

    /// Filter manifest files against database - return files that need processing
    fn filter_files_by_manifest(
        &self,
        git_manifest: &std::collections::HashMap<PathBuf, String>,
        processed_files_set: &HashSet<(String, String)>,
    ) -> Result<Vec<(PathBuf, String)>> {
        let mut files_to_process = Vec::new();
        let mut skipped_count = 0;

        for (file_path, git_file_sha) in git_manifest {
            // Normalize path for lookup (same as database storage)
            let file_path_str = {
                let raw_path = file_path.to_string_lossy().to_string();
                if raw_path.starts_with("./") {
                    raw_path.strip_prefix("./").unwrap().to_string()
                } else {
                    raw_path
                }
            };

            let lookup_key = (file_path_str, git_file_sha.clone());

            if processed_files_set.contains(&lookup_key) {
                skipped_count += 1;
            } else {
                files_to_process.push((file_path.clone(), git_file_sha.clone()));
            }
        }

        tracing::info!(
            "Manifest filtering: {} files to process, {} already in database",
            files_to_process.len(),
            skipped_count
        );

        Ok(files_to_process)
    }
}
