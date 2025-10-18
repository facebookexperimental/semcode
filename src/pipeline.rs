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
use crossbeam_channel::{bounded, unbounded};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::System;
use tracing_indicatif::IndicatifLayer;
use tracing_subscriber::prelude::*;

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

/// Calculate optimal channel sizes based on available system memory
///
/// Returns (file_channel_size, parsed_channel_size, processed_channel_size)
fn calculate_channel_sizes(files_to_process: usize, num_threads: usize) -> (usize, usize, usize) {
    let mut sys = System::new_all();
    sys.refresh_memory();

    let available_bytes = sys.available_memory();
    let available_gb = available_bytes as f64 / 1_073_741_824.0;

    tracing::info!(
        "Available memory: {:.2} GB ({} bytes)",
        available_gb,
        available_bytes
    );

    // Estimate memory per ParsedFile:
    // - PathBuf: ~100 bytes
    // - FunctionInfo: ~500 bytes avg (name, signature, body hash, etc.)
    // - TypeInfo: ~300 bytes avg
    // - MacroInfo: ~400 bytes avg
    // - Assume avg file has 10 functions, 5 types, 3 macros
    // Total: ~100 + 10*500 + 5*300 + 3*400 = ~7,800 bytes per ParsedFile
    const BYTES_PER_PARSED_FILE: usize = 8_000;

    // Use up to 25% of available memory for queues (conservative)
    let max_queue_memory = (available_bytes as f64 * 0.25) as usize;
    let max_parsed_files_in_queue = max_queue_memory / BYTES_PER_PARSED_FILE;

    tracing::info!(
        "Memory budget for queues: {:.2} GB, max parsed files in queue: {}",
        max_queue_memory as f64 / 1_073_741_824.0,
        max_parsed_files_in_queue
    );

    // File channel: size = number of files to process
    // Memory is cheap (~200 bytes per file), and avoiding backpressure here
    // allows parsers to run at full speed without blocking
    // With multi-process enrichment, we want maximum throughput
    let file_channel_size = files_to_process.max(1000); // Minimum 1k for small codebases

    // Parsed channel: NO LIMITS with multi-process enrichment
    // Old single-threaded enrichment needed caps to prevent OOM (enrichment was 14x slower than parsing)
    // Now with N workers, enrichment is only ~1.7x slower than parsing
    // Memory is cheap: even 100k files = ~800MB (nothing on modern machines)
    // Removing caps eliminates backpressure and maximizes throughput
    let parsed_channel_size = files_to_process.max(num_threads * 10); // At least 10 per thread

    // Processed channel: batches are large, so keep queue small
    let processed_channel_size = 200;

    tracing::info!(
        "Calculated channel sizes: file={}, parsed={}, processed={}",
        file_channel_size,
        parsed_channel_size,
        processed_channel_size
    );

    (
        file_channel_size,
        parsed_channel_size,
        processed_channel_size,
    )
}

pub struct PipelineBuilder {
    db_manager: Arc<DatabaseManager>,
    source_root: PathBuf,

    // Optional path to compile_commands.json for clangd enrichment
    compile_commands_path: Option<PathBuf>,

    // Stats
    pub processed_files: Arc<AtomicUsize>,
    pub new_functions: Arc<AtomicUsize>,
    pub new_types: Arc<AtomicUsize>, // Now includes typedefs with kind="typedef"
    pub new_macros: Arc<AtomicUsize>,

    // Clangd enrichment stats
    pub files_with_compile_commands: Arc<AtomicUsize>, // Files that had compile commands
    pub enriched_functions: Arc<AtomicUsize>,          // Functions with USR from clangd
    pub enriched_types: Arc<AtomicUsize>,              // Types with USR from clangd
    pub enriched_macros: Arc<AtomicUsize>,             // Macros with USR from clangd
    pub macros_kept_by_clangd: Arc<AtomicUsize>,       // Non-function-like macros kept due to USR

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
            compile_commands_path: None,
            processed_files: Arc::new(AtomicUsize::new(0)),
            new_functions: Arc::new(AtomicUsize::new(0)),
            new_types: Arc::new(AtomicUsize::new(0)), // Now includes typedefs with kind="typedef"
            new_macros: Arc::new(AtomicUsize::new(0)),
            files_with_compile_commands: Arc::new(AtomicUsize::new(0)),
            enriched_functions: Arc::new(AtomicUsize::new(0)),
            enriched_types: Arc::new(AtomicUsize::new(0)),
            enriched_macros: Arc::new(AtomicUsize::new(0)),
            macros_kept_by_clangd: Arc::new(AtomicUsize::new(0)),
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
            compile_commands_path: None,
            processed_files: Arc::new(AtomicUsize::new(0)),
            new_functions: Arc::new(AtomicUsize::new(0)),
            new_types: Arc::new(AtomicUsize::new(0)),
            new_macros: Arc::new(AtomicUsize::new(0)),
            files_with_compile_commands: Arc::new(AtomicUsize::new(0)),
            enriched_functions: Arc::new(AtomicUsize::new(0)),
            enriched_types: Arc::new(AtomicUsize::new(0)),
            enriched_macros: Arc::new(AtomicUsize::new(0)),
            macros_kept_by_clangd: Arc::new(AtomicUsize::new(0)),
            newly_processed_files: Arc::new(Mutex::new(HashSet::new())),
            git_sha: Some(git_sha),
            force_reprocess: true,       // Always reprocess for git commit mode
            full_tree_incremental: true, // Use incremental processing with deduplication
        }
    }

    /// Set the compile_commands.json path for clangd enrichment
    pub fn with_clangd(mut self, compile_commands_path: PathBuf) -> Self {
        self.compile_commands_path = Some(compile_commands_path);
        self
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

        // Calculate optimal channel sizes based on available memory
        let (file_channel_size, parsed_channel_size, processed_channel_size) =
            calculate_channel_sizes(files_to_process.len(), num_threads);

        // Create channels with bounded capacity to prevent memory bloat
        let (file_tx, file_rx) = bounded::<(PathBuf, String)>(file_channel_size);
        let (parsed_tx, parsed_rx) = bounded::<ParsedFile>(parsed_channel_size);

        // Enrichment channel uses UNBOUNDED to ensure parsers never block on slow libclang
        // Memory usage is monitored in the enrichment thread loop
        let (enrichment_tx, enrichment_rx) = unbounded::<ParsedFile>();

        let (processed_tx, processed_rx) = bounded::<ProcessedBatch>(processed_channel_size);

        tracing::info!(
            "Pipeline configuration: {} threads, channel sizes: files={}, parsed={}, enrichment=unbounded, processed={}",
            num_threads,
            file_channel_size,
            parsed_channel_size,
            processed_channel_size
        );

        // Create multi-progress for pipeline stages with tracing integration
        let multi = MultiProgress::new();
        let total = files_to_process.len() as u64;

        // Set up tracing-indicatif layer to prevent log interference with progress bars
        let indicatif_layer = IndicatifLayer::new();
        tracing_subscriber::registry()
            .with(indicatif_layer)
            .try_init()
            .ok(); // Ignore error if already initialized

        let style = ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:30.cyan/blue} {pos:>7}/{len:7} {msg} (ETA: {eta})",
        )
        .unwrap()
        .progress_chars("##-");

        let pb_feed = multi.add(ProgressBar::new(total));
        pb_feed.set_style(style.clone());
        pb_feed.set_message("fed to pipeline");

        let pb_parse = multi.add(ProgressBar::new(total));
        pb_parse.set_style(style.clone());
        pb_parse.set_message("tree-sitter parsed");

        let pb_enrich = multi.add(ProgressBar::new(total));
        pb_enrich.set_style(style.clone());
        pb_enrich.set_message("clangd enriched");

        let pb_db = multi.add(ProgressBar::new(total));
        pb_db.set_style(style);
        pb_db.set_message("indexed to database");

        // Stage 1: File feeder (runs in main thread)
        let file_feeder = {
            let file_tx = file_tx.clone();
            let total_files = files_to_process.len();
            let pb = pb_feed.clone();
            thread::spawn(move || {
                tracing::info!("File feeder starting with {} files", total_files);
                let start = Instant::now();
                for (idx, (file_path, git_file_sha)) in files_to_process.into_iter().enumerate() {
                    tracing::debug!("File feeder sending file {}: {:?}", idx, file_path);
                    if file_tx.send((file_path, git_file_sha)).is_err() {
                        tracing::error!("File feeder: send failed at index {}", idx);
                        break;
                    }
                    tracing::debug!("File feeder sent file {}", idx);
                    pb.inc(1);

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
                pb.finish();
                drop(file_tx); // Signal completion
                tracing::info!("File feeder completed");
            })
        };

        // Stage 2: Parallel parsing (multiple threads)
        let git_files_shared = Arc::new(git_files);
        let parsing_threads: Vec<_> = (0..num_threads)
            .map(|thread_id| {
                let file_rx = file_rx.clone();
                let parsed_tx = parsed_tx.clone();
                let processed = self.processed_files.clone();
                let source_root = self.source_root.clone();
                let git_files_map = git_files_shared.clone();
                let pb = pb_parse.clone();

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
                                pb.inc(1);

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

        // Drop original receivers/senders to signal completion
        drop(file_rx);       // File feeding channel can close
        drop(parsed_tx);     // Parsing channel can close when all parsers finish

        // Stage 2.5: Multi-process enrichment coordinator
        // Extract compile_commands path if configured
        let compile_commands_path = self.compile_commands_path.clone();
        let source_root = self.source_root.clone();

        // Create ClangdProcessor with worker pool (or None if no compile_commands)
        // Also keep stats references for final sync
        let (processor, final_sync_stats) = if let Some(ref compile_commands_path) = compile_commands_path {
            tracing::info!("Creating ClangdProcessor with worker pool (num_cpus-2)");
            match crate::clangd_processor::ClangdProcessor::new_with_defaults(
                compile_commands_path.clone(),
                source_root.clone(),
            ) {
                Ok(processor) => {
                    // Copy statistics from processor to pipeline stats
                    // These will be updated by the processor's collector threads
                    let proc_stats_files = processor.files_with_compile_commands.clone();
                    let proc_stats_funcs = processor.enriched_functions.clone();
                    let proc_stats_types = processor.enriched_types.clone();
                    let proc_stats_macros = processor.enriched_macros.clone();
                    let proc_stats_kept = processor.macros_kept_by_clangd.clone();

                    // Link processor stats to pipeline stats
                    let pipe_stats_files = self.files_with_compile_commands.clone();
                    let pipe_stats_funcs = self.enriched_functions.clone();
                    let pipe_stats_types = self.enriched_types.clone();
                    let pipe_stats_macros = self.enriched_macros.clone();
                    let pipe_stats_kept = self.macros_kept_by_clangd.clone();

                    // Keep extra copies for final sync
                    let final_proc_stats_files = proc_stats_files.clone();
                    let final_proc_stats_funcs = proc_stats_funcs.clone();
                    let final_proc_stats_types = proc_stats_types.clone();
                    let final_proc_stats_macros = proc_stats_macros.clone();
                    let final_proc_stats_kept = proc_stats_kept.clone();
                    let final_pipe_stats_files = pipe_stats_files.clone();
                    let final_pipe_stats_funcs = pipe_stats_funcs.clone();
                    let final_pipe_stats_types = pipe_stats_types.clone();
                    let final_pipe_stats_macros = pipe_stats_macros.clone();
                    let final_pipe_stats_kept = pipe_stats_kept.clone();

                    // Spawn thread to periodically sync stats (every 2s to avoid perf overhead)
                    thread::spawn(move || {
                        loop {
                            std::thread::sleep(std::time::Duration::from_secs(2));
                            pipe_stats_files.store(
                                proc_stats_files.load(Ordering::Relaxed),
                                Ordering::Relaxed
                            );
                            pipe_stats_funcs.store(
                                proc_stats_funcs.load(Ordering::Relaxed),
                                Ordering::Relaxed
                            );
                            pipe_stats_types.store(
                                proc_stats_types.load(Ordering::Relaxed),
                                Ordering::Relaxed
                            );
                            pipe_stats_macros.store(
                                proc_stats_macros.load(Ordering::Relaxed),
                                Ordering::Relaxed
                            );
                            pipe_stats_kept.store(
                                proc_stats_kept.load(Ordering::Relaxed),
                                Ordering::Relaxed
                            );
                        }
                    });

                    tracing::info!("ClangdProcessor created successfully");
                    (
                        Some(processor),
                        Some((
                            (final_proc_stats_files, final_proc_stats_funcs, final_proc_stats_types, final_proc_stats_macros, final_proc_stats_kept),
                            (final_pipe_stats_files, final_pipe_stats_funcs, final_pipe_stats_types, final_pipe_stats_macros, final_pipe_stats_kept)
                        ))
                    )
                }
                Err(e) => {
                    eprintln!("Warning: Failed to create ClangdProcessor: {}", e);
                    (None, None)
                }
            }
        } else {
            tracing::info!("No compile_commands_path provided, skipping clangd enrichment");
            (None, None)
        };

        // Enrichment coordinator thread - simplified: collect all, spawn all workers, process all
        let enrichment_thread = {
            // MOVE parsed_rx (don't clone) so channel closes when parsing completes
            let enrichment_tx = enrichment_tx.clone();
            let pb = pb_enrich.clone();

            thread::Builder::new()
                .name("enrichment-coordinator".to_string())
                .spawn(move || {
                    tracing::debug!("Enrichment coordinator started - simplified mode");

                    if let Some(mut processor) = processor {
                        // Step 1: Collect all parsed files first
                        tracing::debug!("Collecting all parsed files...");
                        let mut all_parsed_files = Vec::new();
                        while let Ok(parsed) = parsed_rx.recv() {
                            all_parsed_files.push(parsed);
                        }
                        tracing::debug!("Collected {} files for enrichment", all_parsed_files.len());

                        if all_parsed_files.is_empty() {
                            tracing::debug!("No files to enrich");
                            return;
                        }

                        // Step 2: Spawn ALL workers at once
                        let num_workers = crate::clangd_processor::ClangdProcessor::default_worker_count();
                        tracing::debug!("Spawning {} workers", num_workers);

                        for worker_id in 0..num_workers {
                            if let Err(e) = processor.spawn_worker() {
                                tracing::error!("Failed to spawn worker {}: {}", worker_id, e);
                            }
                        }

                        // Step 3: Submit all work using round-robin distribution
                        tracing::info!("Submitting {} files to {} workers (round-robin)...", all_parsed_files.len(), num_workers);
                        let total_files = all_parsed_files.len();
                        for (idx, parsed) in all_parsed_files.into_iter().enumerate() {
                            // Round-robin: file 0→worker 0, file 1→worker 1, ..., file 30→worker 0
                            let worker_id = idx % num_workers;

                            if idx < 3 || idx % 1000 == 0 {
                                tracing::info!("Pipeline submitting file {} (assigned to worker {})", idx, worker_id);
                            }

                            let request = crate::clangd_processor::EnrichmentRequest {
                                path: parsed.path,
                                functions: parsed.functions,
                                types: parsed.types,
                                macros: parsed.macros,
                                git_file_sha: parsed.git_file_sha,
                                worker_id,
                            };

                            if let Err(e) = processor.submit_work(request) {
                                tracing::error!("Failed to submit work: {}", e);
                                break;
                            }
                        }
                        tracing::info!("All {} files submitted to processor", total_files);

                        // Step 3.5: Close work channel to signal workers
                        processor.finish_submitting();

                        // Step 4: Collect all results
                        tracing::debug!("Waiting for {} enriched files...", total_files);
                        for _ in 0..total_files {
                            match processor.recv_result() {
                                Ok(response) => {
                                    let enriched = ParsedFile {
                                        path: response.path,
                                        functions: response.functions,
                                        types: response.types,
                                        macros: response.macros,
                                        git_file_sha: response.git_file_sha,
                                    };

                                    if enrichment_tx.send(enriched).is_err() {
                                        tracing::error!("Failed to send enriched file");
                                        break;
                                    }
                                    pb.inc(1);
                                }
                                Err(e) => {
                                    tracing::error!("Failed to receive result: {}", e);
                                    break;
                                }
                            }
                        }

                        tracing::debug!("Enrichment complete");
                    } else {
                        // No processor: just pass through, but filter macros
                        tracing::debug!("No processor, using pass-through mode");
                        while let Ok(mut parsed) = parsed_rx.recv() {
                            parsed.macros.retain(|m| m.is_function_like);
                            if enrichment_tx.send(parsed).is_err() {
                                break;
                            }
                            pb.inc(1);
                        }
                    }

                    tracing::debug!("Enrichment coordinator finished");
                    drop(enrichment_tx);
                })
                .expect("Failed to spawn enrichment coordinator")
        };

        // parsed_rx was moved into enrichment thread, so it will be dropped when parsing completes

        // Drop the original enrichment_tx to allow the channel to close when enrichment thread completes
        drop(enrichment_tx);

        // Stage 3: Simple batching (no deduplication needed since git SHA pre-filtering ensures uniqueness)
        let batch_thread = {
            let enrichment_rx_for_batch = enrichment_rx.clone();
            let processed_tx = processed_tx.clone();
            let new_functions = self.new_functions.clone();
            let new_types = self.new_types.clone();
            let new_macros = self.new_macros.clone();

            thread::Builder::new()
                .name("batch-processor".to_string())
                .spawn(move || {
                    tracing::info!("Batch processor thread started");
                    let enrichment_rx = enrichment_rx_for_batch;
                    let start = Instant::now();
                    let mut total_processed = 0;

                    let mut batch = ProcessedBatch {
                        functions: Vec::new(),
                        types: Vec::new(),
                        macros: Vec::new(),
                        processed_files: Vec::new(),
                    };

                    // Calculate adaptive batch size based on workload
                    // Aim for ~10 batches per second with multi-process enrichment
                    let num_workers = crate::clangd_processor::ClangdProcessor::default_worker_count();
                    let estimated_files_per_sec = num_workers * 20; // Conservative estimate: 20 files/sec/worker
                    let target_batch_size = estimated_files_per_sec.max(2000).min(8000);
                    let mut batch_size = target_batch_size;
                    let mut last_batch_time = Instant::now();

                    tracing::info!("Batch processor ready, waiting for files...");
                    loop {
                        match enrichment_rx.recv() {
                            Ok(parsed) => {
                                total_processed += 1;
                                tracing::info!(
                                    "Batch processor received file {}: {:?}",
                                    total_processed,
                                    parsed.path
                                );

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

        // Drop the original enrichment_rx to allow the channel to close properly
        drop(enrichment_rx);

        // Stage 4: Database insertion (async in tokio runtime)
        let db_thread = {
            let processed_rx = processed_rx.clone();
            let db_manager = self.db_manager.clone();
            let pb = pb_db.clone();

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
                            let file_count = batch.processed_files.len();

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

                            // Update progress bar after successful database insertion
                            pb.inc(file_count as u64);

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

        // Drop the original processed_rx to allow the channel to close properly
        drop(processed_rx);

        // Drop original senders to signal pipeline start
        drop(file_tx);
        // parsed_tx already dropped after parsing threads spawned
        drop(processed_tx);

        // Wait for all stages to complete
        file_feeder.join().unwrap();

        for thread in parsing_threads.into_iter() {
            thread.join().unwrap();
        }

        enrichment_thread.join().unwrap();
        batch_thread.join().unwrap();
        db_thread.join().unwrap();

        // Finish all progress bars
        pb_feed.finish_with_message("complete");
        pb_parse.finish_with_message("complete");
        pb_enrich.finish_with_message("complete");
        pb_db.finish_with_message("complete");

        // Do final sync of clangd statistics before returning
        // This ensures stats are up-to-date even if periodic sync hasn't run yet
        if let Some(((proc_files, proc_funcs, proc_types, proc_macros, proc_kept),
                     (pipe_files, pipe_funcs, pipe_types, pipe_macros, pipe_kept))) = final_sync_stats {
            tracing::debug!("Performing final sync of clangd statistics");
            pipe_files.store(proc_files.load(Ordering::Relaxed), Ordering::Relaxed);
            pipe_funcs.store(proc_funcs.load(Ordering::Relaxed), Ordering::Relaxed);
            pipe_types.store(proc_types.load(Ordering::Relaxed), Ordering::Relaxed);
            pipe_macros.store(proc_macros.load(Ordering::Relaxed), Ordering::Relaxed);
            pipe_kept.store(proc_kept.load(Ordering::Relaxed), Ordering::Relaxed);
        }

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
