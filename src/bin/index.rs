// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use semcode::git::resolve_to_commit;
use semcode::{
    measure, process_database_path, CodeVectorizer, DatabaseManager, GitFileEntry,
    GitFileManifestEntry, TreeSitterAnalyzer,
};
use semcode::{FunctionInfo, MacroInfo, TypeInfo};
// Temporary call relationships are now embedded in function JSON columns
use dashmap::DashSet;
use gix::revision::walk::Sorting;
use semcode::perf_monitor::PERF_STATS;
use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use tracing::{error, info, warn};
use walkdir::WalkDir;

// Import pipeline
use semcode::pipeline::PipelineBuilder;

#[derive(Parser, Debug)]
#[command(name = "semcode-index")]
#[command(about = "Index a codebase for semantic analysis", long_about = None)]
struct Args {
    /// Path to the codebase directory
    #[arg(short, long)]
    source: PathBuf,

    /// Path to database directory or parent directory containing .semcode.db (default: search source dir, then current dir)
    #[arg(short, long)]
    database: Option<String>,

    /// File extensions to process (can be specified multiple times)
    #[arg(short, long, value_delimiter = ',', default_value = "c,h")]
    extensions: Vec<String>,

    /// Include directories (can be specified multiple times)
    #[arg(short, long)]
    include: Vec<PathBuf>,

    /// Maximum depth for directory traversal
    #[arg(long, default_value = "10")]
    max_depth: usize,

    /// Skip source indexing and only generate vectors for existing database content (requires model files)
    #[arg(long)]
    vectors: bool,

    /// Use GPU for vectorization (if available)
    #[arg(long)]
    gpu: bool,

    /// Path to local model directory (for vector generation)
    #[arg(long, value_name = "PATH")]
    model_path: Option<String>,

    /// Number of files to process in a batch
    #[arg(short, long, default_value = "200")]
    batch_size: usize,

    /// Parallelism configuration (analysis_threads[:batch_size])
    /// Example: -j 16:512 means 16 analysis threads, batch size 512 for vectorization
    #[arg(short = 'j', long = "jobs", value_name = "THREADS[:BATCH]")]
    jobs: Option<String>,

    /// Clear existing data before indexing
    #[arg(long)]
    clear: bool,

    /// Skip typedef declarations (enabled by default)
    #[arg(long)]
    no_typedefs: bool,

    /// Skip function-like macros (enabled by default)
    #[arg(long)]
    no_macros: bool,

    /// Skip extracting comments before definitions (enabled by default)
    #[arg(long)]
    no_extra_comments: bool,

    /// Drop and recreate tables after indexing for maximum space savings
    #[arg(long)]
    drop_recreate: bool,

    /// Enable performance monitoring and display timing statistics
    #[arg(long)]
    perf: bool,

    /// Index files modified in git commit range without checking them out.
    /// Accepts range format only (SHA1..SHA2). Reads files directly from git blobs.
    /// Uses incremental processing and deduplication with parallel streaming pipeline.
    #[arg(long, value_name = "GIT_RANGE")]
    git: Option<String>,

    /// Index only git commit metadata for the specified revision range.
    /// Accepts range format only (SHA1..SHA2), parsed the same way as --git.
    /// Populates only the commits table without indexing any source files.
    #[arg(long, value_name = "COMMIT_RANGE")]
    commits: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Suppress ORT verbose logging
    std::env::set_var("ORT_LOG_LEVEL", "ERROR");

    let args = Args::parse();

    // Enable performance monitoring if --perf flag is set
    if args.perf {
        semcode::perf_monitor::enable_performance_monitoring();
    }

    // Set up parallelism
    let num_analysis_threads = if let Some(jobs_config) = &args.jobs {
        let parts: Vec<&str> = jobs_config.split(':').collect();

        let analysis_threads = if !parts.is_empty() && !parts[0].is_empty() {
            parts[0].parse::<usize>().unwrap_or(0)
        } else {
            0
        };

        // Set vectorization batch size if provided (second parameter now controls batch size)
        match parts.as_slice() {
            [_] => {
                // Just analysis threads specified
            }
            [_, batch] => {
                std::env::set_var("SEMCODE_BATCH_SIZE", batch);
                info!("Set vectorization batch size to {}", batch);
            }
            _ => {
                warn!(
                    "Invalid jobs format '{}'. Expected: threads[:batch_size]",
                    jobs_config
                );
            }
        }

        analysis_threads
    } else {
        0
    };

    // Use all CPU cores if 0 or not specified, but leave one for system/IO
    let num_threads = if num_analysis_threads == 0 {
        // Leave at least one core for system/IO operations for better overall performance
        num_cpus::get().saturating_sub(1).max(1)
    } else {
        num_analysis_threads
    };

    // Configure optimized rayon thread pool
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .thread_name(|idx| format!("semcode-worker-{idx}"))
        // Configure larger stack for complex AST parsing (8MB instead of default 2MB)
        .stack_size(8 * 1024 * 1024)
        .build_global()
        .unwrap_or_else(|e| {
            warn!("Failed to set rayon thread pool size: {}", e);
        });

    // Set environment variable to tune the stealing algorithm
    std::env::set_var("RAYON_NUM_STEALS", "4");

    info!("Using {} parallel threads for analysis", num_threads);
    info!("Each thread will load its own Tree-sitter parser instance for true parallelism");

    // Initialize tracing with SEMCODE_DEBUG environment variable support
    semcode::logging::init_tracing();

    // Validate mutually exclusive options
    if args.git.is_some() && args.commits.is_some() {
        return Err(anyhow::anyhow!(
            "--git and --commits are mutually exclusive. Use --git to index files in a commit range, or --commits to index only commit metadata."
        ));
    }

    info!("Starting semantic code indexing");
    if let Some(ref git_range) = args.git {
        info!("Git commit indexing mode: {}", git_range);
        info!(
            "Source directory: {} (for git repository detection)",
            args.source.display()
        );
    } else if let Some(ref commit_range) = args.commits {
        info!("Commit metadata indexing mode: {}", commit_range);
        info!(
            "Source directory: {} (for git repository detection)",
            args.source.display()
        );
    } else {
        info!("Source directory: {}", args.source.display());
    }

    // Process database path with search order: 1) -d flag, 2) source directory, 3) current directory
    let database_path = process_database_path(args.database.as_deref(), Some(&args.source));
    info!("Database path: {}", database_path);
    if args.gpu {
        info!("GPU acceleration: enabled");
    }
    if !args.no_typedefs {
        info!("Typedef indexing: enabled");
    }
    if !args.no_macros {
        info!("Macro indexing: enabled (function-like macros only)");
    }
    if !args.no_extra_comments {
        info!("Comment extraction: enabled");
    }

    // Handle commits-only mode
    if args.commits.is_some() {
        info!("Running commits-only indexing mode");
        return run_commits_only(args).await;
    }

    // Run TreeSitter pipeline processing (the only option now)
    info!("Using Tree-sitter for code analysis");
    info!("Using pipeline processing for better CPU utilization");
    run_pipeline(args).await
}

async fn run_commits_only(args: Args) -> Result<()> {
    info!("Starting commits-only indexing mode");

    let commit_range = args.commits.as_ref().unwrap();

    // Validate range format
    if !commit_range.contains("..") {
        return Err(anyhow::anyhow!(
            "Commits indexing requires a range format (e.g., 'HEAD~10..HEAD'). Got: '{}'",
            commit_range
        ));
    }

    // Process database path
    let database_path = process_database_path(args.database.as_deref(), Some(&args.source));

    // Create database manager and tables
    let db_manager =
        DatabaseManager::new(&database_path, args.source.to_string_lossy().to_string()).await?;
    db_manager.create_tables().await?;

    if args.clear {
        println!("Clearing existing data...");
        db_manager.clear_all_data().await?;
        println!("Existing data cleared.");
    }

    // Open repository and get list of commits in range
    let repo = gix::discover(&args.source)
        .map_err(|e| anyhow::anyhow!("Not in a git repository: {}", e))?;
    let commit_shas = list_shas_in_range(&repo, commit_range)?;
    let commit_count = commit_shas.len();

    if commit_shas.is_empty() {
        println!("No commits found in range: {}", commit_range);
        return Ok(());
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
        return Ok(());
    }

    let start_time = std::time::Instant::now();

    // Process commits using streaming pipeline
    let batch_size = 100;
    let num_workers = num_cpus::get();

    process_commits_pipeline(
        &args.source,
        new_commit_shas,
        Arc::new(db_manager),
        batch_size,
        num_workers,
        existing_commits,
    )
    .await?;

    let total_time = start_time.elapsed();

    println!("\n=== Commits-Only Indexing Complete ===");
    println!("Total time: {:.1}s", total_time.as_secs_f64());
    println!("Commits indexed: {}", commit_count);
    println!("To query this database, run:");
    println!("  semcode --database {}", database_path);

    Ok(())
}

/// Process commits using a streaming pipeline
async fn process_commits_pipeline(
    repo_path: &std::path::Path,
    commit_shas: Vec<String>,
    db_manager: Arc<DatabaseManager>,
    batch_size: usize,
    num_workers: usize,
    existing_commits: HashSet<String>,
) -> Result<()> {
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
    let (result_tx, result_rx) = mpsc::sync_channel::<Vec<semcode::GitCommitInfo>>(10);

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

    // Use 8 inserter tasks for parallel database insertion
    // Balance between parallelism (faster insertion) and lock contention
    let num_inserters = 16;
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

async fn run_pipeline(args: Args) -> Result<()> {
    info!("Starting Tree-sitter pipeline processing");

    // Process database path with search order: 1) -d flag, 2) source directory, 3) current directory
    let database_path = process_database_path(args.database.as_deref(), Some(&args.source));

    // Create database manager and tables
    let db_manager =
        DatabaseManager::new(&database_path, args.source.to_string_lossy().to_string()).await?;
    db_manager.create_tables().await?;

    if args.clear {
        println!("Clearing existing data...");
        db_manager.clear_all_data().await?;
        println!("Existing data cleared.");
    }

    // Wrap database manager in Arc for sharing across pipeline stages
    let db_manager = Arc::new(db_manager);

    // Skip source indexing if we're only doing vectorization
    if !args.vectors {
        // Determine which files to process based on incremental mode
        let mut files_to_process = Vec::new();
        let git_files_map: Option<std::collections::HashMap<PathBuf, GitFileEntry>> = None;
        let extensions: Vec<String> = args
            .extensions
            .iter()
            .map(|ext| ext.trim_start_matches('.').to_string())
            .collect();

        if let Some(ref git_range) = args.git {
            // Git range indexing mode - only ranges with ".." are supported
            if !git_range.contains("..") {
                return Err(anyhow::anyhow!(
                    "Git indexing requires a range format (e.g., 'HEAD~10..HEAD'). Single commit mode has been removed. Got: '{}'",
                    git_range
                ));
            }

            info!("Running git range indexing for: {}", git_range);
            return process_git_range(&args, db_manager.clone(), git_range, &extensions).await;
        } else {
            // Full scan mode - find all files to process
            for entry in WalkDir::new(&args.source)
                .max_depth(args.max_depth)
                .follow_links(false) // Explicitly disable symlink following to prevent infinite loops
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
            {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if extensions.contains(&ext.to_string_lossy().to_string()) {
                        files_to_process.push(path.to_path_buf());
                    }
                }
            }

            info!("Found {} files to process", files_to_process.len());

            // Extract and store git commit metadata for current commit
            info!("Extracting git commit metadata for current commit");
            match gix::discover(&args.source) {
                Ok(repo) => {
                    // Get current HEAD commit
                    match repo.head_commit() {
                        Ok(commit) => {
                            let commit_sha = commit.id().to_string();
                            info!("Current commit: {}", commit_sha);

                            match extract_commit_metadata(&repo, &commit_sha) {
                                Ok(metadata) => {
                                    info!("Inserting commit metadata for {}", commit_sha);
                                    if let Err(e) =
                                        db_manager.insert_git_commits(vec![metadata]).await
                                    {
                                        warn!("Failed to insert commit metadata: {}", e);
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to extract commit metadata: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to get HEAD commit: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Not in a git repository ({}), skipping commit metadata extraction",
                        e
                    );
                }
            }
        }

        // Build and run pipeline (TreeSitter-only now)
        let pipeline = if args.git.is_some() {
            // Git range mode: use git-specific pipeline with temp tables
            PipelineBuilder::new_for_git_commit(
                db_manager.clone(),
                args.source.clone(),
                args.git.as_ref().unwrap().clone(),
            )
        } else {
            PipelineBuilder::new(db_manager.clone(), args.source.clone())
        };
        let processed = pipeline.processed_files.clone();
        let new_functions = pipeline.new_functions.clone();
        let new_types = pipeline.new_types.clone();
        let new_macros = pipeline.new_macros.clone();

        // Note: Progress bar will be managed by the pipeline itself since it knows
        // the actual number of files that need processing after filtering

        // Run the pipeline
        let cleanup_git_files = git_files_map.clone();
        println!(
            "About to start pipeline processing with {} files...",
            files_to_process.len()
        );

        measure!("pipeline_processing", {
            if args.git.is_some() {
                // Git range mode: use git-specific pipeline with git files mapping
                pipeline
                    .build_and_run_with_git_files(files_to_process, git_files_map)
                    .await
            } else {
                // Standard pipeline with direct file paths
                pipeline.build_and_run(files_to_process).await
            }
        })?;
        println!("Pipeline processing completed successfully");

        // Explicit cleanup of git temp files after pipeline processing
        if let Some(git_files) = cleanup_git_files {
            let temp_file_count = git_files.len();
            println!("Cleaning up {temp_file_count} temporary git files...");
            for (_, git_file) in git_files {
                if let Err(e) = git_file.cleanup() {
                    tracing::warn!(
                        "Failed to cleanup temp file {}: {}",
                        git_file.temp_file_path.display(),
                        e
                    );
                }
            }
            println!("Cleanup completed for {temp_file_count} temporary git files");
        }

        // Progress is managed by the pipeline itself

        // Display stats
        let total_processed = processed.load(Ordering::Relaxed);
        let total_functions = new_functions.load(Ordering::Relaxed);
        let total_types = new_types.load(Ordering::Relaxed);
        let total_macros = new_macros.load(Ordering::Relaxed);

        if args.git.is_some() {
            println!("\n=== Git Commit Pipeline Processing Complete ===");
        } else {
            println!("\n=== Pipeline Processing Complete ===");
        }
        println!("Files processed: {total_processed}");
        println!("Functions indexed: {total_functions}");
        println!("Types indexed: {total_types}");
        if !args.no_macros {
            println!("Macros indexed: {total_macros}");
        }
    } else {
        println!("Skipping source indexing - vectorization only mode");
    }

    // ===============================================================================
    // EMBEDDED RELATIONSHIP DATA IN NEW ARCHITECTURE
    // ===============================================================================
    //
    // The new architecture embeds all relationship data directly in JSON columns
    // for better performance and simplified processing. This eliminates the need
    // for temporary tables, complex resolution phases, and cross-file lookups.
    //
    // ## EMBEDDED JSON APPROACH
    //
    // **Function Table:**
    // - `calls` column: JSON array of function names called by this function
    // - `types` column: JSON array of type names used by this function
    //
    // **Type Table:**
    // - `types` column: JSON array of type names referenced by this type
    //
    // **Macro Table:**
    // - `calls` column: JSON array of function names called in macro expansion
    // - `types` column: JSON array of type names used in macro expansion
    //
    // ## SINGLE-PASS EXTRACTION
    //
    // During TreeSitter analysis of each source file:
    // - Single tree traversal extracts all calls with byte positions
    // - Function analysis filters calls by byte ranges (O(m) vs O(n²))
    // - Call/type data embedded directly in function/type/macro records
    // - No temporary storage or resolution phases needed
    //
    // ## BENEFITS OF EMBEDDED APPROACH
    //
    // 1. **Simplified Processing**: No temporary tables or multi-phase resolution
    // 2. **Better Performance**: ~10-15x faster than old approach
    // 3. **Atomic Operations**: All data for an entity stored together
    // 4. **Query Flexibility**: JSON columns support rich querying with LanceDB
    // 5. **No Deduplication Complexity**: Git SHA-based uniqueness handles this automatically
    // 6. **Reduced I/O**: Single-pass processing with minimal database operations
    //
    // This replaces the previous complex 4-phase approach with optimized single-pass
    // extraction that's both significantly faster and simpler to maintain.
    // ===============================================================================

    // Call relationships are now embedded in function/macro JSON columns

    // Generate vectors if requested
    if args.vectors {
        println!("\nStarting vector generation process...");
        println!("Initializing vectorizer...");
        match measure!("vectorizer_initialization", {
            CodeVectorizer::new_with_config(args.gpu, args.model_path.clone()).await
        }) {
            Ok(vectorizer) => {
                println!("vectorizer initialized successfully");

                // Verify model dimension
                match vectorizer.verify_model_dimension() {
                    Ok(_) => {
                        println!("✓ Model verification passed: producing 256-dimensional vectors");
                    }
                    Err(e) => {
                        eprintln!("✗ Model verification failed: {e}");
                        std::process::exit(1);
                    }
                }
                println!("Generating vectors for all functions...");
                match measure!("vector_generation", {
                    db_manager.update_vectors(&vectorizer).await
                }) {
                    Ok(_) => {
                        println!("Vector generation completed successfully");

                        // Generate vectors for git commits
                        println!("Generating vectors for git commits...");
                        match measure!("commit_vector_generation", {
                            db_manager.update_commit_vectors(&vectorizer).await
                        }) {
                            Ok(_) => println!("Commit vector generation completed successfully"),
                            Err(e) => error!("Failed to generate commit vectors: {}", e),
                        }

                        println!("Creating vector index...");
                        match measure!("vector_index_creation", {
                            db_manager.create_vector_index().await
                        }) {
                            Ok(_) => println!("Vector index created successfully"),
                            Err(e) => error!("Failed to create vector index: {}", e),
                        }
                    }
                    Err(e) => error!("Failed to generate vectors: {}", e),
                }
            }
            Err(e) => {
                error!("Failed to initialize vectorizer: {}", e);
            }
        }
    }

    // Optimize database (skip in git range mode for faster incremental updates)
    if args.git.is_none() {
        println!("\nStarting database optimization...");
        match measure!("database_optimization", {
            db_manager.optimize_database().await
        }) {
            Ok(_) => println!("Database optimization completed successfully"),
            Err(e) => error!("Failed to optimize database: {}", e),
        }
    } else {
        println!("\nSkipping database optimization in git range indexing mode (use full scan for optimization)");
    }

    // Drop and recreate if requested
    if args.drop_recreate {
        println!("\n{}", "Drop and recreate requested...".bright_yellow());
        match measure!("drop_recreate_tables", {
            db_manager.drop_and_recreate_tables().await
        }) {
            Ok(_) => {
                println!("{}", "✓ Drop and recreate operation complete!".green());
            }
            Err(e) => {
                error!("Failed to drop and recreate tables: {}", e);
            }
        }
    }

    // Print mapping resolution statistics
    println!("\n=== Embedded Data Statistics ===");
    println!("Call relationships: embedded in function/macro JSON columns");
    println!("Function-type mappings: embedded in function JSON columns");
    println!("Type-type mappings: embedded in type JSON columns");

    println!("\nTo query this database, run:");
    println!("  semcode --database {database_path}");

    // Print performance statistics if requested
    if args.perf {
        println!("\nPrinting performance statistics...");
        let stats = PERF_STATS.lock().unwrap();
        stats.print_summary();
    }

    if args.vectors {
        println!("\n🎉 Vectorization completed successfully!");
    } else {
        println!("\n🎉 Indexing completed successfully!");
    }
    Ok(())
}

/// Represents a git file for parallel processing
#[derive(Debug, Clone)]
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
    macros: Vec<MacroInfo>,
    files_processed: usize,
}

impl GitTupleResults {
    fn merge(&mut self, other: GitTupleResults) {
        self.functions.extend(other.functions);
        self.types.extend(other.types);
        self.macros.extend(other.macros);
        self.files_processed += other.files_processed;
    }
}

/// Statistics from processing git file tuples (lightweight, no accumulated data)
#[derive(Debug, Default, Clone)]
struct GitTupleStats {
    files_processed: usize,
    functions_count: usize,
    types_count: usize,
    macros_count: usize,
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
    semcode::git::walk_tree_at_commit_with_repo(repo, git_sha, |relative_path, object_id| {
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

/// Parse git range and get all commit SHAs in the range
/// Uses gitoxide's built-in rev-spec parsing for proper A..B semantics
fn list_shas_in_range(repo: &gix::Repository, range: &str) -> Result<Vec<String>> {
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

/// Stream git file tuples to a channel from a subset of commits (producer)
fn stream_git_file_tuples_batch(
    _generator_id: usize,
    repo_path: PathBuf,
    commit_batch: Vec<String>,
    extensions: Vec<String>,
    tuple_tx: mpsc::Sender<GitFileTuple>,
    processed_files: Arc<HashSet<String>>,
    sent_in_this_run: Arc<DashSet<String>>,
) -> Result<()> {
    // Open repository ONCE per generator thread and reuse for all commits
    let repo = gix::discover(&repo_path)?;

    for commit_sha in commit_batch.iter() {
        // Get all files from this commit using reused repo handle
        let manifest = get_git_commit_manifest_with_repo(&repo, commit_sha, &extensions)?;

        for manifest_entry in manifest {
            let file_sha = manifest_entry.object_id.to_string();

            // Filter out files already processed in database
            if processed_files.contains(&file_sha) {
                continue;
            }

            // Filter out files already sent in this run (lock-free with DashSet)
            if !sent_in_this_run.insert(file_sha.clone()) {
                // File already sent by another generator
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
        }
    }

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
    let (functions, types, macros) = analysis_result?;

    // Function-type and type-type mapping extraction removed - now using embedded columns
    // Call relationships are now embedded in function/macro JSON columns

    let results = GitTupleResults {
        functions,
        types,
        macros: if no_macros { Vec::new() } else { macros },
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
) {
    // Open repository ONCE per worker thread and reuse for all tuples
    let thread_repo = match gix::discover(&repo_path) {
        Ok(repo) => repo,
        Err(e) => {
            tracing::error!("Worker {} failed to open repository: {}", worker_id, e);
            return;
        }
    };

    // Accumulate results into a batch for sending to inserters
    let mut batch = GitTupleResults::default();
    const DB_BATCH_SIZE: usize = 2048; // Send to inserters after this many files

    // Process tuples in batches to reduce channel lock overhead
    const TUPLE_BATCH_SIZE: usize = 8;
    loop {
        // Collect a batch of tuples (reduces lock contention)
        let mut tuple_batch = Vec::with_capacity(TUPLE_BATCH_SIZE);
        {
            let rx = match shared_tuple_rx.lock() {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("Worker {} failed to lock receiver: {}", worker_id, e);
                    break;
                }
            };

            // Try to get a batch of tuples without blocking
            for _ in 0..TUPLE_BATCH_SIZE {
                match rx.try_recv() {
                    Ok(tuple) => tuple_batch.push(tuple),
                    Err(mpsc::TryRecvError::Empty) => break, // No more tuples available now
                    Err(mpsc::TryRecvError::Disconnected) => break, // Channel closed
                }
            }

            // If we got nothing with try_recv, do a blocking recv for at least one
            if tuple_batch.is_empty() {
                match rx.recv() {
                    Ok(tuple) => tuple_batch.push(tuple),
                    Err(_) => break, // Channel closed
                }
            }
        }

        // Process the batch
        for tuple in tuple_batch {
            match process_git_file_tuple_with_repo(&tuple, &thread_repo, &source_root, no_macros) {
                Ok(tuple_result) => {
                    batch.merge(tuple_result);
                    processed_count.fetch_add(1, Ordering::Relaxed);

                    // Send batch to inserters when it reaches DB_BATCH_SIZE
                    if batch.files_processed >= DB_BATCH_SIZE {
                        batches_sent.fetch_add(1, Ordering::Relaxed);
                        if result_tx.send(batch.clone()).is_err() {
                            tracing::warn!(
                                "Worker {} failed to send batch (channel closed)",
                                worker_id
                            );
                            return;
                        }
                        batch = GitTupleResults::default(); // Reset for next batch
                    }
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
    }

    // Send remaining batch if not empty
    if batch.files_processed > 0 {
        batches_sent.fetch_add(1, Ordering::Relaxed);
        if let Err(e) = result_tx.send(batch) {
            tracing::warn!("Worker {} failed to send final batch: {}", worker_id, e);
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
            macros_count: 0,
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
    // Bounded channel for results to prevent memory explosion (3 batches in flight max)
    // Each batch = 10000 files, so max 30000 files in memory at inserters
    let (result_tx, result_rx) = mpsc::sync_channel::<GitTupleResults>(3);

    // Wrap receivers for shared access
    let shared_tuple_rx = Arc::new(Mutex::new(tuple_rx));
    let shared_result_rx = Arc::new(Mutex::new(result_rx));

    // Shared progress counters
    let processed_count = Arc::new(AtomicUsize::new(0));
    let inserted_functions = Arc::new(AtomicUsize::new(0));
    let inserted_types = Arc::new(AtomicUsize::new(0));
    let inserted_macros = Arc::new(AtomicUsize::new(0));
    let batches_sent = Arc::new(AtomicUsize::new(0));
    let batches_inserted = Arc::new(AtomicUsize::new(0));

    // Shared deduplication set across all generators (lock-free)
    let sent_in_this_run = Arc::new(DashSet::new());

    // Spawn progress updater thread
    let pb_clone = pb.clone();
    let processed_clone = processed_count.clone();
    let functions_clone = inserted_functions.clone();
    let types_clone = inserted_types.clone();
    let macros_clone = inserted_macros.clone();
    let batches_sent_clone = batches_sent.clone();
    let batches_inserted_clone = batches_inserted.clone();
    let progress_thread = std::thread::spawn(move || {
        loop {
            let files = processed_clone.load(Ordering::Relaxed);
            let funcs = functions_clone.load(Ordering::Relaxed);
            let types = types_clone.load(Ordering::Relaxed);
            let macros = macros_clone.load(Ordering::Relaxed);
            let sent = batches_sent_clone.load(Ordering::Relaxed);
            let inserted = batches_inserted_clone.load(Ordering::Relaxed);
            let pending = sent.saturating_sub(inserted);

            pb_clone.set_position(files as u64);
            pb_clone.set_message(format!(
                "{} funcs, {} types, {} macros | {} batches pending",
                funcs, types, macros, pending
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

    // Spawn worker threads
    let mut worker_handles = Vec::new();
    for worker_id in 0..num_workers {
        let worker_tuple_rx = shared_tuple_rx.clone();
        let worker_result_tx = result_tx.clone();
        let worker_repo_path = repo_path.clone();
        let worker_source_root = source_root.clone();
        let worker_processed_count = processed_count.clone();
        let worker_batches_sent = batches_sent.clone();

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
            );
        });
        worker_handles.push(handle);
    }

    // Close the original result sender (workers have clones)
    drop(result_tx);

    // Spawn database inserter tasks (use 4 for better parallelism without too much contention)
    let num_inserters = 4;
    let mut inserter_handles = Vec::new();

    for inserter_id in 0..num_inserters {
        let db_manager_clone = Arc::clone(&db_manager);
        let result_rx_clone = shared_result_rx.clone();
        let functions_counter = inserted_functions.clone();
        let types_counter = inserted_types.clone();
        let macros_counter = inserted_macros.clone();
        let batches_inserted_counter = batches_inserted.clone();

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
                        let macro_count = batch.macros.len();

                        // Insert all three types in parallel
                        let (func_result, type_result, macro_result) = tokio::join!(
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
                                if !batch.macros.is_empty() {
                                    db_manager_clone.insert_macros(batch.macros).await
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
                        if let Err(e) = macro_result {
                            error!("Inserter {} failed to insert macros: {}", inserter_id, e);
                            insertion_successful = false;
                        } else {
                            macros_counter.fetch_add(macro_count, Ordering::Relaxed);
                        }

                        // Only increment batches_inserted if insertion was successful
                        if insertion_successful {
                            batches_inserted_counter.fetch_add(1, Ordering::Relaxed);
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
        macros_count: inserted_macros.load(Ordering::Relaxed),
    };

    // Finish progress bar
    pb.finish_with_message(format!(
        "Complete: {} files, {} functions, {} types, {} macros",
        stats.files_processed, stats.functions_count, stats.types_count, stats.macros_count
    ));
    progress_thread.join().unwrap();

    Ok(stats)
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
fn extract_commit_metadata(
    repo: &gix::Repository,
    commit_sha: &str,
) -> Result<semcode::GitCommitInfo> {
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

    Ok(semcode::GitCommitInfo {
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
                            let (write_result, file_symbols) = write_diff_and_extract_symbols(
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

/// Write a unified diff and extract symbols from changed lines
fn write_diff_and_extract_symbols(
    output: &mut String,
    old: &str,
    new: &str,
    file_path: &str,
) -> (std::fmt::Result, Vec<String>) {
    use similar::{ChangeTag, TextDiff};
    use std::fmt::Write;

    // Generate a proper diff using the Myers algorithm
    let diff = TextDiff::from_lines(old, new);

    let mut write_result = Ok(());

    // Parse file into lines for symbol lookup
    let new_lines: Vec<&str> = new.lines().collect();

    // Generate unified diff format with 3 lines of context (like git default)
    for hunk in diff.unified_diff().context_radius(3).iter_hunks() {
        // Get the first line number from the hunk to find symbol context
        let start_line = hunk
            .iter_changes()
            .find_map(|c| c.new_index())
            .unwrap_or(1)
            .saturating_sub(1); // Convert to 0-indexed

        // Find the symbol at the start of this hunk using walk-back
        let symbol_context = if file_path.ends_with(".c")
            || file_path.ends_with(".h")
            || file_path.ends_with(".cpp")
            || file_path.ends_with(".cc")
            || file_path.ends_with(".cxx")
        {
            semcode::symbol_walkback::find_symbol_for_line(&new_lines, start_line).or_else(|| {
                // If walk-back fails, try to find the first non-empty line in the hunk
                hunk.iter_changes()
                    .find(|c| !c.value().trim().is_empty())
                    .and_then(|c| c.new_index())
                    .and_then(|idx| {
                        if idx > 0 {
                            semcode::symbol_walkback::find_symbol_for_line(&new_lines, idx - 1)
                        } else {
                            None
                        }
                    })
            })
        } else {
            None
        };

        // Write hunk header with symbol context (like git does)
        if write_result.is_ok() {
            if let Some(ref symbol) = symbol_context {
                // Format: @@ -old_start,old_count +new_start,new_count @@ symbol
                // Convert header to string and append symbol
                let header_str = format!("{}", hunk.header());
                write_result = writeln!(output, "{} {}", header_str.trim_end(), symbol);
            } else {
                write_result = writeln!(output, "{}", hunk.header());
            }
        }

        // Write the actual changes
        for change in hunk.iter_changes() {
            let sign = match change.tag() {
                ChangeTag::Delete => "-",
                ChangeTag::Insert => "+",
                ChangeTag::Equal => " ",
            };
            if write_result.is_ok() {
                write_result = write!(output, "{}{}", sign, change.value());
            }
        }
    }

    // Extract symbols for C/C++ files only using walk-back algorithm
    let symbols = if file_path.ends_with(".c")
        || file_path.ends_with(".h")
        || file_path.ends_with(".cpp")
        || file_path.ends_with(".cc")
        || file_path.ends_with(".cxx")
    {
        // Collect modified line numbers from both old and new files
        let mut new_modified_lines = HashSet::new();
        let mut old_modified_lines = HashSet::new();

        for hunk in diff.unified_diff().context_radius(3).iter_hunks() {
            for change in hunk.iter_changes() {
                use similar::ChangeTag;
                match change.tag() {
                    ChangeTag::Insert => {
                        // Added lines - check in new file
                        if let Some(line_num) = change.new_index() {
                            if line_num > 0 {
                                new_modified_lines.insert(line_num - 1);
                            }
                        }
                    }
                    ChangeTag::Delete => {
                        // Deleted lines - check in old file
                        if let Some(line_num) = change.old_index() {
                            if line_num > 0 {
                                old_modified_lines.insert(line_num - 1);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Extract symbols from both old (deletions) and new (additions/modifications)
        let mut all_symbols = HashSet::new();
        all_symbols.extend(semcode::symbol_walkback::extract_symbols_by_walkback(
            new,
            &new_modified_lines,
        ));
        all_symbols.extend(semcode::symbol_walkback::extract_symbols_by_walkback(
            old,
            &old_modified_lines,
        ));

        all_symbols.into_iter().collect()
    } else {
        Vec::new()
    };

    (write_result, symbols)
}

/// Process git range using streaming file tuple pipeline
async fn process_git_range(
    args: &Args,
    db_manager: Arc<DatabaseManager>,
    git_range: &str,
    extensions: &[String],
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
    let repo = gix::discover(&args.source)
        .map_err(|e| anyhow::anyhow!("Not in a git repository: {}", e))?;
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
                &args.source,
                new_commit_shas,
                db_manager.clone(),
                batch_size,
                num_workers,
                existing_commits,
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
        args.source.clone(),
        git_range.to_string(),
        extensions.to_vec(),
        args.source.clone(),
        args.no_macros,
        processed_files,
        num_workers,
        db_manager.clone(),
    )
    .await?;

    let processing_time = processing_start.elapsed();

    info!(
        "Streaming pipeline completed in {:.1}s: {} files, {} functions, {} types, {} macros (inserted throughout processing)",
        processing_time.as_secs_f64(),
        stats.files_processed,
        stats.functions_count,
        stats.types_count,
        stats.macros_count
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
    if !args.no_macros {
        println!("Macros indexed: {}", stats.macros_count);
    }

    Ok(())
}
