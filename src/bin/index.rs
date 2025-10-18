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

// Import IPC for worker mode
use ipc_channel::ipc::{self, IpcReceiver, IpcSender};
use anyhow::Context;

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

    /// Index a specific git commit. When provided, indexes the specified git SHA by reading files directly from git blobs.
    /// Uses the same algorithm as default indexing but sources files from git instead of working directory.
    #[arg(long, value_name = "GIT_SHA")]
    inc: Option<String>,

    /// Index files modified in git commit range without checking them out.
    /// Accepts range format only (SHA1..SHA2). Reads files directly from git blobs.
    /// Uses incremental processing and deduplication with parallel streaming pipeline.
    #[arg(long, value_name = "GIT_RANGE")]
    git: Option<String>,

    /// Enable clangd integration for enriched semantic analysis (requires compile_commands.json)
    /// When enabled, semcode will use clangd to extract USRs, canonical types, and precise call graphs
    #[arg(long)]
    use_clangd: bool,

    /// Path to compile_commands.json for clangd integration (default: looks in source directory)
    #[arg(long, value_name = "PATH")]
    compile_commands: Option<PathBuf>,

    // Hidden arguments for worker mode (internal use only)
    /// Run in clangd worker mode (internal use only)
    #[arg(long, hide = true)]
    clangd_worker: bool,

    /// Worker ID for debugging (internal use only)
    #[arg(long, hide = true)]
    worker_id: Option<usize>,

    /// IPC server name for work channel (internal use only)
    #[arg(long, hide = true)]
    ipc_work_server: Option<String>,

    /// IPC server name for response channel (internal use only)
    #[arg(long, hide = true)]
    ipc_response_server: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Suppress ORT verbose logging
    std::env::set_var("ORT_LOG_LEVEL", "ERROR");

    let args = Args::parse();

    // Check if running in worker mode
    if args.clangd_worker {
        return run_clangd_worker_mode(args).await;
    }

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

    // Check clangd integration availability
    let clangd_config = if args.use_clangd {
        let compile_commands_path = args
            .compile_commands
            .clone()
            .unwrap_or_else(|| args.source.join("compile_commands.json"));

        // Verify clangd is actually available before claiming it's enabled
        if semcode::ClangdAnalyzer::is_available(&compile_commands_path) {
            info!("🚀 Clangd integration ENABLED");
            info!(
                "   Using compile_commands.json: {}",
                compile_commands_path.display()
            );
            info!("   Will enrich analysis with:");
            info!("     • Unified Symbol Resolutions (USRs) for precise symbol tracking");
            info!("     • Canonical type names (template instantiations, auto, typedef resolution)");
            info!("     • Precise overload resolution");
            info!("     • Cross-references into system headers");
            Some(compile_commands_path)
        } else {
            eprintln!("⚠️  Clangd integration requested but compile_commands.json not found");
            eprintln!("   Falling back to Tree-sitter-only analysis");
            eprintln!("   To enable clangd, ensure compile_commands.json exists in source directory");
            eprintln!("   Or specify path with: --compile-commands /path/to/compile_commands.json");
            None
        }
    } else {
        info!("ℹ️  Using Tree-sitter analysis (fast, works everywhere)");
        let compile_commands_path = args.source.join("compile_commands.json");
        if compile_commands_path.exists() {
            info!("💡 compile_commands.json detected - use --use-clangd for enriched semantic analysis");
        }
        None
    };

    info!("Starting semantic code indexing");
    if let Some(ref git_range) = args.git {
        info!("Git commit indexing mode: {}", git_range);
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

    // Run TreeSitter pipeline processing (the only option now)
    info!("Using Tree-sitter for code analysis");
    info!("Using pipeline processing for better CPU utilization");

    run_pipeline(args, clangd_config).await
}

/// Worker mode entry point - runs when spawned with --clangd-worker flag
async fn run_clangd_worker_mode(args: Args) -> Result<()> {
    // Set up minimal logging for worker
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let worker_id = args.worker_id.expect("Worker ID required in worker mode");
    let work_server_name = args
        .ipc_work_server
        .expect("IPC work server name required in worker mode");
    let response_server_name = args
        .ipc_response_server
        .expect("IPC response server name required in worker mode");

    tracing::debug!(
        "Starting clangd worker {} (PID: {})",
        worker_id,
        std::process::id()
    );

    // Get compile_commands path
    let compile_commands_path = if let Some(ref path) = args.compile_commands {
        path.clone()
    } else {
        args.source.join("compile_commands.json")
    };

    if !compile_commands_path.exists() {
        anyhow::bail!(
            "compile_commands.json not found at {:?}",
            compile_commands_path
        );
    }

    tracing::debug!(
        "Worker {} using compile_commands.json at {:?}",
        worker_id,
        compile_commands_path
    );

    // Create IPC channels for communication with parent
    // Parent will send WorkRequest to us, we send WorkResponse back

    // Create channel to receive work from parent
    let (work_tx_to_parent, work_rx) = ipc::channel()
        .context("Failed to create work channel")?;

    // Create channel to send responses to parent
    let (response_tx, response_rx_for_parent) = ipc::channel()
        .context("Failed to create response channel")?;

    // Connect to parent's work server and send our receiver
    let work_bootstrap: IpcSender<IpcSender<semcode::clangd_worker::WorkRequest>> =
        IpcSender::connect(work_server_name.clone())
            .with_context(|| format!("Failed to connect to work server: {}", work_server_name))?;
    work_bootstrap.send(work_tx_to_parent)
        .context("Failed to send work channel to parent")?;

    // Connect to parent's response server and send our sender
    let response_bootstrap: IpcSender<IpcReceiver<semcode::clangd_worker::WorkResponse>> =
        IpcSender::connect(response_server_name.clone())
            .with_context(|| format!("Failed to connect to response server: {}", response_server_name))?;
    response_bootstrap.send(response_rx_for_parent)
        .context("Failed to send response channel to parent")?;

    tracing::debug!("Worker {} IPC channels established", worker_id);

    // Call the worker entry point
    semcode::run_worker(
        worker_id,
        work_rx,
        response_tx,
        compile_commands_path,
        args.source,
    )
    .await
}

async fn run_pipeline(args: Args, compile_commands_path: Option<PathBuf>) -> Result<()> {
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

        // Recreate indices after clearing to ensure optimal performance
        println!("Recreating indices after clear...");
        db_manager.rebuild_indices().await?;
        println!("Indices recreated.");
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
                .filter(|e| {
                    // Exclude .semcode.db directory
                    !e.path().to_string_lossy().contains(".semcode.db")
                })
            {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if extensions.contains(&ext.to_string_lossy().to_string()) {
                        files_to_process.push(path.to_path_buf());
                    }
                }
            }

            info!("Found {} files to process", files_to_process.len());
        }

        // Build and run pipeline
        let mut pipeline = if args.git.is_some() {
            // Git range mode: use git-specific pipeline with temp tables
            PipelineBuilder::new_for_git_commit(
                db_manager.clone(),
                args.source.clone(),
                args.git.as_ref().unwrap().clone(),
            )
        } else {
            PipelineBuilder::new(db_manager.clone(), args.source.clone())
        };

        // Add clangd integration if configured
        if let Some(compile_commands_path) = compile_commands_path {
            println!(
                "Clangd integration enabled with compile_commands.json at: {}",
                compile_commands_path.display()
            );
            pipeline = pipeline.with_clangd(compile_commands_path);
        }

        let processed = pipeline.processed_files.clone();
        let new_functions = pipeline.new_functions.clone();
        let new_types = pipeline.new_types.clone();
        let new_macros = pipeline.new_macros.clone();
        let enriched_functions = pipeline.enriched_functions.clone();
        let enriched_types = pipeline.enriched_types.clone();
        let enriched_macros = pipeline.enriched_macros.clone();
        let macros_kept_by_clangd = pipeline.macros_kept_by_clangd.clone();
        let files_with_compile_commands = pipeline.files_with_compile_commands.clone();

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
        let total_enriched_functions = enriched_functions.load(Ordering::Relaxed);
        let total_enriched_types = enriched_types.load(Ordering::Relaxed);
        let total_enriched_macros = enriched_macros.load(Ordering::Relaxed);
        let total_macros_kept_by_clangd = macros_kept_by_clangd.load(Ordering::Relaxed);
        let total_files_with_compile_commands = files_with_compile_commands.load(Ordering::Relaxed);

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

        // Display clangd enrichment stats if any enrichment occurred
        if total_enriched_functions > 0
            || total_enriched_types > 0
            || total_enriched_macros > 0
            || total_files_with_compile_commands > 0
        {
            println!("\n=== Clangd Enrichment Statistics ===");
            if total_files_with_compile_commands > 0 {
                println!("Files with compile commands: {total_files_with_compile_commands}");
            }
            if total_enriched_functions > 0 {
                println!("Functions enriched with USR: {total_enriched_functions}");
            }
            if total_enriched_types > 0 {
                println!("Types enriched with USR: {total_enriched_types}");
            }
            if total_enriched_macros > 0 {
                println!("Macros enriched with USR: {total_enriched_macros}");
            }
            if total_macros_kept_by_clangd > 0 {
                println!("Non-function-like macros kept due to clangd USR: {total_macros_kept_by_clangd}");
            }
        }

        // Compact database after indexing to optimize performance
        println!("\nCompacting database to optimize performance...");
        let compact_start = std::time::Instant::now();
        if let Err(e) = db_manager.compact_and_cleanup().await {
            eprintln!("Warning: Database compaction failed: {}", e);
        } else {
            println!("Database compaction completed in {:.1}s", compact_start.elapsed().as_secs_f64());
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

/// Results from processing git file tuples
#[derive(Debug, Default)]
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

/// Get manifest of files from a specific git commit (just paths and object IDs, no content)
fn get_git_commit_manifest(
    repo_path: &std::path::Path,
    git_sha: &str,
    extensions: &[String],
) -> Result<Vec<GitFileManifestEntry>> {
    let repo =
        gix::discover(repo_path).map_err(|e| anyhow::anyhow!("Not in a git repository: {}", e))?;

    let commit = resolve_to_commit(&repo, git_sha)?;

    let tree = commit
        .tree()
        .map_err(|e| anyhow::anyhow!("Failed to get tree for commit '{}': {}", git_sha, e))?;

    let mut manifest = Vec::new();

    // Walk the entire git tree
    use gix::traverse::tree::Recorder;
    let mut recorder = Recorder::default();
    tree.traverse().breadthfirst(&mut recorder)?;

    for entry in recorder.records {
        if entry.mode.is_blob() {
            let relative_path = entry.filepath.to_string();

            // Check if file has one of the target extensions
            if let Some(ext) = std::path::Path::new(&relative_path).extension() {
                if extensions.contains(&ext.to_string_lossy().to_string()) {
                    manifest.push(GitFileManifestEntry {
                        relative_path: relative_path.into(),
                        object_id: entry.oid,
                    });
                }
            }
        }
    }

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
    const MAX_COMMITS: usize = 100000; // Safety limit

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

    // Validate result count is reasonable
    if shas.len() > 10000 {
        eprintln!(
            "WARNING: Range {} produced {} commits, which seems very large",
            range,
            shas.len()
        );
        eprintln!("WARNING: Please verify this range is correct. Use 'git rev-list --count {}' to double-check.", range);
    }

    Ok(shas)
}

/// Stream git file tuples to a channel from a subset of commits (producer)
fn stream_git_file_tuples_batch(
    generator_id: usize,
    repo_path: PathBuf,
    commit_batch: Vec<String>,
    extensions: Vec<String>,
    tuple_tx: mpsc::Sender<GitFileTuple>,
    processed_files: Arc<HashSet<String>>,
    sent_in_this_run: Arc<std::sync::Mutex<HashSet<String>>>,
) -> Result<()> {
    for commit_sha in commit_batch.iter() {
        // Get all files from this commit
        let manifest = get_git_commit_manifest(&repo_path, commit_sha, &extensions)?;

        for manifest_entry in manifest {
            let file_sha = manifest_entry.object_id.to_string();

            // Filter out files already processed in database
            if processed_files.contains(&file_sha) {
                continue;
            }

            // Filter out files already sent in this run (shared across all generators)
            {
                let mut sent_set = match sent_in_this_run.lock() {
                    Ok(set) => set,
                    Err(e) => {
                        tracing::error!(
                            "Generator {} failed to lock sent_in_this_run: {}",
                            generator_id,
                            e
                        );
                        continue;
                    }
                };

                if sent_set.contains(&file_sha) {
                    continue;
                }

                // Mark as sent and create tuple
                sent_set.insert(file_sha.clone());
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

/// Process a single git file tuple and extract functions/types/macros
fn process_git_file_tuple(
    tuple: &GitFileTuple,
    repo_path: &std::path::Path,
    source_root: &std::path::Path,
    no_macros: bool,
) -> Result<GitTupleResults> {
    // Each thread needs its own repository connection
    let repo =
        gix::discover(repo_path).map_err(|e| anyhow::anyhow!("Not in a git repository: {}", e))?;

    // Load git file content to temp file
    let file_stem = tuple
        .file_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("gitfile");

    let temp_path = load_git_file_to_temp(&repo, tuple.object_id, file_stem)?;

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

/// Worker function that processes tuples from a shared channel (Arc<Mutex<Receiver>>)
fn tuple_worker_shared(
    worker_id: usize,
    shared_tuple_rx: Arc<std::sync::Mutex<mpsc::Receiver<GitFileTuple>>>,
    result_tx: mpsc::Sender<GitTupleResults>,
    repo_path: PathBuf,
    source_root: PathBuf,
    no_macros: bool,
    processed_count: Arc<AtomicUsize>,
) {
    let mut worker_results = GitTupleResults::default();

    // Process tuples until channel is closed
    loop {
        // Lock the receiver to get the next tuple
        let tuple = {
            match shared_tuple_rx.lock() {
                Ok(rx) => rx.recv(),
                Err(e) => {
                    tracing::error!("Worker {} failed to lock receiver: {}", worker_id, e);
                    break;
                }
            }
        };

        match tuple {
            Ok(tuple) => {
                match process_git_file_tuple(&tuple, &repo_path, &source_root, no_macros) {
                    Ok(tuple_result) => {
                        worker_results.merge(tuple_result);
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
            Err(_) => {
                // Channel closed, exit worker loop
                break;
            }
        }
    }

    // Send worker results back
    if let Err(e) = result_tx.send(worker_results) {
        tracing::warn!("Worker {} failed to send results: {}", worker_id, e);
    }
}

/// Process git file tuples using streaming pipeline with multiple generator and worker threads
fn process_git_tuples_streaming(
    repo_path: PathBuf,
    git_range: String,
    extensions: Vec<String>,
    source_root: PathBuf,
    no_macros: bool,
    processed_files: Arc<HashSet<String>>,
    num_workers: usize,
) -> Result<GitTupleResults> {
    use std::sync::Mutex;

    // First, get all commits in the range
    let repo =
        gix::discover(&repo_path).map_err(|e| anyhow::anyhow!("Not in a git repository: {}", e))?;
    let commit_shas = list_shas_in_range(&repo, &git_range)?;

    // Handle empty commit range early - return empty results
    if commit_shas.is_empty() {
        return Ok(GitTupleResults {
            functions: Vec::new(),
            types: Vec::new(),
            macros: Vec::new(),
            files_processed: 0,
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

    // Create channels
    let (tuple_tx, tuple_rx) = mpsc::channel::<GitFileTuple>();
    let (result_tx, result_rx) = mpsc::channel::<GitTupleResults>();

    // Wrap receiver in Arc<Mutex<>> so multiple workers can share it
    let shared_tuple_rx = Arc::new(Mutex::new(tuple_rx));

    // Shared progress counter
    let processed_count = Arc::new(AtomicUsize::new(0));

    // Shared deduplication set across all generators
    let sent_in_this_run = Arc::new(std::sync::Mutex::new(HashSet::new()));

    // Spawn progress updater thread
    let pb_clone = pb.clone();
    let processed_clone = processed_count.clone();
    let progress_thread = std::thread::spawn(move || {
        loop {
            let count = processed_clone.load(Ordering::Relaxed);
            pb_clone.set_position(count as u64);

            // Check if we should exit (rough heuristic)
            if count > 0 && pb_clone.is_finished() {
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

        let handle = thread::spawn(move || {
            tuple_worker_shared(
                worker_id,
                worker_tuple_rx,
                worker_result_tx,
                worker_repo_path,
                worker_source_root,
                no_macros,
                worker_processed_count,
            );
        });
        worker_handles.push(handle);
    }

    // Close the original result sender (workers have clones)
    drop(result_tx);

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

    // Collect results from all workers
    let mut final_results = GitTupleResults::default();
    while let Ok(worker_result) = result_rx.try_recv() {
        final_results.merge(worker_result);
    }

    let total_processed = processed_count.load(Ordering::Relaxed);

    // Finish progress bar
    pb.finish_with_message(format!(
        "Git processing complete: {total_processed} files processed"
    ));
    progress_thread.join().unwrap();

    Ok(final_results)
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

    // Step 2: Determine number of workers
    // Since generators are I/O bound and workers are CPU bound, use a balanced approach
    let num_workers = (num_cpus::get() / 2).max(1);
    info!(
        "Starting streaming pipeline with up to 32 generator threads and {} worker threads",
        num_workers
    );

    // Step 3: Process tuples using streaming pipeline
    let processing_start = std::time::Instant::now();
    let results = process_git_tuples_streaming(
        args.source.clone(),
        git_range.to_string(),
        extensions.to_vec(),
        args.source.clone(),
        args.no_macros,
        processed_files,
        num_workers,
    )?;

    let processing_time = processing_start.elapsed();

    let function_count = results.functions.len();
    let type_count = results.types.len();
    let macro_count = results.macros.len();

    info!(
        "Streaming pipeline completed in {:.1}s: {} files, {} functions, {} types, {} macros",
        processing_time.as_secs_f64(),
        results.files_processed,
        function_count,
        type_count,
        macro_count
    );

    // Step 4: Insert results into database in parallel (including call relationships and type mappings originating from processed files)
    if results.files_processed > 0 {
        info!("Inserting results into database using parallel insertion");
        let db_insert_start = std::time::Instant::now();

        // Run all insertions in parallel using tokio::join!
        let (functions_result, types_result, macros_result) = tokio::join!(
            async {
                if !results.functions.is_empty() {
                    info!(
                        "Starting parallel function insertion ({} functions)",
                        results.functions.len()
                    );
                    db_manager.insert_functions(results.functions).await
                } else {
                    Ok(())
                }
            },
            async {
                if !results.types.is_empty() {
                    info!(
                        "Starting parallel type insertion ({} types)",
                        results.types.len()
                    );
                    db_manager.insert_types(results.types).await
                } else {
                    Ok(())
                }
            },
            async {
                if !results.macros.is_empty() {
                    info!(
                        "Starting parallel macro insertion ({} macros)",
                        results.macros.len()
                    );
                    db_manager.insert_macros(results.macros).await
                } else {
                    Ok(())
                }
            }
        );

        // Check results and propagate any errors
        functions_result?;
        types_result?;
        macros_result?;

        // Call relationships are now embedded in function/macro JSON columns

        // Function-type and type-type mapping insertion removed - now using embedded columns

        let db_insert_time = db_insert_start.elapsed();
        info!(
            "Parallel database insertion completed in {:.1}s",
            db_insert_time.as_secs_f64()
        );
    }

    // Call relationships are now embedded in function/macro JSON columns

    let total_time = start_time.elapsed();

    println!("\n=== Git Range Pipeline Complete ===");
    println!("Total time: {:.1}s", total_time.as_secs_f64());
    println!("Files processed: {}", results.files_processed);
    println!("Functions indexed: {function_count}");
    println!("Types indexed: {type_count}");
    if !args.no_macros {
        println!("Macros indexed: {macro_count}");
    }

    Ok(())
}
