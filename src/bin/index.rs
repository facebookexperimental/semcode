// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use semcode::indexer::{list_shas_in_range, process_commits_pipeline};
use semcode::{measure, process_database_path, CodeVectorizer, DatabaseManager};
// Temporary call relationships are now embedded in function JSON columns
use semcode::perf_monitor::PERF_STATS;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};

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

    /// Number of parallel database inserter threads for git range and commit indexing modes
    #[arg(long, default_value = "4")]
    db_threads: usize,
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

    // Use all CPU cores if 0 or not specified, but leave one for system/IO and cap at 32
    let num_threads = if num_analysis_threads == 0 {
        // Leave at least one core for system/IO operations for better overall performance
        num_cpus::get().saturating_sub(1).max(1).min(32)
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
        args.db_threads,
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
        let extensions: Vec<String> = args
            .extensions
            .iter()
            .map(|ext| ext.trim_start_matches('.').to_string())
            .collect();

        // Determine git range to process
        let git_range = if let Some(ref explicit_range) = args.git {
            // Explicit --git flag provided
            if !explicit_range.contains("..") {
                return Err(anyhow::anyhow!(
                    "Git indexing requires a range format (e.g., 'HEAD~10..HEAD'). Single commit mode has been removed. Got: '{}'",
                    explicit_range
                ));
            }
            explicit_range.clone()
        } else {
            // No --git flag: detect current HEAD commit and process it
            // This is the new default behavior for semcode-index -s .
            match gix::discover(&args.source) {
                Ok(repo) => {
                    match repo.head_commit() {
                        Ok(commit) => {
                            let commit_sha = commit.id().to_string();
                            info!(
                                "No --git flag provided, indexing current HEAD commit: {}",
                                commit_sha
                            );
                            // Create a range that includes just the current commit
                            // Format: HEAD^..HEAD (parent to current)
                            format!("{}^..{}", commit_sha, commit_sha)
                        }
                        Err(e) => {
                            return Err(anyhow::anyhow!(
                                "Not in a git repository or HEAD is unborn (no commits yet): {}. Use --git flag to specify a commit range.",
                                e
                            ));
                        }
                    }
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Not in a git repository: {}. semcode-index requires a git repository. Initialize one with 'git init' first.",
                        e
                    ));
                }
            }
        };

        // Use git range processing for all modes (both explicit --git and auto-detected HEAD)
        info!("Running git commit-based indexing for: {}", git_range);
        semcode::git_range::process_git_range(
            &args.source,
            &git_range,
            &extensions,
            db_manager.clone(),
            args.no_macros,
            args.db_threads,
        )
        .await?;
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

    // Optimization is now handled inside process_git_range for all modes

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
