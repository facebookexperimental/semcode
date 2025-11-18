// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use arrow::array::Array;
use clap::Parser;
use colored::Colorize;
use lancedb::query::{ExecutableQuery, QueryBase};
use semcode::indexer::{
    list_shas_in_range, process_commits_pipeline, process_lore_commits_pipeline,
};
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
    /// Path to the codebase directory (defaults to current directory)
    #[arg(short, long, default_value = ".")]
    source: PathBuf,

    /// Path to database directory or parent directory containing .semcode.db (default: search source dir, then current dir)
    #[arg(short, long)]
    database: Option<String>,

    /// File extensions to process (can be specified multiple times)
    #[arg(short, long, value_delimiter = ',', default_value_t = semcode::file_extensions::default_extensions_string())]
    extensions: String,

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
    #[arg(long, default_value = "2")]
    db_threads: usize,

    /// Clone and index a lore.kernel.org archive into <db_dir>/lore/<repo>
    #[arg(long, value_name = "URL")]
    lore: Option<String>,
}

/// Fetch and parse the lore.kernel.org manifest
fn fetch_lore_manifest() -> Result<serde_json::Value> {
    use flate2::read::GzDecoder;
    use std::io::Read;

    info!("Fetching lore.kernel.org manifest...");
    let response = reqwest::blocking::get("https://lore.kernel.org/manifest.js.gz")?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to fetch manifest: HTTP {}",
            response.status()
        ));
    }

    let bytes = response.bytes()?;
    let mut decoder = GzDecoder::new(&bytes[..]);
    let mut json_str = String::new();
    decoder.read_to_string(&mut json_str)?;

    let manifest: serde_json::Value = serde_json::from_str(&json_str)?;
    info!("Successfully fetched and parsed manifest");

    // Print manifest in debug mode
    if std::env::var("SEMCODE_DEBUG").as_deref() == Ok("debug") {
        eprintln!("\n=== Lore Manifest ===");
        eprintln!("{}", serde_json::to_string_pretty(&manifest)?);
        eprintln!("===================\n");
    }

    Ok(manifest)
}

/// Resolve a lore list name to a full git URL
fn resolve_lore_url(lore_arg: &str, manifest: &serde_json::Value) -> Result<String> {
    // Parse the list name and optional archive number
    let (list_name, archive_num) = if let Some(slash_pos) = lore_arg.find('/') {
        let (name, num) = lore_arg.split_at(slash_pos);
        let num = num.trim_start_matches('/');
        (name, Some(num))
    } else {
        (lore_arg, None)
    };

    // The manifest structure has keys like "/lkml/git/0.git", "/lkml/git/1.git", etc.
    let lists = manifest
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Manifest is not a JSON object"))?;

    // Find all entries matching the list name pattern
    let pattern = format!("/{}/git/", list_name);
    let mut matching_archives: Vec<(u32, String)> = Vec::new();

    for (key, _value) in lists.iter() {
        if key.starts_with(&pattern) && key.ends_with(".git") {
            // Extract the archive number from the path
            // Example: "/lkml/git/17.git" -> extract "17"
            if let Some(num_str) = key
                .strip_prefix(&pattern)
                .and_then(|s| s.strip_suffix(".git"))
            {
                if let Ok(num) = num_str.parse::<u32>() {
                    let url = format!("https://lore.kernel.org{}", key);
                    matching_archives.push((num, url));
                }
            }
        }
    }

    if matching_archives.is_empty() {
        return Err(anyhow::anyhow!(
            "List '{}' not found in manifest. Check available lists with SEMCODE_DEBUG=debug",
            list_name
        ));
    }

    // Sort by archive number
    matching_archives.sort_by_key(|(num, _)| *num);

    if let Some(num) = archive_num {
        // Specific archive requested
        let requested_num = num
            .parse::<u32>()
            .map_err(|_| anyhow::anyhow!("Invalid archive number '{}'. Must be a number.", num))?;

        matching_archives
            .into_iter()
            .find(|(n, _)| *n == requested_num)
            .map(|(_, url)| url)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Archive {}/{} not found in manifest",
                    list_name,
                    requested_num
                )
            })
    } else {
        // Find the latest archive (highest number)
        let (max_num, url) = matching_archives
            .last()
            .ok_or_else(|| anyhow::anyhow!("No archives found for list '{}'", list_name))?;

        info!(
            "Resolved '{}' to latest archive: {}/{} (found {} total archives)",
            list_name,
            list_name,
            max_num,
            matching_archives.len()
        );
        Ok(url.clone())
    }
}

/// Clone a lore.kernel.org archive into <db_dir>/lore/<repo>
async fn clone_lore_repository(lore_url: &str, db_path: &str) -> Result<PathBuf> {
    use std::fs;

    // Determine if lore_url is a direct URL or a list name
    let final_url = if lore_url.starts_with("http://") || lore_url.starts_with("https://") {
        // Direct URL provided - try to use it as-is
        info!("Using provided URL: {}", lore_url);

        // Check if it's a git repository by trying to clone
        // We'll validate this later in the actual clone attempt
        lore_url.to_string()
    } else {
        // Not a URL - treat as a list name and fetch manifest
        info!(
            "Resolving list name '{}' from lore.kernel.org manifest",
            lore_url
        );
        println!("Fetching manifest from lore.kernel.org...");
        let manifest = fetch_lore_manifest()?;
        let resolved_url = resolve_lore_url(lore_url, &manifest)?;
        println!("Resolved '{}' to: {}", lore_url, resolved_url);
        info!("Resolved to URL: {}", resolved_url);
        resolved_url
    };

    // Extract list path from URL
    // Example: "https://lore.kernel.org/bpf/git/0.git" -> "bpf/0"
    // We want to remove the "/git/" component that appears in the manifest URLs
    // and strip the .git suffix from the final component
    let url_parts: Vec<&str> = final_url.trim_end_matches('/').split('/').collect();

    // Find where "lore.kernel.org" ends and extract everything after it
    let lore_index = url_parts
        .iter()
        .position(|&part| part.contains("lore.kernel.org"));
    let repo_name = if let Some(idx) = lore_index {
        // Get all parts after lore.kernel.org
        let parts_after = &url_parts[(idx + 1)..];

        // Filter out "git" component if present
        // Example: ["bpf", "git", "0.git"] -> ["bpf", "0.git"]
        let filtered_parts: Vec<&str> = parts_after
            .iter()
            .filter(|&&part| part != "git")
            .copied()
            .collect();

        // Strip .git suffix from the last component
        // Example: "bpf/0.git" -> "bpf/0"
        if filtered_parts.is_empty() {
            return Err(anyhow::anyhow!("Invalid lore URL: {}", final_url));
        }

        let path_parts = filtered_parts;
        let last_idx = path_parts.len() - 1;
        let last_part = path_parts[last_idx]
            .strip_suffix(".git")
            .unwrap_or(path_parts[last_idx]);

        if last_idx == 0 {
            last_part.to_string()
        } else {
            format!("{}/{}", path_parts[..last_idx].join("/"), last_part)
        }
    } else {
        // Fallback: just use the last two parts, filtering out "git"
        let filtered_parts: Vec<&str> = url_parts
            .iter()
            .rev()
            .take(3) // Take last 3 parts in case "git" is in there
            .filter(|&&part| part != "git")
            .take(2) // Only keep 2 parts
            .copied()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        if filtered_parts.is_empty() {
            return Err(anyhow::anyhow!("Invalid lore URL: {}", final_url));
        }

        // Strip .git suffix from the last component
        let last_idx = filtered_parts.len() - 1;
        let last_part = filtered_parts[last_idx]
            .strip_suffix(".git")
            .unwrap_or(filtered_parts[last_idx]);

        if last_idx == 0 {
            last_part.to_string()
        } else {
            format!("{}/{}", filtered_parts[..last_idx].join("/"), last_part)
        }
    };

    // Create lore directory structure
    let lore_base_dir = PathBuf::from(db_path).join("lore");
    let clone_path = lore_base_dir.join(repo_name);

    // Create the full directory tree including any subdirectories (e.g., lore/lkml/17)
    // The parent() gives us everything except the final component, which will be created by git clone
    if let Some(parent) = clone_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Check if already cloned
    if clone_path.exists() {
        info!("Lore archive already exists at: {}", clone_path.display());

        // Fetch new commits from remote
        info!("Fetching new commits from remote...");
        let repo = gix::discover(&clone_path)?;

        // Find the remote named "origin"
        let remote = repo.find_remote("origin")?;

        // Connect and fetch - the receive() call automatically updates references
        let connection = remote
            .connect(gix::remote::Direction::Fetch)?
            .prepare_fetch(gix::progress::Discard, Default::default())?;

        let fetch_outcome =
            connection.receive(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)?;

        // The receive() method in gix automatically calls refs::update() internally,
        // so references should already be updated. Let's report what happened.
        match &fetch_outcome.status {
            gix::remote::fetch::Status::NoPackReceived { update_refs, .. } => {
                info!(
                    "No new pack received. {} references checked, {} updated",
                    update_refs.updates.len(),
                    update_refs.edits.len()
                );
            }
            gix::remote::fetch::Status::Change { update_refs, .. } => {
                info!(
                    "Fetch complete: {} references checked, {} updated",
                    update_refs.updates.len(),
                    update_refs.edits.len()
                );
            }
        }

        // Note: We don't need to update the working tree.
        // The lore indexer reads emails directly from git objects using gix,
        // accessing the 'm' files from the object database, not the working directory.
        // This is more efficient and doesn't require checking out files.

        return Ok(clone_path);
    }

    println!(
        "Cloning lore archive from {} to {}",
        final_url,
        clone_path.display()
    );
    info!(
        "Cloning lore archive from {} to {}",
        final_url,
        clone_path.display()
    );

    // Use gix to clone the repository
    // prepare_clone returns a PrepareFetch which can be configured and then executed
    let mut prepare_clone = gix::prepare_clone(final_url.as_str(), &clone_path)?;

    // Fetch and prepare for checkout
    let (mut prepare_checkout, _fetch_outcome) = prepare_clone
        .fetch_then_checkout(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)?;

    // Checkout the working tree
    let (_repo, _checkout_outcome) =
        prepare_checkout.main_worktree(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)?;

    info!(
        "Successfully cloned lore archive to: {}",
        clone_path.display()
    );

    Ok(clone_path)
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

    // Process database path first (needed for lore cloning)
    let database_path = process_database_path(args.database.as_deref(), Some(&args.source));

    // Handle --lore option if provided - clone and index entire archive
    if let Some(ref lore_url) = args.lore {
        info!("Lore archive processing requested");

        // Clone the repository
        let clone_path = clone_lore_repository(lore_url, &database_path).await?;
        info!("Lore archive cloned to: {}", clone_path.display());

        // Create database manager
        let db_manager =
            DatabaseManager::new(&database_path, args.source.to_string_lossy().to_string()).await?;
        db_manager.create_tables().await?;

        // Get all commits from the lore repository
        info!("Discovering all commits in lore archive...");
        let lore_repo = gix::discover(&clone_path)?;

        // Get the remote tracking branch to include all fetched commits
        // Try refs/remotes/origin/master first, then refs/remotes/origin/main as fallback
        let mut start_ref = lore_repo
            .find_reference("refs/remotes/origin/master")
            .or_else(|_| lore_repo.find_reference("refs/remotes/origin/main"))
            .or_else(|_| {
                // Fallback to HEAD if remote tracking branches don't exist (shouldn't happen after fetch)
                info!("Remote tracking branch not found, using HEAD");
                lore_repo
                    .head()?
                    .try_into_referent()
                    .ok_or_else(|| anyhow::anyhow!("HEAD is not a symbolic reference"))
            })?;

        let start_commit = start_ref.peel_to_commit()?;

        // Use rev_walk to get all commits reachable from the remote tracking branch
        let walk = lore_repo
            .rev_walk([start_commit.id()])
            .sorting(gix::revision::walk::Sorting::ByCommitTime(
                Default::default(),
            ))
            .all()?;

        let mut all_commit_shas = Vec::new();
        for info in walk {
            let info = info?;
            all_commit_shas.push(info.id().to_string());
        }

        // Reverse to get chronological order (oldest first)
        all_commit_shas.reverse();

        let total_commits = all_commit_shas.len();
        info!("Found {} total commits in lore archive", total_commits);

        // Get already indexed commits from database
        println!("Checking for already-indexed commits...");
        let existing_commits: HashSet<String> = {
            let table = db_manager.connection().open_table("lore").execute().await?;
            let stream = table
                .query()
                .select(lancedb::query::Select::Columns(vec![
                    "git_commit_sha".to_string()
                ]))
                .execute()
                .await?;

            use futures::TryStreamExt;
            let batches: Vec<_> = stream.try_collect().await?;

            let mut shas = HashSet::new();
            for batch in batches {
                if let Some(column) = batch.column_by_name("git_commit_sha") {
                    if let Some(string_array) =
                        column.as_any().downcast_ref::<arrow::array::StringArray>()
                    {
                        for i in 0..string_array.len() {
                            shas.insert(string_array.value(i).to_string());
                        }
                    }
                }
            }
            shas
        };

        // Filter out already indexed commits
        let new_commits: Vec<String> = all_commit_shas
            .into_iter()
            .filter(|sha| !existing_commits.contains(sha))
            .collect();

        let already_indexed = total_commits - new_commits.len();
        if already_indexed > 0 {
            println!(
                "{} commits already indexed, processing {} new commits",
                already_indexed,
                new_commits.len()
            );
        } else {
            println!("Processing all {} commits", new_commits.len());
        }

        if new_commits.is_empty() {
            println!("All commits in lore archive are already indexed!");
            return Ok(());
        }

        // Process new commits
        let start_time = std::time::Instant::now();
        let batch_size = 1024;
        let num_workers = num_cpus::get();

        let db_manager = Arc::new(db_manager);
        process_lore_commits_pipeline(
            &clone_path,
            new_commits.clone(),
            db_manager.clone(),
            batch_size,
            num_workers,
            args.db_threads,
        )
        .await?;

        let total_time = start_time.elapsed();

        println!("\n=== Lore Email Indexing Complete ===");
        println!("Total time: {:.1}s", total_time.as_secs_f64());
        println!("New emails indexed: {}", new_commits.len());
        println!("Total emails in archive: {}", total_commits);

        // Create FTS indices for lore table after data is inserted
        println!("\nCreating FTS indices for lore table...");
        match db_manager.create_lore_fts_indices().await {
            Ok(_) => println!("✓ FTS indices created successfully"),
            Err(e) => eprintln!("Warning: Failed to create FTS indices: {}", e),
        }

        // Check if optimization is needed after lore indexing
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

        println!("\nTo query this database, run:");
        println!("  semcode --database {}", database_path);

        return Ok(());
    }

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

    // Database path already processed earlier for lore cloning
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
            .split(',')
            .map(|ext| ext.trim().trim_start_matches('.').to_string())
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

                        // Generate vectors for lore emails
                        println!("Generating vectors for lore emails...");
                        match measure!("lore_vector_generation", {
                            db_manager.update_lore_vectors(&vectorizer).await
                        }) {
                            Ok(_) => {
                                println!("Lore email vector generation completed successfully")
                            }
                            Err(e) => error!("Failed to generate lore vectors: {}", e),
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
