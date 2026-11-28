// SPDX-License-Identifier: MIT OR Apache-2.0
mod index_impl;

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use index_impl::result::{ArchiveReport, BranchReport, Outcome, Report, ReportSink};
use semcode::indexer::{
    list_shas_in_range, process_commits_pipeline, process_lore_commits_pipeline, KnownLoreIds,
    LoreIndexIncomplete,
};
use semcode::{measure, process_database_path, CodeVectorizer, DatabaseManager};
// Temporary call relationships are now embedded in function JSON columns
use semcode::perf_monitor::PERF_STATS;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Upper bound on tokio worker threads and lore parser threads.  One
/// thread per CPU (300+ on large hosts) spends more time in futex and
/// allocator contention than it gains: lore indexing is limited by the
/// database inserters, not by parsing.  The other modes do their CPU
/// work on rayon, std threads or spawn_blocking, not tokio workers.
/// The exception is lance's FTS index build, which tokenizes on tokio
/// workers, so a full lore FTS (re)build is capped too; set
/// TOKIO_WORKER_THREADS to lift the cap.
const MAX_THREADS: usize = 32;

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

    /// File extensions to process (comma-separated). Omitted means the
    /// recorded build options when the index has them, else the indexer
    /// defaults — a later run never silently widens or narrows the build.
    #[arg(short, long)]
    extensions: Option<String>,

    /// Include directories (can be specified multiple times).
    /// Only files under these dirs are indexed. Relative paths resolve
    /// against the repository root; the source dir itself is always in scope.
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

    /// Write the performance statistics as JSON to this file (implies --perf;
    /// source and vector indexing only)
    #[arg(long, value_name = "FILE")]
    perf_json: Option<PathBuf>,

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

    /// Clone and index lore.kernel.org archives into <db_dir>/lore/<repo>
    /// Accepts comma-separated list of archives (e.g., --lore bpf,netdev,lkml/0)
    /// Without arguments, refreshes all previously indexed archives
    /// Run branch indexing in a separate invocation.
    #[arg(long, value_name = "LIST", value_delimiter = ',', num_args = 0..)]
    lore: Option<Vec<String>>,

    /// Leave the lore archive git repositories unpacked after fetching
    #[arg(long)]
    no_lore_repack: bool,

    // ==================== Multi-Branch Indexing ====================
    /// Index a specific branch (can be specified multiple times)
    /// Example: --branch main --branch develop
    #[arg(long, value_name = "BRANCH")]
    branch: Vec<String>,

    /// Comma-separated list of branches to index
    /// Example: --branches main,develop,feature-x
    #[arg(long, value_name = "LIST", value_delimiter = ',')]
    branches: Vec<String>,

    /// Index all local branches
    #[arg(long)]
    all_branches: bool,

    /// Include remote-tracking branches when using --all-branches
    #[arg(long)]
    remote_branches: bool,

    /// Only index branches that have new commits since last indexed
    /// (skip branches already indexed at current tip)
    #[arg(long)]
    update_branches: bool,

    /// Write a JSON report of per-branch or per-archive outcomes to PATH.
    /// Branch and lore modes only; see docs/index-result.md for the format.
    #[arg(long, value_name = "PATH")]
    result_json: Option<PathBuf>,
}

/// Fetch and parse the lore.kernel.org manifest
async fn fetch_lore_manifest() -> Result<serde_json::Value> {
    fetch_lore_manifest_from_url("https://lore.kernel.org/manifest.js.gz").await
}

async fn fetch_lore_manifest_from_url(url: &str) -> Result<serde_json::Value> {
    use flate2::read::GzDecoder;
    use std::io::Read;

    info!("Fetching lore.kernel.org manifest...");
    let response = reqwest::get(url).await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to fetch manifest: HTTP {}",
            response.status()
        ));
    }

    let bytes = response.bytes().await?;
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
        let manifest = fetch_lore_manifest().await?;
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
        release_fetched_pack(&fetch_outcome.status);

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

/// Discover all existing lore archive repositories in <db_dir>/lore/
fn discover_lore_archives(db_path: &str) -> Result<Vec<PathBuf>> {
    use std::fs;

    let lore_base_dir = PathBuf::from(db_path).join("lore");

    if !lore_base_dir.exists() {
        return Ok(Vec::new());
    }

    let mut archives = Vec::new();

    // Recursively find directories that are git repositories
    fn find_git_repos(dir: &Path, repos: &mut Vec<PathBuf>) -> Result<()> {
        if !dir.is_dir() {
            return Ok(());
        }

        // Check if this directory is a git repo (has .git or is a bare repo with objects/)
        let git_dir = dir.join(".git");
        let objects_dir = dir.join("objects");
        if git_dir.exists() || objects_dir.exists() {
            repos.push(dir.to_path_buf());
            return Ok(());
        }

        // Otherwise recurse into subdirectories
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                find_git_repos(&path, repos)?;
            }
        }

        Ok(())
    }

    find_git_repos(&lore_base_dir, &mut archives)?;

    // Sort for consistent ordering
    archives.sort();

    Ok(archives)
}

/// Extract list name and archive number from a local lore archive path.
/// Returns (list_name, archive_number) if the path follows the expected structure.
///
/// Expected path structure: `<db_path>/lore/<list_name>/<archive_number>`
/// Example: `.semcode.db/lore/lkml/17` -> ("lkml", 17)
fn parse_lore_archive_path(archive_path: &Path, lore_base: &Path) -> Option<(String, u32)> {
    // Get the path relative to lore base
    let relative = archive_path.strip_prefix(lore_base).ok()?;
    let components: Vec<_> = relative.components().collect();

    if components.len() != 2 {
        return None;
    }

    let list_name = components[0].as_os_str().to_str()?;
    let archive_num_str = components[1].as_os_str().to_str()?;
    let archive_num = archive_num_str.parse::<u32>().ok()?;

    Some((list_name.to_string(), archive_num))
}

/// Check for new lore archives available on lore.kernel.org that are not locally cached.
/// Returns a list of (list_name, new_archive_numbers) for lists with newer archives.
fn find_new_lore_archives(
    local_archives: &[PathBuf],
    lore_base: &Path,
    manifest: &serde_json::Value,
) -> Vec<(String, Vec<u32>)> {
    use std::collections::HashMap;

    // Build a map of list_name -> max local archive number
    let mut local_max: HashMap<String, u32> = HashMap::new();
    for archive_path in local_archives {
        if let Some((list_name, archive_num)) = parse_lore_archive_path(archive_path, lore_base) {
            local_max
                .entry(list_name)
                .and_modify(|max| {
                    if archive_num > *max {
                        *max = archive_num;
                    }
                })
                .or_insert(archive_num);
        }
    }

    if local_max.is_empty() {
        return Vec::new();
    }

    let lists = match manifest.as_object() {
        Some(obj) => obj,
        None => return Vec::new(),
    };

    let mut new_archives: Vec<(String, Vec<u32>)> = Vec::new();

    for (list_name, max_local) in &local_max {
        // Find all archives for this list in the manifest
        let pattern = format!("/{}/git/", list_name);
        let mut remote_archives: Vec<u32> = Vec::new();

        for key in lists.keys() {
            if key.starts_with(&pattern) && key.ends_with(".git") {
                if let Some(num_str) = key
                    .strip_prefix(&pattern)
                    .and_then(|s| s.strip_suffix(".git"))
                {
                    if let Ok(num) = num_str.parse::<u32>() {
                        if num > *max_local {
                            remote_archives.push(num);
                        }
                    }
                }
            }
        }

        if !remote_archives.is_empty() {
            remote_archives.sort();
            new_archives.push((list_name.clone(), remote_archives));
        }
    }

    // Sort by list name for consistent output
    new_archives.sort_by(|a, b| a.0.cmp(&b.0));
    new_archives
}

/// Fetch new commits from remote for an existing lore archive.
/// Returns the opened repository on success so callers don't need to re-discover it.
///
/// This function wraps blocking git I/O in spawn_blocking to avoid blocking the
/// async executor thread during network operations.
async fn fetch_lore_archive(repo_path: PathBuf) -> Result<gix::Repository> {
    info!(
        "Fetching new commits from remote for {}...",
        repo_path.display()
    );

    // Run blocking git operations on the blocking thread pool
    let repo = tokio::task::spawn_blocking(move || -> Result<gix::Repository> {
        let repo = gix::discover(&repo_path)?;

        // Find the remote named "origin"
        let remote = repo.find_remote("origin")?;

        // Connect and fetch
        let connection = remote
            .connect(gix::remote::Direction::Fetch)?
            .prepare_fetch(gix::progress::Discard, Default::default())?;

        let fetch_outcome =
            connection.receive(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)?;
        release_fetched_pack(&fetch_outcome.status);

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

        Ok(repo)
    })
    .await??;

    Ok(repo)
}

/// Release the pack a fetch wrote.
///
/// gix holds a fetched pack with a `.keep` file until the refs that
/// bind it are updated, and leaves the file in place when no ref
/// changed. A pack held that way is left out of every rollup, so drop
/// the hold here.
fn release_fetched_pack(status: &gix::remote::fetch::Status) {
    let gix::remote::fetch::Status::Change {
        write_pack_bundle, ..
    } = status
    else {
        return;
    };
    if let Some(keep) = &write_pack_bundle.keep_path {
        match std::fs::remove_file(keep) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!("Failed to remove {}: {}", keep.display(), e),
        }
    }
}

/// Packs a lore archive accumulates before a rollup earns its cost.
const LORE_REPACK_THRESHOLD: usize = 20;

/// Consolidate the packs a lore archive has accumulated.
///
/// Runs after indexing rather than straight after the fetch so that a
/// rollup of a large archive does not hold up the emails the caller
/// came for, and only when indexing succeeded, so that it does not
/// delay the report of a failure either. A failure of the rollup is
/// reported and the run carries on, since an archive that keeps its
/// packs stays correct and only searches more slowly.
async fn repack_lore_archive(
    args: &Args,
    archive_path: PathBuf,
    display_name: &str,
    indexed: &Result<LoreIndexResult>,
) {
    if args.no_lore_repack || indexed.is_err() {
        return;
    }
    let outcome = tokio::task::spawn_blocking(move || {
        semcode::lore_repack::repack_if_needed(&archive_path, LORE_REPACK_THRESHOLD)
    })
    .await;

    match outcome {
        Ok(Ok(Some(stats))) => println!(
            "[{}] Repacked {} of {} packs, {} objects",
            display_name, stats.packs_rolled_up, stats.packs_before, stats.objects_written
        ),
        Ok(Ok(None)) => {}
        Ok(Err(e)) => eprintln!("Warning: failed to repack {}: {:#}", display_name, e),
        Err(e) => eprintln!("Warning: the repack of {} did not run: {}", display_name, e),
    }
}

/// Rows a failed archive appended before it failed, counted as
/// LoreIndexResult::new_emails counts them for an archive that finished.
/// They stay in the table, so they count towards the compaction and FTS
/// update that new emails trigger.
fn appended_before_failure(e: &anyhow::Error) -> usize {
    e.downcast_ref::<LoreIndexIncomplete>()
        .map_or(0, |incomplete| incomplete.appended)
}

/// Result of indexing a single lore archive
struct LoreIndexResult {
    /// Rows appended to the lore table.  Emails already stored, such as
    /// crossposts, and commits that hold no message are not counted.
    new_emails: usize,
    /// Commits of the archive that were not yet recorded as indexed.
    /// Zero means the archive was already current.
    new_commits: usize,
    total_emails: usize,
}

/// The report entry for one archive. An archive is current when it had no
/// commit left to index, whether or not its new commits added emails.
fn archive_report(name: String, indexed: &Result<LoreIndexResult>) -> ArchiveReport {
    match indexed {
        Ok(result) if result.new_commits == 0 => ArchiveReport::new(&name, Outcome::Current, None),
        Ok(_) => ArchiveReport::new(&name, Outcome::Indexed, None),
        Err(e) => failed_archive(name, e),
    }
}

fn failed_archive(name: String, e: &anyhow::Error) -> ArchiveReport {
    ArchiveReport::new(&name, Outcome::Failed, Some(format!("{e:#}")))
}

/// Print the failed archives of a lore run, and return the error that
/// fails the run if there are any.
fn lore_failure(reports: &[ArchiveReport], verb: &str) -> Option<anyhow::Error> {
    let failed: Vec<&ArchiveReport> = reports
        .iter()
        .filter(|r| r.outcome == Outcome::Failed)
        .collect();
    if failed.is_empty() {
        return None;
    }
    eprintln!("\nFailed archives:");
    for r in &failed {
        eprintln!("  {}: {}", r.name, r.error.as_deref().unwrap_or(""));
    }
    Some(anyhow::anyhow!(
        "{} of {} lore archive(s) {}",
        failed.len(),
        reports.len(),
        verb
    ))
}

/// Publish the lore report, if one was asked for, then fail the run if
/// any archive failed.
fn finish_lore_run(
    report: Option<ReportSink>,
    reports: Vec<ArchiveReport>,
    failure: Option<anyhow::Error>,
) -> Result<()> {
    if let Some(sink) = report {
        sink.publish(&Report::archives(reports))?;
    }
    match failure {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Index a lore archive repository, filtering out already-indexed commits.
/// This is the common logic shared by both --lore and --refresh-lore handlers.
/// Every archive of one run shares `known_ids`.
#[allow(clippy::too_many_arguments)]
async fn index_lore_archive(
    lore_repo: gix::Repository,
    archive_path: &Path,
    display_name: &str,
    db_manager: &Arc<DatabaseManager>,
    batch_size: usize,
    num_workers: usize,
    db_threads: usize,
    known_ids: &KnownLoreIds,
) -> Result<LoreIndexResult> {
    // Get the remote tracking branch to include all fetched commits
    // Try refs/remotes/origin/master first, then refs/remotes/origin/main as fallback
    let mut start_ref = lore_repo
        .find_reference("refs/remotes/origin/master")
        .or_else(|_| lore_repo.find_reference("refs/remotes/origin/main"))
        .or_else(|_| {
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
        all_commit_shas.push(info?.id().to_string());
    }

    // Reverse to get chronological order (oldest first)
    all_commit_shas.reverse();

    let total_commits = all_commit_shas.len();
    info!("Found {} total commits in lore archive", total_commits);

    // Get already indexed commits from database
    println!("Checking for already-indexed commits...");
    let existing_commits = db_manager.get_indexed_lore_commits().await?;

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
        println!("All commits in {} are already indexed!", display_name);
        return Ok(LoreIndexResult {
            new_emails: 0,
            new_commits: 0,
            total_emails: total_commits,
        });
    }

    let new_count = new_commits.len();

    // Process new commits
    let new_emails = process_lore_commits_pipeline(
        archive_path,
        new_commits,
        db_manager.clone(),
        batch_size,
        num_workers,
        db_threads,
        known_ids,
    )
    .await?;

    println!(
        "Indexed {} new emails from {} new commits of {} (total in archive: {})",
        new_emails, new_count, display_name, total_commits
    );

    Ok(LoreIndexResult {
        new_emails,
        new_commits: new_count,
        total_emails: total_commits,
    })
}

// ==================== Branch Indexing Support ====================

/// Extensions and macro flag for this CLI run: an explicit flag wins;
/// otherwise the recorded build options win, unless `--clear` restarts
/// the build and drops the record; otherwise the indexer defaults. A
/// later CLI run must not silently widen a narrowed index (or narrow a
/// widened one): the record is the build. No flag turns macros back on:
/// only `--clear` drops an inherited `--no-macros`.
async fn cli_options(args: &Args, db_manager: &DatabaseManager) -> Result<(Vec<String>, bool)> {
    // The record is dropped beside every wipe, so a restart reads no
    // record and falls to the defaults below: one mechanism, not two.
    let recorded = db_manager.recorded_index_options().await?;
    let extensions = match (args.extensions.as_deref(), &recorded) {
        (Some(explicit), _) => explicit
            .split(',')
            .map(|ext| ext.trim().trim_start_matches('.').to_string())
            .collect(),
        (None, Some((recorded_extensions, _))) => recorded_extensions.clone(),
        (None, None) => semcode::file_extensions::default_extensions(),
    };
    let no_macros = args.no_macros || recorded.is_some_and(|(_, no_macros)| no_macros);
    Ok((extensions, no_macros))
}

/// Whether any branch flag selects branch indexing mode.
fn branch_mode_requested(args: &Args) -> bool {
    !args.branch.is_empty() || !args.branches.is_empty() || args.all_branches
}

/// The first branch flag on the command line, if any. Lore and branch
/// indexing never share a run; this names the flag for the rejection so
/// every mixed invocation fails the same way with or without a report.
fn first_branch_flag(args: &Args) -> Option<&'static str> {
    if !args.branch.is_empty() {
        Some("--branch")
    } else if !args.branches.is_empty() {
        Some("--branches")
    } else if args.all_branches {
        Some("--all-branches")
    } else if args.remote_branches {
        Some("--remote-branches")
    } else if args.update_branches {
        Some("--update-branches")
    } else {
        None
    }
}

/// `--result-json` reports branch or lore archive outcomes only; refuse it
/// where another mode would run instead, before anything touches the
/// database. Lore and branch flags together are refused in async_main.
fn check_result_json_mode(args: &Args) -> Result<()> {
    if !branch_mode_requested(args) && args.lore.is_none() {
        anyhow::bail!("--result-json requires --branch, --branches, --all-branches or --lore");
    }
    let conflicts = [
        ("--git", args.git.is_some()),
        ("--commits", args.commits.is_some()),
        ("--vectors", args.vectors),
    ];
    if let Some((flag, _)) = conflicts.iter().find(|(_, set)| *set) {
        anyhow::bail!("--result-json cannot be combined with {flag}");
    }
    Ok(())
}

/// A branch requested on the command line, resolved once up front.
struct BranchRequest {
    name: String,
    branch: Result<semcode::git::BranchRef, String>,
}

impl From<semcode::git::BranchRef> for BranchRequest {
    fn from(branch: semcode::git::BranchRef) -> Self {
        Self {
            name: branch.name.clone(),
            branch: Ok(branch),
        }
    }
}

/// Collect branches to index from the various branch-related CLI flags.
/// A name that does not resolve is kept as a failed request so the other
/// branches still get indexed.
fn collect_branches_to_index(args: &Args) -> Result<Vec<BranchRequest>> {
    use semcode::git::{get_branch_info, list_branches};

    let mut branch_names = Vec::new();

    // Collect branch names from --branch flags (can be repeated)
    branch_names.extend(args.branch.iter().cloned());

    // Collect from --branches (comma-separated)
    branch_names.extend(args.branches.iter().cloned());

    // Deduplicate while preserving order
    let mut seen = HashSet::new();
    branch_names.retain(|b| seen.insert(b.clone()));

    let mut branches: Vec<BranchRequest> = branch_names
        .iter()
        .map(|name| BranchRequest {
            name: name.clone(),
            branch: get_branch_info(&args.source, name)
                .map_err(|e| format!("Branch '{name}' does not exist: {e}")),
        })
        .collect();

    // If --all-branches is set, get all branches from git
    if args.all_branches {
        let git_branches = list_branches(&args.source, args.remote_branches)?;
        for branch in git_branches {
            // Skip if already added from --branch/--branches
            if !branches.iter().any(|b| b.name == branch.name) {
                branches.push(branch.into());
            }
        }
    }

    Ok(branches)
}

/// Run branch indexing mode - index multiple branches.
///
/// A branch that fails is reported and the rest are still indexed; the
/// run fails at the end if any branch did. Errors before the first branch
/// (opening the database, --clear, refused build options) fail the run at
/// once and publish no report.
async fn run_branch_indexing(
    args: Args,
    branches: Vec<BranchRequest>,
    report: Option<ReportSink>,
) -> Result<()> {
    info!("Starting multi-branch indexing mode");
    info!(
        "Branches to index: {:?}",
        branches.iter().map(|b| &b.name).collect::<Vec<_>>()
    );

    // A typo must not cost the whole index: --clear wipes everything
    // before the first branch, and the misspelled one would put nothing
    // back.
    if args.clear {
        if let Some(Err(e)) = branches.iter().map(|r| &r.branch).find(|b| b.is_err()) {
            anyhow::bail!("refusing --clear: {e}");
        }
    }

    // Process database path
    let database_path = process_database_path(args.database.as_deref(), Some(&args.source));

    // Create database manager wrapped in Arc for efficient sharing with process_git_range
    // (Arc::clone is cheap - just increments ref count, reuses same LanceDB connection)
    let db_manager = Arc::new(
        DatabaseManager::new(&database_path, args.source.to_string_lossy().to_string()).await?,
    );
    db_manager.create_tables().await?;

    if args.clear {
        println!("Clearing existing data...");
        db_manager.clear_all_data().await?;
        println!("Existing data cleared.");
    }

    let start_time = std::time::Instant::now();

    let stale_index = db_manager.index_predates_reader().await?;
    if stale_index {
        println!(
            "{} Index was written by an older semcode: reading every file again",
            "→".yellow()
        );
    }

    // Same rule as one-off --git ranges: an incremental branch read under
    // flags the recorded build does not hold would poison it. Check once
    // for the whole run: refusing one branch and then reading another's
    // full tree under the same flags would rewrite the record and let
    // the refused branch through on the next run.
    if (args.extensions.is_some() || args.no_macros) && !stale_index {
        let (extensions, no_macros) = cli_options(&args, &db_manager).await?;
        for request in &branches {
            let Ok(branch) = &request.branch else {
                continue;
            };
            if db_manager.get_branch_tip(&branch.name).await?.is_some() {
                refuse_scoped_option_drift(
                    &format!("branch {}", branch.name),
                    &db_manager,
                    &extensions,
                    no_macros,
                )
                .await?;
                break;
            }
        }
    }

    let mut results = Vec::with_capacity(branches.len());
    for request in branches {
        println!(
            "\n{}",
            format!("=== Processing branch: {} ===", request.name).cyan()
        );

        let result = match &request.branch {
            Ok(branch) => index_branch(&args, &db_manager, branch, stale_index)
                .await
                .map(|outcome| (outcome, branch.tip_commit.clone())),
            Err(e) => Err(anyhow::anyhow!("{e}")),
        };

        results.push(match result {
            Ok((outcome, tip)) => BranchReport {
                name: request.name,
                outcome,
                commit: Some(tip),
                error: None,
            },
            Err(e) => {
                let message = format!("{e:#}");
                eprintln!("  {} {}", "✗".red(), message);
                // What queries still see for this branch, if anything.
                let commit = db_manager
                    .get_branch_tip(&request.name)
                    .await
                    .unwrap_or_else(|e| {
                        warn!("Cannot read the recorded tip of {}: {e:#}", request.name);
                        None
                    });
                BranchReport {
                    name: request.name,
                    outcome: Outcome::Failed,
                    commit,
                    error: Some(message),
                }
            }
        });
    }

    let count = |outcome| results.iter().filter(|r| r.outcome == outcome).count();
    let total_time = start_time.elapsed();

    if count(Outcome::Failed) == 0 {
        println!(
            "\n{}",
            "=== Multi-Branch Indexing Complete ===".green().bold()
        );
    } else {
        println!(
            "\n{}",
            "=== Multi-Branch Indexing Finished With Failures ==="
                .red()
                .bold()
        );
    }
    println!("Total time: {:.1}s", total_time.as_secs_f64());
    println!("Branches indexed: {}", count(Outcome::Indexed));
    if count(Outcome::Current) > 0 {
        println!(
            "Branches skipped (already current): {}",
            count(Outcome::Current)
        );
    }
    let failed: Vec<&BranchReport> = results
        .iter()
        .filter(|r| r.outcome == Outcome::Failed)
        .collect();
    if !failed.is_empty() {
        println!("Branches failed: {}", failed.len());
        for branch in &failed {
            println!(
                "  {} {}: {}",
                "✗".red(),
                branch.name,
                branch.error.as_deref().unwrap_or("")
            );
        }
    }

    // Informational only: failing to read it must not fail the run.
    match db_manager.list_indexed_branches().await {
        Ok(indexed) if !indexed.is_empty() => {
            println!("\nIndexed branches:");
            for branch in indexed {
                println!(
                    "  {} → {} (indexed {})",
                    branch.branch_name.cyan(),
                    branch.tip_commit.get(..8).unwrap_or(&branch.tip_commit),
                    chrono::DateTime::from_timestamp(branch.indexed_at, 0)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                );
            }
        }
        Ok(_) => {}
        Err(e) => warn!("Cannot list indexed branches: {e:#}"),
    }

    println!("\nTo query this database, run:");
    println!("  semcode --database {}", database_path);

    // The errors are in the summary above; name the branches only.
    let failure = (!failed.is_empty()).then(|| {
        let names: Vec<&str> = failed.iter().map(|b| b.name.as_str()).collect();
        anyhow::anyhow!(
            "{} of {} branch(es) failed: {}",
            failed.len(),
            results.len(),
            names.join(", ")
        )
    });

    if let Some(sink) = report {
        sink.publish(&Report::branches(results))?;
    }

    match failure {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Index one branch at its resolved tip. Succeeds only once the database
/// records that tip for the branch.
async fn index_branch(
    args: &Args,
    db_manager: &Arc<DatabaseManager>,
    branch: &semcode::git::BranchRef,
    stale_index: bool,
) -> Result<Outcome> {
    let branch_name = &branch.name;
    let tip_commit = &branch.tip_commit;

    info!("Branch {} at commit {}", branch_name, &tip_commit[..8]);

    // An index written before this build does not hold what this build
    // extracts, however current its recorded tip is. Indexing the commits
    // since that tip would add nothing: the files have not changed, and
    // it is the extractor that has. Read the tree again instead.
    let indexed_tip = if stale_index {
        None
    } else {
        db_manager.get_branch_tip(branch_name).await?
    };

    // Check if branch is already indexed at current tip (if --update-branches)
    if args.update_branches && indexed_tip.as_deref() == Some(tip_commit.as_str()) {
        println!(
            "  {} Branch already indexed at current tip, skipping",
            "→".yellow()
        );
        return Ok(Outcome::Current);
    }

    // Get extensions for this indexing operation; see cli_options.
    let (extensions, no_macros) = cli_options(args, db_manager).await?;

    // Check if this is initial or incremental indexing
    if let Some(indexed_tip) = indexed_tip {
        // Incremental indexing: commits from last indexed tip to current tip
        let range = format!("{}..{}", indexed_tip, tip_commit);
        info!("Incremental indexing: {} for branch {}", range, branch_name);

        println!("  {} Processing range: {}", "→".blue(), range);

        // Get commit count for this range
        let repo = gix::discover(&args.source)
            .map_err(|e| anyhow::anyhow!("Not in a git repository: {}", e))?;

        let commit_shas = list_shas_in_range(&repo, &range)
            .with_context(|| format!("Failed to get commits for {range}"))?;

        if commit_shas.is_empty() {
            println!("  {} No new commits to index", "✓".green());
        } else {
            println!(
                "  {} Found {} commits to process",
                "→".blue(),
                commit_shas.len()
            );

            semcode::git_range::process_git_range(
                &args.source,
                &range,
                &extensions,
                db_manager.clone(),
                no_macros,
                args.db_threads,
                &args.include,
            )
            .await?;
        }
    } else {
        // Initial indexing: index the tree snapshot at the tip commit
        // This is MUCH faster than walking all commits (e.g., 80k files vs 1.4M commits for Linux)
        info!(
            "Initial indexing for branch {} (tree at {})",
            branch_name,
            &tip_commit[..8]
        );

        println!("  {} Processing tree at {}", "→".blue(), &tip_commit[..8]);

        semcode::git_range::process_git_tree(
            &args.source,
            tip_commit,
            &extensions,
            db_manager.clone(),
            no_macros,
            args.db_threads,
            &args.include,
        )
        .await?;
    }

    // Record that this branch has been indexed at the current tip
    // Use the proper remote info from BranchRef (not a naive string split)
    db_manager
        .record_branch_indexed(branch_name, tip_commit, branch.remote.as_deref())
        .await?;

    let recorded = db_manager.get_branch_tip(branch_name).await?;
    if recorded.as_deref() != Some(tip_commit.as_str()) {
        anyhow::bail!(
            "recorded tip of {branch_name} is {} after indexing {tip_commit}",
            recorded.as_deref().unwrap_or("missing")
        );
    }

    println!("  {} Branch indexed successfully", "✓".green());
    Ok(Outcome::Indexed)
}

// ==================== End Branch Indexing Support ====================

fn main() -> Result<()> {
    // #[tokio::main] starts one worker per CPU.  Cap it, but let
    // TOKIO_WORKER_THREADS override as it does for the default runtime.
    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    runtime.enable_all();
    if std::env::var_os("TOKIO_WORKER_THREADS").is_none() {
        runtime.worker_threads(num_cpus::get().min(MAX_THREADS));
    }
    runtime
        .build()
        .context("failed to build the tokio runtime")?
        .block_on(async_main())
}

async fn async_main() -> Result<()> {
    // Suppress ORT verbose logging
    std::env::set_var("ORT_LOG_LEVEL", "ERROR");

    let args = Args::parse();

    // The first termination signal raises gix's interrupt flag, which
    // its fetch, clone, and pack writing poll and stop on; the second
    // aborts the process. A rollup stopped this way releases the .keep
    // on the pack it wrote, which a kill would leave holding that pack
    // out of every later rollup.
    // SAFETY: the handler touches only atomics.
    unsafe { gix::interrupt::init_handler(1, || {}) }?;

    // Enable performance monitoring if --perf or --perf-json is set
    if args.perf || args.perf_json.is_some() {
        semcode::perf_monitor::enable_performance_monitoring();
    }
    // The statistics are written where source and vector indexing finish;
    // the lore, commits-only and branch modes return before that point.
    if args.perf_json.is_some()
        && (args.lore.is_some()
            || args.commits.is_some()
            || !args.branch.is_empty()
            || !args.branches.is_empty()
            || args.all_branches)
    {
        anyhow::bail!(
            "--perf-json is supported for source and vector indexing, not with --lore, --commits or branch indexing"
        );
    }
    // Checked now rather than when the statistics are written, after the
    // whole indexing run: a path that is a directory, or in one that does
    // not exist or cannot take a new file, fails before the database is
    // opened.
    if let Some(path) = &args.perf_json {
        ReportSink::prepare(path).context("--perf-json")?;
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
    } else if let Ok(env_jobs) = std::env::var("SEMCODE_JOBS") {
        env_jobs.parse::<usize>().unwrap_or(0)
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

    // Take down any earlier report before anything else can fail, so a
    // run that stops early never leaves a stale report behind.
    let report = match &args.result_json {
        Some(path) => {
            let sink = ReportSink::prepare(path)?;
            check_result_json_mode(&args)?;
            Some(sink)
        }
        None => None,
    };

    // Lore and branch indexing never share a run. This rides after the
    // report takedown so a rejected mix removes a stale report first.
    if let (Some(_), Some(flag)) = (&args.lore, first_branch_flag(&args)) {
        anyhow::bail!(
            "--lore cannot be used with {flag}; run branch indexing in a separate invocation"
        );
    }

    // Process database path first (needed for lore cloning)
    let database_path = process_database_path(args.database.as_deref(), Some(&args.source));

    // Handle --lore option if provided
    if let Some(lore_args) = &args.lore {
        // If --lore has arguments, clone and index specified archives
        // If --lore has no arguments, refresh all existing archives
        if !lore_args.is_empty() {
            // Deduplicate while preserving order: one report entry per
            // distinct name, as for branches.
            let mut seen = HashSet::new();
            let lore_args: Vec<&String> = lore_args
                .iter()
                .filter(|a| seen.insert(a.as_str()))
                .collect();
            info!(
                "Lore archive processing requested for {} archives",
                lore_args.len()
            );

            // Create database manager once for all archives
            let db_manager =
                DatabaseManager::new(&database_path, args.source.to_string_lossy().to_string())
                    .await?;
            db_manager.create_tables().await?;
            let db_manager = Arc::new(db_manager);

            let start_time = std::time::Instant::now();
            let batch_size = 1024;
            let num_workers = num_cpus::get().min(MAX_THREADS);

            let mut total_new_emails = 0usize;
            let mut total_emails_all_archives = 0usize;
            let mut archive_reports: Vec<ArchiveReport> = Vec::with_capacity(lore_args.len());
            let known_ids = KnownLoreIds::new();

            // Process each lore archive
            for &lore_url in &lore_args {
                println!("\n=== Processing lore archive: {} ===", lore_url);
                info!("Processing lore archive: {}", lore_url);

                // Clone the repository
                let clone_path = match clone_lore_repository(lore_url, &database_path).await {
                    Ok(path) => path,
                    Err(e) => {
                        eprintln!("Error cloning {}: {:#}", lore_url, e);
                        archive_reports.push(failed_archive(lore_url.clone(), &e));
                        continue;
                    }
                };
                info!("Lore archive cloned to: {}", clone_path.display());

                // Open the repository
                let lore_repo = match gix::discover(&clone_path) {
                    Ok(repo) => repo,
                    Err(e) => {
                        eprintln!("Error opening repository {}: {}", clone_path.display(), e);
                        archive_reports.push(failed_archive(lore_url.clone(), &e.into()));
                        continue;
                    }
                };

                // Index the archive using the shared function
                let index_result = index_lore_archive(
                    lore_repo,
                    &clone_path,
                    lore_url,
                    &db_manager,
                    batch_size,
                    num_workers,
                    args.db_threads,
                    &known_ids,
                )
                .await;

                repack_lore_archive(&args, clone_path, lore_url, &index_result).await;

                match &index_result {
                    Ok(result) => {
                        total_new_emails += result.new_emails;
                        total_emails_all_archives += result.total_emails;
                    }
                    Err(e) => {
                        eprintln!("Error indexing {}: {}", lore_url, e);
                        total_new_emails += appended_before_failure(e);
                    }
                }
                archive_reports.push(archive_report(lore_url.clone(), &index_result));
            }
            // One string per stored email: free it before compaction.
            drop(known_ids);

            let total_time = start_time.elapsed();

            println!("\n=== Lore Email Indexing Complete ===");
            println!("Total time: {:.1}s", total_time.as_secs_f64());
            println!(
                "Archives processed: {}/{}",
                archive_reports
                    .iter()
                    .filter(|r| r.outcome != Outcome::Failed)
                    .count(),
                lore_args.len()
            );
            println!("New emails indexed: {}", total_new_emails);
            println!(
                "Total emails across archives: {}",
                total_emails_all_archives
            );

            let failure = lore_failure(&archive_reports, "failed");

            if total_new_emails > 0 {
                // Compact only lore tables.  The full optimize_database()
                // method processes every table in the database including
                // code-index tables and content shards that a lore run
                // never touches.  On memory-constrained systems the
                // combined working set triggers the OOM killer.
                println!("\nCompacting lore tables...");
                match db_manager.compact_lore_tables().await {
                    Ok(true) => println!("Lore table compaction completed successfully"),
                    Ok(false) => {}
                    Err(e) => error!("Failed to compact lore tables: {}", e),
                }

                // Create FTS indices on first run; merge new rows on
                // subsequent runs.  LanceDB's native FTS engine serves
                // unindexed rows via brute-force fallback, so queries
                // remain correct before optimize completes.
                println!("\nUpdating FTS indices for lore table...");
                match db_manager.ensure_lore_fts_indices().await {
                    Ok(_) => {}
                    Err(e) => eprintln!("Warning: Failed to ensure FTS indices: {}", e),
                }
                match db_manager.optimize_lore_fts_indices().await {
                    Ok(true) => println!("FTS indices updated successfully"),
                    Ok(false) => {}
                    Err(e) => eprintln!("Warning: Failed to optimize FTS indices: {}", e),
                }
            }

            println!("\nTo query this database, run:");
            println!("  semcode --database {}", database_path);

            return finish_lore_run(report, archive_reports, failure);
        } else {
            // --lore without arguments: refresh all existing archives
            info!("Refreshing all existing lore archives");

            // Discover existing lore archives
            let archives = discover_lore_archives(&database_path)?;

            if archives.is_empty() {
                println!("No lore archives have been indexed yet.");
                println!();
                println!(
                    "To index lore.kernel.org mailing list archives, specify which lists to track:"
                );
                println!("  semcode-index --lore <list>[,<list>...]");
                println!();
                println!("Examples:");
                println!("  semcode-index --lore lkml/0          # Linux kernel mailing list (archive 0)");
                println!("  semcode-index --lore bpf,netdev      # BPF and netdev lists");
                println!("  semcode-index --lore linux-nfs/0     # NFS mailing list");
                println!();
                println!("Browse available lists at: https://lore.kernel.org/");
                return finish_lore_run(report, Vec::new(), None);
            }

            // Pre-compute lore_base and display names once
            let lore_base = PathBuf::from(&database_path).join("lore");
            // Keep a copy of archive paths for checking new archives later
            let archive_paths: Vec<PathBuf> = archives.to_vec();
            let archives_with_names: Vec<(PathBuf, String)> = archives
                .into_iter()
                .map(|archive| {
                    let display_name = archive
                        .strip_prefix(&lore_base)
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|_| archive.display().to_string());
                    (archive, display_name)
                })
                .collect();

            println!(
                "Found {} lore archive(s) to refresh:",
                archives_with_names.len()
            );
            for (_, display_name) in &archives_with_names {
                println!("  - {}", display_name);
            }
            println!();

            // Create database manager once for all archives
            let db_manager =
                DatabaseManager::new(&database_path, args.source.to_string_lossy().to_string())
                    .await?;
            db_manager.create_tables().await?;
            let db_manager = Arc::new(db_manager);

            let start_time = std::time::Instant::now();
            let batch_size = 1024;
            let num_workers = num_cpus::get().min(MAX_THREADS);
            let db_threads = args.db_threads;
            let total_archives = archives_with_names.len();

            // Process archives sequentially.  LanceDB merge_insert
            // uses a shared DataFusion memory pool, and concurrent
            // pipelines writing large lore emails exhaust it,
            // causing both to stall indefinitely.
            let mut results: Vec<Result<(String, LoreIndexResult), (String, anyhow::Error)>> =
                Vec::with_capacity(total_archives);
            let known_ids = KnownLoreIds::new();

            for (archive_path, display_name) in archives_with_names {
                println!("\n=== Refreshing lore archive: {} ===", display_name);
                println!("[{}] Fetching updates from remote...", display_name);

                let lore_repo = match fetch_lore_archive(archive_path.clone()).await {
                    Ok(repo) => repo,
                    Err(e) => {
                        results.push(Err((display_name, e)));
                        continue;
                    }
                };

                let index_result = index_lore_archive(
                    lore_repo,
                    &archive_path,
                    &display_name,
                    &db_manager,
                    batch_size,
                    num_workers,
                    db_threads,
                    &known_ids,
                )
                .await;

                repack_lore_archive(&args, archive_path, &display_name, &index_result).await;

                match index_result {
                    Ok(result) => results.push(Ok((display_name, result))),
                    Err(e) => results.push(Err((display_name, e))),
                }
            }
            // One string per stored email: free it before compaction.
            drop(known_ids);

            // Aggregate results
            let mut total_new_emails = 0usize;
            let mut total_emails_all_archives = 0usize;
            let mut archives_processed = 0usize;
            let mut archive_reports: Vec<ArchiveReport> = Vec::with_capacity(total_archives);

            for result in results {
                match result {
                    Ok((name, index_result)) => {
                        total_new_emails += index_result.new_emails;
                        total_emails_all_archives += index_result.total_emails;
                        archives_processed += 1;
                        archive_reports.push(archive_report(name, &Ok(index_result)));
                    }
                    Err((name, e)) => {
                        total_new_emails += appended_before_failure(&e);
                        archive_reports.push(failed_archive(name, &e));
                    }
                }
            }

            let total_time = start_time.elapsed();

            println!("\n=== Lore Archive Refresh Complete ===");
            println!("Total time: {:.1}s", total_time.as_secs_f64());
            println!(
                "Archives refreshed: {}/{}",
                archives_processed, total_archives
            );
            println!("New emails indexed: {}", total_new_emails);
            println!(
                "Total emails across archives: {}",
                total_emails_all_archives
            );

            let failure = lore_failure(&archive_reports, "failed to refresh");

            if total_new_emails > 0 {
                println!("\nCompacting lore tables...");
                match db_manager.compact_lore_tables().await {
                    Ok(true) => println!("Lore table compaction completed successfully"),
                    Ok(false) => {}
                    Err(e) => error!("Failed to compact lore tables: {}", e),
                }

                println!("\nUpdating FTS indices for lore table...");
                match db_manager.ensure_lore_fts_indices().await {
                    Ok(_) => {}
                    Err(e) => eprintln!("Warning: Failed to ensure FTS indices: {}", e),
                }
                match db_manager.optimize_lore_fts_indices().await {
                    Ok(true) => println!("FTS indices updated successfully"),
                    Ok(false) => {}
                    Err(e) => eprintln!("Warning: Failed to optimize FTS indices: {}", e),
                }
            }

            // Check for new archives available on lore.kernel.org
            println!("\nChecking for new lore archives...");
            match fetch_lore_manifest().await {
                Ok(manifest) => {
                    let new_archives =
                        find_new_lore_archives(&archive_paths, &lore_base, &manifest);
                    if new_archives.is_empty() {
                        println!("All tracked mailing lists are up to date.");
                    } else {
                        println!(
                            "\n{}",
                            "New archives available on lore.kernel.org:".yellow()
                        );
                        for (list_name, archive_nums) in &new_archives {
                            let nums_str: Vec<String> =
                                archive_nums.iter().map(|n| n.to_string()).collect();
                            println!("  {}: archive(s) {}", list_name.cyan(), nums_str.join(", "));
                        }
                        println!("\nTo add these archives, run:");
                        for (list_name, archive_nums) in &new_archives {
                            for num in archive_nums {
                                println!("  semcode-index --lore {}/{}", list_name, num);
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Could not check for new archives: {}", e);
                    println!(
                        "Note: Could not fetch lore manifest to check for new archives: {}",
                        e
                    );
                }
            }

            println!("\nTo query this database, run:");
            println!("  semcode --database {}", database_path);

            return finish_lore_run(report, archive_reports, failure);
        }
    }

    // Validate mutually exclusive options
    if args.git.is_some() && args.commits.is_some() {
        return Err(anyhow::anyhow!(
            "--git and --commits are mutually exclusive. Use --git to index files in a commit range, or --commits to index only commit metadata."
        ));
    }

    // Check if branch indexing mode is requested. An empty --all-branches
    // inventory is still branch mode: there is nothing to index.
    if branch_mode_requested(&args) {
        let branches_to_index = collect_branches_to_index(&args)?;
        info!("Branch indexing mode: {} branches", branches_to_index.len());
        return run_branch_indexing(args, branches_to_index, report).await;
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

    // Resolve the range before anything is wiped: a bad range must fail
    // while the database is still intact, never after a clear.
    let probe_repo = gix::discover(&args.source)
        .map_err(|e| anyhow::anyhow!("Not in a git repository: {}", e))?;
    validate_explicit_range(&probe_repo, commit_range)?;

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

/// Refuse a scoped read under options the recorded build does not hold:
/// explicit flags that disagree with the record would mark the range's
/// files under options no later run reproduces, leaving holes the record
/// denies. Only scoped reads refuse: a standing run rewrites the record,
/// and a tree read records what it read.
async fn refuse_scoped_option_drift(
    what: &str,
    db_manager: &DatabaseManager,
    extensions: &[String],
    no_macros: bool,
) -> Result<()> {
    if let Some((recorded_exts, recorded_macros)) = db_manager.recorded_index_options().await? {
        // Membership, not order or multiplicity: the reader tests
        // membership, so `-e rs,c` and `-e c,rs,c` are the `c,rs` build.
        let mut want = extensions.to_vec();
        want.sort();
        want.dedup();
        let mut have = recorded_exts.clone();
        have.sort();
        have.dedup();
        if have != want || recorded_macros != no_macros {
            return Err(anyhow::anyhow!(
                "{what} names options the recorded build does not hold \
                 (recorded extensions [{}] macros {}; requested extensions [{}] macros {}). \
                 Drop the flags to ask under the build's options, drop the range or branch selection \
                 to change the build with these flags, or add --clear to restart it.",
                recorded_exts.join(","),
                if recorded_macros { "skipped" } else { "on" },
                extensions.join(","),
                if no_macros { "skipped" } else { "on" },
            ));
        }
    }
    Ok(())
}

/// Validate an explicit user range before anything is wiped: the format,
/// both endpoints, and — since the walk falls back silently — the from
/// side under the narrowed fallback rule (see `check_from_side`).
fn validate_explicit_range(repo: &gix::Repository, range: &str) -> Result<()> {
    semcode::indexer::list_shas_in_range(repo, range)?;
    if let Some((from, _)) = range.split_once("..") {
        // The walk falls back to a single commit when the from side fails;
        // without this check a typo in a typed range would pass silently:
        // try the whole endpoint the same way the walk does, and allow
        // the fallback only for well-formed ancestry on a resolvable base.
        if !from.is_empty() {
            check_from_side(repo, from)
                .with_context(|| format!("invalid from side of range '{range}'"))?;
        }
    }
    Ok(())
}

/// The walk's from-side fallback, narrowed to its legitimate use: the
/// endpoint itself resolves, or it is a base that resolves followed
/// only by well-formed ancestry suffixes (`^`, `^N`, `~`, `~N`). `tpyo`,
/// `tpyo^`, `HEAD^foo`, `HEAD^foo^` and `HEAD^{not-a-type}` fail, while
/// `X^`, `X^1` and `X~N` on short history keep root-commit indexing. A
/// `^N` past the first parent must name parents that exist: on linear
/// history `HEAD^5` is a `~5` typo, while `M^2~K` past the root still
/// falls back.
fn check_from_side(repo: &gix::Repository, from: &str) -> Result<()> {
    if let Err(e) = semcode::git::resolve_to_commit(repo, from) {
        let base = from.split(['~', '^']).next().unwrap_or(from);
        // Every suffix after the base must be ancestry: a malformed
        // middle (`HEAD^foo^`) passes unnoticed behind a good ending
        // and base.
        let mut rest = &from[base.len()..];
        while !rest.is_empty() {
            if let Some(tail) = rest.strip_prefix('^') {
                // `^N` selects the Nth parent, like a bare `^` alone. The
                // count follows gitoxide's `isize` bound, as `~N` follows
                // its `usize` one: unparseable counts must fail. And past
                // the first parent the prefix through the count must
                // resolve: on linear history `HEAD^5` is a `~5` typo,
                // while `M^2~K` past the root still falls back.
                let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
                let number = if digits == 0 {
                    1
                } else {
                    match tail[..digits].parse::<isize>() {
                        Ok(n) => n,
                        Err(_) => return Err(e),
                    }
                };
                if number >= 2 {
                    let prefix = &from[..from.len() - rest.len() + 1 + digits];
                    if semcode::git::resolve_to_commit(repo, prefix).is_err() {
                        return Err(e);
                    }
                }
                rest = &tail[digits..];
            } else if let Some(tail) = rest.strip_prefix('~') {
                let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
                // A bare `~` reads as `~1`, matching git; anything else
                // needs digits gitoxide itself can parse.
                if digits > 0 && tail[..digits].parse::<usize>().is_err() {
                    return Err(e);
                }
                rest = &tail[digits..];
            } else {
                return Err(e);
            }
        }
        if semcode::git::resolve_to_commit(repo, base).is_err() {
            return Err(e);
        }
    }
    Ok(())
}

/// Resolve which git range a CLI run reads, before anything is wiped or
/// written. The explicit range is validated now (format and resolvability),
/// not when the pipeline first walks it: a bad range fails while the
/// database is still intact.
fn resolve_git_range(args: &Args) -> Result<String> {
    if let Some(ref explicit_range) = args.git {
        // Explicit --git flag provided
        if !explicit_range.contains("..") {
            return Err(anyhow::anyhow!(
                "Git indexing requires a range format (e.g., 'HEAD~10..HEAD'). Single commit mode has been removed. Got: '{}'",
                explicit_range
            ));
        }
        let repo = gix::discover(&args.source)
            .map_err(|e| anyhow::anyhow!("Not in a git repository: {}", e))?;
        validate_explicit_range(&repo, explicit_range)?;
        Ok(explicit_range.clone())
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
                        Ok(format!("{}^..{}", commit_sha, commit_sha))
                    }
                    Err(e) => Err(anyhow::anyhow!(
                        "Not in a git repository or HEAD is unborn (no commits yet): {}. Use --git flag to specify a commit range.",
                        e
                    )),
                }
            }
            Err(e) => Err(anyhow::anyhow!(
                "Not in a git repository: {}. semcode-index requires a git repository. Initialize one with 'git init' first.",
                e
            )),
        }
    }
}

/// Process commits using a streaming pipeline
async fn run_pipeline(args: Args) -> Result<()> {
    info!("Starting Tree-sitter pipeline processing");

    // Process database path with search order: 1) -d flag, 2) source directory, 3) current directory
    let database_path = process_database_path(args.database.as_deref(), Some(&args.source));

    // Resolve the range before table setup, not just before the wipe: on
    // a stale index the migration inside setup drops functions and types,
    // so a bad range must fail before that too. Skipped for vectors-only
    // runs, which need no repository.
    let git_range = if !args.vectors {
        Some(resolve_git_range(&args)?)
    } else {
        None
    };

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
        let (extensions, no_macros) = cli_options(&args, &db_manager).await?;
        let git_range = git_range.unwrap();

        // A one-off range resolves under the build's options.
        if args.git.is_some() && (args.extensions.is_some() || args.no_macros) {
            refuse_scoped_option_drift(
                &format!("--git {}", args.git.as_deref().unwrap_or("")),
                &db_manager,
                &extensions,
                no_macros,
            )
            .await?;
        }

        // An index written by an older semcode holds rows that no commit
        // range will refresh: the files have not changed, so a range covers
        // none of them. Read the whole tree instead — but only when the
        // caller did not name a range. `--git A..B` asks a question, and
        // answering a different one without saying so is the behaviour this
        // series exists to remove.
        if args.git.is_none() && db_manager.index_predates_reader().await? {
            let repo = gix::discover(&args.source)
                .map_err(|e| anyhow::anyhow!("Not in a git repository: {}", e))?;
            let head = repo.head_commit()?.id().to_string();

            println!(
                "{} Index was written by an older semcode: reading the tree at {} again",
                "→".yellow(),
                &head[..8.min(head.len())]
            );
            semcode::git_range::process_git_tree(
                &args.source,
                &head,
                &extensions,
                db_manager.clone(),
                no_macros,
                args.db_threads,
                &args.include,
            )
            .await?;
        } else {
            // Use git range processing for all modes (both explicit --git and auto-detected HEAD)
            info!("Running git commit-based indexing for: {}", git_range);
            semcode::git_range::process_git_range(
                &args.source,
                &git_range,
                &extensions,
                db_manager.clone(),
                no_macros,
                args.db_threads,
                &args.include,
            )
            .await?;
        }

        // Persist what this build read with: interactive startup reuses
        // recorded options, and a fresh CLI build is otherwise optionless.
        // The initial build records, as does a standing-build run that
        // names options explicitly (typed flags are a deliberate build
        // change). A one-off `--git` range never rewrites an existing
        // record: it resolves under the build's options, the same
        // policy the branch path follows. An inherited run records
        // nothing. Coverage stays where it was (no tree SHA is recorded
        // here). Header routing is not configurable yet: `.h` always
        // reads as C, the same value the row versions consult.
        if args.clear
            || db_manager.recorded_index_options().await?.is_none()
            || (args.git.is_none() && (args.extensions.is_some() || args.no_macros))
        {
            db_manager
                .record_index_build(&extensions, no_macros, false)
                .await?;
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
    if args.perf || args.perf_json.is_some() {
        println!("\nPrinting performance statistics...");
        let stats = PERF_STATS.lock().unwrap();
        stats.print_summary();
    }
    if let Some(path) = &args.perf_json {
        let stats = PERF_STATS.lock().unwrap().to_json();
        ReportSink::prepare(path)
            .and_then(|sink| sink.publish(&stats))
            .context("--perf-json")?;
    }

    if args.vectors {
        println!("\n🎉 Vectorization completed successfully!");
    } else {
        println!("\n🎉 Indexing completed successfully!");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::StatusCode, routing::get, Router};
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    async fn serve_manifest(
        status: StatusCode,
        body: Vec<u8>,
    ) -> (String, tokio::task::JoinHandle<std::io::Result<()>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/manifest.js.gz", listener.local_addr().unwrap());
        let app = Router::new().route(
            "/manifest.js.gz",
            get(move || {
                let body = body.clone();
                async move { (status, body) }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        (url, server)
    }

    #[tokio::test]
    async fn fetches_gzipped_manifest_on_tokio_runtime() {
        let manifest = serde_json::json!({
            "/bpf/git/0.git": { "description": "BPF mailing list" }
        });
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&serde_json::to_vec(&manifest).unwrap())
            .unwrap();
        let (url, server) = serve_manifest(StatusCode::OK, encoder.finish().unwrap()).await;

        // The server and client share a current-thread runtime: the HTTP
        // fetch must yield so the server can answer. A blocking reqwest
        // client also panics when called from within this runtime.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fetch_lore_manifest_from_url(&url),
        )
        .await;
        server.abort();

        assert_eq!(result.unwrap().unwrap(), manifest);
    }

    #[tokio::test]
    async fn manifest_fetch_rejects_http_error() {
        let (url, server) =
            serve_manifest(StatusCode::SERVICE_UNAVAILABLE, b"unavailable".to_vec()).await;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fetch_lore_manifest_from_url(&url),
        )
        .await;
        server.abort();

        assert_eq!(
            result.unwrap().unwrap_err().to_string(),
            "Failed to fetch manifest: HTTP 503 Service Unavailable"
        );
    }
}

#[cfg(test)]
mod cli_round_trip_tests {
    use super::run_branch_indexing;
    use super::run_commits_only;
    use super::run_pipeline;
    use super::Args;
    use clap::Parser;

    /// A fresh CLI build persists what it read with: build with
    /// `--extensions c --no-macros`, and the recorded options say so
    /// instead of falling back to every supported extension.
    #[tokio::test]
    async fn fresh_build_records_its_options() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .env("GIT_AUTHOR_NAME", "Semcode Test")
                .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
                .env("GIT_COMMITTER_NAME", "Semcode Test")
                .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q"]);
        std::fs::write(repo.join("a.c"), "int f(void)\n{\n\treturn 1;\n}\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "v1"]);
        git(&["commit", "-q", "--allow-empty", "-m", "v2"]);

        let args = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--extensions",
            "c",
            "--no-macros",
        ])
        .unwrap();
        run_pipeline(args).await.unwrap();

        let db_path = semcode::process_database_path(None, Some(repo));
        let db = semcode::DatabaseManager::new(&db_path, repo.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(
            db.recorded_index_options().await.unwrap(),
            Some((vec!["c".to_string()], true))
        );
    }

    /// A later CLI run with no flags inherits the record: adding an `.rs`
    /// file and rebuilding plain must not index it, and the record must
    /// still say what the build was built with.
    #[tokio::test]
    async fn plain_rerun_inherits_recorded_options() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .env("GIT_AUTHOR_NAME", "Semcode Test")
                .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
                .env("GIT_COMMITTER_NAME", "Semcode Test")
                .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q"]);
        std::fs::write(
            repo.join("a.c"),
            "int f(void)\n{\n\treturn 1;\n}\n#define CMAC(x) ((x) + 1)\n",
        )
        .unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "v1"]);
        git(&["commit", "-q", "--allow-empty", "-m", "v2"]);

        let args = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--extensions",
            "c",
            "--no-macros",
        ])
        .unwrap();
        run_pipeline(args).await.unwrap();

        std::fs::write(repo.join("b.rs"), "fn rs_fn() -> i32 {\n\t1\n}\n").unwrap();
        std::fs::write(
            repo.join("b.c"),
            "int g(void)\n{\n\treturn 1;\n}\n#define CMAC2(x) ((x) + 1)\n",
        )
        .unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "v3 adds rust"]);
        let sha = semcode::git::get_git_sha(repo).unwrap().unwrap();

        let plain =
            Args::try_parse_from(["semcode-index", "--source", repo.to_str().unwrap()]).unwrap();
        run_pipeline(plain).await.unwrap();

        let db_path = semcode::process_database_path(None, Some(repo));
        let db = semcode::DatabaseManager::new(&db_path, repo.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(
            db.recorded_index_options().await.unwrap(),
            Some((vec!["c".to_string()], true))
        );
        assert!(
            db.find_function_git_aware("rs_fn", &sha)
                .await
                .unwrap()
                .is_none(),
            "a plain rerun must not widen a narrowed index"
        );
        assert!(
            db.find_function_git_aware("CMAC", &sha)
                .await
                .unwrap()
                .is_none(),
            "a plain rerun must inherit the macro opt-out too"
        );
        assert!(
            db.find_function_git_aware("CMAC2", &sha)
                .await
                .unwrap()
                .is_none(),
            "a file the rerun reads must still skip its macro row"
        );
        assert!(
            db.find_function_git_aware("g", &sha)
                .await
                .unwrap()
                .is_some(),
            "the rerun must read plain rows from the files it visits"
        );

        // Restating the record's own flags on a range is agreement, not a
        // change: the guard must let it through.
        let agree = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--git",
            &format!("{sha}^..{sha}"),
            "--no-macros",
        ])
        .unwrap();
        run_pipeline(agree).await.unwrap();
        assert_eq!(
            db.recorded_index_options().await.unwrap(),
            Some((vec!["c".to_string()], true))
        );
    }

    /// A one-off `--git` range asks under the build's options and never
    /// rewrites the record; flags that disagree with the build are
    /// refused, while the same flags on a standing run become the build.
    #[tokio::test]
    async fn scoped_range_leaves_the_build_record_alone() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .env("GIT_AUTHOR_NAME", "Semcode Test")
                .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
                .env("GIT_COMMITTER_NAME", "Semcode Test")
                .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q"]);
        std::fs::write(repo.join("a.c"), "int f(void)\n{\n\treturn 1;\n}\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "v1"]);
        git(&["commit", "-q", "--allow-empty", "-m", "v2"]);
        let sha = semcode::git::get_git_sha(repo).unwrap().unwrap();

        let wide = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--extensions",
            "c,rs",
        ])
        .unwrap();
        run_pipeline(wide).await.unwrap();

        let scoped = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--git",
            &format!("{sha}^..{sha}"),
        ])
        .unwrap();
        run_pipeline(scoped).await.unwrap();

        let db_path = semcode::process_database_path(None, Some(repo));
        let db = semcode::DatabaseManager::new(&db_path, repo.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(
            db.recorded_index_options().await.unwrap(),
            Some((vec!["c".to_string(), "rs".to_string()], false)),
            "a scoped range must not rewrite the build record"
        );

        // Flags that disagree with the build are refused on a range: the
        // range would mark files under options no later run reproduces.
        let foreign = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--extensions",
            "c",
            "--git",
            &format!("{sha}^..{sha}"),
        ])
        .unwrap();
        assert!(
            run_pipeline(foreign).await.is_err(),
            "a scoped range must not smuggle in a flag change"
        );
        assert_eq!(
            db.recorded_index_options().await.unwrap(),
            Some((vec!["c".to_string(), "rs".to_string()], false)),
            "a refused range must not touch the record"
        );

        // The reader tests membership, not order: restating the build's
        // extensions in another order is agreement too.
        let reordered = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--extensions",
            "rs,c",
            "--git",
            &format!("{sha}^..{sha}"),
        ])
        .unwrap();
        run_pipeline(reordered).await.unwrap();
        assert_eq!(
            db.recorded_index_options().await.unwrap(),
            Some((vec!["c".to_string(), "rs".to_string()], false))
        );

        // Multiplicity is not membership either: a repeated flag still
        // agrees with the build it restates.
        let dup = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--extensions",
            "c,rs,c",
            "--git",
            &format!("{sha}^..{sha}"),
        ])
        .unwrap();
        run_pipeline(dup).await.unwrap();

        let standing = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--extensions",
            "c",
        ])
        .unwrap();
        run_pipeline(standing).await.unwrap();
        assert_eq!(
            db.recorded_index_options().await.unwrap(),
            Some((vec!["c".to_string()], false)),
            "the same flags on a standing run become the build"
        );

        let widen = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--extensions",
            "c,rs",
        ])
        .unwrap();
        run_pipeline(widen).await.unwrap();
        assert_eq!(
            db.recorded_index_options().await.unwrap(),
            Some((vec!["c".to_string(), "rs".to_string()], false)),
            "explicit flags on a standing run widen the record too"
        );
    }

    /// `--clear` restarts the build and drops the record: after a
    /// `--no-macros` build, a plain `--clear` reads with macros on, so
    /// the macro row comes back and the record says defaults.
    #[tokio::test]
    async fn clear_forgets_the_recorded_options() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .env("GIT_AUTHOR_NAME", "Semcode Test")
                .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
                .env("GIT_COMMITTER_NAME", "Semcode Test")
                .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q"]);
        std::fs::write(
            repo.join("a.c"),
            "int f(void)\n{\n\treturn 1;\n}\n#define CMAC(x) ((x) + 1)\n",
        )
        .unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "v1"]);
        git(&["commit", "-q", "--allow-empty", "-m", "v2"]);
        let sha = semcode::git::get_git_sha(repo).unwrap().unwrap();

        let narrow = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--extensions",
            "c",
            "--no-macros",
        ])
        .unwrap();
        run_pipeline(narrow).await.unwrap();

        let db_path = semcode::process_database_path(None, Some(repo));
        let db = semcode::DatabaseManager::new(&db_path, repo.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert!(
            db.find_function_git_aware("CMAC", &sha)
                .await
                .unwrap()
                .is_none(),
            "no-macros build must skip the macro row"
        );

        let clear = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--clear",
        ])
        .unwrap();
        run_pipeline(clear).await.unwrap();

        assert_eq!(
            db.recorded_index_options().await.unwrap(),
            Some((semcode::file_extensions::default_extensions(), false)),
            "--clear must reset the record to defaults with macros on"
        );
        assert!(
            db.find_function_git_aware("CMAC", &sha)
                .await
                .unwrap()
                .is_some(),
            "--clear must bring the macro row back"
        );
    }

    /// `--clear --commits` drops the record too: the commits path wipes
    /// source rows without rebuilding them, so a surviving record would
    /// strand the next build under options the wiped rows never held.
    #[tokio::test]
    async fn commits_clear_forgets_the_record() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .env("GIT_AUTHOR_NAME", "Semcode Test")
                .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
                .env("GIT_COMMITTER_NAME", "Semcode Test")
                .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q"]);
        std::fs::write(repo.join("a.c"), "int f(void)\n{\n\treturn 1;\n}\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "v1"]);
        git(&["commit", "-q", "--allow-empty", "-m", "v2"]);
        let old = semcode::git::get_git_sha(repo).unwrap().unwrap();

        let narrow = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--extensions",
            "c",
            "--no-macros",
        ])
        .unwrap();
        run_pipeline(narrow).await.unwrap();

        let head = semcode::git::get_git_sha(repo).unwrap().unwrap();
        let commits = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--clear",
            "--commits",
            &format!("{old}..{head}"),
        ])
        .unwrap();
        run_commits_only(commits).await.unwrap();

        let db_path = semcode::process_database_path(None, Some(repo));
        let db = semcode::DatabaseManager::new(&db_path, repo.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(
            db.recorded_index_options().await.unwrap(),
            None,
            "commits clear must forget the record"
        );
        assert!(
            db.find_function_git_aware("f", &head)
                .await
                .unwrap()
                .is_none(),
            "commits clear still wipes source rows"
        );
    }

    /// A bad `--git` range with `--clear` fails before anything is wiped:
    /// the record and the rows stay as the last good build left them.
    #[tokio::test]
    async fn clear_with_bad_range_leaves_everything_intact() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .env("GIT_AUTHOR_NAME", "Semcode Test")
                .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
                .env("GIT_COMMITTER_NAME", "Semcode Test")
                .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q"]);
        std::fs::write(repo.join("a.c"), "int f(void)\n{\n\treturn 1;\n}\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "v1"]);
        git(&["commit", "-q", "--allow-empty", "-m", "v2"]);

        let build =
            Args::try_parse_from(["semcode-index", "--source", repo.to_str().unwrap()]).unwrap();
        run_pipeline(build).await.unwrap();
        let sha = semcode::git::get_git_sha(repo).unwrap().unwrap();

        let bad = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--clear",
            "--git",
            "nosuch..alsonot",
        ])
        .unwrap();
        assert!(
            run_pipeline(bad).await.is_err(),
            "an unresolvable range must fail"
        );

        let db_path = semcode::process_database_path(None, Some(repo));
        let db = semcode::DatabaseManager::new(&db_path, repo.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(
            db.recorded_index_options().await.unwrap(),
            Some((semcode::file_extensions::default_extensions(), false)),
            "a failed clear must not touch the record"
        );
        assert!(
            db.find_function_git_aware("f", &sha)
                .await
                .unwrap()
                .is_some(),
            "a failed clear must not wipe rows"
        );

        // And a plain run after the failure resumes where the last good
        // build left off: the failure above wiped and rewrote nothing.
        let resume =
            Args::try_parse_from(["semcode-index", "--source", repo.to_str().unwrap()]).unwrap();
        run_pipeline(resume).await.unwrap();
        assert!(
            db.find_function_git_aware("f", &sha)
                .await
                .unwrap()
                .is_some(),
            "a plain run after a failed clear still finds the rows"
        );
        assert_eq!(
            db.recorded_index_options().await.unwrap(),
            Some((semcode::file_extensions::default_extensions(), false)),
            "the resumed run records the build it read"
        );
    }

    /// A `--git` range naming options the build does not hold fails
    /// instead of poisoning it: the failed run marks nothing, so a plain
    /// rerun still reads the range's files whole, macro row included.
    #[tokio::test]
    async fn scoped_range_with_foreign_flags_fails_clean() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .env("GIT_AUTHOR_NAME", "Semcode Test")
                .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
                .env("GIT_COMMITTER_NAME", "Semcode Test")
                .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q"]);
        std::fs::write(repo.join("a.c"), "int f(void)\n{\n\treturn 1;\n}\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "v1"]);
        let old = semcode::git::get_git_sha(repo).unwrap().unwrap();

        let build =
            Args::try_parse_from(["semcode-index", "--source", repo.to_str().unwrap()]).unwrap();
        run_pipeline(build).await.unwrap();

        std::fs::write(
            repo.join("b.c"),
            "int g(void)\n{\n\treturn 1;\n}\n#define CMAC3(x) ((x) + 1)\n",
        )
        .unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "v2 adds macro"]);
        let sha = semcode::git::get_git_sha(repo).unwrap().unwrap();

        let foreign = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--git",
            &format!("{old}..{sha}"),
            "--no-macros",
        ])
        .unwrap();
        let error = run_pipeline(foreign).await.unwrap_err();
        assert!(
            error.to_string().contains("recorded build"),
            "the refusal must name the record: {error}"
        );

        let db_path = semcode::process_database_path(None, Some(repo));
        let db = semcode::DatabaseManager::new(&db_path, repo.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(
            db.recorded_index_options().await.unwrap(),
            Some((semcode::file_extensions::default_extensions(), false)),
            "a refused range must not touch the record"
        );

        let plain =
            Args::try_parse_from(["semcode-index", "--source", repo.to_str().unwrap()]).unwrap();
        run_pipeline(plain).await.unwrap();
        assert!(
            db.find_function_git_aware("CMAC3", &sha)
                .await
                .unwrap()
                .is_some(),
            "the refused run must mark nothing: the rerun reads the macro row"
        );
        assert!(
            db.find_function_git_aware("g", &sha)
                .await
                .unwrap()
                .is_some(),
            "the rerun reads the refused range's files whole"
        );
    }

    /// Forgetting the build clears options and tree coverage together,
    /// and leaves the schema version alone: a wipe claims nothing, but
    /// the database is still current.
    #[tokio::test]
    async fn forget_recorded_build_clears_options_and_tree_sha() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t.db");
        let db = semcode::DatabaseManager::new(
            db_path.to_str().unwrap(),
            dir.path().to_string_lossy().into_owned(),
        )
        .await
        .unwrap();
        db.create_tables().await.unwrap();
        db.record_index_build(&["c".to_string()], true, true)
            .await
            .unwrap();
        db.record_tree_sha("abc123").await.unwrap();
        assert_eq!(db.recorded_headers_as_cpp().await.unwrap(), Some(true));

        db.forget_recorded_build().await.unwrap();

        assert_eq!(db.recorded_index_options().await.unwrap(), None);
        assert_eq!(db.recorded_tree_sha().await.unwrap(), None);
        assert_eq!(db.recorded_headers_as_cpp().await.unwrap(), None);
        assert!(
            !db.index_predates_reader().await.unwrap(),
            "forgetting must not touch the schema version"
        );

        // Forgetting over tables that were never created succeeds too:
        // absence reads as no record.
        let bare = semcode::DatabaseManager::new(
            dir.path().join("bare.db").to_str().unwrap(),
            dir.path().to_string_lossy().into_owned(),
        )
        .await
        .unwrap();
        bare.forget_recorded_build().await.unwrap();
        assert_eq!(bare.recorded_index_options().await.unwrap(), None);

        // A corrupt options table fails loudly instead of reporting a
        // wipe with the record intact: only absence is tolerated.
        std::fs::write(
            dir.path().join("bare.db").join("schema_meta.lance"),
            b"garbage",
        )
        .unwrap();
        bare.forget_recorded_build().await.unwrap_err();
    }

    /// An incremental branch read under disagreeing flags is refused like
    /// a one-off range: the same poisoning, the same guard. A flagless
    /// incremental run still goes through.
    #[tokio::test]
    async fn branch_incremental_with_foreign_flags_fails_clean() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .env("GIT_AUTHOR_NAME", "Semcode Test")
                .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
                .env("GIT_COMMITTER_NAME", "Semcode Test")
                .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q", "-b", "main"]);
        std::fs::write(repo.join("a.c"), "int f(void)\n{\n\treturn 1;\n}\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "v1"]);
        let v1 = semcode::git::get_git_sha(repo).unwrap().unwrap();
        let tip = |sha: &str| semcode::git::BranchRef {
            name: "main".to_string(),
            tip_commit: sha.to_string(),
            is_remote: false,
            remote: None,
        };

        let build =
            Args::try_parse_from(["semcode-index", "--source", repo.to_str().unwrap()]).unwrap();
        run_branch_indexing(build, vec![tip(&v1).into()], None)
            .await
            .unwrap();

        std::fs::write(repo.join("b.c"), "int g(void)\n{\n\treturn 1;\n}\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "v2"]);
        let v2 = semcode::git::get_git_sha(repo).unwrap().unwrap();

        let foreign = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--extensions",
            "c",
        ])
        .unwrap();
        let error = run_branch_indexing(foreign, vec![tip(&v2).into()], None)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("recorded build"),
            "the refusal must name the record: {error}"
        );

        // Same for the macro half of the build: opting out on a range
        // would skip macro rows the record claims.
        let macros = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--no-macros",
        ])
        .unwrap();
        assert!(
            run_branch_indexing(macros, vec![tip(&v2).into()], None)
                .await
                .map_err(|e| e.to_string())
                .unwrap_err()
                .contains("recorded build"),
            "a branch range must not smuggle in a macro opt-out either"
        );

        let plain =
            Args::try_parse_from(["semcode-index", "--source", repo.to_str().unwrap()]).unwrap();
        run_branch_indexing(plain, vec![tip(&v2).into()], None)
            .await
            .unwrap();

        let db_path = semcode::process_database_path(None, Some(repo));
        let db = semcode::DatabaseManager::new(&db_path, repo.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(
            db.recorded_index_options().await.unwrap(),
            Some((semcode::file_extensions::default_extensions(), false)),
            "a refused branch run must not touch the record"
        );
        assert!(
            db.find_function_git_aware("g", &v2)
                .await
                .unwrap()
                .is_some(),
            "the flagless incremental run still reads the new file"
        );
    }

    /// A bad `--commits` range with `--clear` fails before anything is
    /// wiped, like a bad `--git` range.
    #[tokio::test]
    async fn commits_clear_with_bad_range_leaves_everything_intact() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .env("GIT_AUTHOR_NAME", "Semcode Test")
                .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
                .env("GIT_COMMITTER_NAME", "Semcode Test")
                .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q"]);
        std::fs::write(repo.join("a.c"), "int f(void)\n{\n\treturn 1;\n}\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "v1"]);

        let build =
            Args::try_parse_from(["semcode-index", "--source", repo.to_str().unwrap()]).unwrap();
        run_pipeline(build).await.unwrap();
        let sha = semcode::git::get_git_sha(repo).unwrap().unwrap();

        let bad = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--clear",
            "--commits",
            "nosuch..alsonot",
        ])
        .unwrap();
        assert!(
            run_commits_only(bad).await.is_err(),
            "an unresolvable commits range must fail"
        );

        let db_path = semcode::process_database_path(None, Some(repo));
        let db = semcode::DatabaseManager::new(&db_path, repo.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(
            db.recorded_index_options().await.unwrap(),
            Some((semcode::file_extensions::default_extensions(), false)),
            "a failed commits clear must not touch the record"
        );
        assert!(
            db.find_function_git_aware("f", &sha)
                .await
                .unwrap()
                .is_some(),
            "a failed commits clear must not wipe rows"
        );
    }

    /// A bad left endpoint fails before anything is wiped too: the walk
    /// falls back to the right side silently, so the from side needs its
    /// own check. Mirror for `--git` and `--commits`.
    #[tokio::test]
    async fn clear_with_bad_left_endpoint_leaves_everything_intact() {
        bad_left_endpoint_leaves_everything_intact(false).await;
    }

    #[tokio::test]
    async fn commits_clear_with_bad_left_endpoint_leaves_everything_intact() {
        bad_left_endpoint_leaves_everything_intact(true).await;
    }

    async fn bad_left_endpoint_leaves_everything_intact(commits: bool) {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .env("GIT_AUTHOR_NAME", "Semcode Test")
                .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
                .env("GIT_COMMITTER_NAME", "Semcode Test")
                .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q"]);
        std::fs::write(repo.join("a.c"), "int f(void)\n{\n\treturn 1;\n}\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "v1"]);
        git(&["commit", "-q", "--allow-empty", "-m", "v2"]);

        let build =
            Args::try_parse_from(["semcode-index", "--source", repo.to_str().unwrap()]).unwrap();
        run_pipeline(build).await.unwrap();
        let sha = semcode::git::get_git_sha(repo).unwrap().unwrap();

        // A bare typo, a hatted typo, and malformed ancestry must all
        // fail: the walk falls back silently for any of them.
        for range in [
            "nosuch..HEAD",
            "nosuch^..HEAD",
            "HEAD^{not-a-type}..HEAD",
            "HEAD^foo..HEAD",
            "HEAD^foo^..HEAD",
            "HEAD^{x}~2..HEAD",
            "HEAD~18446744073709551616..HEAD",
            "HEAD^9223372036854775808..HEAD",
            "HEAD^9223372036854775807..HEAD",
            "HEAD^5..HEAD",
        ] {
            let bad = if commits {
                Args::try_parse_from([
                    "semcode-index",
                    "--source",
                    repo.to_str().unwrap(),
                    "--clear",
                    "--commits",
                    range,
                ])
                .unwrap()
            } else {
                Args::try_parse_from([
                    "semcode-index",
                    "--source",
                    repo.to_str().unwrap(),
                    "--clear",
                    "--git",
                    range,
                ])
                .unwrap()
            };
            let failed = if commits {
                run_commits_only(bad).await.is_err()
            } else {
                run_pipeline(bad).await.is_err()
            };
            assert!(failed, "an unresolvable from side must fail: {range}");

            let db_path = semcode::process_database_path(None, Some(repo));
            let db = semcode::DatabaseManager::new(&db_path, repo.to_string_lossy().into_owned())
                .await
                .unwrap();
            assert_eq!(
                db.recorded_index_options().await.unwrap(),
                Some((semcode::file_extensions::default_extensions(), false)),
                "a failed clear must not touch the record: {range}"
            );
            assert!(
                db.find_function_git_aware("f", &sha)
                    .await
                    .unwrap()
                    .is_some(),
                "a failed clear must not wipe rows: {range}"
            );
        }
    }

    /// A bad range fails before table setup, not just before the wipe: on
    /// a stale index the migration inside setup drops functions and types,
    /// so validation must precede it.
    #[tokio::test]
    async fn stale_index_with_bad_range_keeps_its_rows() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .env("GIT_AUTHOR_NAME", "Semcode Test")
                .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
                .env("GIT_COMMITTER_NAME", "Semcode Test")
                .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q"]);
        std::fs::write(repo.join("a.c"), "int f(void)\n{\n\treturn 1;\n}\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "v1"]);
        git(&["commit", "-q", "--allow-empty", "-m", "v2"]);

        let build =
            Args::try_parse_from(["semcode-index", "--source", repo.to_str().unwrap()]).unwrap();
        run_pipeline(build).await.unwrap();
        let sha = semcode::git::get_git_sha(repo).unwrap().unwrap();

        // Age the index: a stale mark and an older schema version.
        let db_path = semcode::process_database_path(None, Some(repo));
        let db = semcode::DatabaseManager::new(&db_path, repo.to_string_lossy().into_owned())
            .await
            .unwrap();
        db.mark_files_processed(vec![semcode::ProcessedFileRecord {
            file: "a.c".to_string(),
            git_sha: None,
            git_file_sha: "staleblob".to_string(),
            extractor_version: Some("stale".to_string()),
        }])
        .await
        .unwrap();
        let options = lancedb::database::listing::ListingDatabaseOptions::builder()
            .data_storage_version(lancedb::connection::LanceFileVersion::V2_2)
            .build();
        let connection = lancedb::connect(db_path.as_str())
            .database_options(&options)
            .execute()
            .await
            .unwrap();
        let table = connection
            .open_table("schema_meta")
            .execute()
            .await
            .unwrap();
        table.delete("key = 'schema_version'").await.unwrap();
        let schema = std::sync::Arc::new(arrow::datatypes::Schema::new(vec![
            arrow::datatypes::Field::new("key", arrow::datatypes::DataType::Utf8, false),
            arrow::datatypes::Field::new("value", arrow::datatypes::DataType::Utf8, false),
        ]));
        let batch = arrow::record_batch::RecordBatch::try_new(
            schema,
            vec![
                std::sync::Arc::new(arrow::array::StringArray::from(vec!["schema_version"]))
                    as arrow::array::ArrayRef,
                std::sync::Arc::new(arrow::array::StringArray::from(vec!["0"]))
                    as arrow::array::ArrayRef,
            ],
        )
        .unwrap();
        table.add(vec![batch]).execute().await.unwrap();

        let bad = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--clear",
            "--git",
            "nosuch..HEAD",
        ])
        .unwrap();
        assert!(run_pipeline(bad).await.is_err(), "a bad range must fail");

        let db = semcode::DatabaseManager::new(&db_path, repo.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert!(
            db.index_predates_reader().await.unwrap(),
            "the failed run must not migrate anything"
        );
        assert!(
            db.find_function_git_aware("f", &sha)
                .await
                .unwrap()
                .is_some(),
            "a failed run on a stale index must not drop rows"
        );
    }

    /// An explicit caret range on a root commit still indexes: the from
    /// side has no parent, so the walk's single-commit fallback is the
    /// answer, not an error.
    #[tokio::test]
    async fn root_commit_explicit_caret_range_still_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .env("GIT_AUTHOR_NAME", "Semcode Test")
                .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
                .env("GIT_COMMITTER_NAME", "Semcode Test")
                .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q"]);
        std::fs::write(repo.join("a.c"), "int f(void)\n{\n\treturn 1;\n}\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "v1"]);
        let sha = semcode::git::get_git_sha(repo).unwrap().unwrap();

        // Caret, bare-tilde, and explicit-first-parent spellings all
        // fall back on a root commit: git reads `~` as `~1` and `^1`
        // as `^`. Each leg asserts on its own, since every leg runs
        // `--clear`: a shared assert after the loop would let one leg
        // mask another.
        for range in [
            format!("{sha}^..{sha}"),
            format!("{sha}~..{sha}"),
            format!("{sha}^1..{sha}"),
        ] {
            let root = Args::try_parse_from([
                "semcode-index",
                "--source",
                repo.to_str().unwrap(),
                "--clear",
                "--git",
                &range,
            ])
            .unwrap();
            run_pipeline(root).await.unwrap();

            let db_path = semcode::process_database_path(None, Some(repo));
            let db = semcode::DatabaseManager::new(&db_path, repo.to_string_lossy().into_owned())
                .await
                .unwrap();
            assert!(
                db.find_function_git_aware("f", &sha)
                    .await
                    .unwrap()
                    .is_some(),
                "the root commit's files must be indexed: {range}"
            );
        }
    }

    /// A `~N` range past the root still indexes: the count exceeds the
    /// history, so the walk's single-commit fallback is the answer, not
    /// an error. Companion to the root-caret test for the `~N` spelling.
    #[tokio::test]
    async fn shallow_history_tilde_range_still_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .env("GIT_AUTHOR_NAME", "Semcode Test")
                .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
                .env("GIT_COMMITTER_NAME", "Semcode Test")
                .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q"]);
        std::fs::write(repo.join("a.c"), "int f(void)\n{\n\treturn 1;\n}\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "v1"]);
        let sha = semcode::git::get_git_sha(repo).unwrap().unwrap();

        let shallow = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--clear",
            "--git",
            "HEAD~2..HEAD",
        ])
        .unwrap();
        run_pipeline(shallow).await.unwrap();

        let db_path = semcode::process_database_path(None, Some(repo));
        let db = semcode::DatabaseManager::new(&db_path, repo.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert!(
            db.find_function_git_aware("f", &sha)
                .await
                .unwrap()
                .is_some(),
            "the fallback must index the single commit"
        );
    }

    /// A huge but parseable count still falls back: the platform's
    /// largest count exceeds any history, so the walk indexes the
    /// single commit instead of erroring. Companion to the overflow
    /// leg, which must fail.
    #[tokio::test]
    async fn max_count_tilde_range_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .env("GIT_AUTHOR_NAME", "Semcode Test")
                .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
                .env("GIT_COMMITTER_NAME", "Semcode Test")
                .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q"]);
        std::fs::write(repo.join("a.c"), "int f(void)\n{\n\treturn 1;\n}\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "v1"]);
        let sha = semcode::git::get_git_sha(repo).unwrap().unwrap();

        let huge = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--clear",
            "--git",
            &format!("HEAD~{}..HEAD", usize::MAX),
        ])
        .unwrap();
        run_pipeline(huge).await.unwrap();

        let db_path = semcode::process_database_path(None, Some(repo));
        let db = semcode::DatabaseManager::new(&db_path, repo.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert!(
            db.find_function_git_aware("f", &sha)
                .await
                .unwrap()
                .is_some(),
            "a parseable count past history must fall back, not fail"
        );
    }

    /// A corrupt data table fails the wipe loudly instead of reporting
    /// success with rows left behind.
    #[tokio::test]
    async fn clear_with_corrupt_table_fails_loud() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t.db");
        let db = semcode::DatabaseManager::new(
            db_path.to_str().unwrap(),
            dir.path().to_string_lossy().into_owned(),
        )
        .await
        .unwrap();
        db.create_tables().await.unwrap();
        db.clear_all_data().await.unwrap();

        std::fs::remove_dir_all(db_path.join("functions.lance")).unwrap();
        std::fs::write(db_path.join("functions.lance"), b"garbage").unwrap();
        let error = db.clear_all_data().await.unwrap_err();
        assert!(
            error.to_string().contains("clearing functions"),
            "the wipe must name the table: {error}"
        );
    }

    /// A wipe over tables that were never created succeeds: absence is
    /// skippable, so a half-built database still clears.
    #[tokio::test]
    async fn clear_without_tables_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let db = semcode::DatabaseManager::new(
            dir.path().join("t.db").to_str().unwrap(),
            dir.path().to_string_lossy().into_owned(),
        )
        .await
        .unwrap();
        db.clear_all_data().await.unwrap();
        assert_eq!(db.recorded_index_options().await.unwrap(), None);
    }

    /// A second parent's history past the root still falls back: `M^2`
    /// names a parent that exists, so only the `~K` count exceeds what
    /// is there. Refusing every `^N` would break this spelling.
    #[tokio::test]
    async fn merge_second_parent_range_past_root_still_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .env("GIT_AUTHOR_NAME", "Semcode Test")
                .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
                .env("GIT_COMMITTER_NAME", "Semcode Test")
                .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q", "-b", "main"]);
        std::fs::write(repo.join("a.c"), "int f(void)\n{\n\treturn 1;\n}\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "v1"]);
        git(&["checkout", "-q", "-b", "side"]);
        std::fs::write(repo.join("b.c"), "int g(void)\n{\n\treturn 1;\n}\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "side"]);
        git(&["checkout", "-q", "main"]);
        git(&["merge", "-q", "--no-ff", "side", "-m", "merge"]);
        let sha = semcode::git::get_git_sha(repo).unwrap().unwrap();

        let range = Args::try_parse_from([
            "semcode-index",
            "--source",
            repo.to_str().unwrap(),
            "--clear",
            "--git",
            "HEAD^2~10..HEAD",
        ])
        .unwrap();
        run_pipeline(range).await.unwrap();

        let db_path = semcode::process_database_path(None, Some(repo));
        let db = semcode::DatabaseManager::new(&db_path, repo.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert!(
            db.find_function_git_aware("f", &sha)
                .await
                .unwrap()
                .is_some(),
            "an existing second parent must keep the fallback working"
        );
    }
}
