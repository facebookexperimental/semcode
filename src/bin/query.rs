// SPDX-License-Identifier: MIT OR Apache-2.0
mod query_impl;

use anyhow::Result;
use clap::Parser;
use rustyline::DefaultEditor;
use semcode::{process_database_path, DatabaseManager};
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

use query_impl::commands::handle_command;
use semcode::display::print_welcome_message_with_model;

/// Rebuild the working directory index to pick up any file changes since the last query.
/// Reuses cached analysis results for files whose mtime and size haven't changed.
fn refresh_workdir_index(db_manager: &DatabaseManager, git_repo: &str) {
    let repo_path = std::path::Path::new(git_repo);
    let previous = db_manager.take_workdir_index();
    match semcode::WorkdirIndex::build_incremental(repo_path, previous.as_ref()) {
        Ok(workdir) => {
            if workdir.is_empty() {
                // No need to set — we already took it out
            } else {
                info!(
                    "Working directory overlay: {} dirty, {} deleted, {} functions, {} types",
                    workdir.dirty_file_count(),
                    workdir.deleted_file_count(),
                    workdir.function_count(),
                    workdir.type_count(),
                );
                db_manager.set_workdir_index(workdir);
            }
        }
        Err(e) => {
            info!("Could not build working directory index: {}", e);
            // No need to clear — we already took it out
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "semcode")]
#[command(about = "Query the semantic code database", long_about = None)]
struct Args {
    /// Path to database directory or parent directory containing .semcode.db (default: search current directory)
    #[arg(short, long)]
    database: Option<String>,

    /// Path to the git repository for git-aware queries
    #[arg(long, env = "SEMCODE_GIT_REPO", default_value = ".")]
    git_repo: String,

    /// Path to local model directory (for semantic search)
    #[arg(long, value_name = "PATH")]
    model_path: Option<String>,

    /// Query code at a specific branch instead of current HEAD
    /// Example: --branch main
    #[arg(long, value_name = "BRANCH")]
    branch: Option<String>,

    /// Execute a query and exit (non-interactive mode)
    /// Example: -q "lore -f user@example.com -b keyword"
    #[arg(short = 'q', long = "query", value_name = "QUERY")]
    query: Option<String>,

    /// Parse a diff file and output per-hunk JSON with types, callers, and calls.
    /// Reads from stdin if no file is specified.
    #[arg(long, value_name = "FILE")]
    diffinfo: Option<Option<String>>,

    /// Control callstack depth for --diffinfo: UP/DOWN levels (e.g., 2/3).
    /// UP = how many caller levels, DOWN = how many callee levels.
    /// Default: 1/1 (direct callers and callees only).
    #[arg(long, value_name = "UP/DOWN", requires = "diffinfo")]
    depth: Option<String>,

    /// Disable working directory overlay (only query committed code)
    #[arg(long)]
    git_only: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::env;

    #[test]
    fn test_git_repo_env_var() {
        let key = "SEMCODE_GIT_REPO";
        let value = "/tmp/test_repo";
        env::set_var(key, value);

        // No arguments provided, should use env var
        let args = Args::try_parse_from(&["query"]).unwrap();
        assert_eq!(args.git_repo, value);

        env::remove_var(key);
    }

    #[test]
    fn test_git_repo_priority() {
        let key = "SEMCODE_GIT_REPO";
        let env_value = "/tmp/env_repo";
        let arg_value = "/tmp/arg_repo";
        env::set_var(key, env_value);

        // Argument should take priority over env var
        let args = Args::try_parse_from(&["query", "--git-repo", arg_value]).unwrap();
        assert_eq!(args.git_repo, arg_value);

        env::remove_var(key);
    }

    #[test]
    fn test_git_repo_default() {
        let key = "SEMCODE_GIT_REPO";
        env::remove_var(key);

        // No arguments and no env var, should use default
        let args = Args::try_parse_from(&["query"]).unwrap();
        assert_eq!(args.git_repo, ".");
    }
}

/// Check if the current commit needs indexing and perform incremental indexing if needed
async fn index_current_commit_if_needed(
    db_manager: Arc<DatabaseManager>,
    git_repo: &str,
) -> Result<()> {
    // Get current git SHA
    let git_sha = match semcode::git::get_git_sha(git_repo)? {
        Some(sha) => sha,
        None => {
            info!("Not in a git repository, skipping auto-indexing");
            return Ok(());
        }
    };

    info!("Current commit: {}", git_sha);

    let repo_path = PathBuf::from(git_repo);

    // Quick check: look at files changed in the current commit.
    // If no supported files changed, or the changed files are already indexed, skip.
    match semcode::git::get_changed_files(&repo_path, "HEAD~1", "HEAD") {
        Ok(changed_files) => {
            // Find supported files that were added or modified
            let supported_changes: Vec<_> = changed_files
                .iter()
                .filter(|cf| {
                    matches!(
                        cf.change_type,
                        semcode::git::ChangeType::Added | semcode::git::ChangeType::Modified
                    ) && cf.new_file_hash.is_some()
                        && semcode::file_extensions::is_supported_for_analysis(&cf.path)
                })
                .collect();

            if supported_changes.is_empty() {
                info!("No supported files changed in current commit, skipping auto-indexing");
                return Ok(());
            }

            // Check if the first supported changed file is already indexed
            if let Some(new_hash) = &supported_changes[0].new_file_hash {
                if db_manager.is_file_processed(new_hash).await? {
                    info!(
                        "Changed file '{}' (SHA: {}) already indexed, skipping auto-indexing",
                        supported_changes[0].path,
                        &new_hash[..8]
                    );
                    return Ok(());
                }
                info!(
                    "Changed file '{}' (SHA: {}) needs indexing",
                    supported_changes[0].path,
                    &new_hash[..8]
                );
            }
        }
        Err(e) => {
            // Failed to get changed files (might be initial commit, root commit, etc.)
            info!("Could not get changed files ({}), will check all files", e);
        }
    }

    // Index the current commit
    println!("Checking for files to index...");

    let git_range = format!("{}^..{}", git_sha, git_sha);
    let extensions_vec = semcode::file_extensions::supported_extensions();

    match semcode::git_range::process_git_range(
        &repo_path,
        &git_range,
        &extensions_vec,
        db_manager.clone(),
        false, // no_macros = false (index macros)
        4,     // db_threads
    )
    .await
    {
        Ok(()) => {
            println!("Indexing complete");
        }
        Err(e) => {
            // If git range processing fails (e.g., root commit with no parent), just warn
            tracing::warn!("Auto-indexing skipped: {}", e);
        }
    }

    Ok(())
}

/// Walk a chain index (caller or callee) up to `depth` levels from `start`.
/// Returns a flat JSON array when depth=1, or a nested array of arrays when depth>1.
/// Each level contains only newly-discovered functions (cycle-safe).
fn collect_chain_levels(
    start: &str,
    depth: usize,
    index: &std::collections::HashMap<String, Vec<String>>,
) -> serde_json::Value {
    if depth == 0 {
        return serde_json::json!([]);
    }

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    seen.insert(start.to_string());
    let mut current_names = vec![start.to_string()];
    let mut levels: Vec<Vec<String>> = Vec::new();

    for _ in 0..depth {
        let mut next_level = Vec::new();
        for name in &current_names {
            if let Some(related) = index.get(name) {
                for r in related {
                    if seen.insert(r.clone()) {
                        next_level.push(r.clone());
                    }
                }
            }
        }
        next_level.sort();
        next_level.dedup();
        if next_level.is_empty() {
            break;
        }
        levels.push(next_level.clone());
        current_names = next_level;
    }

    if depth == 1 {
        // Flat array for backwards compatibility
        serde_json::json!(levels.into_iter().next().unwrap_or_default())
    } else {
        serde_json::json!(levels)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Suppress ORT verbose logging
    std::env::set_var("ORT_LOG_LEVEL", "ERROR");

    // Note: model2vec-rs handles threading internally, no manual configuration needed

    // Initialize tracing with SEMCODE_DEBUG environment variable support
    semcode::logging::init_tracing();

    let args = Args::parse();

    // Process database path with search order: 1) -d flag, 2) current directory
    let database_path = process_database_path(args.database.as_deref(), None);

    info!("Connecting to database: {}", database_path);

    // Connect to database
    let db_manager = Arc::new(DatabaseManager::new(&database_path, args.git_repo.clone()).await?);

    // Ensure tables exist
    db_manager.create_tables().await?;

    // Handle --diffinfo flag: process diff and exit
    if let Some(file_path) = args.diffinfo {
        // Parse --depth UP/DOWN (default: 1/1)
        let (up_depth, down_depth) = if let Some(ref depth_str) = args.depth {
            let parts: Vec<&str> = depth_str.split('/').collect();
            if parts.len() != 2 {
                eprintln!("Error: --depth must be in UP/DOWN format (e.g., 2/3)");
                std::process::exit(1);
            }
            let up: usize = parts[0].parse().unwrap_or_else(|_| {
                eprintln!("Error: invalid UP value in --depth: {}", parts[0]);
                std::process::exit(1);
            });
            let down: usize = parts[1].parse().unwrap_or_else(|_| {
                eprintln!("Error: invalid DOWN value in --depth: {}", parts[1]);
                std::process::exit(1);
            });
            (up, down)
        } else {
            (1, 1)
        };

        // Get git SHA
        let git_sha = semcode::git::get_git_sha(&args.git_repo)?
            .unwrap_or_else(|| "0000000000000000000000000000000000000000".to_string());

        // Read diff content
        let diff_content = if let Some(ref path) = file_path {
            // Resolve path (handle ~ expansion)
            let expanded_path = if let Some(stripped) = path.strip_prefix("~/") {
                if let Some(home_dir) = std::env::var_os("HOME") {
                    std::path::Path::new(&home_dir)
                        .join(stripped)
                        .to_string_lossy()
                        .to_string()
                } else {
                    path.to_string()
                }
            } else {
                path.to_string()
            };

            std::fs::read_to_string(&expanded_path)?
        } else {
            // Read from stdin
            let mut content = String::new();
            std::io::stdin().read_to_string(&mut content)?;
            content
        };

        // Parse the diff to extract all modified functions, types, macros
        let parse_result = semcode::diffdump::parse_unified_diff(&diff_content)?;

        // Generate git manifest ONCE for all lookups (fast)
        let git_manifest = db_manager.generate_git_manifest(&git_sha).await?;

        // Build caller index ONCE with one table scan (instead of N LIKE queries)
        // This maps callee -> [callers], used for walking UP the callstack
        let caller_index = db_manager
            .build_caller_index_with_manifest(&git_manifest)
            .await?;

        // Build callee index from the same data: caller -> [callees]
        // This is the reverse of caller_index, used for walking DOWN the callstack
        let callee_index = {
            let mut idx: std::collections::HashMap<String, Vec<String>> =
                std::collections::HashMap::new();
            for (callee, callers) in &caller_index {
                for caller in callers {
                    idx.entry(caller.clone()).or_default().push(callee.clone());
                }
            }
            idx
        };

        // Collect all modified functions with their info
        let mut functions_info = Vec::new();
        let mut sorted_functions: Vec<_> = parse_result.modified_functions.iter().collect();
        sorted_functions.sort();

        for func_name in sorted_functions {
            // Get types directly without fetching body (very fast)
            let types = db_manager
                .get_function_types_with_manifest(func_name, &git_manifest)
                .await
                .unwrap_or_default();

            // Walk UP the callstack to collect callers at each level
            let callers = collect_chain_levels(func_name, up_depth, &caller_index);

            // Get direct calls from the diff parsing and database
            let mut direct_calls: Vec<String> = parse_result
                .function_calls
                .get(func_name)
                .map(|set| {
                    let mut v: Vec<_> = set
                        .iter()
                        .filter(|call| *call != func_name) // Exclude self-references
                        .cloned()
                        .collect();
                    v.sort();
                    v
                })
                .unwrap_or_default();

            // Also try to get calls from database and merge
            let calls_from_db = db_manager
                .get_function_callees_with_manifest(func_name, &git_manifest)
                .await
                .unwrap_or_default();

            // Merge database calls into diff calls (avoiding duplicates)
            for call in calls_from_db {
                if !direct_calls.contains(&call) {
                    direct_calls.push(call);
                }
            }
            direct_calls.sort();

            // Walk DOWN the callstack using the callee index
            let calls = if down_depth <= 1 {
                serde_json::json!(direct_calls)
            } else {
                // Use direct_calls as level 1, then walk deeper via callee_index
                let mut levels: Vec<serde_json::Value> = Vec::new();
                let mut current_level = direct_calls.clone();
                let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
                seen.insert(func_name.to_string());

                for _ in 0..down_depth {
                    // Deduplicate against already-seen functions
                    current_level.retain(|f| seen.insert(f.clone()));
                    current_level.sort();
                    if current_level.is_empty() {
                        break;
                    }
                    levels.push(serde_json::json!(current_level));

                    // Collect the next level from callee_index
                    let mut next_level = Vec::new();
                    for f in &current_level {
                        if let Some(callees) = callee_index.get(f) {
                            for callee in callees {
                                if !next_level.contains(callee) {
                                    next_level.push(callee.clone());
                                }
                            }
                        }
                    }
                    current_level = next_level;
                }

                serde_json::json!(levels)
            };

            let mut func_info = serde_json::Map::new();
            func_info.insert("name".to_string(), serde_json::json!(func_name));
            func_info.insert("types".to_string(), serde_json::json!(types));
            func_info.insert("callers".to_string(), callers);
            func_info.insert("calls".to_string(), calls);
            functions_info.push(serde_json::Value::Object(func_info));
        }

        // Build output JSON
        let mut output = serde_json::Map::new();

        // Modified functions with database info
        output.insert(
            "modified_functions".to_string(),
            serde_json::json!(functions_info),
        );

        // Modified types (sorted)
        let mut sorted_types: Vec<_> = parse_result.modified_types.iter().collect();
        sorted_types.sort();
        output.insert(
            "modified_types".to_string(),
            serde_json::json!(sorted_types),
        );

        // Modified macros (sorted)
        let mut sorted_macros: Vec<_> = parse_result.modified_macros.iter().collect();
        sorted_macros.sort();
        output.insert(
            "modified_macros".to_string(),
            serde_json::json!(sorted_macros),
        );

        println!("{}", serde_json::to_string_pretty(&output)?);

        return Ok(());
    }

    // Handle -q/--query option: execute a single query and exit
    if let Some(query_str) = &args.query {
        // Parse the query string using shell-like parsing (handles quoted strings)
        let parts_owned = match shlex::split(query_str) {
            Some(parts) => parts,
            None => {
                eprintln!("Error: Invalid query syntax (unclosed quotes?)");
                std::process::exit(1);
            }
        };

        if parts_owned.is_empty() {
            eprintln!("Error: Empty query");
            std::process::exit(1);
        }

        // Convert to Vec<&str> for handle_command
        let parts: Vec<&str> = parts_owned.iter().map(|s| s.as_str()).collect();

        // Rebuild workdir index to reflect current file state
        if !args.git_only {
            refresh_workdir_index(&db_manager, &args.git_repo);
        }

        // Execute the command
        match handle_command(
            &parts,
            &db_manager,
            &args.git_repo,
            &args.model_path,
            &args.branch,
        )
        .await
        {
            Ok(_) => return Ok(()),
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Perform incremental indexing if needed
    if let Err(e) = index_current_commit_if_needed(db_manager.clone(), &args.git_repo).await {
        eprintln!("Warning: Auto-indexing failed: {}", e);
    }

    // Show available tables
    let tables = db_manager.list_tables().await?;

    // Print welcome message
    print_welcome_message_with_model(&database_path, &tables, args.model_path.as_deref());

    // Create readline editor
    let mut rl = DefaultEditor::new()?;

    loop {
        let readline = rl.readline("semcode> ");

        match readline {
            Ok(line) => {
                let line = line.trim();

                if line.is_empty() {
                    continue;
                }

                // Add to history
                let _ = rl.add_history_entry(line);

                // Parse command using shell-like parsing (handles quoted strings)
                let parts_owned = match shlex::split(line) {
                    Some(parts) => parts,
                    None => {
                        println!("Error: Invalid command syntax (unclosed quotes?)");
                        continue;
                    }
                };

                if parts_owned.is_empty() {
                    continue;
                }

                // Convert to Vec<&str> for handle_command
                let parts: Vec<&str> = parts_owned.iter().map(|s| s.as_str()).collect();

                // Rebuild workdir index to reflect current file state
                if !args.git_only {
                    refresh_workdir_index(&db_manager, &args.git_repo);
                }

                // Handle command and check if we should exit
                if handle_command(
                    &parts,
                    &db_manager,
                    &args.git_repo,
                    &args.model_path,
                    &args.branch,
                )
                .await?
                {
                    break;
                }
            }
            Err(rustyline::error::ReadlineError::Interrupted) => {
                println!("^C");
                continue;
            }
            Err(rustyline::error::ReadlineError::Eof) => {
                println!("^D");
                break;
            }
            Err(err) => {
                println!("Error: {err:?}");
                break;
            }
        }
    }

    Ok(())
}
