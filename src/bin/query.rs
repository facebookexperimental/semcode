// SPDX-License-Identifier: MIT OR Apache-2.0
mod query_impl;

use anyhow::Result;
use clap::Parser;
use rustyline::DefaultEditor;
use semcode::{process_database_path, DatabaseManager};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

use query_impl::commands::handle_command;
use semcode::display::print_welcome_message_with_model;

#[derive(Parser, Debug)]
#[command(name = "semcode")]
#[command(about = "Query the semantic code database", long_about = None)]
struct Args {
    /// Path to database directory or parent directory containing .semcode.db (default: search current directory)
    #[arg(short, long)]
    database: Option<String>,

    /// Path to the git repository for git-aware queries
    #[arg(long, default_value = ".")]
    git_repo: String,

    /// Path to local model directory (for semantic search)
    #[arg(long, value_name = "PATH")]
    model_path: Option<String>,
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

    // Quick check: if a file changed in the current commit is already indexed with
    // its current SHA, we can skip indexing entirely (nothing new to process)
    // Compare HEAD with HEAD~1 (parent) to find changed files
    match semcode::git::get_changed_files(&repo_path, "HEAD~1", "HEAD") {
        Ok(changed_files) => {
            if !changed_files.is_empty() {
                // Find first C/C++/Rust file that was changed (added or modified)
                if let Some(changed_file) = changed_files.iter().find(|cf| {
                    matches!(
                        cf.change_type,
                        semcode::git::ChangeType::Added | semcode::git::ChangeType::Modified
                    ) && cf.new_file_hash.is_some()
                        && semcode::file_extensions::is_supported_for_analysis(&cf.path)
                }) {
                    if let Some(new_hash) = &changed_file.new_file_hash {
                        // Get already processed files from database
                        let processed_pairs = db_manager.get_processed_file_pairs().await?;

                        // Check if this changed file with its new SHA is already in database
                        if processed_pairs.contains(&(changed_file.path.clone(), new_hash.clone()))
                        {
                            info!(
                                "Changed file '{}' (SHA: {}) already indexed, skipping auto-indexing",
                                changed_file.path,
                                &new_hash[..8]
                            );
                            return Ok(());
                        } else {
                            info!(
                                "Changed file '{}' (SHA: {}) needs indexing",
                                changed_file.path,
                                &new_hash[..8]
                            );
                        }
                    }
                }
            } else {
                // No changes in this commit (might be initial commit or root commit)
                info!("No changed files found in current commit, will check all files");
            }
        }
        Err(e) => {
            // Failed to get changed files (might be initial commit, root commit, etc.)
            info!("Could not get changed files ({}), will check all files", e);
        }
    }

    // Run git range indexing using the shared library function
    // This uses the same code path as semcode-index -s .
    println!("Checking for files to index...");

    // Create synthetic range for current commit: HEAD^..HEAD
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

                // Handle command and check if we should exit
                if handle_command(&parts, &db_manager, &args.git_repo, &args.model_path).await? {
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
