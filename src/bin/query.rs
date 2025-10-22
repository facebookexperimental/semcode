// SPDX-License-Identifier: MIT OR Apache-2.0
mod query_impl;

use anyhow::Result;
use clap::Parser;
use rustyline::DefaultEditor;
use semcode::{process_database_path, DatabaseManager};
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
    let db_manager = DatabaseManager::new(&database_path, args.git_repo.clone()).await?;

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
