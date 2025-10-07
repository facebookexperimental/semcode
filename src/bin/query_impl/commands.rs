// SPDX-License-Identifier: MIT OR Apache-2.0
use anstream::stdout;
use anyhow::Result;
use colored::*;
use regex;
use semcode::{git, DatabaseManager};

use semcode::callchain::{find_all_paths, show_callees, show_callers};
use owo_colors::OwoColorize as _;
use semcode::display::print_help;
use semcode::search::{
    dump_calls, dump_content, dump_functions, dump_macros, dump_processed_files, dump_typedefs,
    dump_types, query_function_or_macro_verbose, query_type_or_typedef, show_tables,
};

/// Parse a potential git SHA from command arguments or default to current HEAD
/// Returns (remaining_args, git_sha)
/// Now always returns a git SHA - either from --git flag, current HEAD, or a default
fn parse_git_sha<'a>(parts: &'a [&'a str], git_repo_path: &str) -> Result<(Vec<&'a str>, String)> {
    if parts.len() >= 3 && parts[1] == "--git" {
        let git_sha = parts[2].to_string();
        let remaining: Vec<&str> = [&parts[0..1], &parts[3..]].concat();
        Ok((remaining, git_sha))
    } else {
        // No --git flag provided, try to get current HEAD
        match git::get_git_sha(git_repo_path) {
            Ok(Some(head_sha)) => {
                tracing::debug!("Using current HEAD as default git SHA: {}", head_sha);
                Ok((parts.to_vec(), head_sha))
            }
            Ok(None) => {
                // Not in a git repository, use a placeholder
                tracing::debug!("Not in a git repository, using placeholder SHA");
                Ok((
                    parts.to_vec(),
                    "0000000000000000000000000000000000000000".to_string(),
                ))
            }
            Err(e) => {
                tracing::warn!("Failed to get current HEAD SHA: {}, using placeholder", e);
                Ok((
                    parts.to_vec(),
                    "0000000000000000000000000000000000000000".to_string(),
                ))
            }
        }
    }
}

/// Parse verbose flag from command arguments
/// Returns (remaining_args, verbose_flag)
fn parse_verbose_flag<'a>(parts: &'a [&'a str]) -> (Vec<&'a str>, bool) {
    let mut verbose = false;
    let mut remaining = Vec::new();

    // Add the command name first
    remaining.push(parts[0]);
    let mut i = 1;

    // Parse flags
    while i < parts.len() {
        match parts[i] {
            "-v" => {
                verbose = true;
                i += 1;
            }
            _ => {
                // This is the function name and any additional arguments
                remaining.extend_from_slice(&parts[i..]);
                break;
            }
        }
    }

    (remaining, verbose)
}

/// Show callchain using git-aware methods directly (same approach as working MCP tool)
async fn show_callchain_with_limits(
    db: &DatabaseManager,
    function_name: &str,
    git_sha: &str,
    up_levels: usize,
    down_levels: usize,
    calls_limit: usize,
) -> Result<()> {
    println!("Building call chain for: {}", function_name.cyan());
    println!("Git SHA: {}", git_sha.bright_black());
    println!(
        "Configuration: up_levels={}, down_levels={}, calls_limit={}\n",
        up_levels, down_levels, calls_limit
    );

    // First, check if function exists using git-aware query
    let func_opt = db.find_function_git_aware(function_name, git_sha).await?;

    let func = match func_opt {
        Some(f) => f,
        None => {
            println!(
                "{} Function '{}' not found in database at git SHA {}",
                "Error:".red(),
                function_name,
                git_sha
            );
            return Ok(());
        }
    };

    println!("{}", "=== Function Information ===".bold().green());
    println!(
        "Function: {} ({}:{})",
        func.name, func.file_path, func.line_start
    );
    println!("Return Type: {}", func.return_type);

    if !func.parameters.is_empty() {
        println!("Parameters:");
        for param in &func.parameters {
            println!("  - {} {}", param.type_name, param.name);
        }
    }

    // Get callers and callees using git-aware methods (same as MCP tool)
    let callers = db.get_function_callers_git_aware(function_name, git_sha).await?;
    let callees = db.get_function_callees_git_aware(function_name, git_sha).await?;

    // Show callers with depth and limit control
    if !callers.is_empty() && up_levels > 0 {
        println!(
            "\n{} ({} levels)",
            "=== Reverse Chain (Callers) ===".bold().magenta(),
            up_levels
        );

        let limited_callers: Vec<_> = if calls_limit == 0 {
            callers.clone()
        } else {
            callers.iter().take(calls_limit).cloned().collect()
        };

        for (i, caller) in limited_callers.iter().enumerate() {
            println!("{}. {}", (i + 1).to_string().yellow(), caller.cyan());

            // Show caller details if available
            if let Ok(Some(caller_func)) = db.find_function_git_aware(caller, git_sha).await {
                println!(
                    "   └─ {} ({}:{})",
                    caller_func.return_type.bright_black(),
                    caller_func.file_path.bright_black(),
                    caller_func.line_start.to_string().bright_black()
                );
            }

            // For multi-level depth, show second-level callers
            if up_levels > 1 {
                if let Ok(second_level_callers) = db.get_function_callers_git_aware(caller, git_sha).await {
                    let limited_second: Vec<_> = if calls_limit == 0 {
                        second_level_callers
                    } else {
                        second_level_callers.iter().take(calls_limit).cloned().collect()
                    };

                    for second_caller in limited_second.iter().take(3) {
                        println!("      └─ {}", second_caller.bright_black());
                    }
                    if limited_second.len() > 3 {
                        println!("      └─ ... and {} more", limited_second.len() - 3);
                    }
                }
            }
        }

        if calls_limit > 0 && callers.len() > calls_limit {
            println!(
                "... and {} more callers (limited by calls_limit={})",
                callers.len() - calls_limit,
                calls_limit
            );
        }
    }

    // Show callees with depth and limit control
    if !callees.is_empty() && down_levels > 0 {
        println!(
            "\n{} ({} levels)",
            "=== Forward Chain (Callees) ===".bold().blue(),
            down_levels
        );

        let limited_callees: Vec<_> = if calls_limit == 0 {
            callees.clone()
        } else {
            callees.iter().take(calls_limit).cloned().collect()
        };

        for (i, callee) in limited_callees.iter().enumerate() {
            println!("{}. {}", (i + 1).to_string().yellow(), callee.cyan());

            // Show callee details if available
            if let Ok(Some(callee_func)) = db.find_function_git_aware(callee, git_sha).await {
                println!(
                    "   └─ {} ({}:{})",
                    callee_func.return_type.bright_black(),
                    callee_func.file_path.bright_black(),
                    callee_func.line_start.to_string().bright_black()
                );
            }

            // For multi-level depth, show second-level callees
            if down_levels > 1 {
                if let Ok(second_level_callees) = db.get_function_callees_git_aware(callee, git_sha).await {
                    let limited_second: Vec<_> = if calls_limit == 0 {
                        second_level_callees
                    } else {
                        second_level_callees.iter().take(calls_limit).cloned().collect()
                    };

                    for second_callee in limited_second.iter().take(3) {
                        println!("      └─ {}", second_callee.bright_black());
                    }
                    if limited_second.len() > 3 {
                        println!("      └─ ... and {} more", limited_second.len() - 3);
                    }
                }
            }
        }

        if calls_limit > 0 && callees.len() > calls_limit {
            println!(
                "... and {} more callees (limited by calls_limit={})",
                callees.len() - calls_limit,
                calls_limit
            );
        }
    }

    // Summary
    println!("\n{}", "=== Summary ===".bold().green());
    println!("Total direct callers: {}", callers.len());
    println!("Total direct callees: {}", callees.len());

    if callers.is_empty() && callees.is_empty() {
        println!(
            "{} This function is isolated (no callers or callees)",
            "Info:".yellow()
        );
    }

    Ok(())
}

pub async fn handle_command(
    parts: &[&str],
    db: &DatabaseManager,
    git_repo_path: &str,
    model_path: &Option<String>,
) -> Result<bool> {
    // Parse potential git SHA first
    let (parts, git_sha) = parse_git_sha(parts, git_repo_path)?;

    match parts[0] {
        "quit" | "exit" | "q" => {
            println!("Goodbye!");
            return Ok(true); // Signal to exit
        }
        "help" | "h" | "?" => {
            print_help();
        }
        "func" | "function" | "f" => {
            // Parse only -v flag (git_sha already parsed by main handler)
            let (parsed_parts, verbose) = parse_verbose_flag(&parts);

            if parsed_parts.len() < 2 {
                println!("{}", "Usage: func [-v] [--git <sha>] <name>".red());
                println!("  Search for a function by name, optionally at a specific git commit");
                println!(
                    "  -v: Show verbose output with all calls/callers (default: truncate at 25)"
                );
            } else {
                let name = parsed_parts[1..].join(" ");
                query_function_or_macro_verbose(db, &name, &git_sha, verbose).await?;
            }
        }
        "type" | "ty" => {
            if parts.len() < 2 {
                println!("{}", "Usage: type [--git <sha>] <name>".red());
                println!("  Search for a type by name, optionally at a specific git commit");
            } else {
                let name = parts[1..].join(" ");
                query_type_or_typedef(db, &name, &git_sha).await?;
            }
        }
        "grep" => {
            if parts.len() < 2 {
                println!("{}", "Usage: grep [--git <sha>] [-v] [-p <path_regex>] [--limit <N>] <regex_pattern>".red());
                println!("  Search function bodies using regex patterns, optionally at a specific git commit");
                println!(
                    "  --git <sha>: Search at specific git commit (defaults to current git HEAD)"
                );
                println!("  -v: Show full function body (default shows only matching lines)");
                println!("  -p <path_regex>: Filter results to files matching the path regex (defaults to unlimited)");
                println!("  --limit <N>: Limit number of results (default: 100, 0 = unlimited)");
                println!("  Example: grep \"malloc\\\\(.*\\\\)\"");
                println!("  Example: grep --git abc123 \"malloc\"");
                println!("  Example: grep -v \"if.*==.*NULL\"");
                println!("  Example: grep -p \"src/.*\\\\.c\" \"malloc\"");
                println!("  Example: grep --limit 50 \"function_call\"");
                println!("  Example: grep --limit 0 \"unlimited_search\"");
                println!("  Example: grep -p \"src/.*\\\\.c\" --limit 25 \"malloc\" # limit applies to filtered results");
            } else {
                // Parse -v, -p, and --limit flags
                let mut verbose = false;
                let mut path_pattern = None;
                let mut limit = 100; // Default limit
                let mut explicit_limit = false;
                let mut pattern_parts = Vec::new();
                let mut i = 1;

                while i < parts.len() {
                    if parts[i] == "-v" {
                        verbose = true;
                        i += 1;
                    } else if parts[i] == "-p" && i + 1 < parts.len() {
                        path_pattern = Some(parts[i + 1].to_string());
                        i += 2;
                    } else if parts[i] == "--limit" && i + 1 < parts.len() {
                        match parts[i + 1].parse::<usize>() {
                            Ok(n) => {
                                limit = n;
                                explicit_limit = true;
                                i += 2;
                            }
                            Err(_) => {
                                println!(
                                    "{} Invalid limit value: {}",
                                    "Error:".red(),
                                    parts[i + 1]
                                );
                                return Ok(false);
                            }
                        }
                    } else {
                        pattern_parts.extend_from_slice(&parts[i..]);
                        break;
                    }
                }

                // If -p is used and no explicit limit was set, use unlimited (0)
                // When -p is used, any limit applies to the path-filtered results
                if path_pattern.is_some() && !explicit_limit {
                    limit = 0;
                }

                if pattern_parts.is_empty() {
                    println!("{}", "Usage: grep [--git <sha>] [-v] [-p <path_regex>] [--limit <N>] <regex_pattern>".red());
                } else {
                    let pattern = pattern_parts.join(" ");
                    match grep_function_bodies(
                        db,
                        &pattern,
                        verbose,
                        path_pattern.as_deref(),
                        limit,
                        &git_sha,
                    )
                    .await
                    {
                        Ok(()) => {}
                        Err(e) => {
                            println!("{} {}", "Error:".red(), e);
                            println!("{} Check your regex pattern syntax and try again.", "Hint:".yellow());
                        }
                    }
                }
            }
        }
        "vgrep" => {
            if parts.len() < 2 {
                println!(
                    "{}",
                    "Usage: vgrep [--git <sha>] [-p <path_regex>] [--limit <N>] <query_text>".red()
                );
                println!(
                    "  Search for functions similar to the provided text using semantic vectors"
                );
                println!(
                    "  --git <sha>: Search at specific git commit (defaults to current git HEAD)"
                );
                println!("  -p <path_regex>: Filter results to files matching the path regex");
                println!("  --limit <N>: Limit number of results (default: 10, max: 100)");
                println!("  Example: vgrep \"memory allocation function\"");
                println!("  Example: vgrep --limit 5 \"string comparison\"");
                println!("  Example: vgrep -p \"src/.*\\\\.c\" \"hash table lookup\"");
                println!("  Example: vgrep --git abc123 \"hash table lookup\"");
                println!(
                    "  Note: Requires vectors to be generated first with 'semcode-index --vectors'"
                );
            } else {
                // Parse --limit and -p flags
                let mut limit = 10; // default
                let mut file_pattern = None;
                let mut query_parts = Vec::new();
                let mut i = 1;

                while i < parts.len() {
                    if parts[i] == "--limit" && i + 1 < parts.len() {
                        match parts[i + 1].parse::<usize>() {
                            Ok(n) => {
                                limit = n.min(100); // Cap at 100
                                i += 2;
                            }
                            Err(_) => {
                                println!(
                                    "{} Invalid limit value: {}",
                                    "Error:".red(),
                                    parts[i + 1]
                                );
                                return Ok(false);
                            }
                        }
                    } else if parts[i] == "-p" && i + 1 < parts.len() {
                        file_pattern = Some(parts[i + 1].to_string());
                        i += 2;
                    } else {
                        query_parts.extend_from_slice(&parts[i..]);
                        break;
                    }
                }

                if query_parts.is_empty() {
                    println!(
                        "{}",
                        "Usage: vgrep [--git <sha>] [-p <path_regex>] [--limit <N>] <query_text>"
                            .red()
                    );
                } else {
                    let query_text = query_parts.join(" ");
                    vgrep_similar_functions(
                        db,
                        &query_text,
                        limit,
                        file_pattern.as_deref(),
                        model_path,
                    )
                    .await?;
                }
            }
        }
        "callers" => {
            // Parse only -v flag (git_sha already parsed by main handler)
            let (parsed_parts, verbose) = parse_verbose_flag(&parts);

            if parsed_parts.len() < 2 {
                println!(
                    "{}",
                    "Usage: callers [-v] [--git <sha>] <function_name>".red()
                );
                println!("  Find functions that call the given function, optionally at a specific git commit");
                println!(
                    "  -v: Show verbose output with file paths, line numbers, and git file hashes"
                );
                println!("  Defaults to current git commit when in a git repository");
            } else {
                let name = parsed_parts[1..].join(" ");
                show_callers(db, &name, verbose, &git_sha).await?;
            }
        }
        "calls" => {
            // Parse only -v flag (git_sha already parsed by main handler)
            let (parsed_parts, verbose) = parse_verbose_flag(&parts);

            if parsed_parts.len() < 2 {
                println!(
                    "{}",
                    "Usage: calls [-v] [--git <sha>] <function_name>".red()
                );
                println!("  Find functions called by the given function, optionally at a specific git commit");
                println!(
                    "  -v: Show verbose output with file paths, line numbers, and git file hashes"
                );
                println!("  Defaults to current git commit when in a git repository");
            } else {
                let name = parsed_parts[1..].join(" ");
                show_callees(db, &name, verbose, &git_sha).await?;
            }
        }
        "callchain" => {
            if parts.len() < 2 {
                println!("{}", "Usage: callchain [--git <sha>] [--up <levels>] [--down <levels>] [--calls <limit>] <function_name>".red());
                println!(
                    "  Show call chain for the given function, optionally at a specific git commit"
                );
                println!(
                    "  --up <levels>:   Number of caller levels to show (default: 2, 0 = no limit)"
                );
                println!(
                    "  --down <levels>: Number of callee levels to show (default: 5, 0 = no limit)"
                );
                println!("  --calls <limit>: Maximum calls to show per level (default: 15, 0 = no limit)");
            } else {
                // Parse --up, --down, and --calls arguments
                let mut up_levels = 2; // default
                let mut down_levels = 3; // default
                let mut calls_limit = 15; // default
                let mut function_name = String::new();
                let mut i = 1;

                while i < parts.len() {
                    if parts[i] == "--up" && i + 1 < parts.len() {
                        if let Ok(levels) = parts[i + 1].parse::<usize>() {
                            up_levels = if levels == 0 { 15 } else { levels }; // 0 means no limit (use 15 as practical max)
                            i += 2;
                        } else {
                            println!(
                                "{} Invalid number for --up: {}",
                                "Error:".red(),
                                parts[i + 1]
                            );
                            return Ok(false);
                        }
                    } else if parts[i] == "--down" && i + 1 < parts.len() {
                        if let Ok(levels) = parts[i + 1].parse::<usize>() {
                            down_levels = if levels == 0 { 15 } else { levels }; // 0 means no limit (use 15 as practical max)
                            i += 2;
                        } else {
                            println!(
                                "{} Invalid number for --down: {}",
                                "Error:".red(),
                                parts[i + 1]
                            );
                            return Ok(false);
                        }
                    } else if parts[i] == "--calls" && i + 1 < parts.len() {
                        if let Ok(limit) = parts[i + 1].parse::<usize>() {
                            calls_limit = limit; // 0 means no limit (keep as 0)
                            i += 2;
                        } else {
                            println!(
                                "{} Invalid number for --calls: {}",
                                "Error:".red(),
                                parts[i + 1]
                            );
                            return Ok(false);
                        }
                    } else {
                        if !function_name.is_empty() {
                            function_name.push(' ');
                        }
                        function_name.push_str(parts[i]);
                        i += 1;
                    }
                }

                if function_name.is_empty() {
                    println!("{} No function name specified", "Error:".red());
                    return Ok(false);
                }

                // Use the same approach as the working MCP tool - call git-aware methods directly
                match show_callchain_with_limits(db, &function_name, &git_sha, up_levels, down_levels, calls_limit).await {
                    Ok(()) => {},
                    Err(e) => {
                        println!("{} Failed to show callchain: {}", "Error:".red(), e);
                    }
                }
            }
        }
        "paths" => {
            if parts.len() < 2 {
                println!("{}", "Usage: paths [--git <sha>] <function_name>".red());
                println!(
                    "  Find all paths to the given function, optionally at a specific git commit"
                );
            } else {
                let name = parts[1..].join(" ");
                find_all_paths(db, &name, &git_sha).await?;
            }
        }
        "tables" | "t" => {
            show_tables(db).await?;
        }
        "dump-functions" | "df" => {
            if parts.len() < 2 {
                println!("{}", "Usage: dump-functions <output_file>".red());
            } else {
                let output_file = parts[1..].join(" ");
                dump_functions(db, &output_file).await?;
            }
        }
        "dump-types" | "dt" => {
            if parts.len() < 2 {
                println!("{}", "Usage: dump-types <output_file>".red());
            } else {
                let output_file = parts[1..].join(" ");
                dump_types(db, &output_file).await?;
            }
        }
        "dump-typedefs" | "dtd" => {
            if parts.len() < 2 {
                println!("{}", "Usage: dump-typedefs <output_file>".red());
            } else {
                let output_file = parts[1..].join(" ");
                dump_typedefs(db, &output_file).await?;
            }
        }
        "dump-macros" | "dm" => {
            if parts.len() < 2 {
                println!("{}", "Usage: dump-macros <output_file>".red());
            } else {
                let output_file = parts[1..].join(" ");
                dump_macros(db, &output_file).await?;
            }
        }
        "dump-calls" | "dc" => {
            if parts.len() < 2 {
                println!("{}", "Usage: dump-calls <output_file>".red());
            } else {
                let output_file = parts[1..].join(" ");
                dump_calls(db, &output_file).await?;
            }
        }
        "dump-processed-files" | "dpf" => {
            if parts.len() < 2 {
                println!("{}", "Usage: dump-processed-files <output_file>".red());
            } else {
                let output_file = parts[1..].join(" ");
                dump_processed_files(db, &output_file).await?;
            }
        }
        "dump-content" | "dcont" => {
            if parts.len() < 2 {
                println!("{}", "Usage: dump-content <output_file>".red());
                println!("  Export the content table to JSON with hashes converted to hex strings");
            } else {
                let output_file = parts[1..].join(" ");
                dump_content(db, &output_file).await?;
            }
        }
        "diffinfo" | "di" => {
            // Parse arguments for -i input_file flag
            let mut input_file = None;
            let mut i = 1;

            while i < parts.len() {
                if parts[i] == "-i" && i + 1 < parts.len() {
                    input_file = Some(parts[i + 1].to_string());
                    i += 2;
                } else {
                    println!("{}", "Usage: diffinfo [-i <diff_file>]".red());
                    println!("  If -i is not specified, reads diff from stdin");
                    return Ok(false);
                }
            }

            use semcode::diffdump::diffinfo;
            diffinfo(input_file.as_deref()).await?;
        }
        "optimize_db" | "optimize" | "opt" => {
            println!(
                "{}",
                "Optimizing database (rebuilding indices and compacting tables)...".yellow()
            );
            match db.optimize_database().await {
                Ok(_) => {
                    println!("{}", "✓ Database optimization complete".green());
                    println!("  - Rebuilt all scalar indices for faster queries");
                    println!(
                        "  - Compacted tables to reduce storage overhead and improve compression"
                    );
                    println!("  - Call chain queries should now perform better");
                }
                Err(e) => {
                    println!("{} Failed to optimize database: {}", "Error:".red(), e);
                }
            }
        }
        "storage_stats" | "stats" | "size" => {
            match db.get_storage_stats().await {
                Ok(_) => {
                    // Stats are printed by the method
                }
                Err(e) => {
                    println!("{} Failed to get storage stats: {}", "Error:".red(), e);
                }
            }
        }
        "compact_db" | "compact" => {
            println!(
                "{}",
                "Running LanceDB optimization with proper handle management...".yellow()
            );
            match db.compact_database().await {
                Ok(_) => {
                    println!("{}", "✓ LanceDB optimization complete".green());
                    println!("  - Optimized tables (compacted files and indices)");
                    println!("  - Checked out latest versions to release old handles");
                    println!("  - Dropped and recreated table handles to trigger cleanup");
                    println!("  - Note: Advanced cleanup methods may not be available in this LanceDB version");
                }
                Err(e) => {
                    println!("{} Failed to optimize database: {}", "Error:".red(), e);
                }
            }
        }
        "scan_duplicates" | "duplicates" | "dupe" => {
            println!(
                "{}",
                "Scanning database for 100% duplicate entries...".yellow()
            );
            match db.scan_for_duplicates().await {
                Ok(_) => {
                    // Results are printed by the method
                }
                Err(e) => {
                    println!("{} Failed to scan for duplicates: {}", "Error:".red(), e);
                }
            }
        }
        "drop_recreate_db" | "drop_recreate" | "recreate_all" => {
            println!(
                "{}",
                "WARNING: This will drop and recreate ALL tables for maximum space savings!"
                    .yellow()
            );
            println!("This operation:");
            println!("  - Exports all data from all tables");
            println!("  - Drops all tables completely");
            println!("  - Recreates tables with fresh schemas");
            println!("  - Re-imports all data");
            println!("  - Rebuilds all indices");
            println!();
            print!("Are you sure you want to continue? (type 'yes' to confirm): ");
            use std::io::{self, Write};
            stdout().flush().unwrap();

            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();

            if input.trim().to_lowercase() == "yes" {
                println!("{}", "Starting drop and recreate operation...".yellow());
                match db.drop_and_recreate_tables().await {
                    Ok(_) => {
                        println!("{}", "✓ Drop and recreate operation complete!".green());
                        println!("  - All tables have been dropped and recreated");
                        println!("  - All data has been preserved");
                        println!("  - Maximum space savings achieved");
                        println!("  - All indices have been rebuilt");
                    }
                    Err(e) => {
                        println!(
                            "{} Failed to drop and recreate tables: {}",
                            "Error:".red(),
                            e
                        );
                        println!("Database may be in an inconsistent state - consider restoring from backup");
                    }
                }
            } else {
                println!("Operation cancelled.");
            }
        }
        "drop_recreate_table" | "recreate_table" => {
            if parts.len() < 2 {
                println!("{}", "Usage: drop_recreate_table <table_name>".red());
                println!("Available tables: functions, types, macros, processed_files");
            } else {
                let table_name = parts[1];
                let valid_tables = ["functions", "types", "macros", "processed_files"];

                if !valid_tables.contains(&table_name) {
                    println!("{} Invalid table name: {}", "Error:".red(), table_name);
                    println!("Available tables: {}", valid_tables.join(", "));
                } else {
                    println!(
                        "{}",
                        format!(
                            "WARNING: This will drop and recreate the '{table_name}' table!"
                        )
                        .yellow()
                    );
                    println!("This operation:");
                    println!("  - Exports all data from the {table_name} table");
                    println!("  - Drops the table completely");
                    println!("  - Recreates the table with fresh schema");
                    println!("  - Re-imports all data");
                    println!("  - Rebuilds indices for this table");
                    println!();
                    print!("Are you sure you want to continue? (type 'yes' to confirm): ");
                    use std::io::{self, Write};
                    stdout().flush().unwrap();

                    let mut input = String::new();
                    io::stdin().read_line(&mut input).unwrap();

                    if input.trim().to_lowercase() == "yes" {
                        println!(
                            "{}",
                            format!("Starting drop and recreate for table '{table_name}'...")
                                .yellow()
                        );
                        match db.drop_and_recreate_table(table_name).await {
                            Ok(_) => {
                                println!(
                                    "{}",
                                    format!(
                                        "✓ Drop and recreate operation complete for table '{table_name}'!"
                                    )
                                    .green()
                                );
                                println!("  - Table has been dropped and recreated");
                                println!("  - All data has been preserved");
                                println!("  - Maximum space savings achieved for this table");
                                println!("  - Indices have been rebuilt");
                            }
                            Err(e) => {
                                println!(
                                    "{} Failed to drop and recreate table '{}': {}",
                                    "Error:".red(),
                                    table_name,
                                    e
                                );
                                println!("Table may be in an inconsistent state - consider running 'optimize_db' to fix indices");
                            }
                        }
                    } else {
                        println!("Operation cancelled.");
                    }
                }
            }
        }
        _ => {
            println!(
                "{} Unknown command: '{}'. Type 'help' for available commands.",
                "Error:".red(),
                parts[0]
            );
        }
    }

    Ok(false) // Continue the loop
}

/// Search function bodies using regex patterns
async fn grep_function_bodies(
    db: &DatabaseManager,
    pattern: &str,
    verbose: bool,
    path_pattern: Option<&str>,
    limit: usize,
    git_sha: &str,
) -> Result<()> {
    match (path_pattern, limit) {
        (Some(path_regex), 0) => println!(
            "Searching function bodies for pattern: {} (filtering paths matching: {}, unlimited) at git commit {}",
            pattern.yellow(),
            path_regex.cyan(),
            git_sha.bright_black()
        ),
        (Some(path_regex), n) => println!(
            "Searching function bodies for pattern: {} (filtering paths matching: {}, limit: {}) at git commit {}",
            pattern.yellow(),
            path_regex.cyan(),
            n,
            git_sha.bright_black()
        ),
        (None, 0) => println!(
            "Searching function bodies for pattern: {} (unlimited) at git commit {}",
            pattern.yellow(),
            git_sha.bright_black()
        ),
        (None, n) => println!(
            "Searching function bodies for pattern: {} (limit: {}) at git commit {}",
            pattern.yellow(),
            n,
            git_sha.bright_black()
        ),
    }

    // Perform regex search on function bodies using LanceDB (git-aware)
    let (matching_functions, limit_hit) = db
        .grep_function_bodies_git_aware(pattern, path_pattern, limit, git_sha)
        .await?;

    if matching_functions.is_empty() {
        println!(
            "{} No functions found matching pattern '{}'",
            "Info:".yellow(),
            pattern
        );
        return Ok(());
    }

    // Show warning if limit was hit
    if limit_hit {
        println!(
            "{} grep warning: limit hit ({} results)",
            "Warning:".yellow(),
            matching_functions.len()
        );
    }

    if verbose {
        // Verbose mode: show full function bodies (original behavior)
        println!(
            "\nFound {} function(s) matching pattern:",
            matching_functions.len()
        );
        println!("{}", "=".repeat(60));

        for func in &matching_functions {
            println!(
                "\n{} {}:{}",
                "Function:".bold().green(),
                func.name.cyan(),
                func.line_start.to_string().bright_black()
            );
            println!(
                "{} {}",
                "File:".bold().blue(),
                func.file_path.bright_black()
            );
            println!(
                "{} {}",
                "File SHA:".bold().blue(),
                func.git_file_hash.bright_black()
            );

            // Show the function body with the matching pattern highlighted
            println!("\n{}", "Function Body:".bold().magenta());
            println!("{}", "─".repeat(60).bright_black());

            // Split function body into lines and show with line numbers relative to function start
            let lines: Vec<&str> = func.body.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let line_num = func.line_start + i as u32;
                println!("{:4}: {}", line_num.to_string().bright_black(), line);
            }

            println!("{}", "─".repeat(60).bright_black());
        }
    } else {
        // Default mode: show only matching lines with file:function: prefix
        println!("\nFound {} matching line(s):", matching_functions.len());

        // Compile regex for line matching
        let regex = match regex::Regex::new(pattern) {
            Ok(re) => re,
            Err(e) => {
                println!(
                    "{} Invalid regex pattern '{}': {}",
                    "Error:".red(),
                    pattern,
                    e
                );
                return Ok(());
            }
        };

        let mut total_matches = 0;

        for func in &matching_functions {
            let lines: Vec<&str> = func.body.lines().collect();

            for (i, line) in lines.iter().enumerate() {
                if regex.is_match(line) {
                    let line_num = func.line_start + i as u32;
                    println!(
                        "{}:{}:{}: {}",
                        func.file_path.bright_black(),
                        func.name.cyan(),
                        line_num.to_string().bright_black(),
                        line.trim()
                    );
                    total_matches += 1;
                }
            }
        }

        if total_matches == 0 {
            println!(
                "{} Functions matched pattern but no individual lines matched",
                "Info:".yellow()
            );
        }
    }

    println!(
        "\n{} Total function matches: {}",
        "Summary:".bold().green(),
        matching_functions.len()
    );
    Ok(())
}

/// Search for functions similar to given query text using vector embeddings
async fn vgrep_similar_functions(
    db: &DatabaseManager,
    query_text: &str,
    limit: usize,
    file_pattern: Option<&str>,
    model_path: &Option<String>,
) -> Result<()> {
    use semcode::CodeVectorizer;

    match file_pattern {
        Some(pattern) => println!(
            "Searching for functions similar to: {} (filtering files matching: {}, limit: {})",
            query_text.yellow(),
            pattern.cyan(),
            limit
        ),
        None => println!(
            "Searching for functions similar to: {} (limit: {})",
            query_text.yellow(),
            limit
        ),
    }

    // Initialize vectorizer
    println!("Initializing vectorizer...");
    let vectorizer = match CodeVectorizer::new_with_config(false, model_path.clone()).await {
        Ok(v) => v,
        Err(e) => {
            println!("{} Failed to initialize vectorizer: {}", "Error:".red(), e);
            println!(
                "Make sure you have a model available. Use --model-path to specify a custom model."
            );
            return Ok(());
        }
    };

    // Generate vector for query text
    println!("Generating query vector...");
    let query_vector = match vectorizer.vectorize_code(query_text) {
        Ok(v) => v,
        Err(e) => {
            println!(
                "{} Failed to generate vector for query: {}",
                "Error:".red(),
                e
            );
            return Ok(());
        }
    };

    // Search for similar functions with scores (no database-level filtering)
    // We'll apply path filtering as post-processing, same as grep command
    let search_limit = if file_pattern.is_some() {
        // When path filtering, get many more results initially since we'll filter them down
        // Use a large limit to ensure we find enough matches after filtering
        1000
    } else {
        limit
    };

    match db
        .search_similar_functions_with_scores(&query_vector, search_limit, None)
        .await
    {
        Ok(matches) if matches.is_empty() => {
            println!("{} No similar functions found", "Info:".yellow());
            println!("Make sure vectors have been generated with 'semcode-index --vectors'");
        }
        Ok(matches) => {
            // Apply path filtering if provided (same approach as grep command)
            let final_matches = if let Some(path_regex) = file_pattern {
                match regex::Regex::new(path_regex) {
                    Ok(path_re) => {
                        let original_count = matches.len();
                        let filtered: Vec<_> = matches
                            .into_iter()
                            .filter(|m| path_re.is_match(&m.function.file_path))
                            .take(limit) // Apply the original limit to filtered results
                            .collect();

                        tracing::debug!(
                            "Path filter '{}' reduced results from {} to {} functions",
                            path_regex,
                            original_count,
                            filtered.len()
                        );

                        filtered
                    }
                    Err(e) => {
                        println!(
                            "{} Invalid regex pattern '{}': {}",
                            "Error:".red(),
                            path_regex,
                            e
                        );
                        return Ok(());
                    }
                }
            } else {
                matches
            };

            if final_matches.is_empty() {
                println!("{} No similar functions found", "Info:".yellow());
                if file_pattern.is_some() {
                    println!("Try adjusting the file pattern or removing the -p filter");
                } else {
                    println!(
                        "Make sure vectors have been generated with 'semcode-index --vectors'"
                    );
                }
                return Ok(());
            }

            println!(
                "\n{} Found {} similar function(s):",
                "Results:".bold().green(),
                final_matches.len()
            );
            println!("{}", "=".repeat(80));

            for (i, match_result) in final_matches.iter().enumerate() {
                let func = &match_result.function;
                println!(
                    "\n{}. {} {} {} {}%",
                    (i + 1).to_string().yellow(),
                    "Function:".bold(),
                    func.name.cyan(),
                    "Similarity:".bold(),
                    format!("{:.1}", match_result.similarity_score * 100.0).bright_green()
                );
                println!(
                    "   {} {}:{}",
                    "Location:".bold(),
                    func.file_path.bright_black(),
                    func.line_start.to_string().bright_black()
                );
                println!("   {} {}", "Return:".bold(), func.return_type.magenta());

                // Show parameters if any
                if !func.parameters.is_empty() {
                    let param_strings: Vec<String> = func
                        .parameters
                        .iter()
                        .map(|p| format!("{} {}", p.type_name, p.name))
                        .collect();
                    println!(
                        "   {} ({})",
                        "Parameters:".bold(),
                        param_strings.join(", ").bright_black()
                    );
                }

                // Show a preview of the function body (first 3 lines)
                if !func.body.is_empty() {
                    let lines: Vec<&str> = func.body.lines().take(3).collect();
                    if !lines.is_empty() {
                        println!("   {} ", "Preview:".bold());
                        for line in lines {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() {
                                println!("     {}", trimmed.bright_black());
                            }
                        }
                        if func.body.lines().count() > 3 {
                            println!("     {}", "...".bright_black());
                        }
                    }
                }
            }

            println!("\n{}", "=".repeat(80));
            println!(
                "{} Use 'func <name>' to see full details of a specific function",
                "Tip:".bold().blue()
            );
        }
        Err(e) => {
            println!("{} Vector search failed: {}", "Error:".red(), e);
            println!("Make sure vectors have been generated with 'semcode-index --vectors'");
        }
    }

    Ok(())
}
