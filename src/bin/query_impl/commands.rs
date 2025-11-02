// SPDX-License-Identifier: MIT OR Apache-2.0
use anstream::stdout;
use anyhow::Result;
use colored::*;
use regex;
use semcode::{git, DatabaseManager};

use owo_colors::OwoColorize as _;
use semcode::callchain::{find_all_paths, show_callees, show_callers};
use semcode::display::print_help;
use semcode::search::{
    dump_calls, dump_content, dump_functions, dump_git_commits, dump_macros, dump_processed_files,
    dump_symbol_filename, dump_typedefs, dump_types, query_function_or_macro_verbose,
    query_type_or_typedef, show_tables,
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
    let callers = db
        .get_function_callers_git_aware(function_name, git_sha)
        .await?;
    let callees = db
        .get_function_callees_git_aware(function_name, git_sha)
        .await?;

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
                if let Ok(second_level_callers) =
                    db.get_function_callers_git_aware(caller, git_sha).await
                {
                    let limited_second: Vec<_> = if calls_limit == 0 {
                        second_level_callers
                    } else {
                        second_level_callers
                            .iter()
                            .take(calls_limit)
                            .cloned()
                            .collect()
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
                if let Ok(second_level_callees) =
                    db.get_function_callees_git_aware(callee, git_sha).await
                {
                    let limited_second: Vec<_> = if calls_limit == 0 {
                        second_level_callees
                    } else {
                        second_level_callees
                            .iter()
                            .take(calls_limit)
                            .cloned()
                            .collect()
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
    // Handle commit command first (before parse_git_sha) since it uses --git differently
    if parts[0] == "commit" {
        // Parse -v, --git, -r, -s, -p, --limit, and --reachable flags
        let mut verbose = false;
        let mut git_range = None;
        let mut regex_patterns = Vec::new();
        let mut symbol_patterns = Vec::new();
        let mut path_patterns = Vec::new();
        let mut limit = 50; // Default display limit
        let mut reachable_sha = None;
        let mut git_ref_parts = Vec::new();
        let mut i = 1;

        while i < parts.len() {
            if parts[i] == "-v" {
                verbose = true;
                i += 1;
            } else if parts[i] == "--git" && i + 1 < parts.len() {
                git_range = Some(parts[i + 1].to_string());
                i += 2;
            } else if parts[i] == "-r" && i + 1 < parts.len() {
                regex_patterns.push(parts[i + 1].to_string());
                i += 2;
            } else if parts[i] == "-s" && i + 1 < parts.len() {
                symbol_patterns.push(parts[i + 1].to_string());
                i += 2;
            } else if parts[i] == "-p" && i + 1 < parts.len() {
                path_patterns.push(parts[i + 1].to_string());
                i += 2;
            } else if parts[i] == "--limit" && i + 1 < parts.len() {
                match parts[i + 1].parse::<usize>() {
                    Ok(n) => {
                        limit = n;
                        i += 2;
                    }
                    Err(_) => {
                        println!("{} Invalid limit value: {}", "Error:".red(), parts[i + 1]);
                        return Ok(false);
                    }
                }
            } else if parts[i] == "--reachable" && i + 1 < parts.len() {
                reachable_sha = Some(parts[i + 1].to_string());
                i += 2;
            } else {
                git_ref_parts.extend_from_slice(&parts[i..]);
                break;
            }
        }

        if git_ref_parts.is_empty() && git_range.is_none() {
            // No arguments provided - show all commits from database
            show_all_commits(
                db,
                verbose,
                &regex_patterns,
                &symbol_patterns,
                &path_patterns,
                limit,
                reachable_sha.as_deref(),
                git_repo_path,
            )
            .await?;
        } else if let Some(range) = git_range {
            show_commit_range(
                db,
                &range,
                verbose,
                &regex_patterns,
                &symbol_patterns,
                &path_patterns,
                limit,
                reachable_sha.as_deref(),
                git_repo_path,
            )
            .await?;
        } else {
            let git_ref = git_ref_parts.join(" ");
            show_commit_metadata(
                db,
                &git_ref,
                verbose,
                &regex_patterns,
                &symbol_patterns,
                &path_patterns,
                reachable_sha.as_deref(),
                git_repo_path,
            )
            .await?;
        }

        return Ok(false); // Continue the loop
    }

    // Parse potential git SHA first (for all other commands)
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
                            println!(
                                "{} Check your regex pattern syntax and try again.",
                                "Hint:".yellow()
                            );
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
        "vcommit" => {
            if parts.len() < 2 {
                println!(
                    "{}",
                    "Usage: vcommit [--git <range>] [-r <regex>] [-s <regex>] [-p <path_regex>] [--limit <N=200>] [--reachable <sha>] <query_text>".red()
                );
                println!(
                    "  Search for commits similar to the provided text using semantic vectors"
                );
                println!("  --git <range>: Filter to commits in git range (e.g., HEAD~100..HEAD)");
                println!("  -r <regex>: Filter results by regex pattern on message + diff (can be used multiple times for AND logic)");
                println!("  -s <regex>: Filter results by regex pattern on symbol list (can be used multiple times for AND logic)");
                println!("  -p <path_regex>: Filter results by regex pattern on file paths (can be used multiple times for OR logic)");
                println!("  --limit <N>: Limit number of results (default: 200, max: 500)");
                println!("  --reachable <sha>: Filter to commits reachable from the given SHA");
                println!("  Example: vcommit \"fix memory leak\"");
                println!("  Example: vcommit --limit 5 \"refactor parser\"");
                println!("  Example: vcommit -r \"buffer.*overflow\" \"security fix\"");
                println!("  Example: vcommit -s \"malloc\" -s \"free\" \"memory management\"  # Both symbols must be in commit");
                println!("  Example: vcommit -p \"mm/.*\\\\.c\" \"memory subsystem changes\"  # Only commits touching mm/*.c files");
                println!("  Example: vcommit --git HEAD~50..HEAD \"performance\"");
                println!("  Example: vcommit --reachable HEAD \"performance\"  # Only commits reachable from HEAD");
                println!("  Example: vcommit --git HEAD~100..HEAD -r \"malloc\" -r \"free\" --limit 20 \"memory management\"  # Both patterns must match");
                println!(
                    "  Note: Requires commit vectors to be generated first with 'semcode-index --vectors'"
                );
            } else {
                // Parse --git, --limit, -r, -s, -p, and --reachable flags
                let mut limit = 200; // default
                let mut regex_patterns = Vec::new();
                let mut symbol_patterns = Vec::new();
                let mut path_patterns = Vec::new();
                let mut git_range = None;
                let mut reachable_sha = None;
                let mut query_parts = Vec::new();
                let mut i = 1;

                while i < parts.len() {
                    if parts[i] == "--limit" && i + 1 < parts.len() {
                        match parts[i + 1].parse::<usize>() {
                            Ok(n) => {
                                limit = n.min(500); // Cap at 500
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
                    } else if parts[i] == "-r" && i + 1 < parts.len() {
                        regex_patterns.push(parts[i + 1].to_string());
                        i += 2;
                    } else if parts[i] == "-s" && i + 1 < parts.len() {
                        symbol_patterns.push(parts[i + 1].to_string());
                        i += 2;
                    } else if parts[i] == "-p" && i + 1 < parts.len() {
                        path_patterns.push(parts[i + 1].to_string());
                        i += 2;
                    } else if parts[i] == "--git" && i + 1 < parts.len() {
                        git_range = Some(parts[i + 1].to_string());
                        i += 2;
                    } else if parts[i] == "--reachable" && i + 1 < parts.len() {
                        reachable_sha = Some(parts[i + 1].to_string());
                        i += 2;
                    } else {
                        query_parts.extend_from_slice(&parts[i..]);
                        break;
                    }
                }

                if query_parts.is_empty() {
                    println!(
                        "{}",
                        "Usage: vcommit [--git <range>] [-r <regex>] [-s <regex>] [-p <path_regex>] [--limit <N=200>] [--reachable <sha>] <query_text>"
                            .red()
                    );
                } else {
                    let query_text = query_parts.join(" ");
                    vcommit_similar_commits(
                        db,
                        &query_text,
                        limit,
                        &regex_patterns,
                        &symbol_patterns,
                        &path_patterns,
                        git_range.as_deref(),
                        reachable_sha.as_deref(),
                        git_repo_path,
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
                match show_callchain_with_limits(
                    db,
                    &function_name,
                    &git_sha,
                    up_levels,
                    down_levels,
                    calls_limit,
                )
                .await
                {
                    Ok(()) => {}
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
        "dump-symbol-filename" | "dsf" => {
            if parts.len() < 2 {
                println!("{}", "Usage: dump-symbol-filename <output_file>".red());
                println!("  Export all symbol-filename pairs to JSON");
            } else {
                let output_file = parts[1..].join(" ");
                dump_symbol_filename(db, &output_file).await?;
            }
        }
        "dump-git-commits" | "dgc" => {
            if parts.len() < 2 {
                println!("{}", "Usage: dump-git-commits <output_file>".red());
                println!("  Export all git commit metadata to JSON");
            } else {
                let output_file = parts[1..].join(" ");
                dump_git_commits(db, &output_file).await?;
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
        "check_health" | "health" | "check_db" => {
            println!("{}", "Checking database health...".yellow());
            match db.check_optimization_health().await {
                Ok((needs_optimization, message)) => {
                    println!("{}", message);
                    if needs_optimization {
                        println!(
                            "{}",
                            "Note: Optimization is recommended but not required for normal operation."
                                .bright_black()
                        );
                    }
                }
                Err(e) => {
                    println!("{} Failed to check database health: {}", "Error:".red(), e);
                }
            }
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
                        format!("WARNING: This will drop and recreate the '{table_name}' table!")
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

/// Search for commits similar to given query text using vector embeddings
async fn vcommit_similar_commits(
    db: &DatabaseManager,
    query_text: &str,
    limit: usize,
    regex_patterns: &[String],
    symbol_patterns: &[String],
    path_patterns: &[String],
    git_range: Option<&str>,
    reachable_sha: Option<&str>,
    git_repo_path: &str,
    model_path: &Option<String>,
) -> Result<()> {
    use semcode::CodeVectorizer;

    let has_filters =
        !regex_patterns.is_empty() || !symbol_patterns.is_empty() || !path_patterns.is_empty();
    match (git_range, has_filters) {
        (Some(range), true) => {
            let mut filter_parts = Vec::new();
            if !regex_patterns.is_empty() {
                filter_parts.push(format!("{} regex pattern(s)", regex_patterns.len()));
            }
            if !symbol_patterns.is_empty() {
                filter_parts.push(format!("{} symbol pattern(s)", symbol_patterns.len()));
            }
            if !path_patterns.is_empty() {
                filter_parts.push(format!("{} path pattern(s)", path_patterns.len()));
            }
            let filter_desc = format!("filtering with {}", filter_parts.join(" and "));
            println!(
                "Searching for commits similar to: {} (git range: {}, {}, limit: {})",
                query_text.yellow(),
                range.cyan(),
                filter_desc,
                limit
            );
        }
        (Some(range), false) => println!(
            "Searching for commits similar to: {} (git range: {}, limit: {})",
            query_text.yellow(),
            range.cyan(),
            limit
        ),
        (None, true) => {
            let mut filter_parts = Vec::new();
            if !regex_patterns.is_empty() {
                filter_parts.push(format!("{} regex pattern(s)", regex_patterns.len()));
            }
            if !symbol_patterns.is_empty() {
                filter_parts.push(format!("{} symbol pattern(s)", symbol_patterns.len()));
            }
            if !path_patterns.is_empty() {
                filter_parts.push(format!("{} path pattern(s)", path_patterns.len()));
            }
            let filter_desc = format!("filtering with {}", filter_parts.join(" and "));
            println!(
                "Searching for commits similar to: {} ({}, limit: {})",
                query_text.yellow(),
                filter_desc,
                limit
            );
        }
        (None, false) => println!(
            "Searching for commits similar to: {} (limit: {})",
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

    // Resolve git range to a set of commit SHAs if provided
    let git_range_shas = if let Some(range) = git_range {
        match gix::discover(git_repo_path) {
            Ok(repo) => {
                // Resolve the git range using gitoxide
                let range_parts: Vec<&str> = range.split("..").collect();
                if range_parts.len() != 2 {
                    println!(
                        "{} Invalid git range format: '{}'. Expected format: FROM..TO (e.g., HEAD~100..HEAD)",
                        "Error:".red(),
                        range
                    );
                    return Ok(());
                }

                let from_ref = range_parts[0];
                let to_ref = range_parts[1];

                let from_commit = match git::resolve_to_commit(&repo, from_ref) {
                    Ok(c) => c,
                    Err(e) => {
                        println!(
                            "{} Failed to resolve git reference '{}': {}",
                            "Error:".red(),
                            from_ref,
                            e
                        );
                        return Ok(());
                    }
                };

                let to_commit = match git::resolve_to_commit(&repo, to_ref) {
                    Ok(c) => c,
                    Err(e) => {
                        println!(
                            "{} Failed to resolve git reference '{}': {}",
                            "Error:".red(),
                            to_ref,
                            e
                        );
                        return Ok(());
                    }
                };

                // Get all commits in the range using gitoxide
                let mut range_commits = std::collections::HashSet::new();

                // Walk from to_commit back to from_commit
                let to_id = to_commit.id().detach();
                let from_id = from_commit.id().detach();

                // Use rev_walk with proper include/exclude (same as in index.rs)
                match repo
                    .rev_walk([to_id])
                    .with_hidden([from_id])
                    .sorting(gix::revision::walk::Sorting::ByCommitTime(
                        Default::default(),
                    ))
                    .all()
                {
                    Ok(walk) => {
                        let mut commit_count = 0;
                        const MAX_COMMITS: usize = 1000000; // Safety limit

                        for commit_result in walk {
                            match commit_result {
                                Ok(commit_info) => {
                                    commit_count += 1;
                                    if commit_count > MAX_COMMITS {
                                        println!(
                                            "{} Git range {} is too large (>{} commits)",
                                            "Error:".red(),
                                            range,
                                            MAX_COMMITS
                                        );
                                        return Ok(());
                                    }

                                    let commit_id = commit_info.id();
                                    range_commits.insert(commit_id.to_string());
                                }
                                Err(e) => {
                                    tracing::warn!("Error walking commits: {}", e);
                                    break;
                                }
                            }
                        }
                        tracing::info!(
                            "Git range {} resolved to {} commits",
                            range,
                            range_commits.len()
                        );
                        Some(range_commits)
                    }
                    Err(e) => {
                        println!("{} Failed to walk git history: {}", "Error:".red(), e);
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                println!("{} Not in a git repository: {}", "Error:".red(), e);
                return Ok(());
            }
        }
    } else {
        None
    };

    // Search for similar commits with higher limit if filtering
    let search_limit = if !regex_patterns.is_empty()
        || !symbol_patterns.is_empty()
        || !path_patterns.is_empty()
        || git_range.is_some()
        || reachable_sha.is_some()
    {
        // When filtering (regex, symbols, paths, git range, or reachability), always fetch many results since we'll filter them down
        // Use a large limit to ensure we find enough matches after filtering
        // Increased to 2M to handle very large repositories like Linux kernel (~1.2M commits)
        2_000_000
    } else {
        limit
    };

    // Search for similar commits
    match db.search_similar_commits(&query_vector, search_limit).await {
        Ok(results) if results.is_empty() => {
            println!("{} No similar commits found", "Info:".yellow());
            println!("Make sure commit vectors have been generated with 'semcode-index --vectors'");
        }
        Ok(results) => {
            // Apply git range filtering if provided
            let filtered_by_range = if let Some(ref range_shas) = git_range_shas {
                let original_count = results.len();
                let filtered: Vec<_> = results
                    .into_iter()
                    .filter(|(commit, _)| range_shas.contains(&commit.git_sha))
                    .collect();

                tracing::info!(
                    "Git range filter reduced results from {} to {} commits",
                    original_count,
                    filtered.len()
                );

                filtered
            } else {
                results
            };

            // Apply regex filtering if provided (ALL patterns must match)
            let filtered_by_regex = if !regex_patterns.is_empty() {
                // Compile all regex patterns
                let mut regexes = Vec::new();
                for pattern in regex_patterns {
                    match regex::Regex::new(pattern) {
                        Ok(re) => regexes.push(re),
                        Err(e) => {
                            println!(
                                "{} Invalid regex pattern '{}': {}",
                                "Error:".red(),
                                pattern,
                                e
                            );
                            return Ok(());
                        }
                    }
                }

                let original_count = filtered_by_range.len();
                let filtered: Vec<_> = filtered_by_range
                    .into_iter()
                    .filter(|(commit, _)| {
                        // Combine message and diff for regex matching
                        let combined = format!("{}\n\n{}", commit.message, commit.diff);
                        // Check if ALL patterns match
                        regexes.iter().all(|re| re.is_match(&combined))
                    })
                    .collect();

                tracing::info!(
                    "Regex filters ({} pattern(s)) reduced results from {} to {} commits",
                    regex_patterns.len(),
                    original_count,
                    filtered.len()
                );

                filtered
            } else {
                filtered_by_range
            };

            // Apply symbol filtering if provided (ALL patterns must match)
            let filtered_by_symbol = if !symbol_patterns.is_empty() {
                // Compile all symbol regex patterns
                let mut symbol_regexes = Vec::new();
                for pattern in symbol_patterns {
                    match regex::Regex::new(pattern) {
                        Ok(re) => symbol_regexes.push(re),
                        Err(e) => {
                            println!(
                                "{} Invalid symbol regex pattern '{}': {}",
                                "Error:".red(),
                                pattern,
                                e
                            );
                            return Ok(());
                        }
                    }
                }

                let original_count = filtered_by_regex.len();
                let filtered: Vec<_> = filtered_by_regex
                    .into_iter()
                    .filter(|(commit, _)| {
                        // Check if ALL symbol patterns match (at least one symbol matches each pattern)
                        symbol_regexes
                            .iter()
                            .all(|re| commit.symbols.iter().any(|symbol| re.is_match(symbol)))
                    })
                    .collect();

                tracing::info!(
                    "Symbol filters ({} pattern(s)) reduced results from {} to {} commits",
                    symbol_patterns.len(),
                    original_count,
                    filtered.len()
                );

                filtered
            } else {
                filtered_by_regex
            };

            // Apply path filtering if provided (ANY pattern must match - OR logic)
            let filtered_by_path = if !path_patterns.is_empty() {
                // Compile all path regex patterns
                let mut path_regexes = Vec::new();
                for pattern in path_patterns {
                    match regex::Regex::new(pattern) {
                        Ok(re) => path_regexes.push(re),
                        Err(e) => {
                            println!(
                                "{} Invalid path regex pattern '{}': {}",
                                "Error:".red(),
                                pattern,
                                e
                            );
                            return Ok(());
                        }
                    }
                }

                let original_count = filtered_by_symbol.len();
                let filtered: Vec<_> = filtered_by_symbol
                    .into_iter()
                    .filter(|(commit, _)| {
                        // Check if ANY path pattern matches any file (OR logic)
                        path_regexes
                            .iter()
                            .any(|re| commit.files.iter().any(|file| re.is_match(file)))
                    })
                    .collect();

                tracing::info!(
                    "Path filters ({} pattern(s)) reduced results from {} to {} commits",
                    path_patterns.len(),
                    original_count,
                    filtered.len()
                );

                filtered
            } else {
                filtered_by_symbol
            };

            // Apply reachability filtering if provided
            let final_results = if let Some(reachable_from) = reachable_sha {
                let original_count = filtered_by_path.len();

                // For > 10 commits, use hashset approach for better performance
                let filtered: Vec<_> = if original_count > 10 {
                    match git::get_reachable_commits(git_repo_path, reachable_from) {
                        Ok(reachable_set) => filtered_by_path
                            .into_iter()
                            .filter(|(commit, _)| reachable_set.contains(&commit.git_sha))
                            .take(limit)
                            .collect(),
                        Err(e) => {
                            tracing::warn!(
                                "Failed to build reachable commits set: {}. Falling back to individual checks",
                                e
                            );
                            // Fallback to individual checks
                            filtered_by_path
                                .into_iter()
                                .filter(|(commit, _)| {
                                    match git::is_commit_reachable(
                                        git_repo_path,
                                        reachable_from,
                                        &commit.git_sha,
                                    ) {
                                        Ok(true) => true,
                                        Ok(false) => false,
                                        Err(e) => {
                                            tracing::warn!(
                                                "Failed to check reachability for commit {}: {}",
                                                commit.git_sha,
                                                e
                                            );
                                            false
                                        }
                                    }
                                })
                                .take(limit)
                                .collect()
                        }
                    }
                } else {
                    // For <= 10 commits, use individual checks
                    filtered_by_path
                        .into_iter()
                        .filter(|(commit, _)| {
                            match git::is_commit_reachable(
                                git_repo_path,
                                reachable_from,
                                &commit.git_sha,
                            ) {
                                Ok(true) => true,
                                Ok(false) => false,
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to check reachability for commit {}: {}",
                                        commit.git_sha,
                                        e
                                    );
                                    false
                                }
                            }
                        })
                        .take(limit)
                        .collect()
                };

                tracing::info!(
                    "Reachability filter reduced results from {} to {} commits",
                    original_count,
                    filtered.len()
                );

                filtered
            } else {
                filtered_by_path.into_iter().take(limit).collect()
            };

            if final_results.is_empty() {
                println!("{} No similar commits found", "Info:".yellow());
                if !regex_patterns.is_empty()
                    || !symbol_patterns.is_empty()
                    || !path_patterns.is_empty()
                    || git_range.is_some()
                {
                    println!("Try adjusting the filters or removing the -r/-s/-p/--git options");
                } else {
                    println!(
                        "Make sure commit vectors have been generated with 'semcode-index --vectors'"
                    );
                }
                return Ok(());
            }

            println!(
                "\n{} Found {} similar commit(s):",
                "Results:".bold().green(),
                final_results.len()
            );
            println!("{}", "=".repeat(80));

            for (i, (commit, similarity)) in final_results.iter().enumerate() {
                println!(
                    "\n{}. {} {} {}%",
                    (i + 1).to_string().yellow(),
                    "Similarity:".bold(),
                    format!("{:.1}", similarity * 100.0).bright_green(),
                    ""
                );
                println!(
                    "   {} {}",
                    "Commit:".bold(),
                    commit.git_sha[..12].to_string().bright_black()
                );
                println!("   {} {}", "Author:".bold(), commit.author.cyan());
                println!("   {} {}", "Subject:".bold(), commit.subject);

                // Show modified symbols if any (limited to first 5)
                if !commit.symbols.is_empty() {
                    let symbol_count = commit.symbols.len();
                    let display_symbols: Vec<_> = commit.symbols.iter().take(5).collect();
                    println!(
                        "   {} ({})",
                        "Modified Symbols:".bold(),
                        symbol_count.to_string().bright_black()
                    );
                    for symbol in display_symbols {
                        println!("     {}", symbol.yellow());
                    }
                    if symbol_count > 5 {
                        println!(
                            "     {} ... and {} more",
                            "".bright_black(),
                            symbol_count - 5
                        );
                    }
                }

                // Show preview of commit message (first 10 lines beyond subject)
                if !commit.message.is_empty() {
                    let message_lines: Vec<&str> = commit
                        .message
                        .lines()
                        .filter(|line| !line.trim().is_empty())
                        .take(11)
                        .collect();
                    if !message_lines.is_empty() && message_lines.len() > 1 {
                        // Only show if there's more than the subject
                        println!("   {} ", "Message Preview:".bold());
                        for line in message_lines.iter().skip(1) {
                            // Skip subject line
                            println!("     {}", line.trim().bright_black());
                        }
                        if commit.message.lines().count() > 11 {
                            println!("     {}", "...".bright_black());
                        }
                    }
                }
            }

            println!("\n{}", "=".repeat(80));
            println!(
                "{} Use 'commit <sha>' to see full details of a specific commit",
                "Tip:".bold().blue()
            );
        }
        Err(e) => {
            println!("{} Commit vector search failed: {}", "Error:".red(), e);
            println!("Make sure commit vectors have been generated with 'semcode-index --vectors'");
        }
    }

    Ok(())
}

/// Compile regex filters from patterns
fn compile_regex_filters(patterns: &[String]) -> Result<Vec<regex::Regex>> {
    let mut filters = Vec::new();
    for pattern in patterns {
        match regex::Regex::new(pattern) {
            Ok(re) => filters.push(re),
            Err(e) => {
                println!(
                    "{} Invalid regex pattern '{}': {}",
                    "Error:".red(),
                    pattern,
                    e
                );
                anyhow::bail!("Invalid regex pattern");
            }
        }
    }
    Ok(filters)
}

/// Compile symbol regex filters from patterns
fn compile_symbol_filters(patterns: &[String]) -> Result<Vec<regex::Regex>> {
    let mut filters = Vec::new();
    for pattern in patterns {
        match regex::Regex::new(pattern) {
            Ok(re) => filters.push(re),
            Err(e) => {
                println!(
                    "{} Invalid symbol regex pattern '{}': {}",
                    "Error:".red(),
                    pattern,
                    e
                );
                anyhow::bail!("Invalid symbol regex pattern");
            }
        }
    }
    Ok(filters)
}

/// Compile path regex filters from patterns
fn compile_path_filters(patterns: &[String]) -> Result<Vec<regex::Regex>> {
    let mut filters = Vec::new();
    for pattern in patterns {
        match regex::Regex::new(pattern) {
            Ok(re) => filters.push(re),
            Err(e) => {
                println!(
                    "{} Invalid path regex pattern '{}': {}",
                    "Error:".red(),
                    pattern,
                    e
                );
                anyhow::bail!("Invalid path regex pattern");
            }
        }
    }
    Ok(filters)
}

/// Check if a commit matches all regex, symbol, and path filters
fn commit_matches_filters(
    commit: &semcode::GitCommitInfo,
    regex_filters: &[regex::Regex],
    symbol_filters: &[regex::Regex],
    path_filters: &[regex::Regex],
) -> bool {
    // Apply regex filters (ALL must match)
    if !regex_filters.is_empty() {
        let combined = format!("{}\n\n{}", commit.message, commit.diff);
        for re in regex_filters {
            if !re.is_match(&combined) {
                return false;
            }
        }
    }

    // Apply symbol filters (ALL must match)
    if !symbol_filters.is_empty() {
        for re in symbol_filters {
            // Check if ANY symbol matches this pattern
            let matches_any = commit.symbols.iter().any(|symbol| re.is_match(symbol));
            if !matches_any {
                return false;
            }
        }
    }

    // Apply path filters (ANY must match - OR logic)
    if !path_filters.is_empty() {
        let matches_any_pattern = path_filters
            .iter()
            .any(|re| commit.files.iter().any(|file| re.is_match(file)));
        if !matches_any_pattern {
            return false;
        }
    }

    true
}

/// Display a single commit (verbose or compact mode)
fn display_commit(commit: &semcode::GitCommitInfo, index: usize, verbose: bool) {
    if verbose {
        // Verbose mode: show full details for each commit
        println!("\n{}", "─".repeat(80).bright_black());
        println!(
            "{}. {} {}",
            index.to_string().yellow(),
            "Commit:".bold(),
            commit.git_sha.yellow()
        );
        println!("   {} {}", "Author:".bold(), commit.author.cyan());
        println!("   {} {}", "Subject:".bold(), commit.subject);

        // Show modified symbols if any (limited to first 5)
        if !commit.symbols.is_empty() {
            let symbol_count = commit.symbols.len();
            let display_symbols: Vec<_> = commit.symbols.iter().take(5).collect();
            println!(
                "   {} ({})",
                "Modified Symbols:".bold().cyan(),
                symbol_count
            );
            for symbol in display_symbols {
                println!("     {}", symbol.yellow());
            }
            if symbol_count > 5 {
                println!("     ... and {} more", symbol_count - 5);
            }
        }

        // Show full message
        if !commit.message.is_empty() && commit.message != commit.subject {
            println!("\n   {}", "Message:".bold());
            for line in commit.message.lines() {
                println!("   {}", line);
            }
        }

        // Show diff if verbose
        if !commit.diff.is_empty() {
            println!("\n   {}", "Diff:".bold().blue());
            println!("   {}", "─".repeat(76).bright_black());
            for line in commit.diff.lines() {
                println!("   {}", line);
            }
            println!("   {}", "─".repeat(76).bright_black());
        }
    } else {
        // Default mode: show compact summary
        println!(
            "{}. {} {} - {}",
            index.to_string().yellow(),
            commit.git_sha[..12].to_string().bright_black(),
            commit.author.cyan(),
            commit.subject
        );
    }
}

/// Show summary statistics for commit display
fn show_commit_summary(
    total_commits: usize,
    matched_count: usize,
    displayed_count: usize,
    limit: usize,
    regex_patterns: &[String],
    symbol_patterns: &[String],
    path_patterns: &[String],
) {
    println!("\n{}", "=".repeat(80));

    // Show summary with filtering/limiting info
    if !regex_patterns.is_empty()
        || !symbol_patterns.is_empty()
        || !path_patterns.is_empty()
        || limit > 0
    {
        println!("{} ", "Summary:".bold().green());
        println!("  Total commits: {}", total_commits);
        if !regex_patterns.is_empty() || !symbol_patterns.is_empty() || !path_patterns.is_empty() {
            println!("  Matched by filters: {}", matched_count);
        }
        println!("  Displayed: {}", displayed_count);
        if limit > 0 && matched_count > limit {
            println!(
                "  {} {} additional matching commits not shown (limited to {})",
                "Note:".yellow(),
                matched_count - displayed_count,
                limit
            );
        }
    } else {
        println!(
            "{} Total: {} commits",
            "Summary:".bold().green(),
            displayed_count
        );
    }

    if displayed_count == 0 {
        let filter_count = (!regex_patterns.is_empty() as usize)
            + (!symbol_patterns.is_empty() as usize)
            + (!path_patterns.is_empty() as usize);

        if filter_count >= 2 {
            let mut filter_types = Vec::new();
            if !regex_patterns.is_empty() {
                filter_types.push(format!("{} regex pattern(s)", regex_patterns.len()));
            }
            if !symbol_patterns.is_empty() {
                filter_types.push(format!("{} symbol pattern(s)", symbol_patterns.len()));
            }
            if !path_patterns.is_empty() {
                filter_types.push(format!("{} path pattern(s)", path_patterns.len()));
            }
            println!(
                "\n{} No commits matched ALL {}",
                "Info:".yellow(),
                filter_types.join(" and ")
            );
        } else if !regex_patterns.is_empty() {
            println!(
                "\n{} No commits matched ALL {} regex pattern(s): {}",
                "Info:".yellow(),
                regex_patterns.len(),
                regex_patterns.join(", ")
            );
        } else if !symbol_patterns.is_empty() {
            println!(
                "\n{} No commits matched ALL {} symbol pattern(s): {}",
                "Info:".yellow(),
                symbol_patterns.len(),
                symbol_patterns.join(", ")
            );
        } else if !path_patterns.is_empty() {
            println!(
                "\n{} No commits matched ALL {} path pattern(s): {}",
                "Info:".yellow(),
                path_patterns.len(),
                path_patterns.join(", ")
            );
        }
    }
}

/// Show all commits from database with optional filters
async fn show_all_commits(
    db: &DatabaseManager,
    verbose: bool,
    regex_patterns: &[String],
    symbol_patterns: &[String],
    path_patterns: &[String],
    limit: usize,
    reachable_sha: Option<&str>,
    git_repo_path: &str,
) -> Result<()> {
    // Step 1: Get all commits from database
    let all_commits = db.get_all_git_commits().await?;

    if all_commits.is_empty() {
        println!("{} No commits found in database", "Info:".yellow());
        return Ok(());
    }

    // Step 2: Compile filters
    let regex_filters = if !regex_patterns.is_empty() {
        compile_regex_filters(regex_patterns)?
    } else {
        Vec::new()
    };

    let symbol_filters = if !symbol_patterns.is_empty() {
        compile_symbol_filters(symbol_patterns)?
    } else {
        Vec::new()
    };

    let path_filters = if !path_patterns.is_empty() {
        compile_path_filters(path_patterns)?
    } else {
        Vec::new()
    };

    println!(
        "\n{} Found {} commit(s) in database:",
        "All Commits:".bold().green(),
        all_commits.len()
    );
    println!("{}", "=".repeat(80));

    // Step 3: Apply regex/symbol/path filters first
    let filtered_commits: Vec<_> = all_commits
        .iter()
        .filter(|commit| {
            commit_matches_filters(commit, &regex_filters, &symbol_filters, &path_filters)
        })
        .collect();

    // Step 4: Build reachable commits set if needed (for > 10 filtered commits)
    let reachable_set = if let Some(reachable_from) = reachable_sha {
        if filtered_commits.len() > 10 {
            match git::get_reachable_commits(git_repo_path, reachable_from) {
                Ok(set) => Some(set),
                Err(e) => {
                    println!(
                        "{} Failed to build reachable commits set: {}. Using individual checks",
                        "Warning:".yellow(),
                        e
                    );
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    // Step 5: Apply reachability filter and display commits
    let mut displayed_count = 0;
    let mut matched_count = 0;

    for commit in &filtered_commits {
        // Apply reachability filter if provided
        if let Some(reachable_from) = reachable_sha {
            // Use hashset if available, otherwise do individual check
            let is_reachable = if let Some(ref set) = reachable_set {
                set.contains(&commit.git_sha)
            } else {
                match git::is_commit_reachable(git_repo_path, reachable_from, &commit.git_sha) {
                    Ok(true) => true,
                    Ok(false) => false,
                    Err(e) => {
                        println!(
                            "{} Failed to check reachability for commit {}: {}",
                            "Warning:".yellow(),
                            commit.git_sha,
                            e
                        );
                        false
                    }
                }
            };

            if !is_reachable {
                continue;
            }
        }

        matched_count += 1;

        // Apply limit
        if limit > 0 && displayed_count >= limit {
            continue;
        }

        displayed_count += 1;
        display_commit(commit, displayed_count, verbose);
    }

    // Step 5: Show summary
    show_commit_summary(
        all_commits.len(),
        matched_count,
        displayed_count,
        limit,
        regex_patterns,
        symbol_patterns,
        path_patterns,
    );

    Ok(())
}

/// Show metadata for a git commit
async fn show_commit_metadata(
    db: &DatabaseManager,
    git_ref: &str,
    verbose: bool,
    regex_patterns: &[String],
    symbol_patterns: &[String],
    path_patterns: &[String],
    reachable_sha: Option<&str>,
    git_repo_path: &str,
) -> Result<()> {
    // Step 1: Resolve git reference to full SHA using gitoxide
    let resolved_sha = match gix::discover(git_repo_path) {
        Ok(repo) => match git::resolve_to_commit(&repo, git_ref) {
            Ok(commit) => commit.id().to_string(),
            Err(e) => {
                let err_msg = e.to_string();
                println!(
                    "{} Failed to resolve git reference '{}': {}",
                    "Error:".red(),
                    git_ref,
                    err_msg
                );

                // Provide helpful hint for common errors
                if err_msg.contains("0 ancestors") || err_msg.contains("out of range") {
                    println!(
                        "{} The reference points to a root commit (no parents). Cannot go back further in history.",
                        "Hint:".yellow()
                    );
                } else {
                    println!(
                        "{} Make sure the reference exists in the repository",
                        "Hint:".yellow()
                    );
                }
                return Ok(());
            }
        },
        Err(e) => {
            println!("{} Not in a git repository: {}", "Error:".red(), e);
            return Ok(());
        }
    };

    println!(
        "Resolved '{}' to commit: {}",
        git_ref.cyan(),
        resolved_sha.bright_black()
    );

    // Step 2: Query database for commit metadata
    let commit_opt = db.get_git_commit_by_sha(&resolved_sha).await?;

    // Try to get from database, fall back to git if not indexed
    let (
        commit_sha,
        commit_author,
        commit_subject,
        commit_message,
        commit_parent_sha,
        commit_symbols,
        commit_files,
        commit_tags,
        commit_diff,
        is_indexed,
    ) = match commit_opt {
        Some(c) => (
            c.git_sha.clone(),
            c.author.clone(),
            c.subject.clone(),
            c.message.clone(),
            c.parent_sha.clone(),
            c.symbols.clone(),
            c.files.clone(),
            c.tags.clone(),
            c.diff.clone(),
            true,
        ),
        None => {
            // Commit not indexed - fall back to reading from git
            println!(
                "{} Commit {} not found in index - reading from git",
                "⚠️ Warning:".yellow(),
                resolved_sha.bright_black()
            );

            match git::get_commit_info_from_git(git_repo_path, &resolved_sha) {
                Ok(git_commit) => {
                    (
                        git_commit.git_sha,
                        git_commit.author,
                        git_commit.subject,
                        git_commit.message,
                        git_commit.parent_sha,
                        git_commit.symbols, // Symbols extracted from diff
                        git_commit.files,   // Files changed in commit
                        std::collections::HashMap::new(), // No tags extracted from git
                        git_commit.diff,
                        false,
                    )
                }
                Err(e) => {
                    println!("{} Failed to read commit from git: {}", "Error:".red(), e);
                    return Ok(());
                }
            }
        }
    };

    // Step 2b: Apply reachability filter if provided
    if let Some(reachable_from) = reachable_sha {
        match git::is_commit_reachable(git_repo_path, reachable_from, &resolved_sha) {
            Ok(true) => {
                // Commit is reachable, continue processing
            }
            Ok(false) => {
                println!(
                    "{} Commit {} is not reachable from {}",
                    "Info:".yellow(),
                    resolved_sha.bright_black(),
                    reachable_from
                );
                return Ok(());
            }
            Err(e) => {
                println!("{} Failed to check reachability: {}", "Error:".red(), e);
                return Ok(());
            }
        }
    }

    // Step 3: Apply regex filters if provided (ALL must match)
    if !regex_patterns.is_empty() {
        // Compile all regex patterns
        let mut regexes = Vec::new();
        for pattern in regex_patterns {
            match regex::Regex::new(pattern) {
                Ok(re) => regexes.push(re),
                Err(e) => {
                    println!(
                        "{} Invalid regex pattern '{}': {}",
                        "Error:".red(),
                        pattern,
                        e
                    );
                    return Ok(());
                }
            }
        }

        // Check if commit message or diff matches ALL regex patterns
        let combined = format!("{}\n\n{}", commit_message, commit_diff);
        let mut failed_patterns = Vec::new();
        for (i, re) in regexes.iter().enumerate() {
            if !re.is_match(&combined) {
                failed_patterns.push(regex_patterns[i].as_str());
            }
        }

        if !failed_patterns.is_empty() {
            println!(
                "{} Commit {} does not match {} regex pattern(s): {}",
                "Info:".yellow(),
                resolved_sha.bright_black(),
                failed_patterns.len(),
                failed_patterns.join(", ")
            );
            return Ok(());
        }
    }

    // Step 3b: Apply symbol filters if provided (ALL must match)
    if !symbol_patterns.is_empty() {
        // Compile all symbol regex patterns
        let mut symbol_regexes = Vec::new();
        for pattern in symbol_patterns {
            match regex::Regex::new(pattern) {
                Ok(re) => symbol_regexes.push(re),
                Err(e) => {
                    println!(
                        "{} Invalid symbol regex pattern '{}': {}",
                        "Error:".red(),
                        pattern,
                        e
                    );
                    return Ok(());
                }
            }
        }

        // Check if commit symbols match ALL symbol patterns
        let mut failed_symbol_patterns = Vec::new();
        for (i, re) in symbol_regexes.iter().enumerate() {
            // Check if ANY symbol matches this pattern
            let matches_any = commit_symbols.iter().any(|symbol| re.is_match(symbol));
            if !matches_any {
                failed_symbol_patterns.push(symbol_patterns[i].as_str());
            }
        }

        if !failed_symbol_patterns.is_empty() {
            println!(
                "{} Commit {} does not match {} symbol pattern(s): {}",
                "Info:".yellow(),
                resolved_sha.bright_black(),
                failed_symbol_patterns.len(),
                failed_symbol_patterns.join(", ")
            );
            return Ok(());
        }
    }

    // Step 3c: Apply path filters if provided (ANY must match - OR logic)
    if !path_patterns.is_empty() {
        // Compile all path regex patterns
        let mut path_regexes = Vec::new();
        for pattern in path_patterns {
            match regex::Regex::new(pattern) {
                Ok(re) => path_regexes.push(re),
                Err(e) => {
                    println!(
                        "{} Invalid path regex pattern '{}': {}",
                        "Error:".red(),
                        pattern,
                        e
                    );
                    return Ok(());
                }
            }
        }

        // Check if commit files match ANY path pattern
        let matches_any_pattern = path_regexes
            .iter()
            .any(|re| commit_files.iter().any(|file| re.is_match(file)));

        if !matches_any_pattern {
            println!(
                "{} Commit {} does not match any of {} path pattern(s): {}",
                "Info:".yellow(),
                resolved_sha.bright_black(),
                path_patterns.len(),
                path_patterns.join(", ")
            );
            return Ok(());
        }
    }

    // Step 4: Display commit metadata
    if !is_indexed {
        println!(
            "\n{}",
            "⚠️  COMMIT NOT INDEXED - SHOWING GIT DATA".bold().yellow()
        );
    }
    println!("\n{}", "=== Git Commit Metadata ===".bold().green());
    println!("{} {}", "Commit:".bold(), commit_sha.yellow());
    println!("{} {}", "Author:".bold(), commit_author.cyan());
    println!("{} {}", "Subject:".bold(), commit_subject);

    // Show parent commits if any
    if !commit_parent_sha.is_empty() {
        println!("\n{}", "Parents:".bold());
        for parent in &commit_parent_sha {
            println!("  {}", parent.bright_black());
        }
    }

    // Show tags if any
    if !commit_tags.is_empty() {
        println!("\n{}", "Tags:".bold());
        for (tag_name, tag_values) in &commit_tags {
            for value in tag_values {
                println!("  {}: {}", tag_name.magenta(), value);
            }
        }
    }

    // Show symbols if any
    if !commit_symbols.is_empty() {
        println!(
            "\n{} ({} symbols)",
            "Modified Symbols:".bold().cyan(),
            commit_symbols.len()
        );
        let mut sorted_symbols = commit_symbols.clone();
        sorted_symbols.sort();
        for symbol in &sorted_symbols {
            println!("  {}", symbol.yellow());
        }
    }

    // Show full message
    if !commit_message.is_empty() && commit_message != commit_subject {
        println!("\n{}", "Message:".bold());
        println!("{}", "─".repeat(60).bright_black());
        println!("{}", commit_message);
        println!("{}", "─".repeat(60).bright_black());
    }

    // Show diff if verbose flag is set
    if verbose {
        if !commit_diff.is_empty() {
            println!("\n{}", "Diff:".bold().blue());
            println!("{}", "─".repeat(80).bright_black());
            println!("{}", commit_diff);
            println!("{}", "─".repeat(80).bright_black());
        } else {
            println!("\n{} No diff available for this commit", "Info:".yellow());
        }
    }

    Ok(())
}

/// Show metadata for commits in a git range
async fn show_commit_range(
    db: &DatabaseManager,
    range: &str,
    verbose: bool,
    regex_patterns: &[String],
    symbol_patterns: &[String],
    path_patterns: &[String],
    limit: usize,
    reachable_sha: Option<&str>,
    git_repo_path: &str,
) -> Result<()> {
    // Step 1: Resolve git range using gitoxide
    let range_commits = match gix::discover(git_repo_path) {
        Ok(repo) => {
            // Parse the range (FROM..TO)
            let range_parts: Vec<&str> = range.split("..").collect();
            if range_parts.len() != 2 {
                println!(
                    "{} Invalid git range format: '{}'. Expected format: FROM..TO (e.g., HEAD~10..HEAD)",
                    "Error:".red(),
                    range
                );
                return Ok(());
            }

            let from_ref = range_parts[0];
            let to_ref = range_parts[1];

            // Resolve both references
            let from_commit = match git::resolve_to_commit(&repo, from_ref) {
                Ok(c) => c,
                Err(e) => {
                    let err_msg = e.to_string();
                    println!(
                        "{} Failed to resolve git reference '{}': {}",
                        "Error:".red(),
                        from_ref,
                        err_msg
                    );

                    // Provide helpful hint for common errors
                    if err_msg.contains("0 ancestors") || err_msg.contains("out of range") {
                        println!(
                            "{} The reference points to a root commit (no parents). Cannot go back further in history.",
                            "Hint:".yellow()
                        );
                    }
                    return Ok(());
                }
            };

            let to_commit = match git::resolve_to_commit(&repo, to_ref) {
                Ok(c) => c,
                Err(e) => {
                    let err_msg = e.to_string();
                    println!(
                        "{} Failed to resolve git reference '{}': {}",
                        "Error:".red(),
                        to_ref,
                        err_msg
                    );

                    // Provide helpful hint for common errors
                    if err_msg.contains("0 ancestors") || err_msg.contains("out of range") {
                        println!(
                            "{} The reference points to a root commit (no parents). Cannot go back further in history.",
                            "Hint:".yellow()
                        );
                    }
                    return Ok(());
                }
            };

            // Walk the commit history
            let to_id = to_commit.id().detach();
            let from_id = from_commit.id().detach();

            match repo
                .rev_walk([to_id])
                .with_hidden([from_id])
                .sorting(gix::revision::walk::Sorting::ByCommitTime(
                    Default::default(),
                ))
                .all()
            {
                Ok(walk) => {
                    let mut commits = Vec::new();
                    // Higher limit when regex or symbol filtering is active, since results will be filtered down
                    let max_commits = if !regex_patterns.is_empty() || !symbol_patterns.is_empty() {
                        1_000_000 // Allow larger ranges when filtering
                    } else {
                        10_000 // Standard safety limit
                    };

                    for commit_result in walk {
                        match commit_result {
                            Ok(commit_info) => {
                                if commits.len() >= max_commits {
                                    println!(
                                        "{} Git range {} is too large (>{} commits)",
                                        "Error:".red(),
                                        range,
                                        max_commits
                                    );
                                    if regex_patterns.is_empty() && symbol_patterns.is_empty() {
                                        println!(
                                            "{} Try using -r <regex> or -s <regex> to filter results, or use a smaller range",
                                            "Hint:".yellow()
                                        );
                                    } else {
                                        println!(
                                            "{} Try using a smaller range or more specific filter patterns",
                                            "Hint:".yellow()
                                        );
                                    }
                                    return Ok(());
                                }

                                let commit_id = commit_info.id().to_string();
                                commits.push(commit_id);
                            }
                            Err(e) => {
                                tracing::warn!("Error walking commits: {}", e);
                                break;
                            }
                        }
                    }

                    commits
                }
                Err(e) => {
                    println!("{} Failed to walk git history: {}", "Error:".red(), e);
                    return Ok(());
                }
            }
        }
        Err(e) => {
            println!("{} Not in a git repository: {}", "Error:".red(), e);
            return Ok(());
        }
    };

    if range_commits.is_empty() {
        println!("{} No commits found in range {}", "Info:".yellow(), range);
        return Ok(());
    }

    // Step 2: Compile filters
    let regex_filters = if !regex_patterns.is_empty() {
        compile_regex_filters(regex_patterns)?
    } else {
        Vec::new()
    };

    let symbol_filters = if !symbol_patterns.is_empty() {
        compile_symbol_filters(symbol_patterns)?
    } else {
        Vec::new()
    };

    let path_filters = if !path_patterns.is_empty() {
        compile_path_filters(path_patterns)?
    } else {
        Vec::new()
    };

    println!(
        "\n{} Found {} commit(s) in range {}:",
        "Git Range:".bold().green(),
        range_commits.len(),
        range.cyan()
    );
    println!("{}", "=".repeat(80));

    // Step 3: Process commits in chunks of 256 with database-level filtering
    const CHUNK_SIZE: usize = 256;

    // Convert regex and symbol patterns to strings for database filtering
    let regex_filter_patterns: Vec<String> = regex_filters
        .iter()
        .map(|re| re.as_str().to_string())
        .collect();
    let symbol_filter_patterns: Vec<String> = symbol_filters
        .iter()
        .map(|re| re.as_str().to_string())
        .collect();

    // Collect all filtered commits from all chunks first
    let mut all_filtered_commits = Vec::new();
    for chunk_start in (0..range_commits.len()).step_by(CHUNK_SIZE) {
        let chunk_end = (chunk_start + CHUNK_SIZE).min(range_commits.len());
        let chunk = &range_commits[chunk_start..chunk_end];

        // Query this chunk with database-level filtering
        let chunk_results = db
            .query_commits_chunk_filtered(chunk, &regex_filter_patterns, &symbol_filter_patterns)
            .await?;

        // Apply path filtering to chunk results
        for commit in chunk_results {
            // Apply path filters (ANY must match - OR logic)
            if !path_filters.is_empty() {
                let matches_any_pattern = path_filters
                    .iter()
                    .any(|re| commit.files.iter().any(|file| re.is_match(file)));
                if !matches_any_pattern {
                    continue;
                }
            }
            all_filtered_commits.push(commit);
        }
    }

    // Step 4: Build reachable commits set if needed (for > 10 filtered commits)
    let reachable_set = if let Some(reachable_from) = reachable_sha {
        if all_filtered_commits.len() > 10 {
            match git::get_reachable_commits(git_repo_path, reachable_from) {
                Ok(set) => Some(set),
                Err(e) => {
                    println!(
                        "{} Failed to build reachable commits set: {}. Using individual checks",
                        "Warning:".yellow(),
                        e
                    );
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    // Step 5: Apply reachability filter and display commits
    let mut displayed_count = 0;
    let mut matched_count = 0;

    for commit in &all_filtered_commits {
        // Apply reachability filter if provided
        if let Some(reachable_from) = reachable_sha {
            // Use hashset if available, otherwise do individual check
            let is_reachable = if let Some(ref set) = reachable_set {
                set.contains(&commit.git_sha)
            } else {
                match git::is_commit_reachable(git_repo_path, reachable_from, &commit.git_sha) {
                    Ok(true) => true,
                    Ok(false) => false,
                    Err(e) => {
                        println!(
                            "{} Failed to check reachability for commit {}: {}",
                            "Warning:".yellow(),
                            commit.git_sha,
                            e
                        );
                        false
                    }
                }
            };

            if !is_reachable {
                continue;
            }
        }

        matched_count += 1;

        // Apply limit
        if limit > 0 && displayed_count >= limit {
            continue;
        }

        displayed_count += 1;
        display_commit(commit, displayed_count, verbose);
    }

    // Step 6: Show summary
    show_commit_summary(
        range_commits.len(),
        matched_count,
        displayed_count,
        limit,
        regex_patterns,
        symbol_patterns,
        path_patterns,
    );

    Ok(())
}
