// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use clap::Parser;
use semcode::{git, pages::PageCache, process_database_path, DatabaseManager};
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

/// Truncate output at 3,000 lines with a warning message
fn truncate_output(output: String) -> String {
    const MAX_LINES: usize = 3000;

    let lines: Vec<&str> = output.lines().collect();
    if lines.len() <= MAX_LINES {
        return output;
    }

    let mut truncated_lines = lines[..MAX_LINES].to_vec();
    let warning_msg = format!(
        "   Original output had {} lines (truncated {} lines)",
        lines.len(),
        lines.len() - MAX_LINES
    );

    truncated_lines.push("");
    truncated_lines.push("⚠️  WARNING: Output truncated at 3,000 lines ⚠️");
    truncated_lines.push(&warning_msg);
    truncated_lines.push("   Use more specific queries to reduce result size");

    truncated_lines.join("\n")
}

// MCP-specific query functions that return strings instead of printing
async fn mcp_query_function_or_macro(
    db: &DatabaseManager,
    name: &str,
    git_sha: &str,
) -> Result<String> {
    // Use the same method as the query tool - find the single best matches
    let func_opt = db.find_function_git_aware(name, git_sha).await?;
    let macro_result = db.find_macro_git_aware(name, git_sha).await?;

    let result = match (func_opt, macro_result) {
        (Some(func), None) => {
            // Found function only
            let mut result = String::new();

            let params_str = func
                .parameters
                .iter()
                .map(|p| format!("{}: {}", p.name, p.type_name))
                .collect::<Vec<_>>()
                .join(", ");

            // Get call relationships for this specific function to show counts
            let calls = db
                .get_function_callees_git_aware(&func.name, git_sha)
                .await
                .unwrap_or_default();

            let callers = db
                .get_function_callers_git_aware(name, git_sha)
                .await
                .unwrap_or_default();

            result.push_str(&format!(
                "Function: {} (git SHA: {})\nFile: {}:{}-{}\nReturn Type: {}\nParameters: ({})\nCalls: {} functions\nCalled by: {} functions\nBody:\n{}\n\n",
                func.name,
                git_sha,
                func.file_path,
                func.line_start,
                func.line_end,
                func.return_type,
                params_str,
                calls.len(),
                callers.len(),
                func.body
            ));

            result
        }
        (None, Some(mac)) => {
            // Found macro only
            let params_str = match &mac.parameters {
                Some(params) => params.join(", "),
                None => "none".to_string(),
            };

            // Get macro call relationships to show counts
            let macro_calls = mac.calls.clone().unwrap_or_default();
            let macro_callers = db
                .get_function_callers_git_aware(&mac.name, git_sha)
                .await
                .unwrap_or_default();

            format!(
                "Macro: {} (git SHA: {})\nFile: {}:{}\nParameters: ({})\nCalls: {} functions\nCalled by: {} functions\nDefinition:\n{}",
                mac.name, git_sha, mac.file_path, mac.line_start, params_str, macro_calls.len(), macro_callers.len(), mac.definition
            )
        }
        (Some(func), Some(mac)) => {
            // Found both function and macro
            let mut result =
                format!("Found function and macro with name '{name}' (git SHA: {git_sha})\n\n");

            // Display function
            let func_params_str = func
                .parameters
                .iter()
                .map(|p| format!("{}: {}", p.name, p.type_name))
                .collect::<Vec<_>>()
                .join(", ");

            // Get call relationships for counts
            let func_calls = db
                .get_function_callees_git_aware(&func.name, git_sha)
                .await
                .unwrap_or_default();

            let func_callers = db
                .get_function_callers_git_aware(name, git_sha)
                .await
                .unwrap_or_default();

            result.push_str(&format!(
                "Function: {}\nFile: {}:{}-{}\nReturn Type: {}\nParameters: ({})\nCalls: {} functions\nCalled by: {} functions\nBody:\n{}\n\n",
                func.name, func.file_path, func.line_start, func.line_end, func.return_type, func_params_str, func_calls.len(), func_callers.len(), func.body
            ));

            // Display macro
            let macro_params_str = match &mac.parameters {
                Some(params) => params.join(", "),
                None => "none".to_string(),
            };

            let macro_calls = mac.calls.clone().unwrap_or_default();

            result.push_str(&format!(
                "==> Macro:\nMacro: {}\nFile: {}:{}\nParameters: ({})\nCalls: {} functions\nCalled by: {} functions\nDefinition:\n{}\n\n",
                mac.name, mac.file_path, mac.line_start, macro_params_str, macro_calls.len(), func_callers.len(), mac.definition
            ));

            result
        }
        (None, None) => {
            // No exact match found, try regex search
            let regex_functions = db
                .search_functions_regex_git_aware(name, git_sha)
                .await
                .unwrap_or_default();
            let regex_macros = db
                .search_macros_regex_git_aware(name, git_sha)
                .await
                .unwrap_or_default();

            if !regex_functions.is_empty() || !regex_macros.is_empty() {
                let mut result = format!("No exact match found for '{name}' at git SHA {git_sha}, but found matches using it as a regex pattern:\n\n");

                if !regex_functions.is_empty() {
                    result.push_str("=== Functions (regex matches) ===\n");
                    for func in regex_functions.iter().take(10) {
                        let params_str = func
                            .parameters
                            .iter()
                            .map(|p| format!("{}: {}", p.name, p.type_name))
                            .collect::<Vec<_>>()
                            .join(", ");

                        result.push_str(&format!(
                            "Function: {} (git SHA: {})\nFile: {}:{}-{}\nReturn Type: {}\nParameters: ({})\n\n",
                            func.name,
                            git_sha,
                            func.file_path,
                            func.line_start,
                            func.line_end,
                            func.return_type,
                            params_str
                        ));
                    }
                }

                if !regex_macros.is_empty() {
                    result.push_str("=== Macros (regex matches) ===\n");
                    for mac in regex_macros.iter().take(10) {
                        let params_str = match &mac.parameters {
                            Some(params) => params.join(", "),
                            None => "none".to_string(),
                        };

                        result.push_str(&format!(
                            "Macro: {} (git SHA: {})\nFile: {}:{}\nParameters: ({})\n\n",
                            mac.name, git_sha, mac.file_path, mac.line_start, params_str
                        ));
                    }
                }

                result
            } else {
                format!("Function or macro '{name}' not found at git SHA {git_sha}")
            }
        }
    };

    Ok(result)
}

async fn mcp_query_type_or_typedef(
    db: &DatabaseManager,
    name: &str,
    git_sha: &str,
) -> Result<String> {
    // Always use git-aware methods
    // Use exact git-aware lookup methods (which load full definition)
    let type_result = db.find_type_git_aware(name, git_sha).await?;
    let typedef_result = db.find_typedef_git_aware(name, git_sha).await?;

    match (type_result, typedef_result) {
                (Some(type_info), None) => {
                    Ok(format!(
                        "Type: {} (git SHA: {})\nFile: {}:{}\nKind: {}\n\nDefinition:\n{}",
                        type_info.name,
                        git_sha,
                        type_info.file_path,
                        type_info.line_start,
                        type_info.kind,
                        type_info.definition
                    ))
                },
                (None, Some(typedef)) => {
                    Ok(format!(
                        "Typedef: {} (git SHA: {})\nFile: {}:{}\nUnderlying Type: {}\n\nDefinition:\n{}",
                        typedef.name,
                        git_sha,
                        typedef.file_path,
                        typedef.line_start,
                        typedef.underlying_type,
                        typedef.definition
                    ))
                },
                (Some(type_info), Some(typedef)) => {
                    Ok(format!(
                        "Found both type and typedef with name '{}' (git SHA: {})\n\nType: {}\nFile: {}:{}\nKind: {}\nDefinition:\n{}\n\nTypedef: {}\nFile: {}:{}\nUnderlying Type: {}\nDefinition:\n{}",
                        name, git_sha,
                        type_info.name, type_info.file_path, type_info.line_start, type_info.kind, type_info.definition,
                        typedef.name, typedef.file_path, typedef.line_start, typedef.underlying_type, typedef.definition
                    ))
                },
                (None, None) => Ok(format!("Type or typedef '{name}' not found at git SHA {git_sha}"))
    }
}

async fn mcp_show_callers(
    db: &DatabaseManager,
    function_name: &str,
    git_sha: &str,
) -> Result<String> {
    let mut buffer = Vec::new();

    // Write the header message
    writeln!(buffer, "Finding all functions that call: {function_name}")?;

    // Use the same method as the query tool - find the single best function match
    let func_opt = db.find_function_git_aware(function_name, git_sha).await?;
    let macro_opt = db.find_macro_git_aware(function_name, git_sha).await?;

    match (func_opt, macro_opt) {
        (Some(_func), None) => {
            // Found function only - get callers
            let callers = db
                .get_function_callers_git_aware(function_name, git_sha)
                .await?;
            if callers.is_empty() {
                writeln!(buffer, "Info: No functions call '{function_name}'")?;
            } else if callers.len() > 1000 {
                // Just show count when there are too many
                writeln!(
                    buffer,
                    "{} functions call '{}' (too many to display)",
                    callers.len(),
                    function_name
                )?;
            } else {
                writeln!(buffer, "\n=== Direct Callers ===")?;
                writeln!(
                    buffer,
                    "{} functions directly call '{}':",
                    callers.len(),
                    function_name
                )?;

                for (i, caller) in callers.iter().enumerate() {
                    writeln!(buffer, "  {}. {}", i + 1, caller)?;

                    // Try to get more info about the caller (function or macro)
                    if let Ok(Some(caller_func)) = db.find_function_git_aware(caller, git_sha).await
                    {
                        writeln!(
                            buffer,
                            "     {} ({}:{})",
                            caller_func.return_type, caller_func.file_path, caller_func.line_start
                        )?;
                    } else if let Ok(Some(caller_macro)) =
                        db.find_macro_git_aware(caller, git_sha).await
                    {
                        writeln!(
                            buffer,
                            "     macro ({}:{})",
                            caller_macro.file_path, caller_macro.line_start
                        )?;
                    }
                }
            }
        }
        (None, Some(_macro_info)) => {
            // Found macro only - get callers
            let callers = db
                .get_function_callers_git_aware(function_name, git_sha)
                .await?;
            if callers.is_empty() {
                writeln!(buffer, "Info: No functions call macro '{function_name}'")?;
            } else {
                writeln!(buffer, "\n=== Direct Callers ===")?;
                writeln!(
                    buffer,
                    "{} functions directly call macro '{}':",
                    callers.len(),
                    function_name
                )?;

                for (i, caller) in callers.iter().enumerate() {
                    writeln!(buffer, "  {}. {}", i + 1, caller)?;
                }
            }
        }
        (Some(_func), Some(_macro_info)) => {
            // Found both - show function callers
            let callers = db
                .get_function_callers_git_aware(function_name, git_sha)
                .await?;
            writeln!(buffer, "Note: Found both a function and a macro with this name! Showing function call relationships.")?;

            if callers.is_empty() {
                writeln!(buffer, "Info: No functions call function '{function_name}'")?;
            } else {
                writeln!(buffer, "\n=== Direct Callers (Function) ===")?;
                writeln!(
                    buffer,
                    "{} functions directly call function '{}':",
                    callers.len(),
                    function_name
                )?;

                for (i, caller) in callers.iter().enumerate() {
                    writeln!(buffer, "  {}. {}", i + 1, caller)?;
                }
            }
        }
        (None, None) => {
            writeln!(
                buffer,
                "Error: Function or macro '{function_name}' not found in database"
            )?;
        }
    }

    Ok(String::from_utf8_lossy(&buffer).to_string())
}

async fn mcp_show_calls(
    db: &DatabaseManager,
    function_name: &str,
    git_sha: &str,
) -> Result<String> {
    let mut buffer = Vec::new();

    // Write the header message
    writeln!(buffer, "Finding all functions called by: {function_name}")?;

    // Use the same method as the query tool - find the single best function match
    let func_opt = db.find_function_git_aware(function_name, git_sha).await?;
    let macro_opt = db.find_macro_git_aware(function_name, git_sha).await?;

    match (func_opt, macro_opt) {
        (Some(_func), None) => {
            // Found function only - get callees
            let calls = db
                .get_function_callees_git_aware(function_name, git_sha)
                .await?;
            if calls.is_empty() {
                writeln!(
                    buffer,
                    "Info: Function '{function_name}' doesn't call any other functions"
                )?;
            } else if calls.len() > 1000 {
                // Just show count when there are too many
                writeln!(
                    buffer,
                    "Function '{}' calls {} functions (too many to display)",
                    function_name,
                    calls.len()
                )?;
            } else {
                writeln!(buffer, "\n=== Direct Calls ===")?;
                writeln!(
                    buffer,
                    "Function '{}' directly calls {} functions:",
                    function_name,
                    calls.len()
                )?;

                for (i, callee) in calls.iter().enumerate() {
                    writeln!(buffer, "  {}. {}", i + 1, callee)?;

                    // Try to get more info about the callee (function or macro)
                    if let Ok(Some(callee_func)) = db.find_function_git_aware(callee, git_sha).await
                    {
                        writeln!(
                            buffer,
                            "     {} ({}:{})",
                            callee_func.return_type, callee_func.file_path, callee_func.line_start
                        )?;
                    } else if let Ok(Some(callee_macro)) =
                        db.find_macro_git_aware(callee, git_sha).await
                    {
                        writeln!(
                            buffer,
                            "     macro ({}:{})",
                            callee_macro.file_path, callee_macro.line_start
                        )?;
                    }
                }
            }
        }
        (None, Some(macro_info)) => {
            // Found macro only - get calls from macro's calls field
            let calls = macro_info.calls.clone().unwrap_or_default();
            if calls.is_empty() {
                writeln!(
                    buffer,
                    "Info: Macro '{function_name}' doesn't call any other functions"
                )?;
            } else {
                writeln!(buffer, "\n=== Direct Calls ===")?;
                writeln!(
                    buffer,
                    "Macro '{}' directly calls {} functions:",
                    function_name,
                    calls.len()
                )?;

                for (i, callee) in calls.iter().enumerate() {
                    writeln!(buffer, "  {}. {}", i + 1, callee)?;
                }
            }
        }
        (Some(_func), Some(macro_info)) => {
            // Found both - show function calls
            let calls = db
                .get_function_callees_git_aware(function_name, git_sha)
                .await?;
            writeln!(buffer, "Note: Found both a function and a macro with this name! Showing function call relationships.")?;

            if calls.is_empty() {
                writeln!(
                    buffer,
                    "Info: Function '{function_name}' doesn't call any other functions"
                )?;

                // Also check macro calls
                let macro_calls = macro_info.calls.clone().unwrap_or_default();
                if !macro_calls.is_empty() {
                    writeln!(
                        buffer,
                        "Note: But macro '{}' calls {} functions",
                        function_name,
                        macro_calls.len()
                    )?;
                }
            } else {
                writeln!(buffer, "\n=== Direct Calls (Function) ===")?;
                writeln!(
                    buffer,
                    "Function '{}' directly calls {} functions:",
                    function_name,
                    calls.len()
                )?;

                for (i, callee) in calls.iter().enumerate() {
                    writeln!(buffer, "  {}. {}", i + 1, callee)?;
                }
            }
        }
        (None, None) => {
            writeln!(
                buffer,
                "Error: Function or macro '{function_name}' not found in database"
            )?;
        }
    }

    Ok(String::from_utf8_lossy(&buffer).to_string())
}

async fn mcp_show_commit_metadata(
    db: &DatabaseManager,
    git_ref: &str,
    verbose: bool,
    regex_patterns: &[String],
    symbol_patterns: &[String],
    path_patterns: &[String],
    reachable_sha: Option<&str>,
    git_repo_path: &str,
) -> Result<String> {
    use std::io::Write;

    let mut buffer = Vec::new();

    // Step 1: Resolve git reference to full SHA using gitoxide
    let resolved_sha = match gix::discover(git_repo_path) {
        Ok(repo) => match git::resolve_to_commit(&repo, git_ref) {
            Ok(commit) => commit.id().to_string(),
            Err(e) => {
                writeln!(
                    buffer,
                    "Error: Failed to resolve git reference '{}': {}",
                    git_ref, e
                )?;
                writeln!(
                    buffer,
                    "Hint: Make sure the reference exists in the repository"
                )?;
                return Ok(String::from_utf8_lossy(&buffer).to_string());
            }
        },
        Err(e) => {
            writeln!(buffer, "Error: Not in a git repository: {}", e)?;
            return Ok(String::from_utf8_lossy(&buffer).to_string());
        }
    };

    writeln!(buffer, "Resolved '{}' to commit: {}", git_ref, resolved_sha)?;

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
            writeln!(
                buffer,
                "⚠️ Warning: Commit {} not found in index - reading from git",
                resolved_sha
            )?;

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
                    writeln!(buffer, "Error: Failed to read commit from git: {}", e)?;
                    return Ok(String::from_utf8_lossy(&buffer).to_string());
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
                writeln!(
                    buffer,
                    "Info: Commit {} is not reachable from {}",
                    resolved_sha, reachable_from
                )?;
                return Ok(String::from_utf8_lossy(&buffer).to_string());
            }
            Err(e) => {
                writeln!(buffer, "Error: Failed to check reachability: {}", e)?;
                return Ok(String::from_utf8_lossy(&buffer).to_string());
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
                    writeln!(buffer, "Error: Invalid regex pattern '{}': {}", pattern, e)?;
                    return Ok(String::from_utf8_lossy(&buffer).to_string());
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
            writeln!(
                buffer,
                "Info: Commit {} does not match {} regex pattern(s): {}",
                resolved_sha,
                failed_patterns.len(),
                failed_patterns.join(", ")
            )?;
            return Ok(String::from_utf8_lossy(&buffer).to_string());
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
                    writeln!(
                        buffer,
                        "Error: Invalid symbol regex pattern '{}': {}",
                        pattern, e
                    )?;
                    return Ok(String::from_utf8_lossy(&buffer).to_string());
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
            writeln!(
                buffer,
                "Info: Commit {} does not match {} symbol pattern(s): {}",
                resolved_sha,
                failed_symbol_patterns.len(),
                failed_symbol_patterns.join(", ")
            )?;
            return Ok(String::from_utf8_lossy(&buffer).to_string());
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
                    writeln!(
                        buffer,
                        "Error: Invalid path regex pattern '{}': {}",
                        pattern, e
                    )?;
                    return Ok(String::from_utf8_lossy(&buffer).to_string());
                }
            }
        }

        // Check if commit files match ANY path pattern
        let matches_any_pattern = path_regexes
            .iter()
            .any(|re| commit_files.iter().any(|file| re.is_match(file)));

        if !matches_any_pattern {
            writeln!(
                buffer,
                "Info: Commit {} does not match any of {} path pattern(s): {}",
                resolved_sha,
                path_patterns.len(),
                path_patterns.join(", ")
            )?;
            return Ok(String::from_utf8_lossy(&buffer).to_string());
        }
    }

    // Step 4: Display commit metadata
    if !is_indexed {
        writeln!(buffer, "\n⚠️  COMMIT NOT INDEXED - SHOWING GIT DATA")?;
    }
    writeln!(buffer, "\n=== Git Commit Metadata ===")?;
    writeln!(buffer, "Commit: {}", commit_sha)?;
    writeln!(buffer, "Author: {}", commit_author)?;
    writeln!(buffer, "Subject: {}", commit_subject)?;

    // Show parent commits if any
    if !commit_parent_sha.is_empty() {
        writeln!(buffer, "\nParents:")?;
        for parent in &commit_parent_sha {
            writeln!(buffer, "  {}", parent)?;
        }
    }

    // Show tags if any
    if !commit_tags.is_empty() {
        writeln!(buffer, "\nTags:")?;
        for (tag_name, tag_values) in &commit_tags {
            for value in tag_values {
                writeln!(buffer, "  {}: {}", tag_name, value)?;
            }
        }
    }

    // Show symbols if any
    if !commit_symbols.is_empty() {
        writeln!(
            buffer,
            "\nModified Symbols: ({} symbols)",
            commit_symbols.len()
        )?;
        let mut sorted_symbols = commit_symbols.clone();
        sorted_symbols.sort();
        for symbol in &sorted_symbols {
            writeln!(buffer, "  {}", symbol)?;
        }
    }

    // Show full message
    if !commit_message.is_empty() && commit_message != commit_subject {
        writeln!(buffer, "\nMessage:")?;
        writeln!(buffer, "{}", "─".repeat(60))?;
        writeln!(buffer, "{}", commit_message)?;
        writeln!(buffer, "{}", "─".repeat(60))?;
    }

    // Show diff if verbose flag is set
    if verbose {
        if !commit_diff.is_empty() {
            writeln!(buffer, "\nDiff:")?;
            writeln!(buffer, "{}", "─".repeat(80))?;
            writeln!(buffer, "{}", commit_diff)?;
            writeln!(buffer, "{}", "─".repeat(80))?;
        } else {
            writeln!(buffer, "\nInfo: No diff available for this commit")?;
        }
    }

    Ok(String::from_utf8_lossy(&buffer).to_string())
}

async fn mcp_show_commit_range(
    db: &DatabaseManager,
    range: &str,
    verbose: bool,
    regex_patterns: &[String],
    symbol_patterns: &[String],
    path_patterns: &[String],
    reachable_sha: Option<&str>,
    git_repo_path: &str,
) -> Result<String> {
    use std::io::Write;

    let mut buffer = Vec::new();

    // Step 1: Resolve git range using gitoxide
    let range_commits = match gix::discover(git_repo_path) {
        Ok(repo) => {
            // Parse the range (FROM..TO)
            let range_parts: Vec<&str> = range.split("..").collect();
            if range_parts.len() != 2 {
                writeln!(
                    buffer,
                    "Error: Invalid git range format: '{}'. Expected format: FROM..TO (e.g., HEAD~10..HEAD)",
                    range
                )?;
                return Ok(String::from_utf8_lossy(&buffer).to_string());
            }

            let from_ref = range_parts[0];
            let to_ref = range_parts[1];

            // Resolve both references
            let from_commit = match git::resolve_to_commit(&repo, from_ref) {
                Ok(c) => c,
                Err(e) => {
                    writeln!(
                        buffer,
                        "Error: Failed to resolve git reference '{}': {}",
                        from_ref, e
                    )?;
                    return Ok(String::from_utf8_lossy(&buffer).to_string());
                }
            };

            let to_commit = match git::resolve_to_commit(&repo, to_ref) {
                Ok(c) => c,
                Err(e) => {
                    writeln!(
                        buffer,
                        "Error: Failed to resolve git reference '{}': {}",
                        to_ref, e
                    )?;
                    return Ok(String::from_utf8_lossy(&buffer).to_string());
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
                    // Higher limit when regex filtering is active, since results will be filtered down
                    let max_commits = if !regex_patterns.is_empty() {
                        100_000 // Allow larger ranges when filtering
                    } else {
                        10_000 // Standard safety limit
                    };

                    for commit_result in walk {
                        match commit_result {
                            Ok(commit_info) => {
                                if commits.len() >= max_commits {
                                    writeln!(
                                        buffer,
                                        "Error: Git range {} is too large (>{} commits)",
                                        range, max_commits
                                    )?;
                                    if regex_patterns.is_empty() {
                                        writeln!(
                                            buffer,
                                            "Hint: Try using regex_patterns to filter results, or use a smaller range"
                                        )?;
                                    } else {
                                        writeln!(
                                            buffer,
                                            "Hint: Try using a smaller range or more specific regex patterns"
                                        )?;
                                    }
                                    return Ok(String::from_utf8_lossy(&buffer).to_string());
                                }

                                let commit_id = commit_info.id().to_string();
                                commits.push(commit_id);
                            }
                            Err(e) => {
                                writeln!(buffer, "Warning: Error walking commits: {}", e)?;
                                break;
                            }
                        }
                    }

                    commits
                }
                Err(e) => {
                    writeln!(buffer, "Error: Failed to walk git history: {}", e)?;
                    return Ok(String::from_utf8_lossy(&buffer).to_string());
                }
            }
        }
        Err(e) => {
            writeln!(buffer, "Error: Not in a git repository: {}", e)?;
            return Ok(String::from_utf8_lossy(&buffer).to_string());
        }
    };

    if range_commits.is_empty() {
        writeln!(buffer, "Info: No commits found in range {}", range)?;
        return Ok(String::from_utf8_lossy(&buffer).to_string());
    }

    // Step 2: Compile regex filters if provided (ALL must match)
    let mut regex_filters = Vec::new();
    if !regex_patterns.is_empty() {
        for pattern in regex_patterns {
            match regex::Regex::new(pattern) {
                Ok(re) => regex_filters.push(re),
                Err(e) => {
                    writeln!(buffer, "Error: Invalid regex pattern '{}': {}", pattern, e)?;
                    return Ok(String::from_utf8_lossy(&buffer).to_string());
                }
            }
        }
    }

    // Step 2b: Compile symbol filters if provided (ALL must match)
    let mut symbol_filters = Vec::new();
    if !symbol_patterns.is_empty() {
        for pattern in symbol_patterns {
            match regex::Regex::new(pattern) {
                Ok(re) => symbol_filters.push(re),
                Err(e) => {
                    writeln!(
                        buffer,
                        "Error: Invalid symbol regex pattern '{}': {}",
                        pattern, e
                    )?;
                    return Ok(String::from_utf8_lossy(&buffer).to_string());
                }
            }
        }
    }

    // Step 2c: Compile path filters if provided (ALL must match)
    let mut path_filters = Vec::new();
    if !path_patterns.is_empty() {
        for pattern in path_patterns {
            match regex::Regex::new(pattern) {
                Ok(re) => path_filters.push(re),
                Err(e) => {
                    writeln!(
                        buffer,
                        "Error: Invalid path regex pattern '{}': {}",
                        pattern, e
                    )?;
                    return Ok(String::from_utf8_lossy(&buffer).to_string());
                }
            }
        }
    }

    writeln!(
        buffer,
        "\nGit Range: Found {} commit(s) in range {}:",
        range_commits.len(),
        range
    )?;
    writeln!(buffer, "{}", "=".repeat(80))?;

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
                    writeln!(
                        buffer,
                        "Warning: Failed to build reachable commits set: {}. Using individual checks",
                        e
                    )?;
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
                        writeln!(
                            buffer,
                            "Warning: Failed to check reachability for commit {}: {}",
                            commit.git_sha, e
                        )?;
                        false
                    }
                }
            };

            if !is_reachable {
                continue;
            }
        }

        matched_count += 1;
        displayed_count += 1;

        if verbose {
            // Verbose mode: show full details for each commit
            writeln!(buffer, "\n{}", "─".repeat(80))?;
            writeln!(buffer, "{}. Commit: {}", displayed_count, commit.git_sha)?;
            writeln!(buffer, "   Author: {}", commit.author)?;
            writeln!(buffer, "   Subject: {}", commit.subject)?;

            // Show modified symbols if any (limited to first 5)
            if !commit.symbols.is_empty() {
                let symbol_count = commit.symbols.len();
                let display_symbols: Vec<_> = commit.symbols.iter().take(5).collect();
                writeln!(buffer, "   Modified Symbols: ({})", symbol_count)?;
                for symbol in display_symbols {
                    writeln!(buffer, "     {}", symbol)?;
                }
                if symbol_count > 5 {
                    writeln!(buffer, "     ... and {} more", symbol_count - 5)?;
                }
            }

            // Show full message
            if !commit.message.is_empty() && commit.message != commit.subject {
                writeln!(buffer, "\n   Message:")?;
                for line in commit.message.lines() {
                    writeln!(buffer, "   {}", line)?;
                }
            }

            // Show diff if verbose
            if !commit.diff.is_empty() {
                writeln!(buffer, "\n   Diff:")?;
                writeln!(buffer, "   {}", "─".repeat(76))?;
                for line in commit.diff.lines() {
                    writeln!(buffer, "   {}", line)?;
                }
                writeln!(buffer, "   {}", "─".repeat(76))?;
            }
        } else {
            // Default mode: show compact summary
            writeln!(
                buffer,
                "{}. {} {} - {}",
                displayed_count,
                &commit.git_sha[..12],
                commit.author,
                commit.subject
            )?;
        }
    }

    writeln!(buffer, "\n{}", "=".repeat(80))?;

    // Show summary with filtering info
    if !regex_patterns.is_empty() || !symbol_patterns.is_empty() || !path_patterns.is_empty() {
        writeln!(buffer, "Summary:")?;
        writeln!(buffer, "  Total commits in range: {}", range_commits.len())?;
        writeln!(buffer, "  Matched by filters: {}", matched_count)?;
        writeln!(buffer, "  Displayed: {}", displayed_count)?;

        if displayed_count == 0 {
            if !regex_patterns.is_empty() && !symbol_patterns.is_empty() {
                writeln!(
                    buffer,
                    "\nInfo: No commits matched ALL {} regex pattern(s) and {} symbol pattern(s)",
                    regex_patterns.len(),
                    symbol_patterns.len()
                )?;
            } else if !regex_patterns.is_empty() {
                writeln!(
                    buffer,
                    "\nInfo: No commits matched ALL {} regex pattern(s): {}",
                    regex_patterns.len(),
                    regex_patterns.join(", ")
                )?;
            } else if !symbol_patterns.is_empty() {
                writeln!(
                    buffer,
                    "\nInfo: No commits matched ALL {} symbol pattern(s): {}",
                    symbol_patterns.len(),
                    symbol_patterns.join(", ")
                )?;
            } else if !path_patterns.is_empty() {
                writeln!(
                    buffer,
                    "\nInfo: No commits matched ALL {} path pattern(s): {}",
                    path_patterns.len(),
                    path_patterns.join(", ")
                )?;
            }
        }
    } else {
        writeln!(buffer, "Summary: Total: {} commits", displayed_count)?;
    }

    Ok(String::from_utf8_lossy(&buffer).to_string())
}

async fn mcp_show_all_commits(
    db: &DatabaseManager,
    verbose: bool,
    regex_patterns: &[String],
    symbol_patterns: &[String],
    path_patterns: &[String],
    reachable_sha: Option<&str>,
    git_repo_path: &str,
) -> Result<String> {
    use std::io::Write;

    let mut buffer = Vec::new();

    // Step 1: Get all commits from database
    let all_commits = db.get_all_git_commits().await?;

    if all_commits.is_empty() {
        writeln!(buffer, "Info: No commits found in database")?;
        return Ok(String::from_utf8_lossy(&buffer).to_string());
    }

    // Step 2: Compile regex filters if provided (ALL must match)
    let mut regex_filters = Vec::new();
    if !regex_patterns.is_empty() {
        for pattern in regex_patterns {
            match regex::Regex::new(pattern) {
                Ok(re) => regex_filters.push(re),
                Err(e) => {
                    writeln!(buffer, "Error: Invalid regex pattern '{}': {}", pattern, e)?;
                    return Ok(String::from_utf8_lossy(&buffer).to_string());
                }
            }
        }
    }

    // Step 2b: Compile symbol filters if provided (ALL must match)
    let mut symbol_filters = Vec::new();
    if !symbol_patterns.is_empty() {
        for pattern in symbol_patterns {
            match regex::Regex::new(pattern) {
                Ok(re) => symbol_filters.push(re),
                Err(e) => {
                    writeln!(
                        buffer,
                        "Error: Invalid symbol regex pattern '{}': {}",
                        pattern, e
                    )?;
                    return Ok(String::from_utf8_lossy(&buffer).to_string());
                }
            }
        }
    }

    // Step 2c: Compile path filters if provided (ALL must match)
    let mut path_filters = Vec::new();
    if !path_patterns.is_empty() {
        for pattern in path_patterns {
            match regex::Regex::new(pattern) {
                Ok(re) => path_filters.push(re),
                Err(e) => {
                    writeln!(
                        buffer,
                        "Error: Invalid path regex pattern '{}': {}",
                        pattern, e
                    )?;
                    return Ok(String::from_utf8_lossy(&buffer).to_string());
                }
            }
        }
    }

    writeln!(
        buffer,
        "\nAll Commits: Found {} commit(s) in database:",
        all_commits.len()
    )?;
    writeln!(buffer, "{}", "=".repeat(80))?;

    // Step 3: Apply regex/symbol/path filters first
    let filtered_commits: Vec<_> = all_commits
        .iter()
        .filter(|commit| {
            // Apply regex filters if provided (ALL must match)
            if !regex_filters.is_empty() {
                let combined = format!("{}\n\n{}", commit.message, commit.diff);
                let mut match_all = true;
                for re in &regex_filters {
                    if !re.is_match(&combined) {
                        match_all = false;
                        break;
                    }
                }
                if !match_all {
                    return false;
                }
            }

            // Apply symbol filters if provided (ALL must match)
            if !symbol_filters.is_empty() {
                let mut match_all = true;
                for re in &symbol_filters {
                    // Check if ANY symbol matches this pattern
                    let matches_any = commit.symbols.iter().any(|symbol| re.is_match(symbol));
                    if !matches_any {
                        match_all = false;
                        break;
                    }
                }
                if !match_all {
                    return false;
                }
            }

            // Apply path filters if provided (ANY must match - OR logic)
            if !path_filters.is_empty() {
                let matches_any_pattern = path_filters
                    .iter()
                    .any(|re| commit.files.iter().any(|file| re.is_match(file)));
                if !matches_any_pattern {
                    return false;
                }
            }

            true
        })
        .collect();

    // Step 4: Build reachable commits set if needed (for > 10 filtered commits)
    let reachable_set = if let Some(reachable_from) = reachable_sha {
        if filtered_commits.len() > 10 {
            match git::get_reachable_commits(git_repo_path, reachable_from) {
                Ok(set) => Some(set),
                Err(e) => {
                    writeln!(
                        buffer,
                        "Warning: Failed to build reachable commits set: {}. Using individual checks",
                        e
                    )?;
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
                        writeln!(
                            buffer,
                            "Warning: Failed to check reachability for commit {}: {}",
                            commit.git_sha, e
                        )?;
                        false
                    }
                }
            };

            if !is_reachable {
                continue;
            }
        }

        matched_count += 1;
        displayed_count += 1;

        if verbose {
            // Verbose mode: show full details for each commit
            writeln!(buffer, "\n{}", "─".repeat(80))?;
            writeln!(buffer, "{}. Commit: {}", displayed_count, commit.git_sha)?;
            writeln!(buffer, "   Author: {}", commit.author)?;
            writeln!(buffer, "   Subject: {}", commit.subject)?;

            // Show modified symbols if any (limited to first 5)
            if !commit.symbols.is_empty() {
                let symbol_count = commit.symbols.len();
                let display_symbols: Vec<_> = commit.symbols.iter().take(5).collect();
                writeln!(buffer, "   Modified Symbols: ({})", symbol_count)?;
                for symbol in display_symbols {
                    writeln!(buffer, "     {}", symbol)?;
                }
                if symbol_count > 5 {
                    writeln!(buffer, "     ... and {} more", symbol_count - 5)?;
                }
            }

            // Show full message
            if !commit.message.is_empty() && commit.message != commit.subject {
                writeln!(buffer, "\n   Message:")?;
                for line in commit.message.lines() {
                    writeln!(buffer, "   {}", line)?;
                }
            }

            // Show diff if verbose
            if !commit.diff.is_empty() {
                writeln!(buffer, "\n   Diff:")?;
                writeln!(buffer, "   {}", "─".repeat(76))?;
                for line in commit.diff.lines() {
                    writeln!(buffer, "   {}", line)?;
                }
                writeln!(buffer, "   {}", "─".repeat(76))?;
            }
        } else {
            // Default mode: show compact summary
            writeln!(
                buffer,
                "{}. {} {} - {}",
                displayed_count,
                &commit.git_sha[..12],
                commit.author,
                commit.subject
            )?;
        }
    }

    writeln!(buffer, "\n{}", "=".repeat(80))?;

    // Step 4: Show summary with filtering info
    if !regex_patterns.is_empty() || !symbol_patterns.is_empty() || !path_patterns.is_empty() {
        writeln!(buffer, "Summary:")?;
        writeln!(buffer, "  Total commits in database: {}", all_commits.len())?;
        writeln!(buffer, "  Matched by filters: {}", matched_count)?;
        writeln!(buffer, "  Displayed: {}", displayed_count)?;

        if displayed_count == 0 {
            if !regex_patterns.is_empty() && !symbol_patterns.is_empty() {
                writeln!(
                    buffer,
                    "\nInfo: No commits matched ALL {} regex pattern(s) and {} symbol pattern(s)",
                    regex_patterns.len(),
                    symbol_patterns.len()
                )?;
            } else if !regex_patterns.is_empty() {
                writeln!(
                    buffer,
                    "\nInfo: No commits matched ALL {} regex pattern(s): {}",
                    regex_patterns.len(),
                    regex_patterns.join(", ")
                )?;
            } else if !symbol_patterns.is_empty() {
                writeln!(
                    buffer,
                    "\nInfo: No commits matched ALL {} symbol pattern(s): {}",
                    symbol_patterns.len(),
                    symbol_patterns.join(", ")
                )?;
            } else if !path_patterns.is_empty() {
                writeln!(
                    buffer,
                    "\nInfo: No commits matched ALL {} path pattern(s): {}",
                    path_patterns.len(),
                    path_patterns.join(", ")
                )?;
            }
        }
    } else {
        writeln!(buffer, "Summary: Total: {} commits", displayed_count)?;
    }

    Ok(String::from_utf8_lossy(&buffer).to_string())
}

async fn mcp_show_callchain_with_limits(
    db: &DatabaseManager,
    function_name: &str,
    git_sha: &str,
    up_levels: usize,
    down_levels: usize,
    calls_limit: usize,
) -> Result<String> {
    use std::io::Write;

    // Use a buffer to capture the output - this will match the query tool's efficient implementation
    let mut buffer = Vec::new();

    // Write header to match query tool output format
    writeln!(buffer, "Building call chain for: {function_name}")?;
    writeln!(buffer, "Git SHA: {git_sha}")?;
    writeln!(
        buffer,
        "Configuration: up_levels={up_levels}, down_levels={down_levels}, calls_limit={calls_limit}\n"
    )?;

    // Try to call the efficient method and capture its output
    // Since the efficient method writes directly to stdout, we'll use a workaround
    // by temporarily redirecting stdout to capture the output

    // First, check if function exists
    let func_exists = db
        .find_function_git_aware(function_name, git_sha)
        .await?
        .is_some();

    if !func_exists {
        writeln!(
            buffer,
            "Error: Function '{function_name}' not found in database at git SHA {git_sha}"
        )?;
        return Ok(String::from_utf8_lossy(&buffer).to_string());
    }

    // Use a more sophisticated approach to capture the efficient method's output
    // Since we can't easily redirect stdout in a library context, let's implement
    // the core efficient logic manually using the database methods

    writeln!(
        buffer,
        "Starting efficient callchain search for function: {function_name} (up: {up_levels}, down: {down_levels})"
    )?;

    // Use a simplified but functional approach that mimics the efficient implementation
    // This calls the underlying database method directly but captures output

    // Get the function info first
    if let Some(func) = db.find_function_git_aware(function_name, git_sha).await? {
        writeln!(buffer, "\n=== Function Information ===")?;
        writeln!(
            buffer,
            "Function: {} ({}:{})",
            func.name, func.file_path, func.line_start
        )?;
        writeln!(buffer, "Return Type: {}", func.return_type)?;

        if !func.parameters.is_empty() {
            writeln!(buffer, "Parameters:")?;
            for param in &func.parameters {
                writeln!(buffer, "  - {} {}", param.type_name, param.name)?;
            }
        }

        // Get callers and callees
        let callers = db
            .get_function_callers_git_aware(function_name, git_sha)
            .await?;
        let callees = db
            .get_function_callees_git_aware(function_name, git_sha)
            .await?;

        // Show callers with depth and limit control
        if !callers.is_empty() && up_levels > 0 {
            writeln!(
                buffer,
                "\n=== Reverse Chain (Callers, {up_levels} levels) ==="
            )?;

            let limited_callers: Vec<_> = if calls_limit == 0 {
                callers.clone()
            } else {
                callers.iter().take(calls_limit).cloned().collect()
            };

            for (i, caller) in limited_callers.iter().enumerate() {
                writeln!(buffer, "{}. {}", i + 1, caller)?;

                // Show caller details if available
                if let Ok(Some(caller_func)) = db.find_function_git_aware(caller, git_sha).await {
                    writeln!(
                        buffer,
                        "   └─ {} ({}:{})",
                        caller_func.return_type, caller_func.file_path, caller_func.line_start
                    )?;
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
                            // Show up to 3 second-level callers
                            writeln!(buffer, "      └─ {second_caller}")?;
                        }
                        if limited_second.len() > 3 {
                            writeln!(buffer, "      └─ ... and {} more", limited_second.len() - 3)?;
                        }
                    }
                }
            }

            if calls_limit > 0 && callers.len() > calls_limit {
                writeln!(
                    buffer,
                    "... and {} more callers (limited by calls_limit={})",
                    callers.len() - calls_limit,
                    calls_limit
                )?;
            }
        }

        // Show callees with depth and limit control
        if !callees.is_empty() && down_levels > 0 {
            writeln!(
                buffer,
                "\n=== Forward Chain (Callees, {down_levels} levels) ==="
            )?;

            let limited_callees: Vec<_> = if calls_limit == 0 {
                callees.clone()
            } else {
                callees.iter().take(calls_limit).cloned().collect()
            };

            for (i, callee) in limited_callees.iter().enumerate() {
                writeln!(buffer, "{}. {}", i + 1, callee)?;

                // Show callee details if available
                if let Ok(Some(callee_func)) = db.find_function_git_aware(callee, git_sha).await {
                    writeln!(
                        buffer,
                        "   └─ {} ({}:{})",
                        callee_func.return_type, callee_func.file_path, callee_func.line_start
                    )?;
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
                            // Show up to 3 second-level callees
                            writeln!(buffer, "      └─ {second_callee}")?;
                        }
                        if limited_second.len() > 3 {
                            writeln!(buffer, "      └─ ... and {} more", limited_second.len() - 3)?;
                        }
                    }
                }
            }

            if calls_limit > 0 && callees.len() > calls_limit {
                writeln!(
                    buffer,
                    "... and {} more callees (limited by calls_limit={})",
                    callees.len() - calls_limit,
                    calls_limit
                )?;
            }
        }

        // Summary
        writeln!(buffer, "\n=== Summary ===")?;
        writeln!(buffer, "Total direct callers: {}", callers.len())?;
        writeln!(buffer, "Total direct callees: {}", callees.len())?;

        if callers.is_empty() && callees.is_empty() {
            writeln!(buffer, "This function is isolated (no callers or callees)")?;
        }
    }

    Ok(String::from_utf8_lossy(&buffer).to_string())
}

#[derive(Parser, Debug)]
#[command(name = "semcode-mcp")]
#[command(about = "Semcode MCP Server - Provides semantic code search via Model Context Protocol", long_about = None)]
struct Args {
    /// Path to database directory or parent directory containing .semcode.db (default: search current directory)
    #[arg(short, long)]
    database: Option<String>,

    /// Path to the git repository for git-aware queries
    #[arg(long, default_value = ".")]
    git_repo: String,

    /// Path to custom model directory (defaults to ~/.cache/semcode/models/)
    #[arg(long)]
    model_path: Option<String>,
}

struct McpServer {
    db: Arc<DatabaseManager>,
    default_git_sha: Option<String>,
    model_path: Option<String>,
    page_cache: PageCache,
}

impl McpServer {
    async fn new(
        database_path: &str,
        git_repo_path: &str,
        model_path: Option<String>,
    ) -> Result<Self> {
        let db = Arc::new(DatabaseManager::new(database_path, git_repo_path.to_string()).await?);

        // Get the default git SHA (current HEAD)
        let default_git_sha = match git::get_git_sha(git_repo_path) {
            Ok(sha) => {
                if let Some(ref sha_val) = sha {
                    eprintln!("Default git SHA: {sha_val}");
                } else {
                    eprintln!(
                        "Not in a git repository - git-aware commands will require explicit SHA"
                    );
                }
                sha
            }
            Err(e) => {
                eprintln!("Warning: Failed to get current git SHA: {e} - git-aware commands will require explicit SHA");
                None
            }
        };

        Ok(Self {
            db,
            default_git_sha,
            model_path,
            page_cache: PageCache::new(),
        })
    }

    /// Resolve git SHA from argument or use default
    /// Always returns a git SHA - either from argument, default, or placeholder
    fn resolve_git_sha(&self, git_sha_arg: Option<&str>) -> String {
        git_sha_arg
            .map(|s| s.to_string())
            .or_else(|| self.default_git_sha.clone())
            .unwrap_or_else(|| "0000000000000000000000000000000000000000".to_string())
    }

    async fn handle_request(&self, request: Value) -> Value {
        let method = request["method"].as_str().unwrap_or("");
        let params = &request["params"];
        let id = request["id"].clone();

        let result = match method {
            "initialize" => self.handle_initialize(params).await,
            "tools/list" => self.handle_list_tools().await,
            "tools/call" => self.handle_tool_call(params).await,
            _ => json!({
                "error": {
                    "code": -32601,
                    "message": "Method not found"
                }
            }),
        };

        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result
        })
    }

    async fn handle_initialize(&self, _params: &Value) -> Value {
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "semcode-mcp",
                "version": "0.1.0"
            }
        })
    }

    async fn handle_list_tools(&self) -> Value {
        json!({
            "tools": [
                {
                    "name": "find_function",
                    "description": "Find a function or macro by exact name, optionally at a specific git commit",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": "The exact name of the function or macro to find"
                            },
                            "git_sha": {
                                "type": "string",
                                "description": "Optional git commit SHA to search at (defaults to current HEAD)"
                            }
                        },
                        "required": ["name"]
                    }
                },
                {
                    "name": "find_type",
                    "description": "Find a type, struct, union, or typedef by exact name, optionally at a specific git commit",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": "The name of the type to find, without the 'struct/enum/typedef' keyboard (e.g., 'task_struct', 'size_t')"
                            },
                            "git_sha": {
                                "type": "string",
                                "description": "Optional git commit SHA to search at (defaults to current HEAD)"
                            }
                        },
                        "required": ["name"]
                    }
                },
                {
                    "name": "find_callers",
                    "description": "Find all functions that call a specific function, optionally at a specific git commit",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": "The name of the function to find callers for"
                            },
                            "git_sha": {
                                "type": "string",
                                "description": "Optional git commit SHA to search at (defaults to current HEAD)"
                            }
                        },
                        "required": ["name"]
                    }
                },
                {
                    "name": "find_calls",
                    "description": "Find all functions called by a specific function, optionally at a specific git commit",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": "The name of the function to find calls for"
                            },
                            "git_sha": {
                                "type": "string",
                                "description": "Optional git commit SHA to search at (defaults to current HEAD)"
                            }
                        },
                        "required": ["name"]
                    }
                },
                {
                    "name": "find_callchain",
                    "description": "Show the complete call chain (both forward and reverse) for a function, optionally at a specific git commit",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": "The name of the function to analyze the call chain for"
                            },
                            "git_sha": {
                                "type": "string",
                                "description": "Optional git commit SHA to search at (defaults to current HEAD)"
                            },
                            "up_levels": {
                                "type": "integer",
                                "description": "Number of caller levels to show (default: 2, 0 = no limit)",
                                "default": 2,
                                "minimum": 0
                            },
                            "down_levels": {
                                "type": "integer",
                                "description": "Number of callee levels to show (default: 3, 0 = no limit)",
                                "default": 3,
                                "minimum": 0
                            },
                            "calls_limit": {
                                "type": "integer",
                                "description": "Maximum calls to show per level (default: 15, 0 = no limit)",
                                "default": 15,
                                "minimum": 0
                            }
                        },
                        "required": ["name"]
                    }
                },
                {
                    "name": "diff_functions",
                    "description": "Extract and list functions from a unified diff",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "diff_content": {
                                "type": "string",
                                "description": "The unified diff content to analyze"
                            }
                        },
                        "required": ["diff_content"]
                    }
                },
                {
                    "name": "grep_functions",
                    "description": "Search function bodies using regex patterns. Shows matching lines by default, full function bodies with verbose flag",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "pattern": {
                                "type": "string",
                                "description": "Regex pattern to search for in function bodies"
                            },
                            "verbose": {
                                "type": "boolean",
                                "description": "Show full function bodies instead of just matching lines (default: false)",
                                "default": false
                            },
                            "git_sha": {
                                "type": "string",
                                "description": "Optional git commit SHA to search at (defaults to current HEAD)"
                            },
                            "path_pattern": {
                                "type": "string",
                                "description": "Optional regex pattern to filter results by file path"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of results to return (default: 100, 0 = unlimited)",
                                "default": 100,
                                "minimum": 0
                            }
                        },
                        "required": ["pattern"]
                    }
                },
                {
                    "name": "vgrep_functions",
                    "description": "Search for functions similar to the provided text using semantic vector embeddings. Requires vectors to be generated first with 'semcode-index --vectors'",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query_text": {
                                "type": "string",
                                "description": "Text describing the kind of functions to find (e.g., 'memory allocation function', 'string comparison')"
                            },
                            "git_sha": {
                                "type": "string",
                                "description": "Optional git commit SHA to search at (defaults to current HEAD)"
                            },
                            "path_pattern": {
                                "type": "string",
                                "description": "Optional regex pattern to filter results by file path"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of results to return (default: 10, max: 100)",
                                "default": 10,
                                "minimum": 1,
                                "maximum": 100
                            }
                        },
                        "required": ["query_text"]
                    }
                },
                {
                    "name": "find_commit",
                    "description": "Find and display metadata for a git commit or range of commits. Accepts flexible git references like SHA, short SHA, branch names, HEAD, or git ranges. Supports regex filtering on commit message and diff - multiple patterns can be provided and ALL must match. Also supports filtering on symbol list and file paths. Results can be paginated with 50 lines per page.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "git_ref": {
                                "type": "string",
                                "description": "Git reference to look up (SHA, short SHA, branch name, HEAD, etc.). Not required if git_range is specified."
                            },
                            "git_range": {
                                "type": "string",
                                "description": "Optional git range to show multiple commits (e.g., 'HEAD~10..HEAD', 'abc123..def456'). Mutually exclusive with git_ref."
                            },
                            "regex_patterns": {
                                "type": "array",
                                "items": {
                                    "type": "string"
                                },
                                "description": "Optional array of regex patterns to filter commits - ALL patterns must match against the combined commit message and unified diff. Equivalent to passing -r multiple times."
                            },
                            "symbol_patterns": {
                                "type": "array",
                                "items": {
                                    "type": "string"
                                },
                                "description": "Optional array of regex patterns to filter commits by symbols - ALL patterns must match at least one symbol in the commit. Equivalent to passing -s multiple times."
                            },
                            "path_patterns": {
                                "type": "array",
                                "items": {
                                    "type": "string"
                                },
                                "description": "Optional array of regex patterns to filter commits by file paths - ALL patterns must match at least one file path in the commit. Equivalent to passing -p multiple times."
                            },
                            "reachable_sha": {
                                "type": "string",
                                "description": "Optional git SHA to filter results to only commits reachable from (i.e., ancestors of) the specified commit. Equivalent to --reachable in the query tool."
                            },
                            "verbose": {
                                "type": "boolean",
                                "description": "Show full diff in addition to metadata (default: false)",
                                "default": false
                            },
                            "page": {
                                "type": "integer",
                                "description": "Optional page number for pagination (1-based). If not provided, returns entire result. Each page contains 50 lines. Results indicate current page and total pages.",
                                "minimum": 1
                            }
                        }
                    }
                },
                {
                    "name": "vcommit_similar_commits",
                    "description": "Search for commits similar to the provided text using semantic vector embeddings. Requires commit vectors to be generated first with 'semcode-index --vectors'. Supports multiple regex filters on message/diff, symbol filters, and path filters - ALL must match. Results can be paginated with 50 lines per page.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query_text": {
                                "type": "string",
                                "description": "Text describing the kind of commits to find (e.g., 'fix memory leak', 'refactor parser', 'performance optimization')"
                            },
                            "git_range": {
                                "type": "string",
                                "description": "Optional git range to filter results (e.g., 'HEAD~100..HEAD', 'main~50..HEAD')"
                            },
                            "regex_patterns": {
                                "type": "array",
                                "items": {
                                    "type": "string"
                                },
                                "description": "Optional array of regex patterns to filter results by commit message and diff - ALL patterns must match. Equivalent to passing -r multiple times."
                            },
                            "symbol_patterns": {
                                "type": "array",
                                "items": {
                                    "type": "string"
                                },
                                "description": "Optional array of regex patterns to filter results by symbols - ALL patterns must match at least one symbol in the commit. Equivalent to passing -s multiple times."
                            },
                            "path_patterns": {
                                "type": "array",
                                "items": {
                                    "type": "string"
                                },
                                "description": "Optional array of regex patterns to filter results by file paths - ALL patterns must match at least one file path in the commit. Equivalent to passing -p multiple times."
                            },
                            "reachable_sha": {
                                "type": "string",
                                "description": "Optional git SHA to filter results to only commits reachable from (i.e., ancestors of) the specified commit. Equivalent to --reachable in the query tool."
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of results to return (default: 10, max: 50)",
                                "default": 10,
                                "minimum": 1,
                                "maximum": 50
                            },
                            "page": {
                                "type": "integer",
                                "description": "Optional page number for pagination (1-based). If not provided, returns entire result. Each page contains 50 lines. Results indicate current page and total pages.",
                                "minimum": 1
                            }
                        },
                        "required": ["query_text"]
                    }
                }
            ]
        })
    }

    async fn handle_tool_call(&self, params: &Value) -> Value {
        let name = params["name"].as_str().unwrap_or("");
        let arguments = &params["arguments"];

        match name {
            "find_function" => self.handle_find_function(arguments).await,
            "find_type" => self.handle_find_type(arguments).await,
            "find_callers" => self.handle_find_callers(arguments).await,
            "find_calls" => self.handle_find_calls(arguments).await,
            "find_callchain" => self.handle_find_callchain(arguments).await,
            "diff_functions" => self.handle_diff_functions(arguments).await,
            "grep_functions" => self.handle_grep_functions(arguments).await,
            "vgrep_functions" => self.handle_vgrep_functions(arguments).await,
            "find_commit" => self.handle_find_commit(arguments).await,
            "vcommit_similar_commits" => self.handle_vcommit_similar_commits(arguments).await,
            _ => json!({
                "error": format!("Unknown tool: {}", name),
                "isError": true
            }),
        }
    }

    // Tool implementation methods
    async fn handle_find_function(&self, args: &Value) -> Value {
        let name = args["name"].as_str().unwrap_or("");
        let git_sha_arg = args["git_sha"].as_str();
        let git_sha = self.resolve_git_sha(git_sha_arg);

        match mcp_query_function_or_macro(&self.db, name, &git_sha).await {
            Ok(output) => json!({
                "content": [{"type": "text", "text": truncate_output(output)}]
            }),
            Err(e) => json!({
                "error": format!("Failed to find function: {}", e),
                "isError": true
            }),
        }
    }

    async fn handle_find_type(&self, args: &Value) -> Value {
        let name = args["name"].as_str().unwrap_or("");
        let git_sha_arg = args["git_sha"].as_str();
        let git_sha = self.resolve_git_sha(git_sha_arg);

        match mcp_query_type_or_typedef(&self.db, name, &git_sha).await {
            Ok(output) => json!({
                "content": [{"type": "text", "text": truncate_output(output)}]
            }),
            Err(e) => json!({
                "error": format!("Failed to find type: {}", e),
                "isError": true
            }),
        }
    }

    async fn handle_find_callers(&self, args: &Value) -> Value {
        let name = args["name"].as_str().unwrap_or("");
        let git_sha_arg = args["git_sha"].as_str();
        let git_sha = self.resolve_git_sha(git_sha_arg);

        match mcp_show_callers(&self.db, name, &git_sha).await {
            Ok(output) => json!({
                "content": [{"type": "text", "text": truncate_output(output)}]
            }),
            Err(e) => json!({
                "error": format!("Failed to find callers: {}", e),
                "isError": true
            }),
        }
    }

    async fn handle_find_calls(&self, args: &Value) -> Value {
        let name = args["name"].as_str().unwrap_or("");
        let git_sha_arg = args["git_sha"].as_str();
        let git_sha = self.resolve_git_sha(git_sha_arg);

        match mcp_show_calls(&self.db, name, &git_sha).await {
            Ok(output) => json!({
                "content": [{"type": "text", "text": truncate_output(output)}]
            }),
            Err(e) => json!({
                "error": format!("Failed to find calls: {}", e),
                "isError": true
            }),
        }
    }

    async fn handle_find_callchain(&self, args: &Value) -> Value {
        let name = args["name"].as_str().unwrap_or("");
        let git_sha_arg = args["git_sha"].as_str();
        let git_sha = self.resolve_git_sha(git_sha_arg);

        // Parse the new parameters with same defaults as query tool
        let up_levels = args["up_levels"].as_u64().unwrap_or(2) as usize;
        let down_levels = args["down_levels"].as_u64().unwrap_or(3) as usize;
        let calls_limit = args["calls_limit"].as_u64().unwrap_or(15) as usize;

        // Apply same logic as query tool: convert 0 to 15 for practical limits (except calls_limit)
        let up_levels = if up_levels == 0 { 15 } else { up_levels };
        let down_levels = if down_levels == 0 { 15 } else { down_levels };

        match mcp_show_callchain_with_limits(
            &self.db,
            name,
            &git_sha,
            up_levels,
            down_levels,
            calls_limit,
        )
        .await
        {
            Ok(output) => json!({
                "content": [{"type": "text", "text": truncate_output(output)}]
            }),
            Err(e) => json!({
                "error": format!("Failed to find callchain: {}", e),
                "isError": true
            }),
        }
    }

    async fn handle_diff_functions(&self, args: &Value) -> Value {
        let diff_content = args["diff_content"].as_str().unwrap_or("");

        match mcp_diff_functions(diff_content).await {
            Ok(output) => json!({
                "content": [{"type": "text", "text": truncate_output(output)}]
            }),
            Err(e) => json!({
                "error": format!("Failed to extract functions from diff: {}", e),
                "isError": true
            }),
        }
    }

    async fn handle_grep_functions(&self, args: &Value) -> Value {
        let pattern = args["pattern"].as_str().unwrap_or("");
        let verbose = args["verbose"].as_bool().unwrap_or(false);
        let git_sha_arg = args["git_sha"].as_str();
        let path_pattern = args["path_pattern"].as_str();
        let limit = args["limit"].as_u64().unwrap_or(100) as usize;

        let git_sha = self.resolve_git_sha(git_sha_arg);

        match mcp_grep_function_bodies(&self.db, pattern, verbose, path_pattern, limit, &git_sha)
            .await
        {
            Ok(output) => json!({
                "content": [{"type": "text", "text": truncate_output(output)}]
            }),
            Err(e) => json!({
                "error": format!("Failed to search function bodies: {}", e),
                "isError": true
            }),
        }
    }

    async fn handle_vgrep_functions(&self, args: &Value) -> Value {
        let query_text = args["query_text"].as_str().unwrap_or("");
        let git_sha_arg = args["git_sha"].as_str();
        let path_pattern = args["path_pattern"].as_str();
        let limit = args["limit"].as_u64().unwrap_or(10) as usize;

        let _git_sha = self.resolve_git_sha(git_sha_arg);

        match mcp_vgrep_similar_functions(
            &self.db,
            query_text,
            limit,
            path_pattern,
            &self.model_path,
        )
        .await
        {
            Ok(output) => json!({
                "content": [{"type": "text", "text": truncate_output(output)}]
            }),
            Err(e) => json!({
                "error": format!("Failed to search similar functions: {}", e),
                "isError": true
            }),
        }
    }

    async fn handle_find_commit(&self, args: &Value) -> Value {
        let git_ref = args["git_ref"].as_str();
        let git_range = args["git_range"].as_str();

        // Extract regex_patterns array
        let regex_patterns: Vec<String> = args["regex_patterns"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        // Extract symbol_patterns array
        let symbol_patterns: Vec<String> = args["symbol_patterns"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        // Extract path_patterns array
        let path_patterns: Vec<String> = args["path_patterns"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let reachable_sha = args["reachable_sha"].as_str();
        let verbose = args["verbose"].as_bool().unwrap_or(false);
        let page = args["page"].as_u64().map(|p| p as usize);

        // Generate a query key for caching
        let query_key = format!(
            "commit:{}:{}:{}:{}:{}:{}:{}",
            git_ref.unwrap_or(""),
            git_range.unwrap_or(""),
            regex_patterns.join("|"),
            symbol_patterns.join("|"),
            path_patterns.join("|"),
            reachable_sha.unwrap_or(""),
            verbose
        );

        // Note: We need git_repo_path for reachability checks
        // Get it from the database manager or discover from current directory
        let git_repo_path = "."; // MCP server typically runs in the repo directory

        // Check if git_range is provided
        if let Some(range) = git_range {
            // Show commit range
            match mcp_show_commit_range(
                &self.db,
                range,
                verbose,
                &regex_patterns,
                &symbol_patterns,
                &path_patterns,
                reachable_sha,
                git_repo_path,
            )
            .await
            {
                Ok(output) => {
                    let (result, _paginated) = self.page_cache.get_page(&query_key, &output, page);
                    json!({
                        "content": [{"type": "text", "text": truncate_output(result)}]
                    })
                }
                Err(e) => json!({
                    "error": format!("Failed to find commits in range: {}", e),
                    "isError": true
                }),
            }
        } else if let Some(git_ref_str) = git_ref {
            // Show single commit
            match mcp_show_commit_metadata(
                &self.db,
                git_ref_str,
                verbose,
                &regex_patterns,
                &symbol_patterns,
                &path_patterns,
                reachable_sha,
                git_repo_path,
            )
            .await
            {
                Ok(output) => {
                    let (result, _paginated) = self.page_cache.get_page(&query_key, &output, page);
                    json!({
                        "content": [{"type": "text", "text": truncate_output(result)}]
                    })
                }
                Err(e) => json!({
                    "error": format!("Failed to find commit: {}", e),
                    "isError": true
                }),
            }
        } else {
            // Neither git_ref nor git_range provided - show all commits from database
            match mcp_show_all_commits(
                &self.db,
                verbose,
                &regex_patterns,
                &symbol_patterns,
                &path_patterns,
                reachable_sha,
                git_repo_path,
            )
            .await
            {
                Ok(output) => {
                    let (result, _paginated) = self.page_cache.get_page(&query_key, &output, page);
                    json!({
                        "content": [{"type": "text", "text": truncate_output(result)}]
                    })
                }
                Err(e) => json!({
                    "error": format!("Failed to find commits: {}", e),
                    "isError": true
                }),
            }
        }
    }

    async fn handle_vcommit_similar_commits(&self, args: &Value) -> Value {
        let query_text = args["query_text"].as_str().unwrap_or("");
        let git_range = args["git_range"].as_str();

        // Extract regex_patterns array
        let regex_patterns: Vec<String> = args["regex_patterns"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        // Extract symbol_patterns array
        let symbol_patterns: Vec<String> = args["symbol_patterns"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        // Extract path_patterns array
        let path_patterns: Vec<String> = args["path_patterns"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let reachable_sha = args["reachable_sha"].as_str();
        let limit = args["limit"].as_u64().unwrap_or(10) as usize;
        let page = args["page"].as_u64().map(|p| p as usize);

        // Generate a query key for caching
        let query_key = format!(
            "vcommit:{}:{}:{}:{}:{}:{}:{}",
            query_text,
            git_range.unwrap_or(""),
            regex_patterns.join("|"),
            symbol_patterns.join("|"),
            path_patterns.join("|"),
            reachable_sha.unwrap_or(""),
            limit
        );

        // Note: We need git_repo_path for git range resolution and reachability checks
        // Get it from the database manager or discover from current directory
        let git_repo_path = "."; // MCP server typically runs in the repo directory

        match mcp_vcommit_similar_commits(
            &self.db,
            query_text,
            limit,
            &regex_patterns,
            &symbol_patterns,
            &path_patterns,
            git_range,
            reachable_sha,
            git_repo_path,
            &self.model_path,
        )
        .await
        {
            Ok(output) => {
                let (result, _paginated) = self.page_cache.get_page(&query_key, &output, page);
                json!({
                    "content": [{"type": "text", "text": truncate_output(result)}]
                })
            }
            Err(e) => json!({
                "error": format!("Failed to search similar commits: {}", e),
                "isError": true
            }),
        }
    }
}

async fn mcp_diff_functions(diff_content: &str) -> Result<String> {
    use semcode::diffdump::parse_unified_diff;
    use std::io::Write;

    let mut buffer = Vec::new();

    // Parse the unified diff to extract both modified and called functions
    let parse_result = parse_unified_diff(diff_content)?;

    writeln!(
        buffer,
        "============================================================"
    )?;
    writeln!(buffer, "                  DIFF FUNCTION ANALYSIS")?;
    writeln!(
        buffer,
        "============================================================"
    )?;

    if parse_result.modified_functions.is_empty() && parse_result.called_functions.is_empty() {
        writeln!(buffer, "Result: No function modifications found in diff")?;
        return Ok(String::from_utf8_lossy(&buffer).to_string());
    }

    // Display modified functions
    if !parse_result.modified_functions.is_empty() {
        writeln!(
            buffer,
            "\nMODIFIED: {} functions:",
            parse_result.modified_functions.len()
        )?;
        let mut sorted_modified: Vec<_> = parse_result.modified_functions.iter().collect();
        sorted_modified.sort();
        for func_name in sorted_modified {
            writeln!(buffer, "  ● {func_name}")?;
        }
    }

    // Display called functions
    if !parse_result.called_functions.is_empty() {
        writeln!(
            buffer,
            "\nCALLED: {} functions:",
            parse_result.called_functions.len()
        )?;
        let mut sorted_called: Vec<_> = parse_result.called_functions.iter().collect();
        sorted_called.sort();
        for func_name in sorted_called {
            // Skip if it's already in modified functions to avoid duplication
            if !parse_result.modified_functions.contains(func_name) {
                writeln!(buffer, "  ○ {func_name}")?;
            }
        }
    }

    // Summary
    let total_unique = parse_result.modified_functions.len()
        + parse_result
            .called_functions
            .iter()
            .filter(|f| !parse_result.modified_functions.contains(*f))
            .count();

    writeln!(
        buffer,
        "\n============================================================"
    )?;
    writeln!(
        buffer,
        "SUMMARY: {} modified, {} called, {} total unique functions",
        parse_result.modified_functions.len(),
        parse_result.called_functions.len(),
        total_unique
    )?;
    writeln!(
        buffer,
        "============================================================"
    )?;

    Ok(String::from_utf8_lossy(&buffer).to_string())
}

async fn mcp_grep_function_bodies(
    db: &DatabaseManager,
    pattern: &str,
    verbose: bool,
    path_pattern: Option<&str>,
    limit: usize,
    git_sha: &str,
) -> Result<String> {
    use std::io::Write;

    let mut buffer = Vec::new();

    // Show search parameters like the query tool does
    match (path_pattern, limit) {
        (Some(path_regex), 0) => writeln!(
            buffer,
            "Searching function bodies for pattern: {pattern} (filtering paths matching: {path_regex}, unlimited) at git commit {git_sha}"
        )?,
        (Some(path_regex), n) => writeln!(
            buffer,
            "Searching function bodies for pattern: {pattern} (filtering paths matching: {path_regex}, limit: {n}) at git commit {git_sha}"
        )?,
        (None, 0) => writeln!(
            buffer,
            "Searching function bodies for pattern: {pattern} (unlimited) at git commit {git_sha}"
        )?,
        (None, n) => writeln!(
            buffer,
            "Searching function bodies for pattern: {pattern} (limit: {n}) at git commit {git_sha}"
        )?,
    }

    // Perform regex search on function bodies using LanceDB (git-aware)
    let (matching_functions, limit_hit) = db
        .grep_function_bodies_git_aware(pattern, path_pattern, limit, git_sha)
        .await?;

    if matching_functions.is_empty() {
        writeln!(
            buffer,
            "Info: No functions found matching pattern '{pattern}'"
        )?;
        return Ok(String::from_utf8_lossy(&buffer).to_string());
    }

    // Show warning if limit was hit
    if limit_hit {
        writeln!(
            buffer,
            "Warning: grep warning: limit hit ({} results)",
            matching_functions.len()
        )?;
    }

    if verbose {
        // Verbose mode: show full function bodies (original behavior)
        writeln!(
            buffer,
            "\nFound {} function(s) matching pattern:",
            matching_functions.len()
        )?;
        writeln!(
            buffer,
            "============================================================"
        )?;

        for func in &matching_functions {
            writeln!(buffer, "\nFunction: {}:{}", func.name, func.line_start)?;
            writeln!(buffer, "File: {}", func.file_path)?;
            writeln!(buffer, "File SHA: {}", func.git_file_hash)?;

            // Show the function body with the matching pattern highlighted
            writeln!(buffer, "\nFunction Body:")?;
            writeln!(
                buffer,
                "────────────────────────────────────────────────────────────"
            )?;

            // Split function body into lines and show with line numbers relative to function start
            let lines: Vec<&str> = func.body.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let line_num = func.line_start + i as u32;
                writeln!(buffer, "{line_num:4}: {line}")?;
            }

            writeln!(
                buffer,
                "────────────────────────────────────────────────────────────"
            )?;
        }
    } else {
        // Default mode: show only matching lines with file:function: prefix
        writeln!(
            buffer,
            "\nFound {} matching line(s):",
            matching_functions.len()
        )?;

        // Compile regex for line matching
        let regex = match regex::Regex::new(pattern) {
            Ok(re) => re,
            Err(e) => {
                writeln!(buffer, "Error: Invalid regex pattern '{pattern}': {e}")?;
                return Ok(String::from_utf8_lossy(&buffer).to_string());
            }
        };

        let mut total_matches = 0;

        for func in &matching_functions {
            let lines: Vec<&str> = func.body.lines().collect();

            for (i, line) in lines.iter().enumerate() {
                if regex.is_match(line) {
                    let line_num = func.line_start + i as u32;
                    writeln!(
                        buffer,
                        "{}:{}:{}: {}",
                        func.file_path,
                        func.name,
                        line_num,
                        line.trim()
                    )?;
                    total_matches += 1;
                }
            }
        }

        if total_matches == 0 {
            writeln!(
                buffer,
                "Info: Functions matched pattern but no individual lines matched"
            )?;
        }
    }

    writeln!(
        buffer,
        "\nSummary: Total function matches: {}",
        matching_functions.len()
    )?;
    Ok(String::from_utf8_lossy(&buffer).to_string())
}

async fn mcp_vgrep_similar_functions(
    db: &DatabaseManager,
    query_text: &str,
    limit: usize,
    path_pattern: Option<&str>,
    model_path: &Option<String>,
) -> Result<String> {
    use semcode::CodeVectorizer;
    use std::io::Write;

    let mut buffer = Vec::new();

    // Show search parameters like the query tool does
    match path_pattern {
        Some(pattern) => writeln!(
            buffer,
            "Searching for functions similar to: {query_text} (filtering files matching: {pattern}, limit: {limit})"
        )?,
        None => writeln!(
            buffer,
            "Searching for functions similar to: {query_text} (limit: {limit})"
        )?,
    }

    // Initialize vectorizer
    writeln!(buffer, "Initializing vectorizer...")?;
    let vectorizer = match CodeVectorizer::new_with_config(false, model_path.clone()).await {
        Ok(v) => v,
        Err(e) => {
            writeln!(buffer, "Error: Failed to initialize vectorizer: {e}")?;
            writeln!(
                buffer,
                "Make sure you have a model available. Use --model-path to specify a custom model."
            )?;
            return Ok(String::from_utf8_lossy(&buffer).to_string());
        }
    };

    // Generate vector for query text
    writeln!(buffer, "Generating query vector...")?;
    let query_vector = match vectorizer.vectorize_code(query_text) {
        Ok(v) => v,
        Err(e) => {
            writeln!(buffer, "Error: Failed to generate vector for query: {e}")?;
            return Ok(String::from_utf8_lossy(&buffer).to_string());
        }
    };

    // Search for similar functions with scores (no database-level filtering)
    // We'll apply path filtering as post-processing, same as grep command
    let search_limit = if path_pattern.is_some() {
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
            writeln!(buffer, "Info: No similar functions found")?;
            writeln!(
                buffer,
                "Make sure vectors have been generated with 'semcode-index --vectors'"
            )?;
        }
        Ok(matches) => {
            // Apply path filtering if provided (same approach as grep command)
            let final_matches = if let Some(path_regex) = path_pattern {
                match regex::Regex::new(path_regex) {
                    Ok(path_re) => {
                        let original_count = matches.len();
                        let filtered: Vec<_> = matches
                            .into_iter()
                            .filter(|m| path_re.is_match(&m.function.file_path))
                            .take(limit) // Apply the original limit to filtered results
                            .collect();

                        writeln!(
                            buffer,
                            "Path filter '{}' reduced results from {} to {} functions",
                            path_regex,
                            original_count,
                            filtered.len()
                        )?;

                        filtered
                    }
                    Err(e) => {
                        writeln!(buffer, "Error: Invalid regex pattern '{path_regex}': {e}")?;
                        return Ok(String::from_utf8_lossy(&buffer).to_string());
                    }
                }
            } else {
                matches
            };

            if final_matches.is_empty() {
                writeln!(buffer, "Info: No similar functions found")?;
                if path_pattern.is_some() {
                    writeln!(
                        buffer,
                        "Try adjusting the file pattern or removing the -p filter"
                    )?;
                } else {
                    writeln!(
                        buffer,
                        "Make sure vectors have been generated with 'semcode-index --vectors'"
                    )?;
                }
                return Ok(String::from_utf8_lossy(&buffer).to_string());
            }

            writeln!(
                buffer,
                "\nResults: Found {} similar function(s):",
                final_matches.len()
            )?;
            writeln!(buffer, "{}", "=".repeat(80))?;

            for (i, match_result) in final_matches.iter().enumerate() {
                let func = &match_result.function;
                writeln!(
                    buffer,
                    "\n{}. Function: {} Similarity: {:.1}%",
                    i + 1,
                    func.name,
                    match_result.similarity_score * 100.0
                )?;
                writeln!(
                    buffer,
                    "   Location: {}:{}",
                    func.file_path, func.line_start
                )?;
                writeln!(buffer, "   Return: {}", func.return_type)?;

                // Show parameters if any
                if !func.parameters.is_empty() {
                    let param_strings: Vec<String> = func
                        .parameters
                        .iter()
                        .map(|p| format!("{} {}", p.type_name, p.name))
                        .collect();
                    writeln!(buffer, "   Parameters: ({})", param_strings.join(", "))?;
                }

                // Show a preview of the function body (first 3 lines)
                if !func.body.is_empty() {
                    let lines: Vec<&str> = func.body.lines().take(3).collect();
                    if !lines.is_empty() {
                        writeln!(buffer, "   Preview:")?;
                        for line in lines {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() {
                                writeln!(buffer, "     {trimmed}")?;
                            }
                        }
                        if func.body.lines().count() > 3 {
                            writeln!(buffer, "     ...")?;
                        }
                    }
                }
            }

            writeln!(buffer, "\n{}", "=".repeat(80))?;
            writeln!(
                buffer,
                "Tip: Use 'find_function' tool to see full details of a specific function"
            )?;
        }
        Err(e) => {
            writeln!(buffer, "Error: Vector search failed: {e}")?;
            writeln!(
                buffer,
                "Make sure vectors have been generated with 'semcode-index --vectors'"
            )?;
        }
    }

    Ok(String::from_utf8_lossy(&buffer).to_string())
}

async fn mcp_vcommit_similar_commits(
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
) -> Result<String> {
    use semcode::CodeVectorizer;
    use std::io::Write;

    let mut buffer = Vec::new();

    // Show search parameters
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
            writeln!(
                buffer,
                "Searching for commits similar to: {query_text} (git range: {range}, {filter_desc}, limit: {limit})"
            )?;
        }
        (Some(range), false) => writeln!(
            buffer,
            "Searching for commits similar to: {query_text} (git range: {range}, limit: {limit})"
        )?,
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
            writeln!(
                buffer,
                "Searching for commits similar to: {query_text} ({filter_desc}, limit: {limit})"
            )?;
        }
        (None, false) => writeln!(
            buffer,
            "Searching for commits similar to: {query_text} (limit: {limit})"
        )?,
    }

    // Initialize vectorizer
    writeln!(buffer, "Initializing vectorizer...")?;
    let vectorizer = match CodeVectorizer::new_with_config(false, model_path.clone()).await {
        Ok(v) => v,
        Err(e) => {
            writeln!(buffer, "Error: Failed to initialize vectorizer: {e}")?;
            writeln!(
                buffer,
                "Make sure you have a model available. Use --model-path to specify a custom model."
            )?;
            return Ok(String::from_utf8_lossy(&buffer).to_string());
        }
    };

    // Generate vector for query text
    writeln!(buffer, "Generating query vector...")?;
    let query_vector = match vectorizer.vectorize_code(query_text) {
        Ok(v) => v,
        Err(e) => {
            writeln!(buffer, "Error: Failed to generate vector for query: {e}")?;
            return Ok(String::from_utf8_lossy(&buffer).to_string());
        }
    };

    // Resolve git range to a set of commit SHAs if provided
    let git_range_shas = if let Some(range) = git_range {
        match gix::discover(git_repo_path) {
            Ok(repo) => {
                // Resolve the git range using gitoxide
                let range_parts: Vec<&str> = range.split("..").collect();
                if range_parts.len() != 2 {
                    writeln!(
                        buffer,
                        "Error: Invalid git range format: '{}'. Expected format: FROM..TO (e.g., HEAD~100..HEAD)",
                        range
                    )?;
                    return Ok(String::from_utf8_lossy(&buffer).to_string());
                }

                let from_ref = range_parts[0];
                let to_ref = range_parts[1];

                let from_commit = match git::resolve_to_commit(&repo, from_ref) {
                    Ok(c) => c,
                    Err(e) => {
                        writeln!(
                            buffer,
                            "Error: Failed to resolve git reference '{}': {}",
                            from_ref, e
                        )?;
                        return Ok(String::from_utf8_lossy(&buffer).to_string());
                    }
                };

                let to_commit = match git::resolve_to_commit(&repo, to_ref) {
                    Ok(c) => c,
                    Err(e) => {
                        writeln!(
                            buffer,
                            "Error: Failed to resolve git reference '{}': {}",
                            to_ref, e
                        )?;
                        return Ok(String::from_utf8_lossy(&buffer).to_string());
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
                        const MAX_COMMITS: usize = 100000; // Safety limit

                        for commit_result in walk {
                            match commit_result {
                                Ok(commit_info) => {
                                    commit_count += 1;
                                    if commit_count > MAX_COMMITS {
                                        writeln!(
                                            buffer,
                                            "Error: Git range {} is too large (>{} commits)",
                                            range, MAX_COMMITS
                                        )?;
                                        return Ok(String::from_utf8_lossy(&buffer).to_string());
                                    }

                                    let commit_id = commit_info.id();
                                    range_commits.insert(commit_id.to_string());
                                }
                                Err(e) => {
                                    writeln!(buffer, "Warning: Error walking commits: {}", e)?;
                                    break;
                                }
                            }
                        }
                        writeln!(
                            buffer,
                            "Git range {} resolved to {} commits",
                            range,
                            range_commits.len()
                        )?;
                        Some(range_commits)
                    }
                    Err(e) => {
                        writeln!(buffer, "Error: Failed to walk git history: {}", e)?;
                        return Ok(String::from_utf8_lossy(&buffer).to_string());
                    }
                }
            }
            Err(e) => {
                writeln!(buffer, "Error: Not in a git repository: {}", e)?;
                return Ok(String::from_utf8_lossy(&buffer).to_string());
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
    {
        // When filtering (regex, symbols, paths, or git range), always fetch many results since we'll filter them down
        // Use a large limit to ensure we find enough matches after filtering
        500_000
    } else {
        limit
    };

    // Search for similar commits
    match db.search_similar_commits(&query_vector, search_limit).await {
        Ok(results) if results.is_empty() => {
            writeln!(buffer, "Info: No similar commits found")?;
            writeln!(
                buffer,
                "Make sure commit vectors have been generated with 'semcode-index --vectors'"
            )?;
        }
        Ok(results) => {
            // Apply git range filtering if provided
            let filtered_by_range = if let Some(ref range_shas) = git_range_shas {
                let original_count = results.len();
                let filtered: Vec<_> = results
                    .into_iter()
                    .filter(|(commit, _)| range_shas.contains(&commit.git_sha))
                    .collect();

                writeln!(
                    buffer,
                    "Git range filter reduced results from {} to {} commits",
                    original_count,
                    filtered.len()
                )?;

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
                            writeln!(buffer, "Error: Invalid regex pattern '{}': {}", pattern, e)?;
                            return Ok(String::from_utf8_lossy(&buffer).to_string());
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

                writeln!(
                    buffer,
                    "Regex filters ({} pattern(s)) reduced results from {} to {} commits",
                    regex_patterns.len(),
                    original_count,
                    filtered.len()
                )?;

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
                            writeln!(
                                buffer,
                                "Error: Invalid symbol regex pattern '{}': {}",
                                pattern, e
                            )?;
                            return Ok(String::from_utf8_lossy(&buffer).to_string());
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

                writeln!(
                    buffer,
                    "Symbol filters ({} pattern(s)) reduced results from {} to {} commits",
                    symbol_patterns.len(),
                    original_count,
                    filtered.len()
                )?;

                filtered
            } else {
                filtered_by_regex
            };

            // Apply path filtering if provided (ANY must match - OR logic)
            let filtered_by_path = if !path_patterns.is_empty() {
                // Compile all path regex patterns
                let mut path_regexes = Vec::new();
                for pattern in path_patterns {
                    match regex::Regex::new(pattern) {
                        Ok(re) => path_regexes.push(re),
                        Err(e) => {
                            writeln!(
                                buffer,
                                "Error: Invalid path regex pattern '{}': {}",
                                pattern, e
                            )?;
                            return Ok(String::from_utf8_lossy(&buffer).to_string());
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

                writeln!(
                    buffer,
                    "Path filters ({} pattern(s)) reduced results from {} to {} commits",
                    path_patterns.len(),
                    original_count,
                    filtered.len()
                )?;

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
                            writeln!(
                                buffer,
                                "Warning: Failed to build reachable commits set: {}. Falling back to individual checks",
                                e
                            )?;
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
                                            writeln!(
                                                buffer,
                                                "Warning: Failed to check reachability for commit {}: {}",
                                                commit.git_sha, e
                                            )
                                            .ok();
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
                                    writeln!(
                                        buffer,
                                        "Warning: Failed to check reachability for commit {}: {}",
                                        commit.git_sha, e
                                    )
                                    .ok();
                                    false
                                }
                            }
                        })
                        .take(limit)
                        .collect()
                };

                writeln!(
                    buffer,
                    "Reachability filter reduced results from {} to {} commits",
                    original_count,
                    filtered.len()
                )?;

                filtered
            } else {
                filtered_by_path.into_iter().take(limit).collect()
            };

            if final_results.is_empty() {
                writeln!(buffer, "Info: No similar commits found")?;
                if !regex_patterns.is_empty()
                    || !symbol_patterns.is_empty()
                    || !path_patterns.is_empty()
                    || git_range.is_some()
                {
                    writeln!(
                        buffer,
                        "Try adjusting the filters or removing the -r/-s/-p/--git options"
                    )?;
                } else {
                    writeln!(
                        buffer,
                        "Make sure commit vectors have been generated with 'semcode-index --vectors'"
                    )?;
                }
                return Ok(String::from_utf8_lossy(&buffer).to_string());
            }

            writeln!(
                buffer,
                "\nResults: Found {} similar commit(s):",
                final_results.len()
            )?;
            writeln!(buffer, "{}", "=".repeat(80))?;

            for (i, (commit, similarity)) in final_results.iter().enumerate() {
                writeln!(
                    buffer,
                    "\n{}. Similarity: {:.1}%",
                    i + 1,
                    similarity * 100.0
                )?;
                writeln!(buffer, "   Commit: {}", &commit.git_sha[..12])?;
                writeln!(buffer, "   Author: {}", commit.author)?;
                writeln!(buffer, "   Subject: {}", commit.subject)?;

                // Show modified symbols if any (limited to first 5)
                if !commit.symbols.is_empty() {
                    let symbol_count = commit.symbols.len();
                    let display_symbols: Vec<_> = commit.symbols.iter().take(5).collect();
                    writeln!(buffer, "   Modified Symbols: ({})", symbol_count)?;
                    for symbol in display_symbols {
                        writeln!(buffer, "     {}", symbol)?;
                    }
                    if symbol_count > 5 {
                        writeln!(buffer, "     ... and {} more", symbol_count - 5)?;
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
                        writeln!(buffer, "   Message Preview:")?;
                        for line in message_lines.iter().skip(1) {
                            // Skip subject line
                            writeln!(buffer, "     {}", line.trim())?;
                        }
                        if commit.message.lines().count() > 11 {
                            writeln!(buffer, "     ...")?;
                        }
                    }
                }
            }

            writeln!(buffer, "\n{}", "=".repeat(80))?;
            writeln!(
                buffer,
                "Tip: Use 'find_commit' tool to see full details of a specific commit"
            )?;
        }
        Err(e) => {
            writeln!(buffer, "Error: Commit vector search failed: {}", e)?;
            writeln!(
                buffer,
                "Make sure commit vectors have been generated with 'semcode-index --vectors'"
            )?;
        }
    }

    Ok(String::from_utf8_lossy(&buffer).to_string())
}

/// Background task to index the current commit if needed (non-blocking)
async fn index_current_commit_background(db_manager: Arc<DatabaseManager>, git_repo: String) {
    use std::fs::OpenOptions;
    use std::io::Write as _;

    eprintln!("[DEBUG] Background task actually started!");

    // Open log file in append mode
    let mut log_file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/wtgdf")
    {
        Ok(f) => {
            eprintln!("[DEBUG] Successfully opened /tmp/wtgdf");
            f
        }
        Err(e) => {
            eprintln!("[Background] Failed to open log file /tmp/wtgdf: {}", e);
            return;
        }
    };

    let mut log = |msg: &str| {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let _ = writeln!(log_file, "[{}] {}", timestamp, msg);
        let _ = log_file.flush();
    };

    log("Background indexing task started");
    eprintln!("[DEBUG] Wrote first log message");

    // Get current git SHA
    let _git_sha = match semcode::git::get_git_sha(&git_repo) {
        Ok(Some(sha)) => {
            log(&format!("Current commit: {}", sha));
            sha
        }
        Ok(None) => {
            log("Not in a git repository, skipping auto-indexing");
            return;
        }
        Err(e) => {
            log(&format!("Warning: Failed to get git SHA: {}", e));
            return;
        }
    };

    let repo_path = PathBuf::from(&git_repo);

    // Quick check: if a file changed in the current commit is already indexed with
    // its current SHA, we can skip indexing entirely (nothing new to process)
    // Compare HEAD with HEAD~1 (parent) to find changed files
    match semcode::git::get_changed_files(&repo_path, "HEAD~1", "HEAD") {
        Ok(changed_files) => {
            if !changed_files.is_empty() {
                // Find first C/C++ file that was changed (added or modified)
                let extensions = vec!["c", "h", "cc", "cpp", "cxx", "c++", "hh", "hpp", "hxx"];
                if let Some(changed_file) = changed_files.iter().find(|cf| {
                    matches!(
                        cf.change_type,
                        semcode::git::ChangeType::Added | semcode::git::ChangeType::Modified
                    ) && cf.new_file_hash.is_some()
                        && extensions.iter().any(|ext| cf.path.ends_with(ext))
                }) {
                    if let Some(new_hash) = &changed_file.new_file_hash {
                        // Get already processed files from database
                        match db_manager.get_processed_file_pairs().await {
                            Ok(processed_pairs) => {
                                // Check if this changed file with its new SHA is already in database
                                if processed_pairs
                                    .contains(&(changed_file.path.clone(), new_hash.clone()))
                                {
                                    log(&format!(
                                        "Changed file '{}' (SHA: {}) already indexed, skipping auto-indexing",
                                        changed_file.path,
                                        &new_hash[..8]
                                    ));
                                    return;
                                } else {
                                    log(&format!(
                                        "Changed file '{}' (SHA: {}) needs indexing",
                                        changed_file.path,
                                        &new_hash[..8]
                                    ));
                                }
                            }
                            Err(e) => {
                                log(&format!("Warning: Failed to get processed files: {}", e));
                                return;
                            }
                        }
                    }
                }
            } else {
                // No changes in this commit (might be initial commit or root commit)
                log("No changed files found in current commit, will check all files");
            }
        }
        Err(e) => {
            // Failed to get changed files (might be initial commit, root commit, etc.)
            log(&format!(
                "Could not get changed files ({}), will check all files",
                e
            ));
        }
    }

    // Run git range indexing using the shared library function
    // This uses the same code path as semcode-index -s .
    log("Checking for files to index...");

    // Create synthetic range for current commit: HEAD^..HEAD
    let git_range = format!("{}^..{}", _git_sha, _git_sha);
    let extensions_vec = vec![
        "c".to_string(),
        "h".to_string(),
        "cc".to_string(),
        "cpp".to_string(),
        "cxx".to_string(),
        "c++".to_string(),
        "hh".to_string(),
        "hpp".to_string(),
        "hxx".to_string(),
    ];

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
            log("Indexing complete");

            // Check if database needs optimization
            match db_manager.check_optimization_health().await {
                Ok((needs_optimization, _diagnostic_msg)) => {
                    if needs_optimization {
                        log("Database needs optimization");
                        log("Running optimization...");
                        match db_manager.optimize_database().await {
                            Ok(()) => {
                                log("Database optimization complete");
                            }
                            Err(e) => {
                                log(&format!("Warning: Database optimization failed: {}", e));
                            }
                        }
                    } else {
                        log("Database is healthy, skipping optimization");
                    }
                }
                Err(e) => {
                    log(&format!(
                        "Warning: Failed to check optimization health: {}",
                        e
                    ));
                }
            }
        }
        Err(e) => {
            log(&format!("Warning: Auto-indexing skipped: {}", e));
        }
    }
}

async fn run_stdio_server(server: Arc<McpServer>) -> Result<()> {
    eprintln!("MCP server ready on stdin/stdout");

    // Handle MCP protocol over stdin/stdout using tokio's async I/O
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let stdin = tokio::io::stdin();
    let mut stdin = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();

    let mut line = String::new();

    loop {
        line.clear();

        match stdin.read_line(&mut line).await {
            Ok(0) => {
                // EOF
                eprintln!("Reached EOF on stdin");
                break;
            }
            Ok(_) => {
                if line.trim().is_empty() {
                    continue;
                }

                match serde_json::from_str::<Value>(&line) {
                    Ok(request) => {
                        let response = server.handle_request(request).await;
                        if let Ok(response_str) = serde_json::to_string(&response) {
                            if let Err(e) = stdout.write_all(response_str.as_bytes()).await {
                                eprintln!("Failed to write response: {e}");
                                break;
                            }
                            if let Err(e) = stdout.write_all(b"\n").await {
                                eprintln!("Failed to write newline: {e}");
                                break;
                            }
                            if let Err(e) = stdout.flush().await {
                                eprintln!("Failed to flush stdout: {e}");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to parse JSON request: {e}");
                        let error_response = json!({
                            "jsonrpc": "2.0",
                            "id": null,
                            "error": {
                                "code": -32700,
                                "message": "Parse error"
                            }
                        });
                        if let Ok(response_str) = serde_json::to_string(&error_response) {
                            let _ = stdout.write_all(response_str.as_bytes()).await;
                            let _ = stdout.write_all(b"\n").await;
                            let _ = stdout.flush().await;
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading from stdin: {e}");
                break;
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Suppress ORT verbose logging
    std::env::set_var("ORT_LOG_LEVEL", "ERROR");

    // Set single-threaded configuration for MCP server
    // Note: model2vec-rs handles threading internally, no manual configuration needed

    // Initialize tracing with SEMCODE_DEBUG environment variable support
    semcode::logging::init_tracing();

    let args = Args::parse();

    eprintln!("Starting Semcode MCP Server...");
    eprintln!(
        "Database: {}",
        args.database.as_deref().unwrap_or("(auto-detect)")
    );
    eprintln!("Git repository: {}", args.git_repo);
    eprintln!("Transport: stdio");

    // Process database path with search order: 1) -d flag, 2) current directory
    let database_path = process_database_path(args.database.as_deref(), None);

    // Create MCP server
    let server = Arc::new(McpServer::new(&database_path, &args.git_repo, args.model_path).await?);

    // Ensure tables exist
    server.db.create_tables().await?;

    // Spawn background task to index current commit if needed
    eprintln!("[DEBUG] About to spawn background indexing task");
    let db_for_indexing = server.db.clone();
    let git_repo_for_indexing = args.git_repo.clone();
    let _indexing_handle = tokio::spawn(async move {
        eprintln!("[DEBUG] Inside spawned task closure");
        index_current_commit_background(db_for_indexing, git_repo_for_indexing).await;
        eprintln!("[DEBUG] Background indexing function returned");
    });
    eprintln!("[DEBUG] Task spawned, handle created");

    // Give the background task a chance to start before entering the blocking loop
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    eprintln!("[DEBUG] Yielded to background task");

    // Run MCP server on stdio
    run_stdio_server(server).await?;

    Ok(())
}
