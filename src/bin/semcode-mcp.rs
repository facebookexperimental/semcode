// SPDX-License-Identifier: MIT OR Apache-2.0
use anstream::stdout;
use anyhow::Result;
use clap::Parser;
use semcode::{git, process_database_path, DatabaseManager};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
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
            let mut result = format!(
                "Found function and macro with name '{name}' (git SHA: {git_sha})\n\n"
            );

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
                format!(
                    "Function or macro '{name}' not found at git SHA {git_sha}"
                )
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
                writeln!(
                    buffer,
                    "Info: No functions call function '{function_name}'"
                )?;
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
            let calls = macro_info
                .calls.clone()
                .unwrap_or_default();
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
                let macro_calls = macro_info
                    .calls.clone()
                    .unwrap_or_default();
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
    db: DatabaseManager,
    default_git_sha: Option<String>,
    model_path: Option<String>,
}

impl McpServer {
    async fn new(
        database_path: &str,
        git_repo_path: &str,
        model_path: Option<String>,
    ) -> Result<Self> {
        let db = DatabaseManager::new(database_path, git_repo_path.to_string()).await?;

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
                        writeln!(
                            buffer,
                            "Error: Invalid regex pattern '{path_regex}': {e}"
                        )?;
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

async fn run_stdio_server(server: Arc<McpServer>) -> Result<()> {
    eprintln!("MCP server ready on stdin/stdout");

    // Handle MCP protocol over stdin/stdout
    let stdin = io::stdin();
    let mut stdout = stdout();

    for line in stdin.lock().lines() {
        match line {
            Ok(line) => {
                if line.trim().is_empty() {
                    continue;
                }

                match serde_json::from_str::<Value>(&line) {
                    Ok(request) => {
                        let response = server.handle_request(request).await;
                        if let Ok(response_str) = serde_json::to_string(&response) {
                            if let Err(e) = writeln!(stdout, "{response_str}") {
                                eprintln!("Failed to write response: {e}");
                                break;
                            }
                            if let Err(e) = stdout.flush() {
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
                            let _ = writeln!(stdout, "{response_str}");
                            let _ = stdout.flush();
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

    // Run MCP server on stdio
    run_stdio_server(server).await?;

    Ok(())
}
