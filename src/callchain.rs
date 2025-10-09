// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{DatabaseManager, FunctionInfo, MacroInfo};
use anstream::stdout;
use anyhow::Result;
use owo_colors::OwoColorize as _;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;

#[derive(Debug)]
pub struct CallNode {
    pub name: String,
    pub file: String,
    pub line: u32,
    pub children: Vec<CallNode>,
}

/// Helper structure to hold call relationships for functions and macros
#[derive(Debug)]
struct CallRelationships {
    function_calls: HashMap<String, Vec<String>>,
    function_callers: HashMap<String, Vec<String>>,
}

impl CallRelationships {
    async fn new_with_git(
        db: &DatabaseManager,
        function_names: &[String],
        git_sha: Option<&str>,
    ) -> Result<Self> {
        let mut function_calls = HashMap::new();
        let mut function_callers = HashMap::new();

        // Load call relationships for all functions in the chain
        for func_name in function_names {
            let (callees, callers) = if let Some(sha) = git_sha {
                // Use git-aware versions when git SHA is provided
                let callees = db
                    .get_function_callees_git_aware(func_name, sha)
                    .await
                    .unwrap_or_default();
                let callers = db
                    .get_function_callers_git_aware(func_name, sha)
                    .await
                    .unwrap_or_default();
                (callees, callers)
            } else {
                // Use regular versions when no git SHA
                let callees = db.get_function_callees(func_name).await.unwrap_or_default();
                let callers = db.get_function_callers(func_name).await.unwrap_or_default();
                (callees, callers)
            };

            if !callees.is_empty() {
                function_calls.insert(func_name.clone(), callees);
            }
            if !callers.is_empty() {
                function_callers.insert(func_name.clone(), callers);
            }
        }

        Ok(CallRelationships {
            function_calls,
            function_callers,
        })
    }
}

pub async fn show_callchain(db: &DatabaseManager, name: &str, git_sha: &str) -> Result<()> {
    show_callchain_to_writer(db, name, &mut stdout(), git_sha).await
}

pub async fn find_all_paths(db: &DatabaseManager, target_name: &str, git_sha: &str) -> Result<()> {
    find_all_paths_to_writer(db, target_name, &mut stdout(), git_sha).await
}

async fn build_forward_callchain_with_git(
    db: &DatabaseManager,
    func_name: &str,
    max_depth: usize,
    git_sha: Option<&str>,
) -> Result<CallNode> {
    // Efficiently collect only the functions we need for this call chain
    let chain_functions = db
        .collect_callchain_functions(func_name, max_depth, true, false, git_sha)
        .await?;
    let function_names: Vec<String> = chain_functions.iter().cloned().collect();
    let function_map = db.get_functions_by_names(&function_names).await?;
    let macro_map = db.get_macros_by_names(&function_names).await?;
    let call_relationships = CallRelationships::new_with_git(db, &function_names, git_sha).await?;

    Ok(build_callchain_recursive_sync(
        &function_map,
        &macro_map,
        &call_relationships,
        func_name,
        max_depth,
        true,
        &mut HashSet::new(),
    ))
}

async fn build_reverse_callchain_with_git(
    db: &DatabaseManager,
    func_name: &str,
    max_depth: usize,
    git_sha: Option<&str>,
) -> Result<CallNode> {
    // Efficiently collect only the functions we need for this call chain
    let chain_functions = db
        .collect_callchain_functions(func_name, max_depth, false, true, git_sha)
        .await?;
    let function_names: Vec<String> = chain_functions.iter().cloned().collect();
    let function_map = db.get_functions_by_names(&function_names).await?;
    let macro_map = db.get_macros_by_names(&function_names).await?;
    let call_relationships = CallRelationships::new_with_git(db, &function_names, git_sha).await?;

    Ok(build_callchain_recursive_sync(
        &function_map,
        &macro_map,
        &call_relationships,
        func_name,
        max_depth,
        false,
        &mut HashSet::new(),
    ))
}

fn build_callchain_recursive_sync(
    function_map: &HashMap<String, FunctionInfo>,
    macro_map: &HashMap<String, MacroInfo>,
    call_relationships: &CallRelationships,
    func_name: &str,
    remaining_depth: usize,
    forward: bool,
    visited: &mut HashSet<String>,
) -> CallNode {
    // Prevent infinite recursion
    if remaining_depth == 0 || visited.contains(func_name) {
        return CallNode {
            name: func_name.to_string(),
            file: String::new(),
            line: 0,
            children: vec![],
        };
    }

    visited.insert(func_name.to_string());

    let mut node = CallNode {
        name: func_name.to_string(),
        file: String::new(),
        line: 0,
        children: vec![],
    };

    if let Some(func) = function_map.get(func_name) {
        node.file = func.file_path.clone();
        node.line = func.line_start;

        let next_funcs = if forward {
            call_relationships.function_calls.get(func_name)
        } else {
            call_relationships.function_callers.get(func_name)
        };

        if let Some(funcs) = next_funcs {
            for next_func in funcs {
                let child = build_callchain_recursive_sync(
                    function_map,
                    macro_map,
                    call_relationships,
                    next_func,
                    remaining_depth - 1,
                    forward,
                    visited,
                );
                node.children.push(child);
            }
        }
    } else if let Some(macro_info) = macro_map.get(func_name) {
        // Handle macros - process their call relationships like functions
        node.file = macro_info.file_path.clone();
        node.line = macro_info.line_start;

        let next_funcs = if forward {
            call_relationships.function_calls.get(func_name)
        } else {
            call_relationships.function_callers.get(func_name)
        };

        if let Some(funcs) = next_funcs {
            for next_func in funcs {
                let child = build_callchain_recursive_sync(
                    function_map,
                    macro_map,
                    call_relationships,
                    next_func,
                    remaining_depth - 1,
                    forward,
                    visited,
                );
                node.children.push(child);
            }
        }
    }

    visited.remove(func_name);
    node
}

pub fn print_callchain_tree(node: &CallNode, indent: usize) {
    let indent_str = "  ".repeat(indent);
    let marker = if indent == 0 { "" } else { "└─ " };

    if node.file.is_empty() {
        println!("{}{}{}", indent_str, marker, node.name.yellow());
    } else {
        println!(
            "{}{}{} ({}:{})",
            indent_str,
            marker,
            node.name.yellow(),
            node.file.bright_black(),
            node.line
        );
    }

    for child in &node.children {
        print_callchain_tree(child, indent + 1);
    }

    if indent > 0 && node.children.is_empty() && node.file.is_empty() {
        println!("{}  {}", indent_str, "(...)".bright_black());
    }
}

fn find_paths_bfs(
    function_map: &HashMap<String, FunctionInfo>,
    _macro_map: &HashMap<String, MacroInfo>,
    call_relationships: &CallRelationships,
    start: &str,
    target: &str,
    max_depth: usize,
) -> Option<Vec<Vec<String>>> {
    if start == target {
        return Some(vec![vec![start.to_string()]]);
    }

    let mut queue = VecDeque::new();
    let mut visited = HashSet::new();
    let mut paths = Vec::new();

    queue.push_back((start.to_string(), vec![start.to_string()]));
    visited.insert(start.to_string());

    while let Some((current, path)) = queue.pop_front() {
        if path.len() > max_depth {
            continue;
        }

        if let Some(_func) = function_map.get(&current) {
            // Get callees from call relationships instead of func.calls
            if let Some(callees) = call_relationships.function_calls.get(&current) {
                for callee in callees {
                    if callee == target {
                        let mut complete_path = path.clone();
                        complete_path.push(callee.clone());
                        paths.push(complete_path);
                    } else if !visited.contains(callee) && path.len() < max_depth {
                        visited.insert(callee.clone());
                        let mut new_path = path.clone();
                        new_path.push(callee.clone());
                        queue.push_back((callee.clone(), new_path));
                    }
                }
            }
        }
        // Macros don't call other functions/macros, so they're always leaf nodes in the call graph
    }

    if paths.is_empty() {
        None
    } else {
        Some(paths)
    }
}

// Writer-based versions of callchain functions for both CLI and MCP usage

pub async fn show_callers_to_writer(
    db: &DatabaseManager,
    name: &str,
    writer: &mut dyn Write,
    verbose: bool,
    git_sha: &str,
) -> Result<()> {
    let search_msg = format!("Finding all functions that call: {}", name.cyan());
    writeln!(writer, "{search_msg}")?;

    // Search for both functions and macros - always use git-aware queries
    let func_opt = db.find_function_git_aware(name, git_sha).await?;
    let macro_opt = db.find_macro_git_aware(name, git_sha).await?;

    match (func_opt, macro_opt) {
        (Some(func), None) => {
            // Always use git-aware callers query
            let callers = db.get_function_callers_git_aware(name, git_sha).await?;
            if callers.is_empty() {
                let info_msg = format!("{} No functions call '{}'", "Info:".yellow(), name);
                writeln!(writer, "{info_msg}")?;
            } else {
                let header = format!("\n{}", "=== Direct Callers ===".bold().green());
                writeln!(writer, "{header}")?;

                // Show git commit SHA and target function file SHA in verbose mode
                if verbose {
                    let commit_info = format!("Using git commit: {}", git_sha.yellow());
                    writeln!(writer, "{commit_info}")?;

                    let target_info = format!(
                        "Target function '{}' defined in: {} [file SHA: {}]",
                        name.cyan(),
                        func.file_path.bright_black(),
                        func.git_file_hash.bright_black()
                    );
                    writeln!(writer, "{target_info}")?;
                }

                writeln!(
                    writer,
                    "{} functions directly call '{}':",
                    callers.len(),
                    name
                )?;

                for (i, caller) in callers.iter().enumerate() {
                    let line = format!("  {}. {}", (i + 1).to_string().yellow(), caller.cyan());
                    writeln!(writer, "{line}")?;

                    // Only perform extra lookups in verbose mode
                    if verbose {
                        // Try to get more info about the caller (function or macro) - always use git-aware version
                        let caller_func_opt = db
                            .find_function_git_aware(caller, git_sha)
                            .await
                            .unwrap_or(None);
                        if let Some(caller_func) = caller_func_opt {
                            let info = format!(
                                "     {} ({}:{}) [file SHA: {}]",
                                caller_func.return_type.bright_black(),
                                caller_func.file_path.bright_black(),
                                caller_func.line_start,
                                caller_func.git_file_hash.bright_black()
                            );
                            writeln!(writer, "{info}")?;
                        } else {
                            // Try to get macro info - always use git-aware version
                            let caller_macro_opt = db
                                .find_macro_git_aware(caller, git_sha)
                                .await
                                .unwrap_or(None);
                            if let Some(caller_macro) = caller_macro_opt {
                                let info = format!(
                                    "     {} ({}:{}) [file SHA: {}]",
                                    "macro".bright_black(),
                                    caller_macro.file_path.bright_black(),
                                    caller_macro.line_start,
                                    caller_macro.git_file_hash.bright_black()
                                );
                                writeln!(writer, "{info}")?;
                            }
                        }
                    }
                }
            }
        }
        (None, Some(macro_info)) => {
            // Handle macros - use git-aware callers query
            let callers = db.get_function_callers_git_aware(name, git_sha).await?;
            if callers.is_empty() {
                let info_msg = format!("{} No functions call macro '{}'", "Info:".yellow(), name);
                writeln!(writer, "{info_msg}")?;
            } else {
                let header = format!("\n{}", "=== Direct Callers ===".bold().green());
                writeln!(writer, "{header}")?;

                // Show git commit SHA and target macro file SHA in verbose mode
                if verbose {
                    let commit_info = format!("Using git commit: {}", git_sha.yellow());
                    writeln!(writer, "{commit_info}")?;

                    let target_info = format!(
                        "Target macro '{}' defined in: {} [file SHA: {}]",
                        name.cyan(),
                        macro_info.file_path.bright_black(),
                        macro_info.git_file_hash.bright_black()
                    );
                    writeln!(writer, "{target_info}")?;
                }

                writeln!(
                    writer,
                    "{} functions directly call macro '{}':",
                    callers.len(),
                    name
                )?;

                for (i, caller) in callers.iter().enumerate() {
                    let line = format!("  {}. {}", (i + 1).to_string().yellow(), caller.cyan());
                    writeln!(writer, "{line}")?;

                    // Only perform extra lookups in verbose mode
                    if verbose {
                        // Try to get more info about the caller (function or macro) - always use git-aware version
                        let caller_func_opt = db
                            .find_function_git_aware(caller, git_sha)
                            .await
                            .unwrap_or(None);
                        if let Some(caller_func) = caller_func_opt {
                            let info = format!(
                                "     {} ({}:{}) [file SHA: {}]",
                                caller_func.return_type.bright_black(),
                                caller_func.file_path.bright_black(),
                                caller_func.line_start,
                                caller_func.git_file_hash.bright_black()
                            );
                            writeln!(writer, "{info}")?;
                        } else {
                            // Try to get macro info - always use git-aware version
                            let caller_macro_opt = db
                                .find_macro_git_aware(caller, git_sha)
                                .await
                                .unwrap_or(None);
                            if let Some(caller_macro) = caller_macro_opt {
                                let info = format!(
                                    "     {} ({}:{}) [file SHA: {}]",
                                    "macro".bright_black(),
                                    caller_macro.file_path.bright_black(),
                                    caller_macro.line_start,
                                    caller_macro.git_file_hash.bright_black()
                                );
                                writeln!(writer, "{info}")?;
                            }
                        }
                    }
                }
            }
        }
        (Some(func), Some(macro_info)) => {
            // Found both - show a note and display function info (could be extended to show both)
            let note = format!("\n{} Found both a function and a macro with this name! Showing function call relationships.", "Note:".yellow());
            writeln!(writer, "{note}")?;

            // Always use git-aware callers query
            let callers = db.get_function_callers_git_aware(name, git_sha).await?;
            if callers.is_empty() {
                let info_msg =
                    format!("{} No functions call function '{}'", "Info:".yellow(), name);
                writeln!(writer, "{info_msg}")?;

                // Also check macro callers
                let macro_callers = db
                    .get_function_callers_git_aware(&macro_info.name, git_sha)
                    .await?;
                if !macro_callers.is_empty() {
                    let info_msg = format!(
                        "{} But {} functions call macro '{}'",
                        "Note:".cyan(),
                        macro_callers.len(),
                        name
                    );
                    writeln!(writer, "{info_msg}")?;
                }
            } else {
                let header = format!("\n{}", "=== Direct Callers (Function) ===".bold().green());
                writeln!(writer, "{header}")?;

                // Show git commit SHA and target function file SHA in verbose mode
                if verbose {
                    let commit_info = format!("Using git commit: {}", git_sha.yellow());
                    writeln!(writer, "{commit_info}")?;

                    let target_info = format!(
                        "Target function '{}' defined in: {} [file SHA: {}]",
                        name.cyan(),
                        func.file_path.bright_black(),
                        func.git_file_hash.bright_black()
                    );
                    writeln!(writer, "{target_info}")?;
                }

                writeln!(
                    writer,
                    "{} functions directly call function '{}':",
                    callers.len(),
                    name
                )?;

                for (i, caller) in callers.iter().enumerate() {
                    let line = format!("  {}. {}", (i + 1).to_string().yellow(), caller.cyan());
                    writeln!(writer, "{line}")?;

                    // Only perform extra lookups in verbose mode
                    if verbose {
                        // Try to get more info about the caller (function or macro) - always use git-aware version
                        let caller_func_opt = db
                            .find_function_git_aware(caller, git_sha)
                            .await
                            .unwrap_or(None);
                        if let Some(caller_func) = caller_func_opt {
                            let info = format!(
                                "     {} ({}:{}) [file SHA: {}]",
                                caller_func.return_type.bright_black(),
                                caller_func.file_path.bright_black(),
                                caller_func.line_start,
                                caller_func.git_file_hash.bright_black()
                            );
                            writeln!(writer, "{info}")?;
                        } else {
                            // Try to get macro info - always use git-aware version
                            let caller_macro_opt = db
                                .find_macro_git_aware(caller, git_sha)
                                .await
                                .unwrap_or(None);
                            if let Some(caller_macro) = caller_macro_opt {
                                let info = format!(
                                    "     {} ({}:{}) [file SHA: {}]",
                                    "macro".bright_black(),
                                    caller_macro.file_path.bright_black(),
                                    caller_macro.line_start,
                                    caller_macro.git_file_hash.bright_black()
                                );
                                writeln!(writer, "{info}")?;
                            }
                        }
                    }
                }

                // Also show macro callers if they exist
                let macro_callers = db
                    .get_function_callers_git_aware(&macro_info.name, git_sha)
                    .await?;
                if !macro_callers.is_empty() {
                    let header = format!("\n{}", "=== Direct Callers (Macro) ===".bold().green());
                    writeln!(writer, "{header}")?;
                    writeln!(
                        writer,
                        "{} functions directly call macro '{}':",
                        macro_callers.len(),
                        name
                    )?;

                    for (i, caller) in macro_callers.iter().enumerate() {
                        let line = format!("  {}. {}", (i + 1).to_string().yellow(), caller.cyan());
                        writeln!(writer, "{line}")?;
                    }
                }
            }
        }
        (None, None) => {
            let error_msg = format!(
                "{} No function or macro '{}' found in database",
                "Error:".red(),
                name
            );
            writeln!(writer, "{error_msg}")?;
        }
    }

    Ok(())
}

pub async fn show_callees_to_writer(
    db: &DatabaseManager,
    name: &str,
    writer: &mut dyn Write,
    verbose: bool,
    git_sha: &str,
) -> Result<()> {
    let search_msg = format!("Finding all functions called by: {}", name.cyan());
    writeln!(writer, "{search_msg}")?;

    // Search for both functions and macros - always use git-aware queries
    let func_opt = db.find_function_git_aware(name, git_sha).await?;
    let macro_opt = db.find_macro_git_aware(name, git_sha).await?;

    match (func_opt, macro_opt) {
        (Some(func), None) => {
            // Always use git-aware callees query
            let callees = db.get_function_callees_git_aware(name, git_sha).await?;
            if callees.is_empty() {
                let info_msg = format!(
                    "{} Function '{}' doesn't call any other functions",
                    "Info:".yellow(),
                    name
                );
                writeln!(writer, "{info_msg}")?;
            } else {
                let header = format!("\n{}", "=== Direct Callees ===".bold().green());
                writeln!(writer, "{header}")?;

                // Show git commit SHA and target function file SHA in verbose mode
                if verbose {
                    let commit_info = format!("Using git commit: {}", git_sha.yellow());
                    writeln!(writer, "{commit_info}")?;

                    let target_info = format!(
                        "Target function '{}' defined in: {} [file SHA: {}]",
                        name.cyan(),
                        func.file_path.bright_black(),
                        func.git_file_hash.bright_black()
                    );
                    writeln!(writer, "{target_info}")?;
                }

                writeln!(
                    writer,
                    "'{}' directly calls {} functions:",
                    name,
                    callees.len()
                )?;

                for (i, callee) in callees.iter().enumerate() {
                    let line = format!("  {}. {}", (i + 1).to_string().yellow(), callee.cyan());
                    writeln!(writer, "{line}")?;

                    // Only perform extra lookups in verbose mode
                    if verbose {
                        // Try to get more info about the callee (function or macro) - always use git-aware version
                        let callee_func_opt = db
                            .find_function_git_aware(callee, git_sha)
                            .await
                            .unwrap_or(None);
                        if let Some(callee_func) = callee_func_opt {
                            let info = format!(
                                "     {} ({}:{}) [file SHA: {}]",
                                callee_func.return_type.bright_black(),
                                callee_func.file_path.bright_black(),
                                callee_func.line_start,
                                callee_func.git_file_hash.bright_black()
                            );
                            writeln!(writer, "{info}")?;
                        } else {
                            // Try to get macro info - always use git-aware version
                            let callee_macro_opt = db
                                .find_macro_git_aware(callee, git_sha)
                                .await
                                .unwrap_or(None);
                            if let Some(callee_macro) = callee_macro_opt {
                                let info = format!(
                                    "     {} ({}:{}) [file SHA: {}]",
                                    "macro".bright_black(),
                                    callee_macro.file_path.bright_black(),
                                    callee_macro.line_start,
                                    callee_macro.git_file_hash.bright_black()
                                );
                                writeln!(writer, "{info}")?;
                            }
                        }
                    }
                }
            }
        }
        (None, Some(macro_info)) => {
            // Handle macros - get callees directly from macro's calls field
            let callees = macro_info.calls.clone().unwrap_or_default();
            if callees.is_empty() {
                let info_msg = format!(
                    "{} Macro '{}' doesn't call any other functions",
                    "Info:".yellow(),
                    name
                );
                writeln!(writer, "{info_msg}")?;
            } else {
                let header = format!("\n{}", "=== Direct Callees ===".bold().green());
                writeln!(writer, "{header}")?;

                // Show git commit SHA and target macro file SHA in verbose mode
                if verbose {
                    let commit_info = format!("Using git commit: {}", git_sha.yellow());
                    writeln!(writer, "{commit_info}")?;

                    let target_info = format!(
                        "Target macro '{}' defined in: {} [file SHA: {}]",
                        name.cyan(),
                        macro_info.file_path.bright_black(),
                        macro_info.git_file_hash.bright_black()
                    );
                    writeln!(writer, "{target_info}")?;
                }

                writeln!(
                    writer,
                    "'{}' directly calls {} functions:",
                    name,
                    callees.len()
                )?;

                for (i, callee) in callees.iter().enumerate() {
                    let line = format!("  {}. {}", (i + 1).to_string().yellow(), callee.cyan());
                    writeln!(writer, "{line}")?;

                    // Only perform extra lookups in verbose mode
                    if verbose {
                        // Try to get more info about the callee (function or macro) - always use git-aware version
                        let callee_func_opt = db
                            .find_function_git_aware(callee, git_sha)
                            .await
                            .unwrap_or(None);
                        if let Some(callee_func) = callee_func_opt {
                            let info = format!(
                                "     {} ({}:{}) [file SHA: {}]",
                                callee_func.return_type.bright_black(),
                                callee_func.file_path.bright_black(),
                                callee_func.line_start,
                                callee_func.git_file_hash.bright_black()
                            );
                            writeln!(writer, "{info}")?;
                        } else {
                            // Try to get macro info - always use git-aware version
                            let callee_macro_opt = db
                                .find_macro_git_aware(callee, git_sha)
                                .await
                                .unwrap_or(None);
                            if let Some(callee_macro) = callee_macro_opt {
                                let info = format!(
                                    "     {} ({}:{}) [file SHA: {}]",
                                    "macro".bright_black(),
                                    callee_macro.file_path.bright_black(),
                                    callee_macro.line_start,
                                    callee_macro.git_file_hash.bright_black()
                                );
                                writeln!(writer, "{info}")?;
                            }
                        }
                    }
                }
            }
        }
        (Some(func), Some(macro_info)) => {
            // Found both - show a note and display function info (could be extended to show both)
            let note = format!("\n{} Found both a function and a macro with this name! Showing function call relationships.", "Note:".yellow());
            writeln!(writer, "{note}")?;

            // Always use git-aware callees query
            let callees = db.get_function_callees_git_aware(name, git_sha).await?;
            if callees.is_empty() {
                let info_msg = format!(
                    "{} Function '{}' doesn't call any other functions",
                    "Info:".yellow(),
                    name
                );
                writeln!(writer, "{info_msg}")?;

                // Also check macro calls
                let macro_callees = macro_info.calls.clone().unwrap_or_default();
                if !macro_callees.is_empty() {
                    let info_msg = format!(
                        "{} But macro '{}' calls {} functions",
                        "Note:".cyan(),
                        name,
                        macro_callees.len()
                    );
                    writeln!(writer, "{info_msg}")?;
                }
            } else {
                let header = format!("\n{}", "=== Direct Callees (Function) ===".bold().green());
                writeln!(writer, "{header}")?;

                // Show git commit SHA and target function file SHA in verbose mode
                if verbose {
                    let commit_info = format!("Using git commit: {}", git_sha.yellow());
                    writeln!(writer, "{commit_info}")?;

                    let target_info = format!(
                        "Target function '{}' defined in: {} [file SHA: {}]",
                        name.cyan(),
                        func.file_path.bright_black(),
                        func.git_file_hash.bright_black()
                    );
                    writeln!(writer, "{target_info}")?;
                }

                writeln!(
                    writer,
                    "Function '{}' directly calls {} functions:",
                    name,
                    callees.len()
                )?;

                for (i, callee) in callees.iter().enumerate() {
                    let line = format!("  {}. {}", (i + 1).to_string().yellow(), callee.cyan());
                    writeln!(writer, "{line}")?;

                    // Only perform extra lookups in verbose mode
                    if verbose {
                        // Try to get more info about the callee (function or macro) - always use git-aware version
                        let callee_func_opt = db
                            .find_function_git_aware(callee, git_sha)
                            .await
                            .unwrap_or(None);
                        if let Some(callee_func) = callee_func_opt {
                            let info = format!(
                                "     {} ({}:{}) [file SHA: {}]",
                                callee_func.return_type.bright_black(),
                                callee_func.file_path.bright_black(),
                                callee_func.line_start,
                                callee_func.git_file_hash.bright_black()
                            );
                            writeln!(writer, "{info}")?;
                        } else {
                            // Try to get macro info - always use git-aware version
                            let callee_macro_opt = db
                                .find_macro_git_aware(callee, git_sha)
                                .await
                                .unwrap_or(None);
                            if let Some(callee_macro) = callee_macro_opt {
                                let info = format!(
                                    "     {} ({}:{}) [file SHA: {}]",
                                    "macro".bright_black(),
                                    callee_macro.file_path.bright_black(),
                                    callee_macro.line_start,
                                    callee_macro.git_file_hash.bright_black()
                                );
                                writeln!(writer, "{info}")?;
                            }
                        }
                    }
                }

                // Also show macro callees if they exist
                let macro_callees = macro_info.calls.clone().unwrap_or_default();
                if !macro_callees.is_empty() {
                    let header = format!("\n{}", "=== Direct Callees (Macro) ===".bold().green());
                    writeln!(writer, "{header}")?;
                    writeln!(
                        writer,
                        "Macro '{}' directly calls {} functions:",
                        name,
                        macro_callees.len()
                    )?;

                    for (i, callee) in macro_callees.iter().enumerate() {
                        let line = format!("  {}. {}", (i + 1).to_string().yellow(), callee.cyan());
                        writeln!(writer, "{line}")?;
                    }
                }
            }
        }
        (None, None) => {
            let error_msg = format!(
                "{} No function or macro '{}' found in database",
                "Error:".red(),
                name
            );
            writeln!(writer, "{error_msg}")?;
        }
    }

    Ok(())
}

pub async fn show_callchain_to_writer(
    db: &DatabaseManager,
    name: &str,
    writer: &mut dyn Write,
    git_sha: &str,
) -> Result<()> {
    let search_msg = format!("Building call chain for: {}", name.cyan());
    writeln!(writer, "{search_msg}")?;

    // Use provided git SHA
    let func_opt = db.find_function_git_aware(name, git_sha).await?;

    match func_opt {
        Some(func) => {
            let header = format!("{}", "=== Function Call Chain ===".bold().green());
            writeln!(writer, "{header}")?;

            // Display basic function info
            writeln!(
                writer,
                "Function: {} ({}:{})",
                func.name, func.file_path, func.line_start
            )?;
            writeln!(writer, "Return Type: {}", func.return_type)?;

            if !func.parameters.is_empty() {
                writeln!(writer, "Parameters:")?;
                for param in &func.parameters {
                    writeln!(writer, "  - {} {}", param.type_name, param.name)?;
                }
            }

            // Always use git-aware queries for callers and callees
            let callers = db.get_function_callers_git_aware(name, git_sha).await?;
            let callees = db.get_function_callees_git_aware(name, git_sha).await?;

            // Show reverse callchain (callers)
            if !callers.is_empty() {
                let callers_header =
                    format!("\n{}", "=== Reverse Chain (Callers) ===".bold().magenta());
                writeln!(writer, "{callers_header}")?;

                let reverse_chain =
                    build_reverse_callchain_with_git(db, name, 3, Some(git_sha)).await?;
                print_callchain_tree_to_writer(&reverse_chain, 0, writer)?;
            }

            // Show forward callchain (callees)
            if !callees.is_empty() {
                let callees_header =
                    format!("\n{}", "=== Forward Chain (Callees) ===".bold().blue());
                writeln!(writer, "{callees_header}")?;

                let forward_chain =
                    build_forward_callchain_with_git(db, name, 3, Some(git_sha)).await?;
                print_callchain_tree_to_writer(&forward_chain, 0, writer)?;
            }

            if callers.is_empty() && callees.is_empty() {
                let info_msg = format!(
                    "\n{} This function is isolated (no callers or callees)",
                    "Info:".yellow()
                );
                writeln!(writer, "{info_msg}")?;
            }
        }
        None => {
            let error_msg = format!(
                "{} Function '{}' not found in database",
                "Error:".red(),
                name
            );
            writeln!(writer, "{error_msg}")?;
        }
    }

    Ok(())
}

pub async fn find_all_paths_to_writer(
    db: &DatabaseManager,
    target_name: &str,
    writer: &mut dyn Write,
    git_sha: &str,
) -> Result<()> {
    let search_msg = format!(
        "Finding all paths that lead to function: {}",
        target_name.cyan()
    );
    writeln!(writer, "{search_msg}")?;

    // Check if target function exists - always use git-aware query
    let target_exists = db
        .find_function_git_aware(target_name, git_sha)
        .await?
        .is_some();

    if !target_exists {
        let error_msg = format!(
            "{} Target function '{}' not found in database",
            "Error:".red(),
            target_name
        );
        writeln!(writer, "{error_msg}")?;
        return Ok(());
    }

    // Get entry points efficiently
    let entry_points = db.get_entry_point_functions().await?;

    // Load only the functions we need for path analysis
    let all_path_functions = {
        let mut functions_needed = std::collections::HashSet::new();
        // Add entry points
        for entry in &entry_points {
            functions_needed.insert(entry.clone());
        }
        // For each entry point that might reach the target, collect the chain
        for entry_point in entry_points.iter().take(10) {
            if let Ok(path_functions) = db
                .collect_callchain_functions(entry_point, 10, true, false, Some(git_sha))
                .await
            {
                functions_needed.extend(path_functions);
            }
        }
        functions_needed
    };

    let function_names: Vec<String> = all_path_functions.iter().cloned().collect();
    let function_map = db.get_functions_by_names(&function_names).await?;
    let macro_map = db.get_macros_by_names(&function_names).await?;
    let call_relationships =
        CallRelationships::new_with_git(db, &function_names, Some(git_sha)).await?;

    let header = format!("{}", "=== Path Analysis ===".bold().green());
    writeln!(writer, "{header}")?;

    writeln!(writer, "Target function: {target_name}")?;
    writeln!(
        writer,
        "Found {} potential entry points",
        entry_points.len()
    )?;

    let mut total_paths = 0;
    let max_depth = 10;

    for entry_point in entry_points.iter() {
        if let Some(paths) = find_paths_bfs(
            &function_map,
            &macro_map,
            &call_relationships,
            entry_point,
            target_name,
            max_depth,
        ) {
            let entry_header = format!(
                "\n{} From '{}' ({} paths found):",
                "Entry:".bold().cyan(),
                entry_point,
                paths.len()
            );
            writeln!(writer, "{entry_header}")?;

            for (i, path) in paths.iter().enumerate() {
                let path_str = path.join(" → ");
                let path_line = format!("  {}. {}", (i + 1).to_string().yellow(), path_str.cyan());
                writeln!(writer, "{path_line}")?;
            }

            total_paths += paths.len();
        }
    }

    if total_paths == 0 {
        let info_msg = format!(
            "\n{} No execution paths found to '{}'",
            "Info:".yellow(),
            target_name
        );
        writeln!(writer, "{info_msg}")?;
        writeln!(
            writer,
            "This function may be an entry point itself or unreachable"
        )?;
    } else {
        let summary = format!(
            "\n{} Total paths found: {}",
            "Summary:".bold().green(),
            total_paths
        );
        writeln!(writer, "{summary}")?;
    }

    Ok(())
}

pub fn print_callchain_tree_to_writer(
    node: &CallNode,
    indent: usize,
    writer: &mut dyn Write,
) -> Result<()> {
    let indent_str = "  ".repeat(indent);
    let marker = if indent == 0 { "" } else { "└─ " };

    if node.file.is_empty() {
        writeln!(writer, "{}{}{}", indent_str, marker, node.name.yellow())?;
    } else {
        writeln!(
            writer,
            "{}{}{} ({}:{})",
            indent_str,
            marker,
            node.name.yellow(),
            node.file.bright_black(),
            node.line
        )?;
    }

    for child in &node.children {
        print_callchain_tree_to_writer(child, indent + 1, writer)?;
    }

    if indent > 0 && node.children.is_empty() && node.file.is_empty() {
        writeln!(writer, "{}  {}", indent_str, "(...)".bright_black())?;
    }

    Ok(())
}

/// Wrapper function for show_callers with verbose option
pub async fn show_callers(
    db: &DatabaseManager,
    name: &str,
    verbose: bool,
    git_sha: &str,
) -> Result<()> {
    show_callers_to_writer(db, name, &mut stdout(), verbose, git_sha).await
}

/// Wrapper function for show_callees with verbose option
pub async fn show_callees(
    db: &DatabaseManager,
    name: &str,
    verbose: bool,
    git_sha: &str,
) -> Result<()> {
    show_callees_to_writer(db, name, &mut stdout(), verbose, git_sha).await
}
