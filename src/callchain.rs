// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::types::Handover;
use crate::{DatabaseManager, FunctionInfo};
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
    let call_relationships = CallRelationships::new_with_git(db, &function_names, git_sha).await?;

    Ok(build_callchain_recursive_sync(
        &function_map,
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
    let call_relationships = CallRelationships::new_with_git(db, &function_names, git_sha).await?;

    Ok(build_callchain_recursive_sync(
        &function_map,
        &call_relationships,
        func_name,
        max_depth,
        false,
        &mut HashSet::new(),
    ))
}

fn build_callchain_recursive_sync(
    function_map: &HashMap<String, Vec<FunctionInfo>>,
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

    if let Some(func) = function_map.get(func_name).and_then(|f| f.first()) {
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
    function_map: &HashMap<String, Vec<FunctionInfo>>,
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
    }

    if paths.is_empty() {
        None
    } else {
        Some(paths)
    }
}

// Writer-based versions of callchain functions for both CLI and MCP usage

/// When the section a function is filed in gets walked.
///
/// A module's exit function runs when the module is removed, and its init
/// function runs when the module is inserted, which is boot only for a
/// built-in. Saying "at boot" for either is wrong for a loadable module.
fn when_it_runs(level: &str) -> &'static str {
    crate::TreeSitterAnalyzer::entry_point_macro(level)
        .map(|(_, when)| when)
        .unwrap_or("runs at boot")
}

pub async fn show_callers_to_writer(
    db: &DatabaseManager,
    name: &str,
    writer: &mut dyn Write,
    verbose: bool,
    git_sha: &str,
) -> Result<()> {
    let search_msg = format!("Finding all functions that call: {}", name.cyan());
    writeln!(writer, "{search_msg}")?;

    // Search for function - macros are now stored as functions
    let chosen_opt = db.find_function_git_aware_reporting(name, git_sha).await?;

    match chosen_opt {
        Some(chosen) => {
            // Callers are found by name, and a name can belong to several
            // functions. Listing them under one definition's heading says the
            // callers of the others belong to it.
            if let Some(note) = chosen.ambiguity_note() {
                writeln!(writer, "{} {}", "Ambiguous:".bold().yellow(), note)?;
            }
            let func = chosen.function;
            // Always use git-aware callers query
            let callers = db.get_function_callers_git_aware(name, git_sha).await?;
            let indirect = db.find_indirect_callers(name, git_sha).await?;
            // Nothing in the source calls an initcall: the pointer sits in a
            // section that do_initcalls() walks at boot. Saying only that
            // nothing calls it reads as dead code, which is the opposite of
            // the truth for an entry point.
            let boot_levels: Vec<String> = db
                .find_registrations_of_git_aware(name, git_sha)
                .await?
                .into_iter()
                .filter(|registration| {
                    crate::TreeSitterAnalyzer::is_initcall_macro(&registration.container_type)
                })
                .map(|registration| registration.container_type)
                .collect();

            if !boot_levels.is_empty() {
                let mut levels = boot_levels.clone();
                levels.sort();
                levels.dedup();
                for level in &levels {
                    writeln!(
                        writer,
                        "{} {}, filed as {}",
                        "Entry point:".bold().green(),
                        when_it_runs(level),
                        level.cyan()
                    )?;
                }
            }

            // A name handed to another call is reached through that call, not
            // by anyone naming it. `printk(fmt, ...)` hands `_printk` to
            // `printk_index_wrap`, so nothing in the tree calls `_printk` by
            // name and 5,729 functions reach it. Saying "no functions call it"
            // and stopping there ends a search that should continue at the
            // macro named here.
            let handed = db
                .find_argument_functions_of_git_aware(name, git_sha)
                .await?;
            if !handed.is_empty() {
                let mut sites: Vec<String> = handed
                    .iter()
                    .map(|argument| {
                        let inside = if argument.enclosing_function.is_empty() {
                            String::new()
                        } else {
                            format!(" in {}", argument.enclosing_function)
                        };
                        format!(
                            "{}() argument {} at {}:{}{}",
                            argument.callee,
                            argument.argument_index,
                            argument.file_path,
                            argument.line,
                            inside
                        )
                    })
                    .collect();
                sites.sort();
                sites.dedup();
                writeln!(
                    writer,
                    "{} it is handed to {} as an argument, so a caller of that reaches it:",
                    "Handed over:".bold().green(),
                    if sites.len() == 1 {
                        "another call".to_string()
                    } else {
                        format!("{} calls", sites.len())
                    }
                )?;
                for site in sites.iter().take(10) {
                    writeln!(writer, "  {}", site.bright_black())?;
                }
                if sites.len() > 10 {
                    writeln!(writer, "  ... and {} more", sites.len() - 10)?;
                }
            }

            if callers.is_empty() && indirect.is_empty() {
                if !boot_levels.is_empty() {
                } else if !handed.is_empty() {
                    writeln!(
                        writer,
                        "{} nothing calls '{}' by name; follow the handover above",
                        "Info:".yellow(),
                        name
                    )?;
                } else {
                    let info_msg = format!("{} No functions call '{}'", "Info:".yellow(), name);
                    writeln!(writer, "{info_msg}")?;
                }
                if !boot_levels.is_empty() {
                    writeln!(
                        writer,
                        "{} nothing in the source calls it",
                        "Info:".yellow()
                    )?;
                }
            } else if !callers.is_empty() {
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
                        // Get more info about the caller
                        if let Ok(Some(caller_func)) =
                            db.find_function_git_aware(caller, git_sha).await
                        {
                            let info = format!(
                                "     {} ({}:{}) [file SHA: {}]",
                                caller_func.return_type.bright_black(),
                                caller_func.file_path.bright_black(),
                                caller_func.line_start,
                                caller_func.git_file_hash.bright_black()
                            );
                            writeln!(writer, "{info}")?;
                        }
                    }
                }
            }

            show_indirect_callers(&indirect, writer)?;
        }
        None => {
            let error_msg = format!(
                "{} No function '{}' found in database",
                "Error:".red(),
                name
            );
            writeln!(writer, "{error_msg}")?;
        }
    }

    Ok(())
}

/// Callers that reach the function without naming it, with the evidence for
/// each: a reader has to be able to check the claim, since a member call can
/// reach anything installed in that member.
fn show_indirect_callers(
    indirect: &[crate::database::resolution::IndirectCaller],
    writer: &mut dyn Write,
) -> Result<()> {
    use crate::database::resolution::Evidence;

    if indirect.is_empty() {
        return Ok(());
    }

    // A member-name match with no receiver type reaches every call through a
    // member of that name anywhere in the tree, which for a name like
    // `handler` is most of the kernel. Those are reported as a count, not as
    // an answer.
    let (confident, by_name_only): (Vec<_>, Vec<_>) = indirect
        .iter()
        .partition(|caller| caller.evidence.is_type_matched());

    if confident.is_empty() && by_name_only.is_empty() {
        return Ok(());
    }

    // The header goes up whenever anything indirect was found, including the
    // case where all of it is member-name evidence: a bare `Note:` hanging
    // off the direct callers reads as a footnote to them, and "further" says
    // there was a list above when there was not.
    let header = format!("\n{}", "=== Indirect Callers ===".bold().green());
    writeln!(writer, "{header}")?;
    if !confident.is_empty() {
        writeln!(
            writer,
            "{} call sites can reach it through a function pointer:",
            confident.len()
        )?;
    }

    for (i, caller) in confident.iter().enumerate() {
        let where_from = if caller.caller_name.is_empty() {
            "(file scope)".to_string()
        } else {
            caller.caller_name.clone()
        };

        writeln!(
            writer,
            "  {}. {} at {}:{} [{}]",
            (i + 1).to_string().yellow(),
            where_from.cyan(),
            caller.site_file.bright_black(),
            caller.site_line,
            caller.site_kind.bright_black()
        )?;

        match &caller.evidence {
            Evidence::StatedAtSite => {
                writeln!(writer, "     names it at the call site")?;
            }
            Evidence::Registered {
                container_type,
                registration_file,
                registration_line,
                registration_count,
                type_matched,
            } => {
                let confidence = if *type_matched {
                    "receiver type matches"
                } else {
                    "member name matches, receiver type unknown"
                };
                let elsewhere = match registration_count {
                    1 => String::new(),
                    n => format!(" and {} other places", n - 1),
                };
                writeln!(
                    writer,
                    "     installed in {}::{} at {}:{}{} ({})",
                    container_type.cyan(),
                    caller.member.cyan(),
                    registration_file.bright_black(),
                    registration_line,
                    elsewhere.bright_black(),
                    confidence.bright_black()
                )?;
            }
        }
    }

    if !by_name_only.is_empty() {
        let further = if confident.is_empty() { "" } else { "further " };
        let note = format!(
            "\n{} {} {}call sites go through a member of the same name, \
             but nothing says their receiver has the type the function was \
             installed in.",
            "Note:".yellow(),
            by_name_only.len(),
            further
        );
        writeln!(writer, "{note}")?;
    }

    Ok(())
}

/// Functions installed in one member of one type: the other side of the
/// question `callers` answers.
pub async fn show_implementors_to_writer(
    db: &DatabaseManager,
    container_type: &str,
    member: &str,
    writer: &mut dyn Write,
    git_sha: &str,
) -> Result<()> {
    writeln!(
        writer,
        "Finding functions installed in {}::{}",
        container_type.cyan(),
        member.cyan()
    )?;

    let found = db
        .find_registrations_for_slot_git_aware(container_type, member, git_sha)
        .await?;

    if found.is_empty() {
        writeln!(
            writer,
            "{} Nothing is installed in {}::{}",
            "Info:".yellow(),
            container_type,
            member
        )?;
        return Ok(());
    }

    let header = format!("\n{}", "=== Implementors ===".bold().green());
    writeln!(writer, "{header}")?;
    writeln!(writer, "{} installed:", found.len())?;

    for (i, registration) in found.iter().enumerate() {
        let where_from = if registration.enclosing_function.is_empty() {
            String::new()
        } else {
            format!(" in {}", registration.enclosing_function)
        };
        writeln!(
            writer,
            "  {}. {} at {}:{}{} [{}]",
            (i + 1).to_string().yellow(),
            registration.target.cyan(),
            registration.file_path.bright_black(),
            registration.line,
            where_from.bright_black(),
            registration.kind.as_str().bright_black()
        )?;
    }

    Ok(())
}

/// Where a function is installed, which is how it can be reached without
/// being named.
pub async fn show_registrations_to_writer(
    db: &DatabaseManager,
    name: &str,
    writer: &mut dyn Write,
    git_sha: &str,
) -> Result<()> {
    writeln!(writer, "Finding where {} is installed", name.cyan())?;

    let found = db.find_registrations_of_git_aware(name, git_sha).await?;
    let handed = db
        .find_argument_functions_of_git_aware(name, git_sha)
        .await?;

    if found.is_empty() && handed.is_empty() {
        writeln!(
            writer,
            "{} {} is not installed in any struct member, and no call is \
             handed it",
            "Info:".yellow(),
            name
        )?;
        return Ok(());
    }

    if !found.is_empty() {
        let header = format!("\n{}", "=== Registrations ===".bold().green());
        writeln!(writer, "{header}")?;
        writeln!(writer, "{} places install it:", found.len())?;
    }

    for (i, registration) in found.iter().enumerate() {
        let where_from = if registration.enclosing_function.is_empty() {
            String::new()
        } else {
            format!(" in {}", registration.enclosing_function)
        };
        writeln!(
            writer,
            "  {}. {}::{} at {}:{}{} [{}]",
            (i + 1).to_string().yellow(),
            registration.container_type.cyan(),
            registration.member.cyan(),
            registration.file_path.bright_black(),
            registration.line,
            where_from.bright_black(),
            registration.kind.as_str().bright_black()
        )?;
    }

    if !handed.is_empty() {
        let header = format!("\n{}", "=== Handed to ===".bold().green());
        writeln!(writer, "{header}")?;
        writeln!(
            writer,
            "{} calls are handed it as an argument:",
            handed.len()
        )?;
        for (i, argument) in handed.iter().enumerate() {
            let where_from = if argument.enclosing_function.is_empty() {
                String::new()
            } else {
                format!(" in {}", argument.enclosing_function)
            };
            writeln!(
                writer,
                "  {}. {}() argument {} at {}:{}{}",
                (i + 1).to_string().yellow(),
                argument.callee.cyan(),
                argument.argument_index,
                argument.file_path.bright_black(),
                argument.line,
                where_from.bright_black(),
            )?;

            // Where that call puts it, and by what route: the slot is a
            // claim about the registrar, not about this call site.
            let handovers = db
                .follow_handed_parameter(&argument.callee, argument.argument_index, git_sha)
                .await?;

            // The object is only the one this function was attached to if it
            // holds the thing the callee stored into. `call_rcu(&inode->i_rcu,
            // cb)` passes an rcu_head and the callback lands in
            // rcu_head::func, so the inode is the subject. `request_irq(...,
            // handler, ..., netdev->name, ...)` also passes a member, and the
            // handler has nothing to do with it.
            if let (Some(subject_type), Some(subject_member)) =
                (&argument.subject_type, &argument.subject_member)
            {
                for (handover, _) in &handovers {
                    let Handover::StoredIn { container_type, .. } = handover else {
                        continue;
                    };
                    let holds = db
                        .member_aggregate_git_aware(subject_type, subject_member, git_sha)
                        .await?;
                    if holds.as_deref() == Some(container_type.as_str()) {
                        writeln!(
                            writer,
                            "     attached to {}::{}",
                            subject_type.cyan(),
                            subject_member.cyan(),
                        )?;
                        break;
                    }
                }
            }

            // Definitions that disagree about where the parameter goes are two
            // claims about two configurations, and reporting one of them reads
            // as the tree having one answer.
            if handovers.len() > 1 {
                writeln!(
                    writer,
                    "     {} the definitions of {} disagree about where it goes:",
                    "Ambiguous:".bold().yellow(),
                    argument.callee.cyan(),
                )?;
            }
            for (handover, agreeing) in &handovers {
                let agreement = match agreeing {
                    0 | 1 => String::new(),
                    count => format!(" ({count} definitions agree)"),
                };
                match handover {
                    Handover::StoredIn {
                        path,
                        container_type,
                        member,
                    } => writeln!(
                        writer,
                        "     installs it in {}::{}, {} through {}{}",
                        container_type.cyan(),
                        member.cyan(),
                        "called later".yellow(),
                        path.join(" -> ").bright_black(),
                        agreement.bright_black(),
                    )?,
                    Handover::Invoked { path } => writeln!(
                        writer,
                        "     calls it {} through {}{}",
                        "before returning".yellow(),
                        path.join(" -> ").bright_black(),
                        agreement.bright_black(),
                    )?,
                }
            }
        }
    }

    Ok(())
}

pub async fn show_implementors(
    db: &DatabaseManager,
    container_type: &str,
    member: &str,
    git_sha: &str,
) -> Result<()> {
    show_implementors_to_writer(db, container_type, member, &mut stdout(), git_sha).await
}

pub async fn show_registrations(db: &DatabaseManager, name: &str, git_sha: &str) -> Result<()> {
    show_registrations_to_writer(db, name, &mut stdout(), git_sha).await
}

/// Where to look, as one line: role and place, in the order stored.
fn describe_locations(locations: &[crate::types::EdgeLocation]) -> String {
    locations
        .iter()
        .map(|location| format!("{} {}:{}", location.role, location.file_path, location.line))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The callees of each definition of a name, kept apart.
///
/// The workdir overlay is not consulted here: it answers for one file, and this
/// reports every file that defines the name.
fn write_callees_per_definition(
    name: &str,
    total: usize,
    answering: &[crate::types::CalleeDefinition],
    writer: &mut dyn Write,
) -> Result<()> {
    writeln!(
        writer,
        "\n{} defines '{}' {} times, {} of them definitions. Which one a call\n\
         reaches depends on the file it is written in and on the configuration\n\
         it is built with, so each is reported separately:",
        "This revision".bold(),
        name.cyan(),
        total,
        answering.len()
    )?;
    for definition in answering {
        writeln!(
            writer,
            "\n  {}:{}",
            definition.file_path.bright_black(),
            definition.line_start
        )?;
        if definition.callees.is_empty() {
            writeln!(writer, "    calls nothing")?;
            continue;
        }
        for (i, callee) in definition.callees.iter().enumerate() {
            writeln!(
                writer,
                "    {}. {}",
                (i + 1).to_string().yellow(),
                callee.cyan()
            )?;
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

    // Search for function - macros are now stored as functions
    // The silent resolver is what this wants: where the name has more than one
    // definition the answer below is every definition and this returns before
    // reaching anything that names a single file, so nothing here picks one on
    // a reader's behalf. Moving that early return above this line would change
    // that.
    let func_opt = db.find_function_git_aware(name, git_sha).await?;

    match func_opt {
        Some(func) => {
            // An edge the index cannot record is still an edge. Printing the
            // callees it does have and stopping there says the rest is not
            // there; naming the mechanism and where to look says it is
            // somewhere else.
            let unresolved = db.find_unresolved_edges_git_aware(name, git_sha).await?;
            for edge in unresolved.iter().filter(|e| e.direction == "out") {
                writeln!(
                    writer,
                    "{} a call here goes to {}, which this file does not name: {}",
                    "Unresolved:".bold().green(),
                    edge.evidence.cyan(),
                    describe_locations(&edge.locations).bright_black()
                )?;
            }

            // Every definition, not the one a heuristic prefers: a name with
            // more than one definition has more than one answer, and picking
            // silently reports a caller nobody asked about.
            let definitions = db
                .get_function_callees_by_definition_git_aware(name, git_sha)
                .await?;
            // A prototype answers nothing about what a name calls, and nearly
            // every exported function has one. A definition that calls nothing
            // is a different matter: it is a second answer, and reporting only
            // the other one hides that the tree disagrees with itself.
            let answering: Vec<crate::types::CalleeDefinition> = definitions
                .iter()
                .filter(|definition| definition.is_definition)
                .cloned()
                .collect();
            if answering.len() > 1 {
                write_callees_per_definition(name, definitions.len(), &answering, writer)?;
                return Ok(());
            }
            if definitions.len() > answering.len() {
                writeln!(
                    writer,
                    "{} {} of the {} rows for '{}' declare it without defining it.",
                    "Note:".yellow(),
                    definitions.len() - answering.len(),
                    definitions.len(),
                    name
                )?;
            }
            let callees = answering
                .into_iter()
                .next()
                .map(|definition| definition.callees)
                .unwrap_or_default();
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
                        // Get more info about the callee
                        if let Ok(Some(callee_func)) =
                            db.find_function_git_aware(callee, git_sha).await
                        {
                            let info = format!(
                                "     {} ({}:{}) [file SHA: {}]",
                                callee_func.return_type.bright_black(),
                                callee_func.file_path.bright_black(),
                                callee_func.line_start,
                                callee_func.git_file_hash.bright_black()
                            );
                            writeln!(writer, "{info}")?;
                        }
                    }
                }
            }
        }
        None => {
            let error_msg = format!(
                "{} No function '{}' found in database",
                "Error:".red(),
                name
            );
            writeln!(writer, "{error_msg}")?;
        }
    }

    Ok(())
}

/// The sites that reach a function through a pointer, and the chain above each.
///
/// A function only ever called through a pointer has no direct callers, so a
/// reverse chain built from calls alone renders it as a root: `callers
/// super_cache_scan` named three sites while `callchain super_cache_scan`
/// reported none, from the same index. The dispatching function is where the
/// chain continues upward, and is walked like any other caller.
///
/// A site outside any function — a store into a table at file scope — has
/// nothing above it and is named without a chain.
///
/// Returns the number of dispatching sites shown.
/// One caller above a dispatching site, and the callers above it.
///
/// Kept separate from the tree printer used for a direct chain, which marks an
/// unexpanded node with `(...)`. Here every entry is one already, and a column
/// of them says nothing.
fn write_caller_above(
    node: &CallNode,
    indent: usize,
    remaining: usize,
    writer: &mut dyn Write,
) -> Result<()> {
    let pad = "  ".repeat(indent);
    if node.file.is_empty() {
        writeln!(writer, "{}└─ {}", pad, node.name.yellow())?;
    } else {
        writeln!(
            writer,
            "{}└─ {} ({}:{})",
            pad,
            node.name.yellow(),
            node.file.bright_black(),
            node.line
        )?;
    }

    if remaining > 1 {
        for child in &node.children {
            write_caller_above(child, indent + 1, remaining - 1, writer)?;
        }
    }

    Ok(())
}

pub async fn write_indirect_reverse_chain(
    db: &DatabaseManager,
    name: &str,
    git_sha: &str,
    depth: usize,
    limit: usize,
    writer: &mut dyn Write,
) -> Result<usize> {
    let indirect = db.find_indirect_callers(name, git_sha).await?;
    if indirect.is_empty() {
        return Ok(0);
    }

    // One entry per dispatching function: a function dispatching through the
    // same member twice is one way in, not two.
    let mut order: Vec<String> = Vec::new();
    let mut sites: HashMap<String, Vec<&crate::database::resolution::IndirectCaller>> =
        HashMap::new();
    for caller in &indirect {
        let key = if caller.caller_name.is_empty() {
            format!("{}:{}", caller.site_file, caller.site_line)
        } else {
            caller.caller_name.clone()
        };
        if !sites.contains_key(&key) {
            order.push(key.clone());
        }
        sites.entry(key).or_default().push(caller);
    }

    writeln!(
        writer,
        "\n{}",
        "=== Reverse Chain (Through a Function Pointer) ==="
            .bold()
            .magenta()
    )?;

    let shown = order.len().min(limit.max(1));
    for key in order.iter().take(shown) {
        let group = &sites[key];
        let first = group[0];
        let more = if group.len() > 1 {
            format!(" ({} sites)", group.len())
        } else {
            String::new()
        };

        if first.caller_name.is_empty() {
            writeln!(
                writer,
                "{} at {}:{} dispatches {}{}",
                "STORE".yellow(),
                first.site_file.bright_black(),
                first.site_line,
                first.member,
                more
            )?;
            continue;
        }

        writeln!(
            writer,
            "{} ({}:{}) dispatches {}{}",
            first.caller_name.yellow(),
            first.site_file.bright_black(),
            first.site_line,
            first.member,
            more
        )?;

        // A chain above the site can only be walked by name, so the name must
        // belong to the code the site is in. bcache writes its sysfs stores
        // with a STORE() macro and lib/raid has another, so walking `STORE`
        // answers with the callers of every macro sharing the name — the
        // altivec xor routines, under a shrinker callback.
        //
        // One definition, in the file the site is in, or no chain.
        let definitions = db
            .find_all_functions_git_aware(&first.caller_name, git_sha)
            .await?;
        let names_the_site = definitions.len() == 1
            && definitions
                .first()
                .is_some_and(|f| f.file_path == first.site_file);

        if depth > 0 && names_the_site {
            // One level deeper than is printed, so the printed nodes carry the
            // file and line the deeper walk resolves for them.
            let above =
                build_reverse_callchain_with_git(db, &first.caller_name, depth + 1, Some(git_sha))
                    .await?;
            for child in &above.children {
                write_caller_above(child, 1, depth, writer)?;
            }
        }
    }

    if order.len() > shown {
        writeln!(
            writer,
            "{}",
            format!("... and {} more dispatching sites", order.len() - shown).bright_black()
        )?;
    }

    Ok(shown)
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
    let chosen_opt = db.find_function_git_aware_reporting(name, git_sha).await?;

    match chosen_opt {
        Some(chosen) => {
            // A chain is read as one path, so it starts at one definition. It
            // said which file that was and not that there had been a choice,
            // which reads as the tree having one.
            if let Some(note) = chosen.ambiguity_note() {
                writeln!(writer, "{} {}", "Ambiguous:".bold().yellow(), note)?;
            }
            let func = chosen.function;
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

            let dispatched = write_indirect_reverse_chain(db, name, git_sha, 2, 10, writer).await?;

            // Show forward callchain (callees)
            if !callees.is_empty() {
                let callees_header =
                    format!("\n{}", "=== Forward Chain (Callees) ===".bold().blue());
                writeln!(writer, "{callees_header}")?;

                let forward_chain =
                    build_forward_callchain_with_git(db, name, 3, Some(git_sha)).await?;
                print_callchain_tree_to_writer(&forward_chain, 0, writer)?;
            }

            if callers.is_empty() && callees.is_empty() && dispatched == 0 {
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

#[cfg(test)]
mod tests {
    use super::show_indirect_callers;
    use crate::database::resolution::{Evidence, IndirectCaller};

    fn caller(name: &str, type_matched: bool) -> IndirectCaller {
        IndirectCaller {
            caller_name: name.to_string(),
            site_file: "fs/read_write.c".to_string(),
            site_line: 572,
            site_byte_start: 100,
            member: "read".to_string(),
            site_kind: "member_arrow".to_string(),
            evidence: Evidence::Registered {
                container_type: "file_operations".to_string(),
                registration_file: "fs/proc/inode.c".to_string(),
                registration_line: 556,
                registration_count: 1,
                type_matched,
            },
        }
    }

    fn rendered(callers: &[IndirectCaller]) -> String {
        let mut out = Vec::new();
        show_indirect_callers(callers, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn the_count_alone_still_gets_a_heading() {
        // Without one the note hangs off the direct callers above it and
        // reads as a footnote to them.
        let text = rendered(&[caller("vfs_read", false)]);

        assert!(text.contains("Indirect Callers"), "{text}");
        assert!(text.contains("1 call sites"), "{text}");
        assert!(
            !text.contains("further"),
            "nothing was listed above the note: {text}"
        );
    }

    #[test]
    fn a_note_after_answers_says_further() {
        let text = rendered(&[caller("vfs_read", true), caller("loop_rw_iter", false)]);

        assert!(text.contains("1 call sites can reach it"), "{text}");
        assert!(text.contains("1 further call sites"), "{text}");
    }
}
