// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{CodeVectorizer, DatabaseManager};
use anstream::stdout;
use anyhow::Result;
use owo_colors::OwoColorize as _;
use std::fs::File;
use std::io::Write;

use crate::display::{
    display_function_to_writer_with_options, display_macro_to_writer, display_type_to_writer,
    display_typedef_to_writer,
};

/// Get functions called by the given function name (or macro name) - git-aware version
async fn get_function_calls_git_aware(
    db: &DatabaseManager,
    function_name: &str,
    git_sha: &str,
) -> Result<Vec<String>> {
    // First try to get callees from functions table using git-aware method
    match db
        .get_function_callees_git_aware(function_name, git_sha)
        .await
    {
        Ok(callees) if !callees.is_empty() => Ok(callees),
        _ => {
            // If no function found or no callees, try to find a macro using git-aware method
            match db.find_macro_git_aware(function_name, git_sha).await {
                Ok(Some(macro_info)) => {
                    // Get calls directly from macro's calls field
                    Ok(macro_info.calls.unwrap_or_default())
                }
                _ => Ok(vec![]), // No function or macro found
            }
        }
    }
}

/// Get functions that call the given function name
async fn get_function_callers(db: &DatabaseManager, function_name: &str) -> Result<Vec<String>> {
    db.get_function_callers(function_name).await
}

/// Display call relationships for a function with truncation control
fn display_call_relationships_with_truncation(
    _function_name: &str,
    calls: &[String],
    called_by: &[String],
    writer: &mut dyn Write,
    truncate: bool,
    verbose: bool,
) -> Result<()> {
    display_call_relationships_with_options(
        _function_name,
        calls,
        called_by,
        writer,
        truncate,
        verbose,
        true,
        true,
    )
}

/// Display call relationships for a function with full control over what to show
fn display_call_relationships_with_options(
    _function_name: &str,
    calls: &[String],
    called_by: &[String],
    writer: &mut dyn Write,
    truncate: bool,
    verbose: bool,
    show_calls: bool,
    show_callers: bool,
) -> Result<()> {
    const TRUNCATE_LIMIT: usize = 25;

    if show_calls && !calls.is_empty() {
        writeln!(writer, "\nCalls: {}", calls.len())?;

        let should_truncate = truncate && !verbose && calls.len() > TRUNCATE_LIMIT;
        let display_calls = if should_truncate {
            &calls[..TRUNCATE_LIMIT]
        } else {
            calls
        };

        for call in display_calls.iter() {
            writeln!(writer, "  → {}", call.cyan())?;
        }

        if should_truncate {
            writeln!(
                writer,
                "  {} ... ({} more calls, use -v to show all)",
                "...".bright_black(),
                calls.len() - TRUNCATE_LIMIT
            )?;
        }
    }

    if show_callers && !called_by.is_empty() {
        writeln!(writer, "\nCalled By: {}", called_by.len())?;

        let should_truncate = truncate && !verbose && called_by.len() > TRUNCATE_LIMIT;
        let display_callers = if should_truncate {
            &called_by[..TRUNCATE_LIMIT]
        } else {
            called_by
        };

        for caller in display_callers.iter() {
            writeln!(writer, "  ← {}", caller.cyan())?;
        }

        if should_truncate {
            writeln!(
                writer,
                "  {} ... ({} more callers, use -v to show all)",
                "...".bright_black(),
                called_by.len() - TRUNCATE_LIMIT
            )?;
        }
    }

    Ok(())
}

pub async fn query_function_or_macro(
    db: &DatabaseManager,
    name: &str,
    git_sha: &str,
) -> Result<()> {
    query_function_or_macro_to_writer(db, name, git_sha, &mut stdout()).await
}

pub async fn query_function_or_macro_verbose(
    db: &DatabaseManager,
    name: &str,
    git_sha: &str,
    verbose: bool,
) -> Result<()> {
    query_function_or_macro_to_writer_verbose(db, name, git_sha, &mut stdout(), verbose).await
}

pub async fn query_type_or_typedef(db: &DatabaseManager, name: &str, git_sha: &str) -> Result<()> {
    query_type_or_typedef_to_writer(db, name, git_sha, &mut stdout()).await
}

pub async fn query_similar(
    db: &DatabaseManager,
    vectorizer: &CodeVectorizer,
    code: &str,
) -> Result<()> {
    println!("Searching for functions similar to: {}", code.cyan());
    println!("Generating vector...");

    // Generate vector for the query code
    let query_vector = match vectorizer.vectorize_code(code) {
        Ok(vec) => vec,
        Err(e) => {
            println!("{} Failed to generate vector: {}", "Error:".red(), e);
            return Ok(());
        }
    };

    // Search for similar functions
    match db.search_similar_functions(&query_vector, 10, None).await? {
        functions if functions.is_empty() => {
            println!("{} No similar functions found", "Error:".red());
        }
        functions => {
            println!("\n{}", "=== Similar Functions ===".bold().green());
            for (i, func) in functions.iter().enumerate() {
                println!(
                    "\n{}. {} in {}",
                    (i + 1).to_string().yellow(),
                    func.name.bold(),
                    func.file_path.cyan()
                );
                println!("   Lines: {}-{}", func.line_start, func.line_end);

                // Show preview of the function
                let preview: String = func.body.lines().take(3).collect::<Vec<_>>().join("\n   ");

                if !preview.is_empty() {
                    println!("   {}", preview.bright_black());
                    if func.body.lines().count() > 3 {
                        println!("   ...");
                    }
                }
            }
        }
    }

    Ok(())
}

pub async fn query_similar_by_name(
    db: &DatabaseManager,
    vectorizer: &CodeVectorizer,
    name: &str,
) -> Result<()> {
    println!("Searching for functions similar to name: {}", name.cyan());
    println!("Generating vector...");

    match db.search_similar_by_name(vectorizer, name, 10).await? {
        functions if functions.is_empty() => {
            println!("{} No similar functions found", "Error:".red());
        }
        functions => {
            println!("\n{}", "=== Similar Functions ===".bold().green());
            for (i, func) in functions.iter().enumerate() {
                println!(
                    "\n{}. {} in {}",
                    (i + 1).to_string().yellow(),
                    func.name.bold(),
                    func.file_path.cyan()
                );
                println!("   Lines: {}-{}", func.line_start, func.line_end);
                println!("   Return: {}", func.return_type.magenta());
            }
        }
    }

    Ok(())
}

pub async fn list_functions_and_macros(
    db: &DatabaseManager,
    pattern: &str,
    git_sha: &str,
) -> Result<()> {
    list_functions_and_macros_to_writer(db, pattern, git_sha, &mut stdout()).await
}

pub async fn list_types_and_typedefs(
    db: &DatabaseManager,
    pattern: &str,
    git_sha: &str,
) -> Result<()> {
    list_types_and_typedefs_to_writer(db, pattern, git_sha, &mut stdout()).await
}

pub async fn show_tables(db: &DatabaseManager) -> Result<()> {
    show_tables_to_writer(db, &mut stdout()).await
}

pub async fn dump_functions(db: &DatabaseManager, output_file: &str) -> Result<()> {
    println!("Dumping all functions to {}...", output_file.cyan());

    let functions = db.get_all_functions_metadata_only().await?;
    let json = serde_json::to_string_pretty(&functions)?;

    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    println!(
        "{} Dumped {} functions to {}",
        "Success:".green(),
        functions.len(),
        output_file.cyan()
    );

    Ok(())
}

pub async fn dump_types(db: &DatabaseManager, output_file: &str) -> Result<()> {
    println!("Dumping all types to {}...", output_file.cyan());

    let types = db.get_all_types_metadata_only().await?;
    let json = serde_json::to_string_pretty(&types)?;

    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    println!(
        "{} Dumped {} types to {}",
        "Success:".green(),
        types.len(),
        output_file.cyan()
    );

    Ok(())
}

pub async fn dump_typedefs(db: &DatabaseManager, output_file: &str) -> Result<()> {
    println!("Dumping all typedefs to {}...", output_file.cyan());

    let typedefs = db.get_all_typedefs().await?;
    let json = serde_json::to_string_pretty(&typedefs)?;

    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    println!(
        "{} Dumped {} typedefs to {}",
        "Success:".green(),
        typedefs.len(),
        output_file.cyan()
    );

    Ok(())
}

pub async fn dump_macros(db: &DatabaseManager, output_file: &str) -> Result<()> {
    println!("Dumping all macros to {}...", output_file.cyan());

    let macros = db.get_all_macros_metadata_only().await?;
    let json = serde_json::to_string_pretty(&macros)?;

    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    println!(
        "{} Dumped {} macros to {}",
        "Success:".green(),
        macros.len(),
        output_file.cyan()
    );

    Ok(())
}

pub async fn dump_calls(db: &DatabaseManager, output_file: &str) -> Result<()> {
    println!(
        "Dumping all call relationships to {}...",
        output_file.cyan()
    );

    let calls = db.get_all_call_relationships().await?;

    // Convert to JSON-serializable format with hex strings
    #[derive(serde::Serialize)]
    struct CallRelationshipJson {
        caller: String,
        callee: String,
        caller_git_file_hash: String, // Converted from Vec<u8> to hex string
        callee_git_file_hash: Option<String>, // Converted from Option<Vec<u8>> to hex string
    }

    let json_calls: Vec<CallRelationshipJson> = calls
        .into_iter()
        .map(|call| CallRelationshipJson {
            caller: call.caller,
            callee: call.callee,
            caller_git_file_hash: hex::encode(&call.caller_git_file_hash),
            callee_git_file_hash: call.callee_git_file_hash.map(|hash| hex::encode(&hash)),
        })
        .collect();

    let json = serde_json::to_string_pretty(&json_calls)?;

    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    println!(
        "{} Dumped {} call relationships to {}",
        "Success:".green(),
        json_calls.len(),
        output_file.cyan()
    );

    Ok(())
}

pub async fn dump_processed_files(db: &DatabaseManager, output_file: &str) -> Result<()> {
    println!("Dumping all processed files to {}...", output_file.cyan());

    let processed_files = db.get_all_processed_files().await?;

    // Convert to JSON-serializable format with hex strings
    let json_records: Vec<crate::database::processed_files::ProcessedFileRecordJson> =
        processed_files
            .into_iter()
            .map(|record| record.into())
            .collect();

    let json = serde_json::to_string_pretty(&json_records)?;

    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    println!(
        "{} Dumped {} processed files to {}",
        "Success:".green(),
        json_records.len(),
        output_file.cyan()
    );

    Ok(())
}

pub async fn dump_content(db: &DatabaseManager, output_file: &str) -> Result<()> {
    println!("Dumping all content to {}...", output_file.cyan());

    let content_items = db.get_all_content().await?;

    // Convert to JSON-serializable format with hex strings
    let json_records: Vec<crate::database::content::ContentInfoJson> = content_items
        .into_iter()
        .map(|content| content.into())
        .collect();

    let json = serde_json::to_string_pretty(&json_records)?;

    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    println!(
        "{} Dumped {} content entries to {}",
        "Success:".green(),
        json_records.len(),
        output_file.cyan()
    );

    Ok(())
}

// Writer-based versions of search functions for both CLI and MCP usage

pub async fn query_function_or_macro_to_writer(
    db: &DatabaseManager,
    name: &str,
    git_sha: &str,
    writer: &mut dyn Write,
) -> Result<()> {
    query_function_or_macro_to_writer_with_options(db, name, git_sha, writer, false).await
}

pub async fn query_function_or_macro_to_writer_verbose(
    db: &DatabaseManager,
    name: &str,
    git_sha: &str,
    writer: &mut dyn Write,
    verbose: bool,
) -> Result<()> {
    query_function_or_macro_to_writer_with_options(db, name, git_sha, writer, verbose).await
}

/// Check if a function is actually a definition (has implementation) vs just a declaration
fn is_function_definition(func: &crate::FunctionInfo) -> bool {
    if func.body.is_empty() {
        return false; // Empty body is definitely a declaration
    }

    let body = func.body.trim();

    // If body ends with just a semicolon, it's a declaration
    if body.ends_with(';') && !body.contains('{') {
        return false;
    }

    // If it contains braces, it's likely a definition
    if body.contains('{') && body.contains('}') {
        return true;
    }

    // Header files typically contain declarations
    if func.file_path.ends_with(".h") || func.file_path.ends_with(".hpp") {
        // In header files, be more strict - require braces for definitions
        return body.contains('{') && body.contains('}');
    }

    // For .c/.cpp files, if it's not just a semicolon-terminated line, assume it's a definition
    !body.ends_with(';')
}

async fn query_function_or_macro_to_writer_with_options(
    db: &DatabaseManager,
    name: &str,
    git_sha: &str,
    writer: &mut dyn Write,
    verbose: bool,
) -> Result<()> {
    let search_msg = format!(
        "Searching for function or macro: {} (git SHA: {})",
        name.cyan(),
        git_sha.yellow()
    );
    writeln!(writer, "{search_msg}")?;

    // First try to find all functions at the specific git SHA (excluding declarations)
    let func_results = db.find_all_functions_git_aware(name, git_sha).await?;
    // Then try to find a macro at the specific git SHA
    let macro_result = db.find_macro_git_aware(name, git_sha).await?;

    match (func_results.is_empty(), macro_result) {
        (false, Some(macro_info)) => {
            // Found both functions and macro - display all
            // Filter out declarations and display only definitions
            let definitions: Vec<_> = func_results
                .iter()
                .filter(|func| is_function_definition(func))
                .collect();

            let note = format!(
                "\n{} Found {} function definition(s) and a macro with this name at git SHA {}!",
                "Note:".yellow(),
                definitions.len(),
                git_sha.yellow()
            );
            writeln!(writer, "{note}")?;

            for (i, func) in definitions.iter().enumerate() {
                if definitions.len() > 1 {
                    writeln!(
                        writer,
                        "\n{} Function {} of {}:",
                        "==>".bold().blue(),
                        i + 1,
                        definitions.len()
                    )?;
                }
                display_function_to_writer_with_options(func, writer, true)?;
                // Get and display calls (outgoing) for each function definition
                let calls = db
                    .get_function_callees_git_aware(&func.name, git_sha)
                    .await?;
                display_call_relationships_with_options(
                    &func.name,
                    &calls,
                    &[],
                    writer,
                    true,
                    verbose,
                    true,
                    false,
                )?;
            }

            // Display macro
            writeln!(writer, "\n{} Macro:", "==>".bold().blue())?;
            display_macro_to_writer(&macro_info, writer)?;
            // Get and display call relationships for the macro too (use macro's calls field directly)
            let macro_calls = macro_info.calls.clone().unwrap_or_default();
            display_call_relationships_with_options(
                &macro_info.name,
                &macro_calls,
                &[],
                writer,
                true,
                verbose,
                true,
                false,
            )?;

            // Display callers once at the end for all functions and macro with this name
            if definitions.is_empty() {
                writeln!(
                    writer,
                    "\n{} Found function declarations but no definitions for '{}' at git SHA {}",
                    "Info:".yellow(),
                    name,
                    git_sha.yellow()
                )?;
            }

            let called_by = db.get_function_callers_git_aware(name, git_sha).await?;
            if !called_by.is_empty() {
                if definitions.is_empty() {
                    writeln!(
                        writer,
                        "\n{} Callers to '{}' macro:",
                        "==>".bold().blue(),
                        name
                    )?;
                } else {
                    writeln!(
                        writer,
                        "\n{} Callers to all '{}' functions and macro:",
                        "==>".bold().blue(),
                        name
                    )?;
                }
                display_call_relationships_with_options(
                    name,
                    &[],
                    &called_by,
                    writer,
                    true,
                    verbose,
                    false,
                    true,
                )?;
            }
        }
        (false, None) => {
            // Found functions only - filter out declarations and display only definitions
            let definitions: Vec<_> = func_results
                .iter()
                .filter(|func| is_function_definition(func))
                .collect();

            if definitions.len() > 1 {
                writeln!(
                    writer,
                    "\n{} Found {} function definitions with name '{}' at git SHA {}:",
                    "Note:".yellow(),
                    definitions.len(),
                    name,
                    git_sha.yellow()
                )?;
            }

            // Display each function definition with its outgoing calls
            for (i, func) in definitions.iter().enumerate() {
                if definitions.len() > 1 {
                    writeln!(
                        writer,
                        "\n{} Function {} of {}:",
                        "==>".bold().blue(),
                        i + 1,
                        definitions.len()
                    )?;
                }
                display_function_to_writer_with_options(func, writer, true)?;
                // Get and display calls (outgoing) for each function definition
                let calls = db
                    .get_function_callees_git_aware(&func.name, git_sha)
                    .await?;
                display_call_relationships_with_options(
                    &func.name,
                    &calls,
                    &[],
                    writer,
                    true,
                    verbose,
                    true,
                    false,
                )?;
            }

            // If there are multiple definitions, display callers once at the end
            if definitions.len() > 1 {
                let called_by = db.get_function_callers_git_aware(name, git_sha).await?;
                if !called_by.is_empty() {
                    writeln!(
                        writer,
                        "\n{} Callers to all '{}' functions:",
                        "==>".bold().blue(),
                        name
                    )?;
                    display_call_relationships_with_options(
                        name,
                        &[],
                        &called_by,
                        writer,
                        true,
                        verbose,
                        false,
                        true,
                    )?;
                }
            } else if definitions.len() == 1 {
                // For single definition, show callers normally (maintain existing behavior)
                let called_by = db.get_function_callers_git_aware(name, git_sha).await?;
                display_call_relationships_with_options(
                    name,
                    &[],
                    &called_by,
                    writer,
                    true,
                    verbose,
                    false,
                    true,
                )?;
            } else {
                // No definitions found, only declarations
                writeln!(
                    writer,
                    "\n{} Found function declarations but no definitions for '{}' at git SHA {}",
                    "Info:".yellow(),
                    name,
                    git_sha.yellow()
                )?;
            }
        }
        (true, Some(macro_info)) => {
            // Found macro only
            display_macro_to_writer(&macro_info, writer)?;
            // Get and display call relationships for macros too (use macro's calls field directly)
            let calls = macro_info.calls.clone().unwrap_or_default();
            let called_by = db
                .get_function_callers_git_aware(&macro_info.name, git_sha)
                .await?;
            display_call_relationships_with_truncation(
                &macro_info.name,
                &calls,
                &called_by,
                writer,
                true,
                verbose,
            )?;
        }
        (true, None) => {
            // No exact match found, try regex search
            let regex_functions = db.search_functions_regex_git_aware(name, git_sha).await?;
            let regex_macros = db.search_macros_regex_git_aware(name, git_sha).await?;

            match (regex_functions.is_empty(), regex_macros.is_empty()) {
                (false, false) => {
                    // Found both functions and macros with regex
                    writeln!(writer, "\n{} No exact match found for '{}' at git SHA {}, but found matches using it as a regex pattern:", "Info:".yellow(), name, git_sha.yellow())?;

                    writeln!(
                        writer,
                        "\n{}",
                        "=== Functions (regex matches) ===".bold().green()
                    )?;
                    // Filter out declarations and show only definitions
                    let regex_definitions: Vec<_> = regex_functions
                        .iter()
                        .filter(|func| is_function_definition(func))
                        .collect();
                    for func in &regex_definitions {
                        display_function_to_writer_with_options(func, writer, true)?;
                        // Get and display calls (outgoing) for each function definition
                        let calls = get_function_calls_git_aware(db, &func.name, git_sha).await?;
                        display_call_relationships_with_options(
                            &func.name,
                            &calls,
                            &[],
                            writer,
                            true,
                            verbose,
                            true,
                            false,
                        )?;
                    }

                    writeln!(
                        writer,
                        "\n{}",
                        "=== Macros (regex matches) ===".bold().green()
                    )?;
                    for macro_info in &regex_macros {
                        display_macro_to_writer(macro_info, writer)?;
                        // Get and display only calls (outgoing) for macros too
                        let macro_calls =
                            get_function_calls_git_aware(db, &macro_info.name, git_sha).await?;
                        display_call_relationships_with_options(
                            &macro_info.name,
                            &macro_calls,
                            &[],
                            writer,
                            true,
                            verbose,
                            true,
                            false,
                        )?;
                    }

                    // Collect and display callers for all matched function definitions and macros
                    let mut all_callers = std::collections::HashSet::new();
                    for func in &regex_definitions {
                        let func_callers = get_function_callers(db, &func.name).await?;
                        all_callers.extend(func_callers);
                    }
                    for macro_info in &regex_macros {
                        let macro_callers = get_function_callers(db, &macro_info.name).await?;
                        all_callers.extend(macro_callers);
                    }
                    if !all_callers.is_empty() {
                        let callers: Vec<String> = all_callers.into_iter().collect();
                        writeln!(
                            writer,
                            "\n{} Callers to all matched functions and macros:",
                            "==>".bold().blue()
                        )?;
                        display_call_relationships_with_options(
                            "",
                            &[],
                            &callers,
                            writer,
                            true,
                            verbose,
                            false,
                            true,
                        )?;
                    }
                }
                (false, true) => {
                    // Found only functions with regex
                    writeln!(writer, "\n{} No exact match found for '{}' at git SHA {}, but found functions using it as a regex pattern:", "Info:".yellow(), name, git_sha.yellow())?;

                    // Filter out declarations and display only function definitions
                    let regex_definitions: Vec<_> = regex_functions
                        .iter()
                        .filter(|func| !func.body.is_empty())
                        .collect();

                    // Display each function definition with its outgoing calls
                    for func in &regex_definitions {
                        display_function_to_writer_with_options(func, writer, true)?;
                        // Get and display calls (outgoing) for each function definition
                        let calls = get_function_calls_git_aware(db, &func.name, git_sha).await?;
                        display_call_relationships_with_options(
                            &func.name,
                            &calls,
                            &[],
                            writer,
                            true,
                            verbose,
                            true,
                            false,
                        )?;
                    }

                    // For regex results with multiple function definitions, collect unique function names and show consolidated callers
                    if regex_definitions.len() > 1 {
                        let mut all_callers = std::collections::HashSet::new();
                        for func in &regex_definitions {
                            let func_callers = get_function_callers(db, &func.name).await?;
                            all_callers.extend(func_callers);
                        }
                        if !all_callers.is_empty() {
                            let callers: Vec<String> = all_callers.into_iter().collect();
                            writeln!(
                                writer,
                                "\n{} Callers to all matched functions:",
                                "==>".bold().blue()
                            )?;
                            display_call_relationships_with_options(
                                "",
                                &[],
                                &callers,
                                writer,
                                true,
                                verbose,
                                false,
                                true,
                            )?;
                        }
                    } else if regex_definitions.len() == 1 {
                        // For single function definition, show callers normally
                        let called_by =
                            get_function_callers(db, &regex_definitions[0].name).await?;
                        display_call_relationships_with_options(
                            &regex_definitions[0].name,
                            &[],
                            &called_by,
                            writer,
                            true,
                            verbose,
                            false,
                            true,
                        )?;
                    } else {
                        // No definitions found, only declarations
                        writeln!(writer, "\n{} Found function declarations but no definitions matching '{}' at git SHA {}",
                            "Info:".yellow(), name, git_sha.yellow())?;
                    }
                }
                (true, false) => {
                    // Found only macros with regex
                    writeln!(writer, "\n{} No exact match found for '{}' at git SHA {}, but found macros using it as a regex pattern:", "Info:".yellow(), name, git_sha.yellow())?;

                    // Display each macro with only its outgoing calls
                    for macro_info in &regex_macros {
                        display_macro_to_writer(macro_info, writer)?;
                        // Get and display only calls (outgoing) for macros too
                        let macro_calls =
                            get_function_calls_git_aware(db, &macro_info.name, git_sha).await?;
                        display_call_relationships_with_options(
                            &macro_info.name,
                            &macro_calls,
                            &[],
                            writer,
                            true,
                            verbose,
                            true,
                            false,
                        )?;
                    }

                    // For regex results with multiple macros, collect unique callers and show consolidated callers
                    if regex_macros.len() > 1 {
                        let mut all_callers = std::collections::HashSet::new();
                        for macro_info in &regex_macros {
                            let macro_callers = get_function_callers(db, &macro_info.name).await?;
                            all_callers.extend(macro_callers);
                        }
                        if !all_callers.is_empty() {
                            let callers: Vec<String> = all_callers.into_iter().collect();
                            writeln!(
                                writer,
                                "\n{} Callers to all matched macros:",
                                "==>".bold().blue()
                            )?;
                            display_call_relationships_with_options(
                                "",
                                &[],
                                &callers,
                                writer,
                                true,
                                verbose,
                                false,
                                true,
                            )?;
                        }
                    } else if regex_macros.len() == 1 {
                        // For single macro, show callers normally
                        let called_by = get_function_callers(db, &regex_macros[0].name).await?;
                        display_call_relationships_with_options(
                            &regex_macros[0].name,
                            &[],
                            &called_by,
                            writer,
                            true,
                            verbose,
                            false,
                            true,
                        )?;
                    }
                }
                (true, true) => {
                    // No regex matches either, show fuzzy suggestions
                    let error_msg = format!(
                        "{} No function or macro '{}' found at git SHA {}",
                        "Error:".red(),
                        name,
                        git_sha.yellow()
                    );
                    writeln!(writer, "{error_msg}")?;

                    // Try git-aware fuzzy search for suggestions
                    let func_suggestions =
                        db.search_functions_fuzzy_git_aware(name, git_sha).await?;
                    let macro_suggestions = db.search_macros_fuzzy_git_aware(name, git_sha).await?;

                    if !func_suggestions.is_empty() || !macro_suggestions.is_empty() {
                        writeln!(writer, "\nDid you mean:")?;
                        for func in func_suggestions.iter().take(3) {
                            writeln!(
                                writer,
                                "  - {} {} (function at git SHA {})",
                                "func --git".yellow(),
                                func.name,
                                git_sha.yellow()
                            )?;
                        }
                        for mac in macro_suggestions.iter().take(3) {
                            writeln!(
                                writer,
                                "  - {} {} (macro at git SHA {})",
                                "func --git".yellow(),
                                mac.name,
                                git_sha.yellow()
                            )?;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

pub async fn show_tables_to_writer(db: &DatabaseManager, writer: &mut dyn Write) -> Result<()> {
    // Get counts using efficient count methods (no table scans)
    let function_count = db.count_functions().await?;
    let macro_count = db.count_macros().await?;
    let type_count = db.count_types().await?;
    let typedef_count = db.count_typedefs().await?;

    writeln!(writer, "{}", "=== Database Tables ===".bold().green())?;

    writeln!(
        writer,
        "{}: {}",
        "Functions".bold(),
        function_count.to_string().cyan()
    )?;
    writeln!(
        writer,
        "{}: {}",
        "Macros".bold(),
        macro_count.to_string().cyan()
    )?;
    writeln!(
        writer,
        "{}: {}",
        "Types".bold(),
        type_count.to_string().cyan()
    )?;
    writeln!(
        writer,
        "{}: {}",
        "Typedefs".bold(),
        typedef_count.to_string().cyan()
    )?;

    let total = function_count + macro_count + type_count + typedef_count;
    writeln!(writer, "{}: {}", "Total".bold(), total.to_string().cyan())?;

    Ok(())
}

pub async fn query_type_or_typedef_to_writer(
    db: &DatabaseManager,
    name: &str,
    git_sha: &str,
    writer: &mut dyn Write,
) -> Result<()> {
    // Handle "struct", "union", "enum" prefixes
    let clean_name = name
        .trim_start_matches("struct ")
        .trim_start_matches("union ")
        .trim_start_matches("enum ");

    let search_msg = format!(
        "Searching for type or typedef: {} (git SHA: {})",
        clean_name.cyan(),
        git_sha.yellow()
    );
    writeln!(writer, "{search_msg}")?;

    // First try to find a type at the specific git SHA
    let type_result = db.find_type_git_aware(clean_name, git_sha).await?;
    // Then try to find a typedef at the specific git SHA
    let typedef_result = db.find_typedef_git_aware(clean_name, git_sha).await?;

    match (type_result, typedef_result) {
        (Some(type_info), Some(typedef_info)) => {
            // Found both - display both
            let note = format!(
                "\n{} Found both a type and a typedef with this name at git SHA {}!",
                "Note:".yellow(),
                git_sha.yellow()
            );
            writeln!(writer, "{note}")?;
            display_type_to_writer(&type_info, writer)?;
            display_typedef_to_writer(&typedef_info, writer)?;
        }
        (Some(type_info), None) => {
            display_type_to_writer(&type_info, writer)?;
        }
        (None, Some(typedef_info)) => {
            display_typedef_to_writer(&typedef_info, writer)?;
        }
        (None, None) => {
            // No exact match found, try regex search
            let regex_types = db.search_types_regex_git_aware(clean_name, git_sha).await?;
            let regex_typedefs = db
                .search_typedefs_regex_git_aware(clean_name, git_sha)
                .await?;

            match (regex_types.is_empty(), regex_typedefs.is_empty()) {
                (false, false) => {
                    // Found both types and typedefs with regex
                    writeln!(writer, "\n{} No exact match found for '{}' at git SHA {}, but found matches using it as a regex pattern:", "Info:".yellow(), clean_name, git_sha.yellow())?;

                    writeln!(
                        writer,
                        "\n{}",
                        "=== Types (regex matches) ===".bold().green()
                    )?;
                    for type_info in &regex_types {
                        display_type_to_writer(type_info, writer)?;
                    }

                    writeln!(
                        writer,
                        "\n{}",
                        "=== Typedefs (regex matches) ===".bold().green()
                    )?;
                    for typedef_info in &regex_typedefs {
                        display_typedef_to_writer(typedef_info, writer)?;
                    }
                }
                (false, true) => {
                    // Found only types with regex
                    writeln!(writer, "\n{} No exact match found for '{}' at git SHA {}, but found types using it as a regex pattern:", "Info:".yellow(), clean_name, git_sha.yellow())?;
                    for type_info in &regex_types {
                        display_type_to_writer(type_info, writer)?;
                    }
                }
                (true, false) => {
                    // Found only typedefs with regex
                    writeln!(writer, "\n{} No exact match found for '{}' at git SHA {}, but found typedefs using it as a regex pattern:", "Info:".yellow(), clean_name, git_sha.yellow())?;
                    for typedef_info in &regex_typedefs {
                        display_typedef_to_writer(typedef_info, writer)?;
                    }
                }
                (true, true) => {
                    // No regex matches either, show fuzzy suggestions
                    let error_msg = format!(
                        "{} No type or typedef '{}' found at git SHA {}",
                        "Error:".red(),
                        clean_name,
                        git_sha.yellow()
                    );
                    writeln!(writer, "{error_msg}")?;

                    // Try git-aware fuzzy search for suggestions
                    let type_suggestions =
                        db.search_types_fuzzy_git_aware(clean_name, git_sha).await?;
                    let typedef_suggestions = db
                        .search_typedefs_fuzzy_git_aware(clean_name, git_sha)
                        .await?;

                    if !type_suggestions.is_empty() || !typedef_suggestions.is_empty() {
                        writeln!(writer, "\nDid you mean:")?;
                        for typ in type_suggestions.iter().take(3) {
                            writeln!(
                                writer,
                                "  - {} {} {} (at git SHA {})",
                                "type --git".yellow(),
                                typ.kind,
                                typ.name,
                                git_sha.yellow()
                            )?;
                        }
                        for typedef in typedef_suggestions.iter().take(3) {
                            writeln!(
                                writer,
                                "  - {} {} (at git SHA {})",
                                "typedef --git".yellow(),
                                typedef.name,
                                git_sha.yellow()
                            )?;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

pub async fn list_functions_and_macros_to_writer(
    db: &DatabaseManager,
    pattern: &str,
    git_sha: &str,
    writer: &mut dyn Write,
) -> Result<()> {
    writeln!(
        writer,
        "Searching for functions and macros matching: {} (git SHA: {})",
        pattern.cyan(),
        git_sha.yellow()
    )?;

    let functions = db
        .search_functions_fuzzy_git_aware(pattern, git_sha)
        .await?;
    let macros = db.search_macros_fuzzy_git_aware(pattern, git_sha).await?;

    if !functions.is_empty() {
        writeln!(writer, "\n{}", "=== Functions ===".bold().green())?;

        for (i, func) in functions.iter().enumerate() {
            writeln!(
                writer,
                "  {}. {} ({}:{})",
                (i + 1).to_string().yellow(),
                func.name.cyan(),
                func.file_path.bright_black(),
                func.line_start
            )?;
        }
    }

    if !macros.is_empty() {
        writeln!(writer, "\n{}", "=== Macros ===".bold().green())?;

        for (i, mac) in macros.iter().enumerate() {
            writeln!(
                writer,
                "  {}. {} ({}:{})",
                (i + 1).to_string().yellow(),
                mac.name.cyan(),
                mac.file_path.bright_black(),
                mac.line_start
            )?;
        }
    }

    if functions.is_empty() && macros.is_empty() {
        writeln!(
            writer,
            "{} No matches found for pattern '{}' at git SHA {}",
            "Info:".yellow(),
            pattern,
            git_sha.yellow()
        )?;
    } else {
        writeln!(
            writer,
            "\n{} Found {} functions, {} macros at git SHA {}",
            "Summary:".bold().cyan(),
            functions.len(),
            macros.len(),
            git_sha.yellow()
        )?;
    }

    Ok(())
}

pub async fn list_types_and_typedefs_to_writer(
    db: &DatabaseManager,
    pattern: &str,
    git_sha: &str,
    writer: &mut dyn Write,
) -> Result<()> {
    writeln!(
        writer,
        "Searching for types and typedefs matching: {} (git SHA: {})",
        pattern.cyan(),
        git_sha.yellow()
    )?;

    let types = db.search_types_fuzzy_git_aware(pattern, git_sha).await?;
    let typedefs = db.search_typedefs_fuzzy_git_aware(pattern, git_sha).await?;

    if !types.is_empty() {
        writeln!(writer, "\n{}", "=== Types ===".bold().green())?;

        for (i, typ) in types.iter().enumerate() {
            writeln!(
                writer,
                "  {}. {} {} ({}:{})",
                (i + 1).to_string().yellow(),
                typ.kind.magenta(),
                typ.name.cyan(),
                typ.file_path.bright_black(),
                typ.line_start
            )?;
        }
    }

    if !typedefs.is_empty() {
        writeln!(writer, "\n{}", "=== Typedefs ===".bold().green())?;

        for (i, typedef) in typedefs.iter().enumerate() {
            writeln!(
                writer,
                "  {}. {} -> {} ({}:{})",
                (i + 1).to_string().yellow(),
                typedef.name.cyan(),
                typedef.underlying_type.magenta(),
                typedef.file_path.bright_black(),
                typedef.line_start
            )?;
        }
    }

    if types.is_empty() && typedefs.is_empty() {
        writeln!(
            writer,
            "{} No matches found for pattern '{}' at git SHA {}",
            "Info:".yellow(),
            pattern,
            git_sha.yellow()
        )?;
    } else {
        writeln!(
            writer,
            "\n{} Found {} types, {} typedefs at git SHA {}",
            "Summary:".bold().cyan(),
            types.len(),
            typedefs.len(),
            git_sha.yellow()
        )?;
    }

    Ok(())
}
