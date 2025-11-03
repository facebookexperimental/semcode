// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{FunctionInfo, TypeInfo, TypedefInfo};
use anstream::stdout;
use anyhow::Result;
use owo_colors::OwoColorize as _;
use std::io::Write;

fn print_command_help() {
    println!("\n{}", "Available Commands:".bold().cyan());

    // Query Commands
    println!(
        "  {} ({}, {}) <name> - Find a function or macro by name or regex",
        "func".yellow(),
        "function".yellow(),
        "f".yellow()
    );
    println!(
        "  {} ({}) <name>     - Find a type or typedef by name or regex",
        "type".yellow(),
        "ty".yellow()
    );

    // Call Graph Commands
    println!(
        "  {} <name>           - Show all functions that call <name>",
        "callers".yellow()
    );
    println!(
        "  {} <name>             - Show all functions called by <name>",
        "calls".yellow()
    );
    println!(
        "  {} <name>           - Show complete callchain for <name>",
        "callchain".yellow()
    );
    println!(
        "  {} [-v] <pattern>          - Search function bodies using regex patterns",
        "grep".yellow()
    );
    println!(
        "                                   -v: Show full function body (default shows only matching lines)"
    );
    println!(
        "  {} <query_text>           - Search functions similar to query text using vectors",
        "vgrep".yellow()
    );
    println!(
        "                                   Requires vectors generated with 'semcode-index --vectors'"
    );
    println!(
        "  {} <query_text>         - Search commits similar to query text using vectors",
        "vcommit".yellow()
    );
    println!(
        "                                   Supports --git <range>, -r <regex>, -s <symbol>, --limit <N>"
    );
    println!(
        "                                   Requires commit vectors generated with 'semcode-index --vectors'"
    );

    // Git Commit Commands
    println!();
    println!("{}", "Git Commit Commands:".bold().cyan());
    println!(
        "  {} [ref]                  - Show commit metadata for git reference",
        "commit".yellow()
    );
    println!(
        "                                   Supports -v (verbose), -r <regex>, -s <symbol>, --limit <N>"
    );
    println!(
        "                                   Use --git <range> for commit ranges (e.g., HEAD~10..HEAD)"
    );

    println!(
        "  {} ({}) [-i file]             - List functions from diff (no analysis)",
        "diffinfo".yellow(),
        "di".yellow()
    );

    println!(
        "  {} ({})             - List available tables",
        "tables".yellow(),
        "t".yellow()
    );

    println!();
    println!("{}", "Export Commands:".bold().cyan());
    println!(
        "  {} ({}) <file>      - Export all functions to JSON file",
        "dump-functions".yellow(),
        "df".yellow()
    );
    println!(
        "  {} ({}) <file>      - Export all types to JSON file",
        "dump-types".yellow(),
        "dt".yellow()
    );
    println!(
        "  {} ({}) <file>     - Export all typedefs to JSON file",
        "dump-typedefs".yellow(),
        "dtd".yellow()
    );
    println!(
        "  {} ({}) <file>      - Export all macros to JSON file",
        "dump-macros".yellow(),
        "dm".yellow()
    );
    println!(
        "  {} ({}) <file>      - Export all call relationships to JSON file",
        "dump-calls".yellow(),
        "dc".yellow()
    );
    println!(
        "  {} ({}) <file>   - Export processed file table to JSON file",
        "dump-processed-files".yellow(),
        "dpf".yellow()
    );
    println!(
        "  {} ({}) <file>      - Export content table to JSON file",
        "dump-content".yellow(),
        "dcont".yellow()
    );

    println!();
    println!("{}", "General:".bold().cyan());
    println!(
        "  {} ({}, {}) - Check if database needs optimization",
        "check_health".yellow(),
        "health".yellow(),
        "check_db".yellow()
    );
    println!(
        "  {} ({}, {})      - Optimize database (rebuild indices, compact)",
        "optimize_db".yellow(),
        "optimize".yellow(),
        "opt".yellow()
    );
    println!(
        "  {} ({}, {})     - Show storage statistics and compression info",
        "storage_stats".yellow(),
        "stats".yellow(),
        "size".yellow()
    );
    println!(
        "  {} ({}, {}) - Scan for 100% duplicate entries across all tables",
        "scan_duplicates".yellow(),
        "duplicates".yellow(),
        "dupe".yellow()
    );
    println!(
        "  {} ({}) - Drop and recreate ALL tables (max space savings)",
        "drop_recreate_db".yellow(),
        "drop_recreate".yellow()
    );
    println!(
        "  {} <table>  - Drop and recreate single table",
        "drop_recreate_table".yellow()
    );
    println!(
        "  {} ({}, {})         - Show this help",
        "help".yellow(),
        "h".yellow(),
        "?".yellow()
    );
    println!(
        "  {} ({}, {})         - Exit the program",
        "quit".yellow(),
        "exit".yellow(),
        "q".yellow()
    );
}

pub fn print_help() {
    print_command_help();

    println!("\n{}", "Examples:".bold().cyan());
    println!("  func printk                    # Find function by name");
    println!("  func \"btrfs_.*\"                # Find functions using regex pattern");
    println!("  type struct task_struct        # Find struct by name");
    println!("  callers mutex_lock             # Show what calls mutex_lock");
    println!("  calls schedule                 # Show what schedule calls");
    println!("  callchain kmalloc              # Show complete call graph");
    println!("  diffinfo -i patch.diff         # List functions from diff only");
    println!("  grep malloc\\\\(.*\\\\)               # Search function bodies for malloc calls (shows matching lines)");
    println!("  grep -v if.*==.*NULL             # Find functions with NULL equality checks (shows full body)");
    println!("  grep return.*-1                # Find functions returning -1 (shows matching lines only)");
    println!("  vgrep \"memory allocation\"         # Find functions similar to \"memory allocation\" using vectors");
    println!(
        "  vgrep --limit 5 \"string ops\"      # Find top 5 functions similar to \"string ops\""
    );
    println!("  commit HEAD                        # Show metadata for HEAD commit");
    println!("  commit HEAD~5                      # Show metadata for HEAD~5 commit");
    println!("  commit --git HEAD~10..HEAD         # Show all commits in range");
    println!("  commit --git HEAD~10..HEAD -v      # Show commits with full diffs");
    println!("  commit -r \"malloc\" -r \"free\"      # Show commits matching both \"malloc\" AND \"free\"");
    println!("  commit -s \"kmalloc\"                # Show commits that modified kmalloc");
    println!("  commit --git HEAD~100..HEAD -s \"struct.*\" --limit 20  # Show up to 20 commits modifying structs");
    println!("  vcommit \"fix memory leak\"          # Find commits semantically similar to \"fix memory leak\"");
    println!("  vcommit --git HEAD~50..HEAD \"performance\"  # Search commits in range");
    println!("  vcommit -r \"malloc\" -r \"free\" --limit 10 \"memory\"  # Find memory-related commits with both malloc and free");
    println!();
}

pub fn display_function(func: &FunctionInfo) {
    let _ = display_function_to_writer(func, &mut stdout());
}

pub fn display_type(type_info: &TypeInfo) {
    let _ = display_type_to_writer(type_info, &mut stdout());
}

pub fn display_typedef(typedef_info: &TypedefInfo) {
    let _ = display_typedef_to_writer(typedef_info, &mut stdout());
}

pub fn print_welcome_message(database_path: &str, tables: &[String]) {
    print_welcome_message_with_model(database_path, tables, None);
}

pub fn print_welcome_message_with_model(
    database_path: &str,
    tables: &[String],
    model_path: Option<&str>,
) {
    // Print welcome message
    println!("{}", "=== Semantic Code Query Tool ===".bold().green());
    println!("Database: {}", database_path.cyan());

    if let Some(path) = model_path {
        println!(
            "Model Path: {} {}",
            path.bright_blue(),
            "(for vgrep semantic search)".bright_black()
        );
    }

    if tables.is_empty() {
        println!("{}", "Warning: No tables found in database!".red());
        println!("Make sure you've indexed some code first with semcode-index");
    }

    println!(
        "\nType '{}' for complete command list with examples.",
        "help".yellow()
    );

    println!("\n{}", "Quick Start:".bold().cyan());
    println!(
        "  {} <name>                      # Find function/macro",
        "func".yellow()
    );
    println!(
        "  {} <name>                      # Find type/struct",
        "type".yellow()
    );
    println!(
        "  {} <name>                     # Show call relationships",
        "callers".yellow()
    );
    println!(
        "  {} <name>                     # Show complete call graph",
        "callchain".yellow()
    );
    println!(
        "  {} <pattern>                        # Search function bodies with regex",
        "grep".yellow()
    );
    println!(
        "  {} <query>                         # Search similar functions with vectors",
        "vgrep".yellow()
    );
    println!(
        "  {} <ref>                        # Show commit metadata",
        "commit".yellow()
    );
    println!(
        "  {} <query>                       # Search similar commits with vectors",
        "vcommit".yellow()
    );
    println!(
        "  {} [-i file]                   # List diff functions",
        "diffinfo".yellow()
    );
    println!(
        "  {}                             # Show available data",
        "tables".yellow()
    );
    println!("  {}                             # Exit", "quit".yellow());
    println!();
}

// Writer-based display functions that can output to any Write destination

pub fn display_function_to_writer(func: &FunctionInfo, writer: &mut dyn Write) -> Result<()> {
    display_function_to_writer_with_options(func, writer, true)
}

pub fn display_function_to_writer_with_options(
    func: &FunctionInfo,
    writer: &mut dyn Write,
    show_body: bool,
) -> Result<()> {
    writeln!(
        writer,
        "\n{}",
        "=== Function Information ===".bold().green()
    )?;

    writeln!(writer, "Name: {}", func.name.yellow())?;
    writeln!(writer, "File: {}", func.file_path.cyan())?;
    writeln!(writer, "Hash: {}", func.git_file_hash.bright_black())?;
    writeln!(writer, "Lines: {} - {}", func.line_start, func.line_end)?;

    // Construct and display function declaration/signature
    let params = if func.parameters.is_empty() {
        "void".to_string()
    } else {
        func.parameters
            .iter()
            .map(|p| format!("{} {}", p.type_name, p.name))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let declaration = format!("{} {}({})", func.return_type, func.name, params);
    writeln!(writer, "\nDeclaration: {}", declaration.green())?;

    if show_body && !func.body.is_empty() {
        writeln!(writer, "\nFunction Definition:")?;
        writeln!(writer, "{}", "─".repeat(80).bright_black())?;
        writeln!(writer, "{}", func.body)?;
        writeln!(writer, "{}", "─".repeat(80).bright_black())?;
    }

    writeln!(writer)?;
    Ok(())
}

pub fn display_type_to_writer(type_info: &TypeInfo, writer: &mut dyn Write) -> Result<()> {
    writeln!(writer, "\n{}", "=== Type Information ===".bold().green())?;

    writeln!(
        writer,
        "Name: {} {}",
        type_info.kind.magenta(),
        type_info.name.yellow()
    )?;
    writeln!(writer, "File: {}", type_info.file_path.cyan())?;
    writeln!(writer, "Hash: {}", type_info.git_file_hash.bright_black())?;
    writeln!(writer, "Line: {}", type_info.line_start)?;

    if let Some(size) = type_info.size {
        writeln!(writer, "Size: {size} bytes")?;
    }

    if !type_info.members.is_empty() {
        writeln!(writer, "\nFields:")?;
        for field in &type_info.members {
            let offset_str = field
                .offset
                .map(|o| format!(" (offset: {o})"))
                .unwrap_or_default();
            writeln!(
                writer,
                "  - {} {}{}",
                field.type_name.magenta(),
                field.name.yellow(),
                offset_str.bright_black()
            )?;
        }
    } else if type_info.kind != "enum" {
        writeln!(writer, "\nFields: (none)")?;
    }

    if !type_info.definition.is_empty() {
        writeln!(writer, "\nType Definition:")?;
        writeln!(writer, "{}", "─".repeat(80).bright_black())?;
        writeln!(writer, "{}", type_info.definition)?;
        writeln!(writer, "{}", "─".repeat(80).bright_black())?;
    }

    writeln!(writer)?;
    Ok(())
}

pub fn display_typedef_to_writer(typedef_info: &TypedefInfo, writer: &mut dyn Write) -> Result<()> {
    writeln!(writer, "\n{}", "=== Typedef Information ===".bold().green())?;

    writeln!(writer, "Name: {}", typedef_info.name.yellow())?;
    writeln!(writer, "File: {}", typedef_info.file_path.cyan())?;
    writeln!(
        writer,
        "Hash: {}",
        typedef_info.git_file_hash.bright_black()
    )?;
    writeln!(writer, "Line: {}", typedef_info.line_start)?;
    writeln!(
        writer,
        "Underlying Type: {}",
        typedef_info.underlying_type.magenta()
    )?;

    if !typedef_info.definition.is_empty() {
        writeln!(writer, "\nTypedef Definition:")?;
        writeln!(writer, "{}", "─".repeat(80).bright_black())?;
        writeln!(writer, "{}", typedef_info.definition)?;
        writeln!(writer, "{}", "─".repeat(80).bright_black())?;
    }

    writeln!(writer)?;
    Ok(())
}
