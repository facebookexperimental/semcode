// SPDX-License-Identifier: MIT OR Apache-2.0
//! Clangd integration for enriching semantic analysis with compiler-grade precision
//!
//! This module uses libclang to enhance the Tree-sitter based analysis
//! with semantic information that requires compilation context:
//! - Unified Symbol Resolution (USR) for unique symbol identification
//! - Canonical types for templates, auto, typedef resolution
//! - Precise overload resolution
//! - Cross-reference into system headers

use anyhow::{anyhow, Context, Result};
use clang::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

/// GCC-specific compiler flags that clang doesn't recognize
///
/// These flags will cause clang to emit warnings or errors if passed,
/// so we filter them out when invoking libclang.
///
/// Note: This list only includes flags that clang genuinely doesn't support.
/// Flags that both compilers support (like -Wenum-conversion) are NOT filtered.
const FLAGS_TO_FILTER_FOR_LIBCLANG: &[&str] = &[
    // Stack and memory management (GCC-only)
    "-fconserve-stack",
    "-fno-allow-store-data-races",
    "-fzero-init-padding-bits=all",
    // Function alignment (GCC-only)
    "-fmin-function-alignment=", // Matches any value
    // Security mitigations (GCC-only)
    "-mindirect-branch-register",
    "-mindirect-branch=", // Matches any variant
    // Architecture-specific (GCC-only)
    "-mpreferred-stack-boundary=", // Matches any value
    "-mrecord-mcount",
    // GCC-specific warnings
    "-Wdefault-const-init-var-unsafe",
    "-Wno-dangling-pointer",
    "-Wno-stringop-overflow",
    "-Wno-alloc-size-larger-than",
    "-Wno-packed-not-aligned",
    "-Wpacked-not-aligned",
    "-Wno-stringop-truncation",
    "-Wstringop-truncation",
    "-Wrestrict",
    "-Wimplicit-fallthrough=", // Matches any value like -Wimplicit-fallthrough=5
    "-Werror=designated-init",
    "-Wno-maybe-uninitialized",
    // Tree optimization flags (GCC-only)
    "-fno-var-tracking-assignments",
    "-fno-tree-loop-im",
    "-fno-tree-loop-ivcanon",
    // Plugin flags (GCC-only, not portable to clang)
    "-fplugin=",
    "-fplugin-arg-",
];

/// Compilation command from compile_commands.json
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompileCommand {
    directory: String,
    command: Option<String>,
    arguments: Option<Vec<String>>,
    file: String,
}

/// Clangd analyzer that uses libclang for semantic enrichment
pub struct ClangdAnalyzer {
    pub compile_commands_path: PathBuf,
    source_root: PathBuf,
    compile_commands: Arc<Mutex<HashMap<String, CompileCommand>>>,
    index: Index<'static>,
}

/// Symbol enrichment result
#[derive(Debug, Clone)]
pub struct SymbolEnrichment {
    pub usr: Option<String>,
    pub signature: Option<String>,
    pub canonical_type: Option<String>,
}

impl ClangdAnalyzer {
    /// Create a new ClangdAnalyzer
    ///
    /// # Arguments
    /// * `compile_commands_path` - Path to compile_commands.json or the directory containing it
    /// * `source_root` - The root directory of the source code (for resolving relative paths)
    pub fn new(
        compile_commands_path: impl AsRef<Path>,
        source_root: impl AsRef<Path>,
    ) -> Result<Self> {
        let path = compile_commands_path.as_ref();
        let compile_commands_path = if path.is_dir() {
            path.join("compile_commands.json")
        } else {
            path.to_path_buf()
        };

        let source_root = source_root.as_ref().to_path_buf();

        // Leak Clang to get 'static reference - ClangdAnalyzer is long-lived anyway
        let clang = Box::leak(Box::new(
            Clang::new().map_err(|e| anyhow!("Failed to load libclang: {}", e))?,
        ));

        // Create shared index that will be reused across all parses
        let index = Index::new(clang, false, false);

        Ok(Self {
            compile_commands_path,
            source_root,
            compile_commands: Arc::new(Mutex::new(HashMap::new())),
            index,
        })
    }

    /// Check if clangd enrichment is available
    ///
    /// # Arguments
    /// * `path` - Path to compile_commands.json or directory containing it
    ///
    /// # Returns
    /// True if compile_commands.json exists and libclang is available
    pub fn is_available(path: impl AsRef<Path>) -> bool {
        let path = path.as_ref();
        let compile_commands_path = if path.is_dir() {
            path.join("compile_commands.json")
        } else {
            path.to_path_buf()
        };

        // Check if compile_commands.json exists and libclang is available
        compile_commands_path.exists() && Clang::new().is_ok()
    }

    /// Load compile_commands.json
    async fn load_compile_commands(&self) -> Result<()> {
        let content = tokio::fs::read_to_string(&self.compile_commands_path)
            .await
            .context("Failed to read compile_commands.json")?;

        let commands: Vec<CompileCommand> =
            serde_json::from_str(&content).context("Failed to parse compile_commands.json")?;

        let mut map = self.compile_commands.lock().await;
        map.clear();

        // Get the directory containing compile_commands.json to resolve relative paths
        let compile_commands_dir = self
            .compile_commands_path
            .parent()
            .unwrap_or_else(|| Path::new("."));

        let mut loaded_count = 0;
        let mut failed_count = 0;

        for cmd in commands {
            // Resolve directory relative to compile_commands.json location
            let directory = if cmd.directory.starts_with('/') {
                // Absolute path
                PathBuf::from(&cmd.directory)
            } else {
                // Relative path - resolve relative to compile_commands.json
                compile_commands_dir.join(&cmd.directory)
            };

            // Handle both relative and absolute file paths
            let file_path = if cmd.file.starts_with('/') {
                // File is already absolute - use as-is
                PathBuf::from(&cmd.file)
            } else {
                // File is relative - join with directory
                directory.join(&cmd.file)
            };

            // Try to canonicalize, but if it fails (file doesn't exist yet), use the path as-is
            let canonical = file_path.canonicalize().unwrap_or_else(|_| {
                failed_count += 1;
                file_path.clone()
            });

            let path_str = canonical.display().to_string();
            map.insert(path_str, cmd);
            loaded_count += 1;
        }

        tracing::debug!(
            "Loaded {} compile commands from {} ({} paths canonicalized, {} used as-is)",
            map.len(),
            self.compile_commands_path.display(),
            loaded_count - failed_count,
            failed_count
        );

        // Log a sample entry for debugging
        if let Some((path, _)) = map.iter().next() {
            tracing::debug!("Sample compile command entry key: {}", path);
        }

        Ok(())
    }

    /// Initialize the analyzer (load compile commands)
    pub async fn initialize(&self) -> Result<()> {
        self.load_compile_commands().await
    }

    /// Get compile arguments for a file
    async fn get_compile_args(&self, file_path: &Path) -> Option<Vec<String>> {
        // If the path is relative, make it absolute by joining with source_root
        let absolute_path = if file_path.is_absolute() {
            file_path.to_path_buf()
        } else {
            self.source_root.join(file_path)
        };

        // Then canonicalize to match how paths are stored in the HashMap
        let canonical_path = absolute_path
            .canonicalize()
            .unwrap_or_else(|_| absolute_path);

        let commands = self.compile_commands.lock().await;

        let lookup_key = canonical_path.display().to_string();
        tracing::debug!(
            "Looking up compile args for path: {:?} -> canonical: {}",
            file_path,
            lookup_key
        );

        let cmd = commands.get(&lookup_key)?;

        // Get the working directory for this compilation
        let working_dir = PathBuf::from(&cmd.directory);

        // Extract arguments from command or arguments field
        let mut args = if let Some(ref args) = cmd.arguments {
            // arguments field is already a proper array
            args.clone()
        } else if let Some(ref command) = cmd.command {
            // Parse command string properly using shell-words
            // This handles quotes, escapes, and complex arguments correctly
            match shell_words::split(command) {
                Ok(args) => args,
                Err(e) => {
                    tracing::debug!("Failed to parse compile command '{}': {}", command, e);
                    return None;
                }
            }
        } else {
            return None;
        };

        // Remove the compiler name (first argument) if present
        // The first arg is the compiler executable, which libclang doesn't need
        // It could be gcc, clang, cc, or a full path like /usr/bin/gcc
        if !args.is_empty() {
            let first_arg = &args[0];
            // Check if it looks like a compiler (doesn't start with -)
            if !first_arg.starts_with('-') {
                args.remove(0);
            }
        }

        // Filter out flags that libclang doesn't need or that might cause issues
        args.retain(|arg| !Self::should_filter_flag(arg));

        // Remove -include and -o directives (and their arguments)
        // -include can cause AstDeserialization errors if headers have GCC PCH versions
        // -o is for output files which libclang doesn't need
        let mut filtered_args = Vec::new();
        let mut skip_next = false;
        for arg in args.iter() {
            if skip_next {
                tracing::debug!("Filtering out flagged argument: {}", arg);
                skip_next = false;
                continue;
            }
            if arg == "-include" || arg == "-o" {
                // Skip this flag and the next argument
                tracing::debug!("Found {} flag, will skip next arg", arg);
                skip_next = true;
                continue;
            }
            filtered_args.push(arg.clone());
        }
        args = filtered_args;

        tracing::debug!("After filtering, {} args remain", args.len());

        // Convert relative include paths to absolute paths using the working directory
        // This is critical because libclang doesn't know what directory to resolve relative paths from
        let mut absolute_args = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];

            if arg == "-I" && i + 1 < args.len() {
                // -I with separate path argument
                let path = &args[i + 1];
                absolute_args.push(arg.clone());
                if path.starts_with('/') {
                    // Already absolute
                    absolute_args.push(path.clone());
                } else {
                    // Relative - make absolute
                    let abs_path = working_dir.join(path);
                    absolute_args.push(abs_path.display().to_string());
                }
                i += 2;
            } else if arg.starts_with("-I") && arg.len() > 2 {
                // -I with path attached like -I./include
                let path = &arg[2..];
                if path.starts_with('/') {
                    // Already absolute
                    absolute_args.push(arg.clone());
                } else {
                    // Relative - make absolute
                    let abs_path = working_dir.join(path);
                    absolute_args.push(format!("-I{}", abs_path.display()));
                }
                i += 1;
            } else {
                absolute_args.push(arg.clone());
                i += 1;
            }
        }
        args = absolute_args;

        // Remove the source file from arguments if present
        // libclang's parser() takes the file separately, it should NOT be in the args
        let original_file = &cmd.file;
        let canonical_str = canonical_path.display().to_string();

        // Extract just the filename for matching
        let canonical_filename = canonical_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        args.retain(|arg| {
            // Check if this argument is the source file in any form:
            // 1. Exact match with original path from compile_commands.json
            // 2. Exact match with canonical path
            // 3. Ends with the original file path (catches relative paths)
            // 4. Argument is just the filename (catches "8250_dma.c" style)
            // 5. Argument ends with a path separator followed by the filename
            let is_source_file = arg == original_file
                || arg == &canonical_str
                || arg.ends_with(original_file)
                || arg == canonical_filename
                || arg.ends_with(&format!("/{}", canonical_filename));

            !is_source_file
        });

        // Add flags to help libclang parse correctly
        // -fno-pch prevents trying to use GCC precompiled headers
        // -x c explicitly tells clang this is C code
        args.push("-fno-pch".to_string());
        args.push("-x".to_string());
        args.push("c".to_string());
        tracing::debug!("Added -fno-pch and -x c flags for libclang");

        Some(args)
    }

    /// Check if a compiler flag should be filtered out when passing to libclang
    fn should_filter_flag(flag: &str) -> bool {
        FLAGS_TO_FILTER_FOR_LIBCLANG.iter().any(|filter_flag| {
            if filter_flag.ends_with('=') {
                // For flags like "-mpreferred-stack-boundary=", match the prefix
                flag.starts_with(filter_flag)
            } else {
                // Exact match
                flag == *filter_flag
            }
        })
    }

    /// Enrich a function symbol with libclang data
    ///
    /// # Arguments
    /// * `file_path` - Source file path
    /// * `function_name` - Function name
    /// * `line` - Line number where function is defined
    ///
    /// # Returns
    /// Enrichment data if available
    pub async fn enrich_function(
        &self,
        file_path: &Path,
        function_name: &str,
        line: u32,
    ) -> Result<SymbolEnrichment> {
        tracing::debug!(
            "enrich_function called for {} at line {} in {:?}",
            function_name,
            line,
            file_path
        );

        // Canonicalize the file path - libclang needs an absolute path
        let canonical_path = file_path
            .canonicalize()
            .unwrap_or_else(|_| file_path.to_path_buf());

        // Get compile arguments for this file
        let args = match self.get_compile_args(&canonical_path).await {
            Some(args) => args,
            None => {
                // No compile command = no enrichment
                return Ok(SymbolEnrichment {
                    usr: None,
                    signature: None,
                    canonical_type: None,
                });
            }
        };

        tracing::debug!("Parsing {:?} with args: {:?}", canonical_path, args);

        // Parse the file with libclang using the canonical path and shared index
        let tu = match self.index
            .parser(&canonical_path)
            .arguments(&args)
            .detailed_preprocessing_record(true) // Required to access macro definitions in AST
            .skip_function_bodies(false)
            .parse()
        {
            Ok(tu) => {
                // Log diagnostics even on successful parse
                let diags = tu.get_diagnostics();
                if !diags.is_empty() {
                    tracing::debug!(
                        "Parse succeeded with {} diagnostics for {:?}",
                        diags.len(),
                        canonical_path
                    );
                    for (i, diag) in diags.iter().take(3).enumerate() {
                        tracing::debug!("  Diagnostic {}: {:?}", i, diag.get_text());
                    }
                }
                tu
            }
            Err(e) => {
                tracing::debug!(
                    "Failed to parse {:?} with libclang: {:?}\nArgs were: {:?}",
                    canonical_path,
                    e,
                    args
                );
                // Return empty enrichment instead of error
                return Ok(SymbolEnrichment {
                    usr: None,
                    signature: None,
                    canonical_type: None,
                });
            }
        };

        // Find the function at the specified line
        let entity = tu.get_entity();
        let mut enrichment = SymbolEnrichment {
            usr: None,
            signature: None,
            canonical_type: None,
        };

        // Traverse AST to find the function
        entity.visit_children(|cursor, _| {
            if let Some(name) = cursor.get_name() {
                if name == function_name {
                    if let Some(loc) = cursor.get_location() {
                        let file_loc = loc.get_file_location();
                        if file_loc.line as u32 == line {
                            // Found the function! Extract enrichment data
                            if let Some(usr) = cursor.get_usr() {
                                enrichment.usr = Some(usr.0); // Usr is a newtype wrapper
                            }

                            // Get signature from display name
                            if let Some(display_name) = cursor.get_display_name() {
                                enrichment.signature = Some(display_name);
                            }

                            // Get canonical return type
                            if let Some(result_type) = cursor.get_result_type() {
                                let canonical = result_type.get_canonical_type();
                                enrichment.canonical_type = Some(canonical.get_display_name());
                            }

                            return EntityVisitResult::Break;
                        }
                    }
                }
            }
            EntityVisitResult::Recurse
        });

        if enrichment.usr.is_some() {
            tracing::debug!(
                "Enriched function {}:{} with USR",
                file_path.display(),
                function_name
            );
        }

        Ok(enrichment)
    }

    /// Enrich a type symbol with libclang data
    pub async fn enrich_type(
        &self,
        file_path: &Path,
        type_name: &str,
        line: u32,
    ) -> Result<SymbolEnrichment> {
        // Canonicalize the file path - libclang needs an absolute path
        let canonical_path = file_path
            .canonicalize()
            .unwrap_or_else(|_| file_path.to_path_buf());

        let args = match self.get_compile_args(&canonical_path).await {
            Some(args) => args,
            None => {
                return Ok(SymbolEnrichment {
                    usr: None,
                    signature: None,
                    canonical_type: None,
                });
            }
        };

        let tu = self
            .index
            .parser(&canonical_path)
            .arguments(&args)
            .parse()
            .context("Failed to parse file with libclang")?;

        let entity = tu.get_entity();
        let mut enrichment = SymbolEnrichment {
            usr: None,
            signature: None,
            canonical_type: None,
        };

        entity.visit_children(|cursor, _| {
            if let Some(loc) = cursor.get_location() {
                let file_loc = loc.get_file_location();
                if file_loc.line as u32 == line {
                    if let Some(name) = cursor.get_name() {
                        // Match type name (may have struct/union/enum prefix)
                        if name == type_name
                            || format!("struct {}", name) == type_name
                            || format!("union {}", name) == type_name
                            || format!("enum {}", name) == type_name
                        {
                            if let Some(usr) = cursor.get_usr() {
                                enrichment.usr = Some(usr.0);
                            }

                            if let Some(cursor_type) = cursor.get_type() {
                                let canonical = cursor_type.get_canonical_type();
                                enrichment.canonical_type = Some(canonical.get_display_name());
                            }

                            return EntityVisitResult::Break;
                        }
                    }
                }
            }
            EntityVisitResult::Recurse
        });

        Ok(enrichment)
    }

    /// Enrich a macro symbol with libclang data
    pub async fn enrich_macro(
        &self,
        file_path: &Path,
        macro_name: &str,
        line: u32,
    ) -> Result<SymbolEnrichment> {
        // Canonicalize the file path - libclang needs an absolute path
        let canonical_path = file_path
            .canonicalize()
            .unwrap_or_else(|_| file_path.to_path_buf());

        let args = match self.get_compile_args(&canonical_path).await {
            Some(args) => args,
            None => {
                return Ok(SymbolEnrichment {
                    usr: None,
                    signature: None,
                    canonical_type: None,
                });
            }
        };

        let tu = self
            .index
            .parser(&canonical_path)
            .arguments(&args)
            .parse()
            .context("Failed to parse file with libclang")?;

        let entity = tu.get_entity();
        let mut enrichment = SymbolEnrichment {
            usr: None,
            signature: None,
            canonical_type: None,
        };

        entity.visit_children(|cursor, _| {
            if cursor.get_kind() == EntityKind::MacroDefinition {
                if let Some(loc) = cursor.get_location() {
                    let file_loc = loc.get_file_location();
                    if file_loc.line as u32 == line {
                        if let Some(name) = cursor.get_name() {
                            if name == macro_name {
                                if let Some(usr) = cursor.get_usr() {
                                    enrichment.usr = Some(usr.0);
                                }
                                return EntityVisitResult::Break;
                            }
                        }
                    }
                }
            }
            EntityVisitResult::Recurse
        });

        Ok(enrichment)
    }

    /// Enrich multiple symbols from a single file in one pass
    ///
    /// This is much more efficient than calling enrich_function/type/macro individually
    /// because it parses the file once and extracts all symbols in a single AST traversal.
    ///
    /// # Arguments
    /// * `file_path` - Source file path
    /// * `functions` - Functions to enrich (name, line)
    /// * `types` - Types to enrich (name, line)
    /// * `macros` - Macros to enrich (name, line)
    ///
    /// # Returns
    /// Maps from (name, line) to enrichment data for each symbol type
    pub async fn enrich_file_batch(
        &self,
        file_path: &Path,
        functions: &[(String, u32)],
        types: &[(String, u32)],
        macros: &[(String, u32)],
    ) -> Result<(
        HashMap<(String, u32), SymbolEnrichment>,
        HashMap<(String, u32), SymbolEnrichment>,
        HashMap<(String, u32), SymbolEnrichment>,
    )> {
        use std::collections::HashMap;

        // Canonicalize the file path - libclang needs an absolute path
        let canonical_path = file_path
            .canonicalize()
            .unwrap_or_else(|_| file_path.to_path_buf());

        // Get compile arguments for this file
        let args = match self.get_compile_args(&canonical_path).await {
            Some(args) => args,
            None => {
                // No compile command = no enrichment
                return Ok((HashMap::new(), HashMap::new(), HashMap::new()));
            }
        };

        tracing::debug!(
            "Batch enriching {:?}: {} functions, {} types, {} macros",
            file_path,
            functions.len(),
            types.len(),
            macros.len()
        );

        // Parse the file ONCE with libclang using shared index
        let tu = match self
            .index
            .parser(&canonical_path)
            .arguments(&args)
            .detailed_preprocessing_record(true) // Required to access macro definitions in AST
            .skip_function_bodies(false)
            .parse()
        {
            Ok(tu) => {
                // Log diagnostics even on successful parse
                let diags = tu.get_diagnostics();
                if !diags.is_empty() {
                    tracing::debug!(
                        "Parse succeeded with {} diagnostics for {:?}",
                        diags.len(),
                        canonical_path
                    );
                    for (i, diag) in diags.iter().take(3).enumerate() {
                        tracing::debug!("  Diagnostic {}: {:?}", i, diag.get_text());
                    }
                }
                tu
            }
            Err(e) => {
                tracing::debug!(
                    "Failed to parse {:?} with libclang: {:?}\nArgs were: {:?}",
                    canonical_path,
                    e,
                    args
                );
                // Return empty enrichment instead of error
                return Ok((HashMap::new(), HashMap::new(), HashMap::new()));
            }
        };

        // Build lookup sets for fast O(1) checking
        let function_set: HashMap<_, _> = functions
            .iter()
            .map(|(name, line)| ((name.as_str(), *line), ()))
            .collect();
        let macro_set: HashMap<_, _> = macros
            .iter()
            .map(|(name, line)| ((name.as_str(), *line), ()))
            .collect();

        // For types, build a line -> type_names map for efficient lookup
        // This avoids O(n*m) nested loop when checking types
        let mut type_line_map: HashMap<u32, Vec<&String>> = HashMap::new();
        for (type_name, type_line) in types {
            type_line_map
                .entry(*type_line)
                .or_insert_with(Vec::new)
                .push(type_name);
        }

        // Result maps
        let mut function_enrichments = HashMap::new();
        let mut type_enrichments = HashMap::new();
        let mut macro_enrichments = HashMap::new();

        // Single AST traversal to extract ALL symbols
        let entity = tu.get_entity();
        entity.visit_children(|cursor, _| {
            let kind = cursor.get_kind();

            // Check if this is a macro definition
            if kind == EntityKind::MacroDefinition {
                if let (Some(name), Some(loc)) = (cursor.get_name(), cursor.get_location()) {
                    let file_loc = loc.get_file_location();
                    let line = file_loc.line as u32;

                    if macro_set.contains_key(&(name.as_str(), line)) {
                        tracing::debug!("Processing macro {} at line {}", name, line);
                        tracing::debug!("  Cursor kind: {:?}", cursor.get_kind());
                        tracing::debug!("  Cursor display name: {:?}", cursor.get_display_name());
                        tracing::debug!("  Cursor is definition: {}", cursor.is_definition());

                        let mut enrichment = SymbolEnrichment {
                            usr: None,
                            signature: None,
                            canonical_type: None,
                        };

                        let usr_result = cursor.get_usr();
                        tracing::debug!("  get_usr() returned: {:?}", usr_result);

                        if let Some(usr) = usr_result {
                            tracing::debug!("  ✓ Macro {} HAS USR: {}", name, usr.0);
                            enrichment.usr = Some(usr.0);
                        } else {
                            tracing::debug!("  ✗ Macro {} has NO USR from libclang (cursor.get_usr() returned None)", name);
                        }

                        macro_enrichments.insert((name.clone(), line), enrichment);
                    }
                }
                return EntityVisitResult::Recurse;
            }

            // For functions and types, we need name and location
            if let (Some(name), Some(loc)) = (cursor.get_name(), cursor.get_location()) {
                let file_loc = loc.get_file_location();
                let line = file_loc.line as u32;

                // Check if this is a function we're looking for (O(1) HashMap lookup)
                if function_set.contains_key(&(name.as_str(), line)) {
                    let mut enrichment = SymbolEnrichment {
                        usr: None,
                        signature: None,
                        canonical_type: None,
                    };

                    if let Some(usr) = cursor.get_usr() {
                        enrichment.usr = Some(usr.0);
                    }

                    if let Some(display_name) = cursor.get_display_name() {
                        enrichment.signature = Some(display_name);
                    }

                    if let Some(result_type) = cursor.get_result_type() {
                        let canonical = result_type.get_canonical_type();
                        enrichment.canonical_type = Some(canonical.get_display_name());
                    }

                    function_enrichments.insert((name.clone(), line), enrichment);
                }

                // Check if this is a type we're looking for (O(1) lookup by line, then small vector check)
                // Types can have various names with struct/union/enum prefixes
                if let Some(type_names) = type_line_map.get(&line) {
                    for type_name in type_names {
                        let matches = name == **type_name
                            || format!("struct {}", name) == **type_name
                            || format!("union {}", name) == **type_name
                            || format!("enum {}", name) == **type_name;

                        if matches {
                            let mut enrichment = SymbolEnrichment {
                                usr: None,
                                signature: None,
                                canonical_type: None,
                            };

                            if let Some(usr) = cursor.get_usr() {
                                enrichment.usr = Some(usr.0);
                            }

                            if let Some(cursor_type) = cursor.get_type() {
                                let canonical = cursor_type.get_canonical_type();
                                enrichment.canonical_type = Some(canonical.get_display_name());
                            }

                            type_enrichments.insert(((*type_name).clone(), line), enrichment);
                            break; // Found the match, no need to check other type names
                        }
                    }
                }
            }

            EntityVisitResult::Recurse
        });

        tracing::debug!(
            "Batch enrichment complete for {:?}: {} functions, {} types, {} macros enriched",
            file_path,
            function_enrichments.len(),
            type_enrichments.len(),
            macro_enrichments.len()
        );

        Ok((function_enrichments, type_enrichments, macro_enrichments))
    }

    /// Check if a file can be enriched (has compile commands)
    pub async fn can_enrich_file(&self, file_path: &Path) -> bool {
        let canonical_path = file_path
            .canonicalize()
            .unwrap_or_else(|_| file_path.to_path_buf());

        self.get_compile_args(&canonical_path).await.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_clangd_availability() {
        let temp_dir = tempfile::tempdir().unwrap();
        let compile_commands = temp_dir.path().join("compile_commands.json");

        // Should return false when file doesn't exist
        assert!(!ClangdAnalyzer::is_available(&compile_commands));

        // Create empty compile_commands.json
        std::fs::write(&compile_commands, "[]").unwrap();

        // Should return true when file exists (if libclang is available)
        // This may fail in CI without libclang installed
        let available = ClangdAnalyzer::is_available(&compile_commands);
        if available {
            let analyzer = ClangdAnalyzer::new(&compile_commands, temp_dir.path());
            assert!(analyzer.is_ok());
        }
    }
}
