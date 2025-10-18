// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::git::resolve_to_commit;
use crate::CallRelationship;
use anyhow::Result;
use arrow::array::{Array, StringArray};
use colored::*;
use futures::TryStreamExt;
use lancedb::connection::Connection;
use lancedb::query::ExecutableQuery;
use lancedb::query::QueryBase;

use crate::database::functions::FunctionStore;
use crate::database::schema::SchemaManager;
use crate::database::search::{SearchManager, VectorSearchManager};
use crate::database::types::{MacroStore, TypeStore, TypedefStore};
// CallStore removed - call relationships are now embedded in function JSON columns
use crate::database::content::{ContentInfo, ContentStore};
use crate::database::processed_files::{ProcessedFileRecord, ProcessedFileStore};
use crate::database::vectors::VectorStore;
use crate::types::{FunctionInfo, MacroInfo, TypeInfo, TypedefInfo};
use crate::vectorizer::CodeVectorizer;

// Optimal batch size for LanceDB operations
pub const OPTIMAL_BATCH_SIZE: usize = 65536;

pub struct DatabaseManager {
    connection: Connection,
    git_repo_path: String,
    function_store: FunctionStore,
    type_store: TypeStore,
    typedef_store: TypedefStore,
    macro_store: MacroStore,
    search_manager: SearchManager,
    vector_search_manager: VectorSearchManager,
    schema_manager: SchemaManager,
    processed_file_store: ProcessedFileStore,
    content_store: ContentStore,
}

impl DatabaseManager {
    pub async fn new(db_path: &str, git_repo_path: String) -> Result<Self> {
        let connection = lancedb::connect(db_path).execute().await?;

        Ok(Self {
            connection: connection.clone(),
            git_repo_path: git_repo_path.clone(),
            function_store: FunctionStore::new(connection.clone()),
            type_store: TypeStore::new(connection.clone()),
            typedef_store: TypedefStore::new(connection.clone()),
            macro_store: MacroStore::new(connection.clone()),
            search_manager: SearchManager::new(connection.clone(), git_repo_path),
            vector_search_manager: VectorSearchManager::new(connection.clone()),
            schema_manager: SchemaManager::new(connection.clone()),
            processed_file_store: ProcessedFileStore::new(connection.clone()),
            content_store: ContentStore::new(connection.clone()),
        })
    }

    pub async fn list_tables(&self) -> Result<Vec<String>> {
        Ok(self.connection.table_names().execute().await?)
    }

    pub async fn create_tables(&self) -> Result<()> {
        self.schema_manager.create_all_tables().await?;
        self.schema_manager.create_scalar_indices().await?;
        Ok(())
    }

    pub async fn clear_all_data(&self) -> Result<()> {
        // Delete all data from each main table
        for table_name in &["functions", "types", "macros", "processed_files"] {
            if let Ok(table) = self.connection.open_table(*table_name).execute().await {
                table.delete("1=1").await?;
            }
        }

        // Delete all data from content shard tables (content_0 through content_15)
        for shard in 0..16u8 {
            let table_name = format!("content_{shard}");
            if let Ok(table) = self.connection.open_table(&table_name).execute().await {
                table.delete("1=1").await?;
            }
        }

        Ok(())
    }

    /// Scan all tables for 100% duplicate entries and report statistics
    pub async fn scan_for_duplicates(&self) -> Result<()> {
        println!("{}", "=== Database Duplicate Scan ===".bold().green());
        println!("Scanning for entries where ALL columns are identical...\n");

        let tables_to_scan = ["functions", "types", "macros", "processed_files"];

        // Scan main tables
        for table_name in &tables_to_scan {
            if let Ok(table) = self.connection.open_table(*table_name).execute().await {
                match self.scan_table_for_duplicates(table_name, &table).await {
                    Ok((total_rows, duplicate_groups, duplicate_count, examples)) => {
                        println!("{}", format!("=== {table_name} ===").bold().cyan());
                        println!("Total rows: {}", total_rows.to_string().yellow());

                        if duplicate_groups > 0 {
                            println!("Duplicate groups: {}", duplicate_groups.to_string().red());
                            println!(
                                "Total duplicate rows: {}",
                                duplicate_count.to_string().red()
                            );

                            // Debug the calculation
                            let percentage = duplicate_count as f64 / total_rows as f64 * 100.0;
                            println!("Duplicate percentage: {percentage:.2}%");

                            if !examples.is_empty() {
                                println!("\nExample duplicates (showing up to 5 groups):");
                                for (i, example) in examples.iter().enumerate().take(5) {
                                    println!(
                                        "  Group {}: {} identical rows",
                                        i + 1,
                                        example.len().to_string().yellow()
                                    );
                                    if let Some(first_row) = example.first() {
                                        println!("    Sample: {}", first_row.cyan());
                                    }
                                }
                            }
                        } else {
                            println!("{}", "No duplicates found ✓".green());
                        }
                        println!();
                    }
                    Err(e) => {
                        println!(
                            "{} Failed to scan table {}: {}",
                            "Error:".red(),
                            table_name,
                            e
                        );
                    }
                }
            } else {
                println!("{} Table {} not found", "Warning:".yellow(), table_name);
            }
        }

        // Scan content shard tables (content_0 through content_15)
        for shard in 0..16u8 {
            let table_name = format!("content_{shard}");
            if let Ok(table) = self.connection.open_table(&table_name).execute().await {
                match self.scan_table_for_duplicates(&table_name, &table).await {
                    Ok((total_rows, duplicate_groups, duplicate_count, examples)) => {
                        println!("{}", format!("=== {table_name} ===").bold().cyan());
                        println!("Total rows: {}", total_rows.to_string().yellow());

                        if duplicate_groups > 0 {
                            println!("Duplicate groups: {}", duplicate_groups.to_string().red());
                            println!(
                                "Total duplicate rows: {}",
                                duplicate_count.to_string().red()
                            );

                            let percentage = duplicate_count as f64 / total_rows as f64 * 100.0;
                            println!("Duplicate percentage: {percentage:.2}%");

                            if !examples.is_empty() {
                                println!("\nExample duplicates (showing up to 5 groups):");
                                for (i, example) in examples.iter().enumerate().take(5) {
                                    println!(
                                        "  Group {}: {} identical rows",
                                        i + 1,
                                        example.len().to_string().yellow()
                                    );
                                    if let Some(first_row) = example.first() {
                                        println!("    Sample: {}", first_row.cyan());
                                    }
                                }
                            }
                        } else {
                            println!("{}", "No duplicates found ✓".green());
                        }
                        println!();
                    }
                    Err(e) => {
                        println!(
                            "{} Failed to scan table {}: {}",
                            "Error:".red(),
                            table_name,
                            e
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Scan a specific table for duplicates
    async fn scan_table_for_duplicates(
        &self,
        table_name: &str,
        table: &lancedb::Table,
    ) -> Result<(usize, usize, usize, Vec<Vec<String>>)> {
        use futures::TryStreamExt;
        use std::collections::HashMap;

        let results = table
            .query()
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;
        let mut row_counts: HashMap<String, usize> = HashMap::new();
        let mut row_examples: HashMap<String, String> = HashMap::new();
        let mut total_rows = 0;

        for batch in results {
            if batch.num_rows() == 0 {
                continue;
            }

            for row_idx in 0..batch.num_rows() {
                total_rows += 1;

                // Create a string representation of all columns for this row
                let row_signature = self.create_row_signature(&batch, row_idx, table_name)?;

                // Count occurrences and store example
                *row_counts.entry(row_signature.clone()).or_insert(0) += 1;
                row_examples
                    .entry(row_signature.clone())
                    .or_insert_with(|| {
                        self.create_readable_row_summary(&batch, row_idx, table_name)
                            .unwrap_or_default()
                    });
            }
        }

        // Find duplicates (count > 1)
        let mut duplicate_groups = 0;
        let mut total_duplicate_rows = 0;
        let mut examples = Vec::new();

        for (signature, count) in &row_counts {
            if *count > 1 {
                duplicate_groups += 1;
                total_duplicate_rows += count;

                // Create example entries for this duplicate group
                if examples.len() < 5 {
                    let example_description = row_examples.get(signature).unwrap_or(signature);
                    examples.push(vec![example_description.clone(); *count]);
                }
            }
        }

        Ok((total_rows, duplicate_groups, total_duplicate_rows, examples))
    }

    /// Create a unique signature for a row by concatenating all column values
    fn create_row_signature(
        &self,
        batch: &arrow::record_batch::RecordBatch,
        row_idx: usize,
        _table_name: &str,
    ) -> Result<String> {
        use arrow::array::Array;

        let mut signature_parts = Vec::new();

        for col_idx in 0..batch.num_columns() {
            let column = batch.column(col_idx);
            let value_str = match column.data_type() {
                arrow::datatypes::DataType::Utf8 => {
                    let string_array = column
                        .as_any()
                        .downcast_ref::<arrow::array::StringArray>()
                        .unwrap();
                    if string_array.is_null(row_idx) {
                        "NULL".to_string()
                    } else {
                        string_array.value(row_idx).to_string()
                    }
                }
                // FixedSizeBinary(32) case removed - all hashes now stored as Utf8 hex strings
                arrow::datatypes::DataType::UInt32 => {
                    let uint32_array = column
                        .as_any()
                        .downcast_ref::<arrow::array::UInt32Array>()
                        .unwrap();
                    if uint32_array.is_null(row_idx) {
                        "NULL".to_string()
                    } else {
                        uint32_array.value(row_idx).to_string()
                    }
                }
                arrow::datatypes::DataType::UInt64 => {
                    let uint64_array = column
                        .as_any()
                        .downcast_ref::<arrow::array::UInt64Array>()
                        .unwrap();
                    if uint64_array.is_null(row_idx) {
                        "NULL".to_string()
                    } else {
                        uint64_array.value(row_idx).to_string()
                    }
                }
                arrow::datatypes::DataType::Boolean => {
                    let bool_array = column
                        .as_any()
                        .downcast_ref::<arrow::array::BooleanArray>()
                        .unwrap();
                    if bool_array.is_null(row_idx) {
                        "NULL".to_string()
                    } else {
                        bool_array.value(row_idx).to_string()
                    }
                }
                arrow::datatypes::DataType::Float32 => {
                    let float32_array = column
                        .as_any()
                        .downcast_ref::<arrow::array::Float32Array>()
                        .unwrap();
                    if float32_array.is_null(row_idx) {
                        "NULL".to_string()
                    } else {
                        float32_array.value(row_idx).to_string()
                    }
                }
                _ => format!("UNSUPPORTED_TYPE_{}", column.data_type()),
            };
            signature_parts.push(value_str);
        }

        Ok(signature_parts.join("||"))
    }

    /// Create a human-readable summary of a row for examples
    fn create_readable_row_summary(
        &self,
        batch: &arrow::record_batch::RecordBatch,
        row_idx: usize,
        table_name: &str,
    ) -> Result<String> {
        use arrow::array::Array;

        match table_name {
            "functions" => {
                let name_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let file_path_array = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let git_hash_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                let name = if name_array.is_null(row_idx) {
                    "NULL"
                } else {
                    name_array.value(row_idx)
                };
                let file_path = if file_path_array.is_null(row_idx) {
                    "NULL"
                } else {
                    file_path_array.value(row_idx)
                };
                let git_hash = if git_hash_array.is_null(row_idx) {
                    "NULL".to_string()
                } else {
                    let hash_str = git_hash_array.value(row_idx);
                    if hash_str.len() >= 8 {
                        hash_str[..8].to_string()
                    } else {
                        hash_str.to_string()
                    }
                };

                Ok(format!("{name}() in {file_path} ({git_hash}...)"))
            }
            "types" => {
                let name_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let file_path_array = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let kind_array = batch
                    .column(4)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                let name = if name_array.is_null(row_idx) {
                    "NULL"
                } else {
                    name_array.value(row_idx)
                };
                let file_path = if file_path_array.is_null(row_idx) {
                    "NULL"
                } else {
                    file_path_array.value(row_idx)
                };
                let kind = if kind_array.is_null(row_idx) {
                    "NULL"
                } else {
                    kind_array.value(row_idx)
                };

                Ok(format!("{kind} {name} in {file_path}"))
            }
            _ => {
                // Generic format for other tables
                let first_col = batch.column(0);
                let first_value = match first_col.data_type() {
                    arrow::datatypes::DataType::Utf8 => {
                        let string_array = first_col
                            .as_any()
                            .downcast_ref::<arrow::array::StringArray>()
                            .unwrap();
                        if string_array.is_null(row_idx) {
                            "NULL".to_string()
                        } else {
                            string_array.value(row_idx).to_string()
                        }
                    }
                    _ => "...".to_string(),
                };
                Ok(format!("{table_name} row: {first_value}"))
            }
        }
    }

    pub async fn optimize_tables(&self) -> Result<()> {
        self.schema_manager.optimize_tables().await
    }

    pub async fn compact_and_cleanup(&self) -> Result<()> {
        self.schema_manager.compact_and_cleanup().await
    }

    /// Drop and recreate all tables for maximum space savings
    pub async fn drop_and_recreate_tables(&self) -> Result<()> {
        self.schema_manager.drop_and_recreate_tables().await
    }

    /// Drop and recreate a specific table
    pub async fn drop_and_recreate_table(&self, table_name: &str) -> Result<()> {
        self.schema_manager
            .drop_and_recreate_table(table_name)
            .await
    }

    pub async fn rebuild_indices(&self) -> Result<()> {
        self.schema_manager.rebuild_indices().await
    }

    pub async fn create_vector_index(&self) -> Result<()> {
        self.vector_search_manager.create_vector_index().await
    }

    // Combined batch operations for optimal performance
    pub async fn insert_batch_combined(
        &self,
        functions: Vec<FunctionInfo>,
        types: Vec<TypeInfo>,
        macros: Vec<MacroInfo>,
    ) -> Result<()> {
        // Step 1: Extract all content and combine into a single batch
        let mut all_content_items = Vec::new();

        // Extract function bodies
        for func in &functions {
            if !func.body.is_empty() {
                all_content_items.push(crate::database::content::ContentInfo {
                    blake3_hash: crate::hash::compute_blake3_hash(&func.body),
                    content: func.body.clone(),
                });
            }
        }

        // Extract type definitions
        for type_info in &types {
            if !type_info.definition.is_empty() {
                all_content_items.push(crate::database::content::ContentInfo {
                    blake3_hash: crate::hash::compute_blake3_hash(&type_info.definition),
                    content: type_info.definition.clone(),
                });
            }
        }

        // Extract macro definitions
        for macro_info in &macros {
            if !macro_info.definition.is_empty() {
                all_content_items.push(crate::database::content::ContentInfo {
                    blake3_hash: crate::hash::compute_blake3_hash(&macro_info.definition),
                    content: macro_info.definition.clone(),
                });
            }
        }

        // Step 2: Single content store operation (uses 16-way parallelization)
        if !all_content_items.is_empty() {
            self.content_store.insert_batch(all_content_items).await?;
        }

        // Step 3: Insert metadata in parallel (without individual content operations)
        let (func_result, type_result, macro_result) = tokio::join!(
            async {
                if !functions.is_empty() {
                    self.insert_functions_metadata_only(functions).await
                } else {
                    Ok(())
                }
            },
            async {
                if !types.is_empty() {
                    self.insert_types_metadata_only(types).await
                } else {
                    Ok(())
                }
            },
            async {
                if !macros.is_empty() {
                    self.insert_macros_metadata_only(macros).await
                } else {
                    Ok(())
                }
            }
        );

        func_result?;
        type_result?;
        macro_result?;

        Ok(())
    }

    // Function operations
    pub async fn insert_functions(&self, functions: Vec<FunctionInfo>) -> Result<()> {
        // FunctionStore now handles content storage internally
        self.function_store.insert_batch(functions).await
    }

    pub async fn find_function(&self, name: &str) -> Result<Option<FunctionInfo>> {
        // Get all functions with this name and select the best one (prefers .c over .h, implementations over declarations)
        let all_matches = self
            .function_store
            .find_all_by_name_unfiltered(name)
            .await?;
        if all_matches.is_empty() {
            return Ok(None);
        }

        // Use the same smart selection logic as git-aware lookups
        let best_match = self.select_best_function_match(all_matches);
        Ok(Some(best_match))
    }

    pub async fn find_function_git_aware(
        &self,
        name: &str,
        git_sha: &str,
    ) -> Result<Option<FunctionInfo>> {
        // Step 1: Get all functions with this name (no filtering)
        let all_functions = self
            .function_store
            .find_all_by_name_unfiltered(name)
            .await?;
        if all_functions.is_empty() {
            return Ok(None);
        }

        // Step 2: Extract unique file paths where this function appears
        let unique_file_paths: Vec<String> = all_functions
            .iter()
            .map(|f| f.file_path.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // Step 3: Resolve file paths to git hashes at target commit
        let resolved_hashes = self
            .resolve_git_file_hashes(&unique_file_paths, git_sha)
            .await?;
        if resolved_hashes.is_empty() {
            tracing::info!(
                "No files resolved for '{}' at commit '{}' - falling back to non-git lookup",
                name,
                git_sha
            );
            return self.find_function_fallback(name, &all_functions).await;
        }

        // Step 4: Direct targeted search for each (filename, git_hash) combination
        let mut matches = Vec::new();
        for (file_path, git_hash) in &resolved_hashes {
            if let Some(func) = self
                .function_store
                .find_by_name_file_and_hash(name, file_path, git_hash)
                .await?
            {
                matches.push(func);
            }
        }

        // Step 5: Pick the best result (prefer implementation over declaration)
        if matches.is_empty() {
            tracing::info!(
                "No exact matches found for '{}' at commit '{}', falling back to non-git lookup",
                name,
                git_sha
            );
            return self.find_function_fallback(name, &all_functions).await;
        }

        if matches.len() > 1 {
            tracing::info!(
                "WARNING: Found {} function matches for '{}' at git SHA {} - this may indicate a git filtering bug!",
                matches.len(),
                name,
                git_sha
            );
        }

        let best_match = self.select_best_function_match(matches);
        Ok(Some(best_match))
    }

    /// Find ALL functions by name at a specific git commit, excluding declarations
    pub async fn find_all_functions_git_aware(
        &self,
        name: &str,
        git_sha: &str,
    ) -> Result<Vec<FunctionInfo>> {
        // Step 1: Get all functions with this name (no filtering)
        let all_functions = self
            .function_store
            .find_all_by_name_unfiltered(name)
            .await?;
        if all_functions.is_empty() {
            return Ok(Vec::new());
        }

        // Step 2: Extract unique file paths where this function appears
        let unique_file_paths: Vec<String> = all_functions
            .iter()
            .map(|f| f.file_path.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        tracing::debug!(
            "find_all_functions_git_aware: Found {} unique files for function '{}'",
            unique_file_paths.len(),
            name
        );

        // Step 3: Resolve file paths to git hashes at target commit
        let resolved_hashes = self
            .resolve_git_file_hashes(&unique_file_paths, git_sha)
            .await?;
        if resolved_hashes.is_empty() {
            tracing::warn!("No files resolved for '{}' at commit '{}'", name, git_sha);
            // Return all functions but filter out declarations
            return Ok(self.filter_implementations_only(all_functions));
        }

        // Step 4: Direct targeted search for each (filename, git_hash) combination
        let mut matches = Vec::new();
        for (file_path, git_hash) in &resolved_hashes {
            tracing::debug!(
                "Searching for: name='{}' file='{}' hash='{}'",
                name,
                file_path,
                git_hash
            );
            if let Some(func) = self
                .function_store
                .find_by_name_file_and_hash(name, file_path, git_hash)
                .await?
            {
                tracing::debug!(
                    "Found match: {} in {} (hash: {})",
                    name,
                    file_path,
                    git_hash
                );
                matches.push(func);
            }
        }

        // Step 5: Filter out declarations but keep all implementations
        if matches.is_empty() {
            tracing::warn!(
                "No exact matches found for '{}' at commit '{}', falling back",
                name,
                git_sha
            );
            return Ok(self.filter_implementations_only(all_functions));
        }

        let implementations = self.filter_implementations_only(matches);
        tracing::info!(
            "Git-aware lookup succeeded: found {} implementations of '{}' at commit '{}'",
            implementations.len(),
            name,
            git_sha
        );
        Ok(implementations)
    }

    /// Filter out declarations, keeping only function implementations
    fn filter_implementations_only(&self, functions: Vec<FunctionInfo>) -> Vec<FunctionInfo> {
        functions
            .into_iter()
            .filter(|func| {
                // Filter criteria: exclude likely declarations
                let span = func.line_end.saturating_sub(func.line_start);
                let has_substantial_body = func.body.len() > 50; // More than just a declaration
                let is_likely_declaration = span <= 1 && func.body.trim().ends_with(';');

                // Keep functions that have substantial bodies and are not declarations
                has_substantial_body && !is_likely_declaration
            })
            .collect()
    }

    /// Select the best function match, prioritizing definitions over declarations
    fn select_best_function_match(&self, mut matches: Vec<FunctionInfo>) -> FunctionInfo {
        if matches.len() == 1 {
            return matches.into_iter().next().unwrap();
        }

        // Prioritize by multiple criteria
        matches.sort_by(|a, b| {
            // 1. Prefer .c files over .h files
            let a_is_source = a.file_path.ends_with(".c");
            let b_is_source = b.file_path.ends_with(".c");
            if a_is_source != b_is_source {
                return b_is_source.cmp(&a_is_source);
            }

            // 2. Prefer functions with bodies (implementations)
            let a_span = a.line_end.saturating_sub(a.line_start);
            let b_span = b.line_end.saturating_sub(b.line_start);
            let a_has_body = a_span > 0 && a.body.len() > 50;
            let b_has_body = b_span > 0 && b.body.len() > 50;
            if a_has_body != b_has_body {
                return b_has_body.cmp(&a_has_body);
            }

            // 3. Prefer functions with parameters
            let a_has_params = !a.parameters.is_empty();
            let b_has_params = !b.parameters.is_empty();
            if a_has_params != b_has_params {
                return b_has_params.cmp(&a_has_params);
            }

            // 4. Prefer longer bodies (more implementation detail)
            b.body.len().cmp(&a.body.len())
        });

        tracing::debug!(
            "Selected best match from {} candidates: {} in {}",
            matches.len(),
            matches[0].name,
            matches[0].file_path
        );

        matches.into_iter().next().unwrap()
    }

    /// Fallback function selection for git-aware lookups
    async fn find_function_fallback(
        &self,
        name: &str,
        available_functions: &[FunctionInfo],
    ) -> Result<Option<FunctionInfo>> {
        if let Some(fallback_func) = available_functions.first() {
            tracing::info!(
                "Using fallback function: {} in {} (hash: {})",
                name,
                fallback_func.file_path,
                fallback_func.git_file_hash
            );
            return Ok(Some(fallback_func.clone()));
        }
        Ok(None)
    }

    pub async fn find_all_functions(&self, name: &str) -> Result<Vec<FunctionInfo>> {
        self.function_store.find_all_by_name(name).await
    }

    /// Get access to the vector store for dimension verification
    pub async fn get_vector_store(&self) -> Result<VectorStore> {
        Ok(VectorStore::new(self.connection.clone()))
    }

    pub async fn get_all_functions(&self) -> Result<Vec<FunctionInfo>> {
        self.function_store.get_all().await
    }

    pub async fn get_all_functions_metadata_only(&self) -> Result<Vec<FunctionInfo>> {
        self.function_store.get_all_metadata_only().await
    }

    pub async fn search_functions_fuzzy(&self, pattern: &str) -> Result<Vec<FunctionInfo>> {
        self.search_manager.search_functions_fuzzy(pattern).await
    }

    pub async fn search_functions_fuzzy_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<FunctionInfo>> {
        self.search_manager
            .search_functions_fuzzy_git_aware(pattern, git_sha)
            .await
    }

    pub async fn update_vectors(&self, vectorizer: &CodeVectorizer) -> Result<()> {
        self.vector_search_manager.update_vectors(vectorizer).await
    }

    pub async fn search_similar_functions_with_scores(
        &self,
        query_vector: &[f32],
        limit: usize,
        filter: Option<String>,
    ) -> Result<Vec<crate::database::search::FunctionMatch>> {
        self.vector_search_manager
            .search_similar_functions_with_scores(query_vector, limit, filter)
            .await
    }

    pub async fn search_similar_functions(
        &self,
        query_vector: &[f32],
        limit: usize,
        filter: Option<String>,
    ) -> Result<Vec<FunctionInfo>> {
        self.vector_search_manager
            .search_similar_functions(query_vector, limit, filter)
            .await
    }

    pub async fn search_similar_by_name(
        &self,
        vectorizer: &CodeVectorizer,
        name: &str,
        limit: usize,
    ) -> Result<Vec<FunctionInfo>> {
        self.vector_search_manager
            .search_similar_by_name(vectorizer, name, limit)
            .await
    }

    // Type operations
    pub async fn insert_types(&self, types: Vec<TypeInfo>) -> Result<()> {
        // Extract unique type definitions and store them in content table for deduplication
        let mut unique_definitions = std::collections::HashSet::new();
        for type_info in &types {
            if !type_info.definition.is_empty() {
                unique_definitions.insert(type_info.definition.clone());
            }
        }

        // Store unique type definitions in content table
        if !unique_definitions.is_empty() {
            let unique_count = unique_definitions.len();
            let content_items: Vec<crate::database::content::ContentInfo> = unique_definitions
                .into_iter()
                .map(|definition| crate::database::content::ContentInfo {
                    blake3_hash: crate::hash::compute_blake3_hash(&definition),
                    content: definition,
                })
                .collect();

            // Insert content items with batch existence checking
            if let Err(e) = self.content_store.insert_batch(content_items).await {
                tracing::warn!("Failed to populate content table during insertion: {}", e);
                // Continue with insertion even if content storage fails
            } else {
                tracing::debug!(
                    "Successfully populated content table with {} unique type definitions",
                    unique_count
                );
            }
        }

        // Insert types as usual (keeping existing definition column for now)
        self.type_store.insert_batch(types).await
    }

    pub async fn find_type(&self, name: &str) -> Result<Option<TypeInfo>> {
        self.type_store.find_by_name(name).await
    }

    pub async fn find_type_git_aware(&self, name: &str, git_sha: &str) -> Result<Option<TypeInfo>> {
        self.type_store
            .find_by_name_git_aware(name, git_sha, &self.git_repo_path)
            .await
    }

    pub async fn get_all_types(&self) -> Result<Vec<TypeInfo>> {
        self.type_store.get_all().await
    }

    /// Get all types without resolving content hashes - much faster for dumps
    pub async fn get_all_types_metadata_only(&self) -> Result<Vec<TypeInfo>> {
        self.type_store.get_all_metadata_only().await
    }

    /// Count all types without resolving content - much faster for counts
    pub async fn count_types(&self) -> Result<usize> {
        self.type_store.count_all().await
    }

    /// Count all functions without resolving content - much faster for counts
    pub async fn count_functions(&self) -> Result<usize> {
        self.function_store.count_all().await
    }

    /// Count all macros without resolving content - much faster for counts
    pub async fn count_macros(&self) -> Result<usize> {
        self.macro_store.count_all().await
    }

    /// Count all typedefs without resolving content - much faster for counts
    pub async fn count_typedefs(&self) -> Result<usize> {
        self.typedef_store.count_all().await
    }

    pub async fn search_types_fuzzy(&self, pattern: &str) -> Result<Vec<TypeInfo>> {
        self.search_manager.search_types_fuzzy(pattern).await
    }

    pub async fn search_types_fuzzy_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<TypeInfo>> {
        self.search_manager
            .search_types_fuzzy_git_aware(pattern, git_sha)
            .await
    }

    pub async fn search_types_by_kind(&self, kind: &str) -> Result<Vec<TypeInfo>> {
        self.search_manager.search_types_by_kind(kind).await
    }

    pub async fn type_exists(&self, name: &str, kind: &str, file_path: &str) -> Result<bool> {
        self.type_store.exists(name, kind, file_path).await
    }

    // Typedef operations
    pub async fn insert_typedefs(&self, typedefs: Vec<TypedefInfo>) -> Result<()> {
        // Extract unique typedef definitions and store them in content table for deduplication
        let mut unique_definitions = std::collections::HashSet::new();
        for typedef_info in &typedefs {
            if !typedef_info.definition.is_empty() {
                unique_definitions.insert(typedef_info.definition.clone());
            }
        }

        // Store unique typedef definitions in content table
        if !unique_definitions.is_empty() {
            let unique_count = unique_definitions.len();
            let content_items: Vec<crate::database::content::ContentInfo> = unique_definitions
                .into_iter()
                .map(|definition| crate::database::content::ContentInfo {
                    blake3_hash: crate::hash::compute_blake3_hash(&definition),
                    content: definition,
                })
                .collect();

            // Insert content items with batch existence checking
            if let Err(e) = self.content_store.insert_batch(content_items).await {
                tracing::warn!("Failed to populate content table during insertion: {}", e);
                // Continue with insertion even if content storage fails
            } else {
                tracing::debug!(
                    "Successfully populated content table with {} unique typedef definitions",
                    unique_count
                );
            }
        }

        // Insert typedefs as usual (keeping existing definition column for now)
        self.typedef_store.insert_batch(typedefs).await
    }

    pub async fn find_typedef(&self, name: &str) -> Result<Option<TypedefInfo>> {
        self.typedef_store.find_by_name(name).await
    }

    pub async fn find_typedef_git_aware(
        &self,
        name: &str,
        git_sha: &str,
    ) -> Result<Option<TypedefInfo>> {
        self.typedef_store
            .find_by_name_git_aware(name, git_sha, &self.git_repo_path)
            .await
    }

    pub async fn get_all_typedefs(&self) -> Result<Vec<TypedefInfo>> {
        self.typedef_store.get_all().await
    }

    pub async fn search_typedefs_fuzzy(&self, pattern: &str) -> Result<Vec<TypedefInfo>> {
        self.search_manager.search_typedefs_fuzzy(pattern).await
    }

    pub async fn search_typedefs_fuzzy_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<TypedefInfo>> {
        self.search_manager
            .search_typedefs_fuzzy_git_aware(pattern, git_sha)
            .await
    }

    pub async fn typedef_exists(&self, name: &str, file_path: &str) -> Result<bool> {
        self.typedef_store.exists(name, file_path).await
    }

    /// Search types using regex patterns on the name column
    pub async fn search_types_regex(&self, pattern: &str) -> Result<Vec<TypeInfo>> {
        self.search_manager.search_types_regex(pattern).await
    }

    /// Search types using regex patterns on the name column (git-aware)
    pub async fn search_types_regex_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<TypeInfo>> {
        self.search_manager
            .search_types_regex_git_aware(pattern, git_sha)
            .await
    }

    /// Search typedefs using regex patterns on the name column
    pub async fn search_typedefs_regex(&self, pattern: &str) -> Result<Vec<TypedefInfo>> {
        self.search_manager.search_typedefs_regex(pattern).await
    }

    /// Search typedefs using regex patterns on the name column (git-aware)
    pub async fn search_typedefs_regex_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<TypedefInfo>> {
        self.search_manager
            .search_typedefs_regex_git_aware(pattern, git_sha)
            .await
    }

    // Macro operations
    pub async fn insert_macros(&self, macros: Vec<MacroInfo>) -> Result<()> {
        // Extract unique macro definitions and expansions and store them in content table for deduplication
        let mut unique_content = std::collections::HashSet::new();
        for macro_info in &macros {
            if !macro_info.definition.is_empty() {
                unique_content.insert(macro_info.definition.clone());
            }
        }

        // Store unique macro content in content table
        if !unique_content.is_empty() {
            let unique_count = unique_content.len();
            let content_items: Vec<crate::database::content::ContentInfo> = unique_content
                .into_iter()
                .map(|content| crate::database::content::ContentInfo {
                    blake3_hash: crate::hash::compute_blake3_hash(&content),
                    content,
                })
                .collect();

            // Insert content items with batch existence checking
            if let Err(e) = self.content_store.insert_batch(content_items).await {
                tracing::warn!("Failed to populate content table during insertion: {}", e);
                // Continue with insertion even if content storage fails
            } else {
                tracing::debug!("Successfully populated content table with {} unique macro definitions/expansions", unique_count);
            }
        }

        // Insert macros as usual (keeping existing definition and expansion columns for now)
        self.macro_store.insert_batch(macros).await
    }

    pub async fn find_macro(&self, name: &str) -> Result<Option<MacroInfo>> {
        self.macro_store.find_by_name(name).await
    }

    // Metadata-only insertion methods (skip content storage for performance)
    async fn insert_functions_metadata_only(&self, functions: Vec<FunctionInfo>) -> Result<()> {
        self.function_store.insert_metadata_only(functions).await
    }

    async fn insert_types_metadata_only(&self, types: Vec<TypeInfo>) -> Result<()> {
        self.type_store.insert_metadata_only(types).await
    }

    async fn insert_macros_metadata_only(&self, macros: Vec<MacroInfo>) -> Result<()> {
        self.macro_store.insert_metadata_only(macros).await
    }

    pub async fn find_macro_git_aware(
        &self,
        name: &str,
        git_sha: &str,
    ) -> Result<Option<MacroInfo>> {
        // Phase 1: Get all file paths for macros with this name
        let all_macros = self.macro_store.find_all_by_name(name).await?;
        if all_macros.is_empty() {
            return Ok(None);
        }

        // Phase 2: Resolve file paths to git blob hashes using centralized method
        let file_paths: Vec<String> = all_macros
            .iter()
            .map(|m| m.file_path.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let resolved_hashes = self.resolve_git_file_hashes(&file_paths, git_sha).await?;
        if resolved_hashes.is_empty() {
            return Ok(None);
        }

        // Phase 3: Find macro with matching git blob hash
        for mac in all_macros {
            if let Some(expected_hash) = resolved_hashes.get(&mac.file_path) {
                if &mac.git_file_hash == expected_hash {
                    return Ok(Some(mac));
                }
            }
        }

        Ok(None)
    }

    pub async fn get_all_macros(&self) -> Result<Vec<MacroInfo>> {
        self.macro_store.get_all().await
    }

    pub async fn get_all_macros_metadata_only(&self) -> Result<Vec<MacroInfo>> {
        self.macro_store.get_all_metadata_only().await
    }

    pub async fn search_macros_fuzzy(&self, pattern: &str) -> Result<Vec<MacroInfo>> {
        self.search_manager.search_macros_fuzzy(pattern).await
    }

    pub async fn search_macros_fuzzy_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<MacroInfo>> {
        self.search_manager
            .search_macros_fuzzy_git_aware(pattern, git_sha)
            .await
    }

    // ==================== USR-based lookups (clangd integration) ====================

    /// Find a function by its USR (Unified Symbol Resolution from clangd)
    pub async fn find_function_by_usr(&self, usr: &str) -> Result<Option<FunctionInfo>> {
        self.function_store.find_by_usr(usr).await
    }

    /// Find a type by its USR
    pub async fn find_type_by_usr(&self, usr: &str) -> Result<Option<TypeInfo>> {
        self.type_store.find_by_usr(usr).await
    }

    /// Find a macro by its USR
    pub async fn find_macro_by_usr(&self, usr: &str) -> Result<Option<MacroInfo>> {
        self.macro_store.find_by_usr(usr).await
    }

    /// Find any symbol by USR (checks functions, macros, and types in priority order)
    pub async fn find_symbol_by_usr(&self, usr: &str) -> Result<Option<String>> {
        // Check functions first
        if let Some(func) = self.find_function_by_usr(usr).await? {
            return Ok(Some(format!(
                "function {} in {}:{}",
                func.name, func.file_path, func.line_start
            )));
        }

        // Check macros
        if let Some(mac) = self.find_macro_by_usr(usr).await? {
            return Ok(Some(format!(
                "macro {} in {}:{}",
                mac.name, mac.file_path, mac.line_start
            )));
        }

        // Check types
        if let Some(ty) = self.find_type_by_usr(usr).await? {
            return Ok(Some(format!(
                "type {} in {}:{}",
                ty.name, ty.file_path, ty.line_start
            )));
        }

        Ok(None)
    }

    /// Search functions using regex patterns on the name column
    pub async fn search_functions_regex(&self, pattern: &str) -> Result<Vec<FunctionInfo>> {
        self.search_manager.search_functions_regex(pattern).await
    }

    /// Search functions using regex patterns on the name column (git-aware)
    pub async fn search_functions_regex_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<FunctionInfo>> {
        self.search_manager
            .search_functions_regex_git_aware(pattern, git_sha)
            .await
    }

    /// Search macros using regex patterns on the name column
    pub async fn search_macros_regex(&self, pattern: &str) -> Result<Vec<MacroInfo>> {
        self.search_manager.search_macros_regex(pattern).await
    }

    /// Search macros using regex patterns on the name column (git-aware)
    pub async fn search_macros_regex_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<MacroInfo>> {
        self.search_manager
            .search_macros_regex_git_aware(pattern, git_sha)
            .await
    }

    pub async fn macro_exists(&self, name: &str, file_path: &str) -> Result<bool> {
        self.macro_store.exists(name, file_path).await
    }

    // Call relationship operations
    // Call relationship insertion/resolution methods removed - call relationships are now embedded in function JSON columns

    pub async fn get_function_callers(&self, function_name: &str) -> Result<Vec<String>> {
        // Use efficient filtering: find functions whose calls JSON contains the target function name
        let escaped_name = function_name.replace("'", "''"); // SQL escape
        let table = self.connection.open_table("functions").execute().await?;

        // Filter for functions whose calls column contains the target function name
        // This is much more efficient than a full table scan
        let filter = format!("calls IS NOT NULL AND calls LIKE '%\"{escaped_name}\"%%'");
        let results = table
            .query()
            .only_if(filter)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut callers = std::collections::HashSet::new();
        for batch in results {
            if batch.num_rows() > 0 {
                let name_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                // Find the calls column (should be at index based on schema)
                let calls_column_idx = batch
                    .schema()
                    .fields()
                    .iter()
                    .position(|f| f.name() == "calls")
                    .ok_or_else(|| anyhow::anyhow!("calls column not found in functions table"))?;
                let calls_array = batch
                    .column(calls_column_idx)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    if !calls_array.is_null(i) {
                        let caller_name = name_array.value(i).to_string();
                        let calls_json = calls_array.value(i);

                        // Parse JSON and verify it actually contains function_name
                        // (the LIKE filter might have false positives)
                        if let Ok(calls_list) = serde_json::from_str::<Vec<String>>(calls_json) {
                            if calls_list.contains(&function_name.to_string()) {
                                callers.insert(caller_name);
                            }
                        }
                    }
                }
            }
        }

        Ok(callers.into_iter().collect())
    }

    pub async fn get_function_callers_git_aware(
        &self,
        function_name: &str,
        git_sha: &str,
    ) -> Result<Vec<String>> {
        // Step 1: Get all file paths that exist at the target git SHA
        // This is much more efficient than checking each file individually
        let all_file_paths: Vec<String> = {
            let table = self.connection.open_table("functions").execute().await?;
            let results = table
                .query()
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            let mut paths = std::collections::HashSet::new();
            for batch in results {
                if batch.num_rows() > 0 {
                    let file_path_array = batch
                        .column(1) // file_path is column index 1
                        .as_any()
                        .downcast_ref::<arrow::array::StringArray>()
                        .unwrap();
                    for i in 0..batch.num_rows() {
                        paths.insert(file_path_array.value(i).to_string());
                    }
                }
            }
            paths.into_iter().collect()
        };

        // Step 2: Resolve all file hashes at once (bulk operation)
        let resolved_hashes = self
            .resolve_git_file_hashes(&all_file_paths, git_sha)
            .await?;
        if resolved_hashes.is_empty() {
            return Ok(Vec::new());
        }

        // Step 3: Build hash set of valid git file hashes for fast lookup
        let valid_hashes: std::collections::HashSet<String> =
            resolved_hashes.values().cloned().collect();

        // Step 4: Query functions with optimized filtering
        let escaped_name = function_name.replace("'", "''"); // SQL escape
        let table = self.connection.open_table("functions").execute().await?;

        // Filter for functions whose calls column contains the target function name
        let filter = format!("calls IS NOT NULL AND calls LIKE '%\"{escaped_name}\"%%'");
        let results = table
            .query()
            .only_if(filter)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut callers = Vec::new();

        for batch in results {
            if batch.num_rows() > 0 {
                let name_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let git_file_hash_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                // Find the calls column
                let calls_column_idx = batch
                    .schema()
                    .fields()
                    .iter()
                    .position(|f| f.name() == "calls")
                    .ok_or_else(|| anyhow::anyhow!("calls column not found in functions table"))?;
                let calls_array = batch
                    .column(calls_column_idx)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    let caller_name = name_array.value(i);
                    let git_file_hash = git_file_hash_array.value(i).to_string();

                    // Step 5: Fast hash lookup instead of expensive per-file git resolution
                    if valid_hashes.contains(&git_file_hash) {
                        // This function exists at the git SHA, verify it actually calls our target
                        // (the LIKE filter might have false positives)
                        if !calls_array.is_null(i) {
                            let calls_json = calls_array.value(i);
                            if let Ok(calls_list) = serde_json::from_str::<Vec<String>>(calls_json)
                            {
                                if calls_list.contains(&function_name.to_string()) {
                                    callers.push(caller_name.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(callers)
    }

    // Optimized methods for call chain analysis

    /// Get functions that have no callers (entry points)
    pub async fn get_entry_point_functions(&self) -> Result<Vec<String>> {
        // New schema: find functions that make calls but are never called by others
        let table = self.connection.open_table("functions").execute().await?;
        let results = table
            .query()
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut functions_with_calls = std::collections::HashSet::new();
        let mut functions_that_are_called = std::collections::HashSet::new();

        for batch in results {
            if batch.num_rows() > 0 {
                let name_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                // Find the calls column
                let calls_column_idx = batch
                    .schema()
                    .fields()
                    .iter()
                    .position(|f| f.name() == "calls")
                    .ok_or_else(|| anyhow::anyhow!("calls column not found in functions table"))?;
                let calls_array = batch
                    .column(calls_column_idx)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    let function_name = name_array.value(i).to_string();

                    // Check if this function makes calls
                    if !calls_array.is_null(i) {
                        let calls_json = calls_array.value(i);
                        if let Ok(calls_list) = serde_json::from_str::<Vec<String>>(calls_json) {
                            if !calls_list.is_empty() {
                                functions_with_calls.insert(function_name.clone());
                                // Add all called functions to the set
                                for called_func in calls_list {
                                    functions_that_are_called.insert(called_func);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Entry points are functions that make calls but are never called
        let entry_points: Vec<String> = functions_with_calls
            .difference(&functions_that_are_called)
            .cloned()
            .collect();

        Ok(entry_points)
    }

    /// Get functions by a list of names (batch lookup)
    pub async fn get_functions_by_names(
        &self,
        names: &[String],
    ) -> Result<std::collections::HashMap<String, FunctionInfo>> {
        self.function_store.get_by_names(names).await
    }

    /// Get macros by a list of names (batch lookup)
    pub async fn get_macros_by_names(
        &self,
        names: &[String],
    ) -> Result<std::collections::HashMap<String, MacroInfo>> {
        self.macro_store.get_by_names(names).await
    }

    /// Get types by a list of names (batch lookup)
    pub async fn get_types_by_names(
        &self,
        names: &[String],
    ) -> Result<std::collections::HashMap<String, TypeInfo>> {
        self.type_store.get_by_names(names).await
    }

    /// Get typedefs by a list of names (batch lookup)
    pub async fn get_typedefs_by_names(
        &self,
        names: &[String],
    ) -> Result<std::collections::HashMap<String, TypedefInfo>> {
        self.typedef_store.get_by_names(names).await
    }

    /// Efficiently collect functions in a call chain from a starting function
    /// Uses different strategies based on database size
    pub async fn collect_callchain_functions(
        &self,
        start_function: &str,
        max_depth: usize,
        include_forward: bool,
        include_reverse: bool,
        git_sha: Option<&str>,
    ) -> Result<std::collections::HashSet<String>> {
        // For small databases (< 1000 functions), use the old full-scan approach
        // For large databases, use targeted queries
        let function_count = self.get_function_count().await?;

        if function_count < 1000 {
            // Small database: use in-memory approach (faster for small datasets)
            self.collect_callchain_functions_in_memory(
                start_function,
                max_depth,
                include_forward,
                include_reverse,
                git_sha,
            )
            .await
        } else {
            // Large database: use targeted queries
            self.collect_callchain_functions_targeted(
                start_function,
                max_depth,
                include_forward,
                include_reverse,
                git_sha,
            )
            .await
        }
    }

    /// Get total function count (cached/efficient)
    async fn get_function_count(&self) -> Result<usize> {
        let table = self.connection.open_table("functions").execute().await?;
        Ok(table.count_rows(None).await?)
    }

    /// Use full in-memory approach (good for small databases)
    async fn collect_callchain_functions_in_memory(
        &self,
        start_function: &str,
        max_depth: usize,
        include_forward: bool,
        include_reverse: bool,
        git_sha: Option<&str>,
    ) -> Result<std::collections::HashSet<String>> {
        // For small databases, we'll still use the targeted approach with call store
        // since the embedded call fields have been removed
        self.collect_callchain_functions_targeted(
            start_function,
            max_depth,
            include_forward,
            include_reverse,
            git_sha,
        )
        .await
    }

    /// Use targeted queries (good for large databases) - optimized with git manifest for 10-100x speedup
    async fn collect_callchain_functions_targeted(
        &self,
        start_function: &str,
        max_depth: usize,
        include_forward: bool,
        include_reverse: bool,
        git_sha: Option<&str>,
    ) -> Result<std::collections::HashSet<String>> {
        // Optimize git-aware operations by generating manifest once
        let git_manifest = if let Some(sha) = git_sha {
            tracing::info!(
                "Generating git manifest for callchain optimization at commit: {}",
                sha
            );
            Some(self.generate_git_manifest(sha).await?)
        } else {
            None
        };

        let mut result = std::collections::HashSet::new();
        let mut to_visit = std::collections::VecDeque::new();
        let mut visited = std::collections::HashSet::new();

        to_visit.push_back((start_function.to_string(), 0));
        result.insert(start_function.to_string());

        while let Some((func_name, depth)) = to_visit.pop_front() {
            if depth >= max_depth || visited.contains(&func_name) {
                continue;
            }

            visited.insert(func_name.clone());

            // Get function details to find call relationships
            let function_exists = if let Some(manifest) = &git_manifest {
                self.function_exists_in_manifest(&func_name, manifest)
                    .await?
            } else {
                self.find_function(&func_name).await?.is_some()
            };

            if function_exists {
                if include_forward {
                    let callees = if let Some(manifest) = &git_manifest {
                        self.get_function_callees_with_manifest(&func_name, manifest)
                            .await?
                    } else {
                        self.get_function_callees(&func_name).await?
                    };
                    for callee in callees {
                        if !result.contains(&callee) {
                            result.insert(callee.clone());
                            to_visit.push_back((callee, depth + 1));
                        }
                    }
                }

                if include_reverse {
                    let callers = if let Some(manifest) = &git_manifest {
                        self.get_function_callers_with_manifest(&func_name, manifest)
                            .await?
                    } else {
                        self.get_function_callers(&func_name).await?
                    };
                    for caller in callers {
                        if !result.contains(&caller) {
                            result.insert(caller.clone());
                            to_visit.push_back((caller, depth + 1));
                        }
                    }
                }
            }

            // Also check if it's a macro
            let macro_exists = if let Some(manifest) = &git_manifest {
                self.macro_exists_in_manifest(&func_name, manifest).await?
            } else {
                self.find_macro(&func_name).await?.is_some()
            };

            if macro_exists {
                if include_forward {
                    let callees = if let Some(manifest) = &git_manifest {
                        self.get_function_callees_with_manifest(&func_name, manifest)
                            .await?
                    } else {
                        self.get_function_callees(&func_name).await?
                    };
                    for callee in callees {
                        if !result.contains(&callee) {
                            result.insert(callee.clone());
                            to_visit.push_back((callee, depth + 1));
                        }
                    }
                }

                if include_reverse {
                    let callers = if let Some(manifest) = &git_manifest {
                        self.get_function_callers_with_manifest(&func_name, manifest)
                            .await?
                    } else {
                        self.get_function_callers(&func_name).await?
                    };
                    for caller in callers {
                        if !result.contains(&caller) {
                            result.insert(caller.clone());
                            to_visit.push_back((caller, depth + 1));
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    pub async fn get_function_callees(&self, function_name: &str) -> Result<Vec<String>> {
        // Get all functions with this name and select the best one (prefers definitions over declarations)
        let all_matches = self
            .function_store
            .find_all_by_name_unfiltered(function_name)
            .await?;
        if all_matches.is_empty() {
            return Ok(Vec::new());
        }

        // Use the same smart selection logic to prefer implementations over declarations
        let best_match = self.select_best_function_match(all_matches);

        // Get the calls from the best match (already deserialized as Vec<String>)
        if let Some(ref calls_list) = best_match.calls {
            return Ok(calls_list.clone());
        }

        Ok(Vec::new())
    }

    pub async fn get_function_callees_git_aware(
        &self,
        function_name: &str,
        git_sha: &str,
    ) -> Result<Vec<String>> {
        // First find the specific function at the given git SHA
        let func_opt = self.find_function_git_aware(function_name, git_sha).await?;
        let func = match func_opt {
            Some(f) => f,
            None => return Ok(Vec::new()), // Function doesn't exist at this git SHA
        };

        // Get callees from the specific function's embedded JSON
        // Since we found the function at the specific git SHA, its calls list is already accurate for that commit
        let callees = match &func.calls {
            Some(calls_list) => calls_list.clone(),
            None => Vec::new(),
        };

        Ok(callees)
    }

    pub async fn get_all_call_relationships(&self) -> Result<Vec<CallRelationship>> {
        // New schema: reconstruct call relationships from embedded JSON in functions table
        let table = self.connection.open_table("functions").execute().await?;
        let results = table
            .query()
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut all_relationships = Vec::new();

        for batch in results {
            if batch.num_rows() > 0 {
                let name_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let git_file_hash_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                // Find the calls column
                let calls_column_idx = batch
                    .schema()
                    .fields()
                    .iter()
                    .position(|f| f.name() == "calls")
                    .ok_or_else(|| anyhow::anyhow!("calls column not found in functions table"))?;
                let calls_array = batch
                    .column(calls_column_idx)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    let caller_name = name_array.value(i).to_string();
                    let caller_git_file_hash = git_file_hash_array.value(i).to_string();

                    if !calls_array.is_null(i) {
                        let calls_json = calls_array.value(i);
                        if let Ok(calls_list) = serde_json::from_str::<Vec<String>>(calls_json) {
                            for callee_name in calls_list {
                                // For now, we can't easily get callee git hash without additional lookups
                                // This is a limitation of the new schema - we'd need to do individual lookups
                                all_relationships.push(CallRelationship {
                                    caller: caller_name.clone(),
                                    callee: callee_name,
                                    caller_git_file_hash: caller_git_file_hash.clone(),
                                    callee_git_file_hash: None, // Would require lookup
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(all_relationships)
    }

    /// Run database optimization and rebuild indices
    pub async fn optimize_database(&self) -> Result<()> {
        tracing::info!("Running database optimization...");

        // Rebuild all scalar indices to ensure they're optimal
        self.rebuild_indices().await?;

        // Run table optimization
        self.optimize_tables().await?;

        // Compact and cleanup (triggers compression)
        self.compact_and_cleanup().await?;

        tracing::info!("Database optimization complete");
        Ok(())
    }

    /// Get database storage statistics and compression info
    pub async fn get_storage_stats(&self) -> Result<()> {
        let table_names = self.connection.table_names().execute().await?;
        let mut total_rows = 0;

        println!("{}", "=== Database Storage Statistics ===".bold().green());

        // Process main tables
        for table_name in &["functions", "types", "macros", "processed_files"] {
            if table_names.iter().any(|n| n == table_name) {
                let table = self.connection.open_table(*table_name).execute().await?;
                match table.count_rows(None).await {
                    Ok(count) => {
                        println!("{}: {} rows", table_name.cyan(), count.to_string().yellow());
                        total_rows += count;

                        // Estimate storage for functions table (largest consumer)
                        if *table_name == "functions" {
                            // Get vector statistics from the separate vectors table
                            use crate::database::vectors::VectorStore;
                            let vector_store = VectorStore::new(self.connection.clone());
                            let total_vectors = vector_store.get_stats().await.unwrap_or(0);
                            // Since we now store vectors by content hash, we can't directly
                            // correlate with function count, so we'll estimate
                            let functions_with_vectors = total_vectors; // Approximate
                            let functions_without_vectors = count - functions_with_vectors;
                            let actual_vector_storage = functions_with_vectors * 256 * 4; // bytes for actual vectors (model2vec)
                            let est_text_storage = count * 2048; // rough estimate for bodies

                            println!(
                                "  Functions with vectors: {}",
                                functions_with_vectors.to_string().green()
                            );
                            println!(
                                "  Functions without vectors: {}",
                                functions_without_vectors.to_string().cyan()
                            );
                            println!(
                                "  Vector storage: {} MB",
                                (actual_vector_storage / 1024 / 1024).to_string().yellow()
                            );
                            println!(
                                "  Estimated text storage: {} MB",
                                (est_text_storage / 1024 / 1024).to_string().yellow()
                            );

                            if functions_with_vectors > 0 {
                                let vector_efficiency =
                                    (functions_with_vectors as f64 / count as f64) * 100.0;
                                println!(
                                    "  Vector coverage: {:.1}%",
                                    vector_efficiency.to_string().bold().green()
                                );
                            }
                        }
                    }
                    Err(e) => {
                        println!("{}: Error getting count - {}", table_name.red(), e);
                    }
                }
            }
        }

        // Process content shard tables (content_0 through content_15) and aggregate stats
        let mut total_content_rows = 0;
        for shard in 0..16u8 {
            let table_name = format!("content_{shard}");
            let table = self.connection.open_table(&table_name).execute().await?;
            match table.count_rows(None).await {
                Ok(count) => {
                    total_content_rows += count;
                }
                Err(e) => {
                    println!("{}: Error getting count - {}", table_name.red(), e);
                }
            }
        }

        if total_content_rows > 0 {
            println!(
                "{}: {} rows (across 16 shards)",
                "content".cyan(),
                total_content_rows.to_string().yellow()
            );
            total_rows += total_content_rows;
        }

        println!(
            "{}: {} rows",
            "Total".bold(),
            total_rows.to_string().yellow()
        );
        println!(
            "\n{}",
            "Note: LanceDB uses columnar compression (LZ4/ZSTD) automatically".bright_black()
        );
        println!(
            "{}",
            "Vectors are stored in a separate table for deduplication and efficiency"
                .bright_black()
        );

        Ok(())
    }

    /// Optimize database files and consolidate data fragments  
    pub async fn compact_database(&self) -> Result<()> {
        tracing::info!("Running database optimization to reduce file size...");

        // Step 1: Run optimization and cleanup sequence
        self.compact_and_cleanup().await?;

        // Step 2: CRITICAL - Drop old table references and recreate to release handles
        tracing::info!("Releasing old table handles and checking out latest versions...");

        // Force recreation of table connections to release old version handles
        // This is crucial for LanceDB garbage collection to work properly
        let table_names = self.connection.table_names().execute().await?;

        for table_name in &["functions", "types", "macros"] {
            if table_names.iter().any(|n| n == table_name) {
                // Open table with fresh handle and checkout latest
                match self.connection.open_table(*table_name).execute().await {
                    Ok(table) => {
                        // Checkout latest version to ensure we're not holding old handles
                        if let Err(e) = table.checkout_latest().await {
                            tracing::warn!("Could not checkout latest for {}: {}", table_name, e);
                        }
                        // Table handle will be dropped automatically when it goes out of scope
                    }
                    Err(e) => {
                        tracing::warn!("Could not reopen table {}: {}", table_name, e);
                    }
                }
            }
        }

        tracing::info!("Database optimization and handle cleanup complete");
        Ok(())
    }

    /// Get compaction statistics
    pub async fn get_compaction_stats(&self) -> Result<()> {
        let table_names = self.connection.table_names().execute().await?;

        println!(
            "{}",
            "=== Database Compaction Statistics ===".bold().green()
        );

        // Process main tables
        for table_name in &["functions", "types", "macros", "processed_files"] {
            if table_names.iter().any(|n| n == table_name) {
                let table = self.connection.open_table(*table_name).execute().await?;

                match table.count_rows(None).await {
                    Ok(count) => {
                        println!("{}: {} rows", table_name.cyan(), count.to_string().yellow());

                        // Try to get more detailed stats if available
                        // Note: Specific LanceDB version info may not be accessible in all versions
                    }
                    Err(e) => {
                        println!("{}: Error - {}", table_name.red(), e);
                    }
                }
            }
        }

        // Process content shard tables (content_0 through content_15)
        let mut total_content_rows = 0;
        for shard in 0..16u8 {
            let table_name = format!("content_{shard}");
            let table = self.connection.open_table(&table_name).execute().await?;
            match table.count_rows(None).await {
                Ok(count) => {
                    total_content_rows += count;
                }
                Err(e) => {
                    println!("{}: Error - {}", table_name.red(), e);
                }
            }
        }

        if total_content_rows > 0 {
            println!(
                "{}: {} rows (across 16 shards)",
                "content".cyan(),
                total_content_rows.to_string().yellow()
            );
        }

        println!("\n{}", "Tips for compaction and cleanup:".bold().cyan());
        println!("• Run 'compact_db' periodically after large data imports");
        println!(
            "• Current implementation uses optimize() + checkout_latest() + handle management"
        );
        println!("• If database keeps growing, the LanceDB version may not expose cleanup_old_versions()");
        println!("• Manual cleanup may require external tools or newer LanceDB versions");
        println!("• Check LanceDB logs for actual cleanup statistics");

        Ok(())
    }

    // clear_call_relationships removed - calls table no longer exists

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Centralized git file hash resolution for all stores
    /// Resolves file paths to git blob hashes at a specific commit using gitoxide
    pub async fn resolve_git_file_hashes(
        &self,
        file_paths: &[String],
        git_sha: &str,
    ) -> Result<std::collections::HashMap<String, String>> {
        match crate::git::resolve_files_at_commit(&self.git_repo_path, git_sha, file_paths) {
            Ok(resolved_hashes) => {
                // If no files were resolved, log this as a warning
                if resolved_hashes.is_empty() {
                    tracing::warn!(
                        "No files were resolved at commit {} in repository {}",
                        git_sha,
                        self.git_repo_path
                    );
                }

                Ok(resolved_hashes)
            }
            Err(e) => {
                tracing::error!("DatabaseManager::resolve_git_file_hashes: Failed to resolve git files at commit {}: {}", git_sha, e);
                tracing::error!("Repository path: {}", self.git_repo_path);
                tracing::error!("Requested file paths: {:?}", file_paths);
                Ok(std::collections::HashMap::new()) // Return empty map instead of failing, let caller handle
            }
        }
    }

    // Processed files operations

    /// Record that a file has been processed with the given git SHA and file content hash
    pub async fn mark_file_processed(
        &self,
        file: String,
        git_sha: Option<String>,
        git_file_sha: String,
    ) -> Result<()> {
        let record = ProcessedFileRecord {
            file,
            git_sha,
            git_file_sha,
        };
        self.processed_file_store.insert(record).await
    }

    /// Record multiple processed files
    pub async fn mark_files_processed(&self, records: Vec<ProcessedFileRecord>) -> Result<()> {
        self.processed_file_store.insert_batch(records).await
    }

    /// Check if a file has been processed with the given git SHA and file content hash
    pub async fn is_file_processed(&self, git_file_sha: &str) -> Result<bool> {
        self.processed_file_store.is_processed(git_file_sha).await
    }

    /// Get all processed files for a specific git SHA
    pub async fn get_processed_files_for_git_sha(
        &self,
        git_sha: Option<&str>,
    ) -> Result<Vec<ProcessedFileRecord>> {
        self.processed_file_store
            .get_processed_files_for_git_sha(git_sha)
            .await
    }

    /// Remove processed file records for a specific git SHA (useful when git head changes)
    pub async fn clear_processed_files_for_git_sha(&self, git_sha: Option<&str>) -> Result<()> {
        self.processed_file_store.remove_for_git_sha(git_sha).await
    }

    /// Remove a specific processed file record
    pub async fn unmark_file_processed(
        &self,
        file: &str,
        git_sha: Option<&str>,
        git_file_sha: &str,
    ) -> Result<()> {
        self.processed_file_store
            .remove_file(file, git_sha, git_file_sha)
            .await
    }

    /// Get total count of processed files
    pub async fn get_processed_files_count(&self) -> Result<usize> {
        self.processed_file_store.count().await
    }

    /// Get all processed file records
    pub async fn get_all_processed_files(&self) -> Result<Vec<ProcessedFileRecord>> {
        self.processed_file_store.get_all().await
    }

    /// Get all existing git file SHAs from processed files for deduplication (optimized streaming version)
    pub async fn get_existing_git_file_shas(&self) -> Result<std::collections::HashSet<String>> {
        // Use the optimized method that only loads git_file_sha column
        self.processed_file_store.get_all_git_file_shas().await
    }

    /// Get file/git_file_sha pairs for pipeline deduplication (optimized for large datasets)
    pub async fn get_processed_file_pairs(
        &self,
    ) -> Result<std::collections::HashSet<(String, String)>> {
        // Use the optimized method that only loads the two needed columns
        self.processed_file_store.get_all_file_git_sha_pairs().await
    }

    pub async fn get_existing_function_names(&self) -> Result<std::collections::HashSet<String>> {
        use futures::TryStreamExt;

        let table = self.connection.open_table("functions").execute().await?;
        let results = table
            .query()
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut function_names = std::collections::HashSet::new();

        for batch in results {
            if batch.num_rows() == 0 {
                continue;
            }

            let name_array = batch
                .column(0)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap();

            for i in 0..batch.num_rows() {
                let function_name = name_array.value(i);
                function_names.insert(function_name.to_string());
            }
        }

        tracing::debug!(
            "Loaded {} existing function names for call relationship filtering",
            function_names.len()
        );
        Ok(function_names)
    }

    // Incremental scan support methods

    /// Determine which files need to be rescanned for incremental updates
    /// Given commitA and commitB, finds all files that should be processed
    pub async fn get_files_for_incremental_scan(
        &self,
        commit_a: &str,
        commit_b: &str,
    ) -> Result<std::collections::HashSet<String>> {
        use crate::git::{get_changed_files, ChangeType};

        tracing::info!(
            "Calculating files for incremental scan from {} to {}",
            commit_a,
            commit_b
        );

        // Step 1: Get directly changed files between commits
        let changed_files = get_changed_files(&self.git_repo_path, commit_a, commit_b)?;
        let mut files_to_scan = std::collections::HashSet::new();

        // Add all directly changed files (except deleted ones)
        for changed_file in &changed_files {
            if changed_file.change_type != ChangeType::Deleted {
                files_to_scan.insert(changed_file.path.clone());
            }
        }

        tracing::info!("Found {} directly changed files", files_to_scan.len());

        // Step 2: Find files connected via relationship tables
        let connected_files = self.find_files_connected_to_changes(&changed_files).await?;
        files_to_scan.extend(connected_files);

        tracing::info!("Total files for incremental scan: {}", files_to_scan.len());

        Ok(files_to_scan)
    }

    /// Find files that are connected to changed files via call graphs and type relationships
    async fn find_files_connected_to_changes(
        &self,
        changed_files: &[crate::git::ChangedFile],
    ) -> Result<std::collections::HashSet<String>> {
        let mut connected_files = std::collections::HashSet::new();

        // Collect all file paths that changed
        let changed_file_paths: std::collections::HashSet<String> =
            changed_files.iter().map(|cf| cf.path.clone()).collect();

        tracing::debug!(
            "Finding files connected to {} changed files",
            changed_file_paths.len()
        );
        for (i, file) in changed_file_paths.iter().enumerate() {
            tracing::debug!("  Changed file {}: {}", i + 1, file);
        }

        // Step 1: Find files connected via call relationships
        let call_connected = self.find_files_connected_via_calls(changed_files).await?;
        connected_files.extend(call_connected.iter().cloned());
        tracing::debug!("Found {} files connected via calls", call_connected.len());

        // Step 2 & 3: Function-type and type-type relationship tracking disabled
        // (will be reimplemented using embedded calls/types columns)

        // Remove files that are already in the changed files list
        connected_files.retain(|f| !changed_file_paths.contains(f));

        tracing::info!(
            "Found {} additional files connected to changes",
            connected_files.len()
        );
        if !connected_files.is_empty() {
            tracing::info!("Connected files:");
            for (i, file) in connected_files.iter().enumerate() {
                tracing::info!("  Connected file {}: {}", i + 1, file);
            }
        }

        Ok(connected_files)
    }

    /// Find files connected via call relationships (optimized with pre-loaded mappings)
    /// If fileA changes, find all files that:
    /// 1. Call functions in fileA (callers of changed functions)
    /// 2. Contain functions called by fileA (callees of changed functions)
    async fn find_files_connected_via_calls(
        &self,
        changed_files: &[crate::git::ChangedFile],
    ) -> Result<std::collections::HashSet<String>> {
        // TODO: Reimplement this method using embedded JSON calls columns instead of the old calls table
        // The calls table no longer exists - call relationships are now embedded in function JSON columns
        // This method should:
        // 1. Read the calls JSON column from functions table
        // 2. Parse the JSON arrays to find call relationships
        // 3. Find files connected to changed files via these relationships

        let _changed_file_paths: std::collections::HashSet<String> =
            changed_files.iter().map(|cf| cf.path.clone()).collect();

        tracing::debug!("Call connection analysis disabled - calls table removed, embedded JSON approach not yet implemented");
        tracing::debug!(
            "Returning empty set for {} changed files",
            changed_files.len()
        );

        // Return empty set until reimplemented
        Ok(std::collections::HashSet::new())
    }

    /// Search function bodies using regex patterns via LanceDB - searches sharded content tables
    pub async fn grep_function_bodies(
        &self,
        pattern: &str,
        path_pattern: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<FunctionInfo>, bool)> {
        use futures::TryStreamExt;

        // Step 1: Search all content shard tables for matching content
        // Only escape single quotes for SQL string literal - preserve backslashes for regex
        let escaped_pattern = pattern.replace("'", "''");

        let where_clause = format!("regexp_match(content, '{escaped_pattern}')");

        // Collect matching blake3 hashes from all content shards (content_0 through content_15)
        let mut matching_hashes: Vec<String> = Vec::new();

        // Query all 16 content shard tables
        for shard in 0..16u8 {
            let table_name = format!("content_{shard}");
            let content_table = self.connection.open_table(&table_name).execute().await?;
            let content_results = content_table
                .query()
                .only_if(&where_clause)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            // Collect matching hashes from this shard
            for batch in &content_results {
                let blake3_hash_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    matching_hashes.push(blake3_hash_array.value(i).to_string());
                }
            }
        }

        if matching_hashes.is_empty() {
            return Ok((Vec::new(), false));
        }

        // Step 2: Find functions that have these body hashes
        let functions_table = self.connection.open_table("functions").execute().await?;
        let mut matching_functions = Vec::new();
        let mut limit_hit = false;

        // Optimize batch processing based on hash count
        let hash_count = matching_hashes.len();
        let function_lookup_start = std::time::Instant::now();

        // Determine processing strategy based on hash count and available parallelism
        let available_cores = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4);
        let parallel_threshold = if available_cores >= 8 { 1000 } else { 2000 };

        if hash_count <= parallel_threshold {
            // For smaller result sets, use a single query for optimal performance
            tracing::debug!(
                "Using optimized single query for {} hashes (threshold: {})",
                hash_count,
                parallel_threshold
            );

            let hash_list: Vec<String> = matching_hashes
                .iter()
                .map(|hash| format!("'{hash}'"))
                .collect();

            let in_clause = hash_list.join(", ");
            let filter = format!("body_hash IN ({in_clause})");

            let function_results = functions_table
                .query()
                .only_if(filter)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            // Extract function info from results
            for batch in &function_results {
                for i in 0..batch.num_rows() {
                    if path_pattern.is_none() && limit > 0 && matching_functions.len() >= limit {
                        limit_hit = true;
                        break;
                    }

                    if let Some(func) = self
                        .function_store
                        .extract_function_from_batch(batch, i)
                        .await?
                    {
                        matching_functions.push(func);
                    }
                }
            }
        } else {
            // For larger result sets, use batched queries optimized for parallel processing
            let chunk_size = 500; // Balanced size for parallel processing with 16 CPUs

            // Process chunks concurrently for better performance
            use futures::stream::{self, StreamExt};

            let chunks: Vec<_> = matching_hashes.chunks(chunk_size).collect();
            // Use up to 16 CPUs, but adapt based on available cores and chunk count
            let max_concurrency = std::cmp::min(
                16,
                std::thread::available_parallelism()
                    .map(|p| p.get())
                    .unwrap_or(4),
            );
            let concurrent_limit = std::cmp::min(max_concurrency, chunks.len());

            tracing::debug!("Using parallel batched queries: {} chunks of {} hashes each, {} concurrent workers ({} CPU cores available)",
                chunks.len(), chunk_size, concurrent_limit,
                std::thread::available_parallelism().map(|p| p.get()).unwrap_or(1));

            let mut chunk_stream = stream::iter(chunks)
                .map(|chunk| {
                    let functions_table = &functions_table;
                    let function_store = &self.function_store;
                    async move {
                        let hash_list: Vec<String> =
                            chunk.iter().map(|hash| format!("'{hash}'")).collect();

                        let in_clause = hash_list.join(", ");
                        let filter = format!("body_hash IN ({in_clause})");

                        let function_results = functions_table
                            .query()
                            .only_if(filter)
                            .execute()
                            .await?
                            .try_collect::<Vec<_>>()
                            .await?;

                        // Extract functions from this chunk with potential parallel batch processing
                        let mut chunk_functions = Vec::new();
                        for batch in &function_results {
                            // For large batches, we could add more parallelism here if needed
                            // Currently keeping sequential to avoid over-parallelization
                            for i in 0..batch.num_rows() {
                                if let Some(func) =
                                    function_store.extract_function_from_batch(batch, i).await?
                                {
                                    chunk_functions.push(func);
                                }
                            }
                        }

                        Ok::<Vec<crate::types::FunctionInfo>, anyhow::Error>(chunk_functions)
                    }
                })
                .buffer_unordered(concurrent_limit);

            // Collect results from parallel chunks
            while let Some(chunk_result) = chunk_stream.next().await {
                let chunk_functions = chunk_result?;

                for func in chunk_functions {
                    if path_pattern.is_none() && limit > 0 && matching_functions.len() >= limit {
                        limit_hit = true;
                        break;
                    }
                    matching_functions.push(func);
                }

                // Early termination if we've hit the limit
                if limit_hit {
                    break;
                }
            }
        }

        let function_lookup_duration = function_lookup_start.elapsed();
        tracing::debug!(
            "Function body grep: pattern '{}' matched {} content entries, {} functions in {:?}{}",
            pattern,
            matching_hashes.len(),
            matching_functions.len(),
            function_lookup_duration,
            if path_pattern.is_some() {
                " (no limit applied yet - will limit after path filtering)"
            } else {
                ""
            }
        );

        // Filter by path pattern if provided
        let (final_functions, final_limit_hit) = if let Some(path_regex) = path_pattern {
            match regex::Regex::new(path_regex) {
                Ok(path_re) => {
                    let original_count = matching_functions.len();
                    let mut filtered = Vec::new();
                    let mut path_limit_hit = false;

                    // Apply path filter while respecting limit (0 = unlimited)
                    for func in matching_functions {
                        if path_re.is_match(&func.file_path) {
                            if limit > 0 && filtered.len() >= limit {
                                path_limit_hit = true;
                                break;
                            }
                            filtered.push(func);
                        }
                    }

                    tracing::debug!(
                        "Path filter '{}' reduced results from {} to {} functions",
                        path_regex,
                        original_count,
                        filtered.len()
                    );

                    // When path filtering is used, limit applies to filtered results only
                    (filtered, path_limit_hit)
                }
                Err(e) => {
                    tracing::error!("Invalid path regex '{}': {}", path_regex, e);
                    return Err(anyhow::anyhow!(
                        "Invalid path regex '{}': {}",
                        path_regex,
                        e
                    ));
                }
            }
        } else {
            (matching_functions, limit_hit)
        };

        Ok((final_functions, final_limit_hit))
    }

    /// Git-aware search function bodies using regex patterns via LanceDB - searches sharded content tables
    /// Filters results to only include functions that exist at the specified git commit
    pub async fn grep_function_bodies_git_aware(
        &self,
        pattern: &str,
        path_pattern: Option<&str>,
        limit: usize,
        git_sha: &str,
    ) -> Result<(Vec<FunctionInfo>, bool)> {
        // Step 1: Get all matching functions using the existing non-git-aware method
        let (all_matching_functions, limit_hit_pre_filter) =
            self.grep_function_bodies(pattern, path_pattern, 0).await?; // Use 0 for unlimited to get all matches first

        if all_matching_functions.is_empty() {
            return Ok((Vec::new(), false));
        }

        // Step 2: Extract unique file paths from matching functions
        let unique_file_paths: Vec<String> = all_matching_functions
            .iter()
            .map(|f| f.file_path.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        tracing::debug!(
            "grep_function_bodies_git_aware: Found {} matching functions in {} unique files, filtering by git SHA {}",
            all_matching_functions.len(),
            unique_file_paths.len(),
            git_sha
        );

        // Step 3: Resolve file paths to git hashes at target commit
        let resolved_hashes = self
            .resolve_git_file_hashes(&unique_file_paths, git_sha)
            .await?;
        if resolved_hashes.is_empty() {
            tracing::warn!(
                "No files resolved for grep pattern '{}' at commit '{}'",
                pattern,
                git_sha
            );
            return Ok((Vec::new(), false));
        }

        // Step 4: Filter functions to only those that exist in the git manifest
        let mut git_filtered_functions = Vec::new();
        let mut limit_hit = false;
        let total_matching_functions = all_matching_functions.len();

        for func in &all_matching_functions {
            // Check if this function's file SHA matches the git manifest
            if let Some(expected_hash) = resolved_hashes.get(&func.file_path) {
                if &func.git_file_hash == expected_hash {
                    if limit > 0 && git_filtered_functions.len() >= limit {
                        limit_hit = true;
                        break;
                    }
                    tracing::debug!(
                        "Including function: {} in {} (hash: {})",
                        func.name,
                        func.file_path,
                        func.git_file_hash
                    );
                    git_filtered_functions.push(func.clone());
                } else {
                    tracing::debug!(
                        "Filtered out function: {} in {} (hash mismatch: {} vs {})",
                        func.name,
                        func.file_path,
                        func.git_file_hash,
                        expected_hash
                    );
                }
            } else {
                tracing::debug!(
                    "Filtered out function: {} in {} (file not found in git manifest)",
                    func.name,
                    func.file_path
                );
            }
        }

        tracing::info!(
            "Git-aware grep: pattern '{}' matched {} functions, filtered to {} functions at git commit {}",
            pattern,
            total_matching_functions,
            git_filtered_functions.len(),
            git_sha
        );

        Ok((git_filtered_functions, limit_hit || limit_hit_pre_filter))
    }

    /// Efficient callers function implementation following the 4-step algorithm:
    /// 1. Identify git commit SHA (passed as argument or default to current commit)
    /// 2. Generate manifest of all file SHAs in that git commit
    /// 3. Find functions that call the target function using efficient LanceDB query
    /// 4. Report the results
    pub async fn find_callers_efficient(
        &self,
        target_function: &str,
        git_sha: Option<&str>,
    ) -> Result<Vec<FunctionInfo>> {
        tracing::info!(
            "Starting efficient callers search for function: {}",
            target_function
        );

        // Step 1: Identify git commit SHA
        let effective_git_sha = match git_sha {
            Some(sha) => {
                tracing::info!("Using provided git commit SHA: {}", sha);
                sha.to_string()
            }
            None => {
                // Default to current commit
                match crate::git::get_git_sha(&self.git_repo_path) {
                    Ok(Some(current_sha)) => {
                        tracing::info!("Using current git commit SHA: {}", current_sha);
                        current_sha
                    }
                    Ok(None) => {
                        tracing::warn!(
                            "Not in a git repository, falling back to non-git-aware search"
                        );
                        return self.find_callers_non_git_aware(target_function).await;
                    }
                    Err(e) => {
                        tracing::error!("Failed to get current git SHA: {}, falling back to non-git-aware search", e);
                        return self.find_callers_non_git_aware(target_function).await;
                    }
                }
            }
        };

        // Step 2: Generate manifest of all file SHAs in that git commit
        tracing::info!(
            "Generating complete git file manifest for commit: {}",
            effective_git_sha
        );
        let git_manifest = self.generate_git_manifest(&effective_git_sha).await?;
        tracing::info!(
            "Generated manifest with {} files at commit {}",
            git_manifest.len(),
            effective_git_sha
        );

        if git_manifest.is_empty() {
            tracing::warn!("No files found in git commit {}", effective_git_sha);
            return Ok(Vec::new());
        }

        // Step 3: Find functions that call the target function using efficient LanceDB query
        tracing::info!("Searching for functions that call: {}", target_function);

        // Use the new embedded JSON schema to find all potential callers
        let all_callers = self.get_function_callers(target_function).await?;
        if all_callers.is_empty() {
            tracing::info!("No functions call '{}' in database", target_function);
            return Ok(Vec::new());
        }

        tracing::info!(
            "Found {} potential callers, filtering against {} files in git manifest",
            all_callers.len(),
            git_manifest.len()
        );

        // Get function details for all callers
        let caller_functions = self.function_store.get_by_names(&all_callers).await?;
        if caller_functions.is_empty() {
            tracing::warn!("No caller function details found");
            return Ok(Vec::new());
        }

        // Step 4: Filter callers to only those that exist in the git manifest and report results
        let mut valid_callers = Vec::new();

        for caller_name in &all_callers {
            if let Some(func) = caller_functions.get(caller_name) {
                // Check if this function's file SHA matches the git manifest
                if let Some(expected_hash) = git_manifest.get(&func.file_path) {
                    if &func.git_file_hash == expected_hash {
                        valid_callers.push(func.clone());
                        tracing::debug!(
                            "Valid caller: {} in {} (hash: {})",
                            func.name,
                            func.file_path,
                            func.git_file_hash
                        );
                    } else {
                        tracing::debug!(
                            "Filtered out caller: {} in {} (hash mismatch: {} vs {})",
                            func.name,
                            func.file_path,
                            func.git_file_hash,
                            expected_hash
                        );
                    }
                } else {
                    tracing::debug!(
                        "Filtered out caller: {} in {} (file not found in git manifest)",
                        func.name,
                        func.file_path
                    );
                }
            }
        }

        tracing::info!(
            "Found {} valid callers for '{}' at git commit {}",
            valid_callers.len(),
            target_function,
            effective_git_sha
        );

        Ok(valid_callers)
    }

    /// Get callers using pre-loaded git manifest for filtering

    /// Generate a complete manifest of all file paths and their SHAs at a specific git commit
    async fn generate_git_manifest(
        &self,
        git_sha: &str,
    ) -> Result<std::collections::HashMap<String, String>> {
        match gix::discover(&self.git_repo_path) {
            Ok(repo) => {
                // Parse the commit SHA using revparse (supports short SHAs, tags, etc.)
                let commit = resolve_to_commit(&repo, git_sha)?;

                let tree = commit.tree().map_err(|e| {
                    anyhow::anyhow!("Failed to get tree for commit '{}': {}", git_sha, e)
                })?;

                let mut manifest = std::collections::HashMap::new();

                // Walk the entire git tree and build manifest
                use gix::traverse::tree::Recorder;
                let mut recorder = Recorder::default();
                tree.traverse().breadthfirst(&mut recorder)?;

                for entry in recorder.records {
                    if entry.mode.is_blob() {
                        let relative_path = entry.filepath.to_string();

                        // Normalize path by removing any double slashes
                        let normalized_path = relative_path.replace("//", "/");

                        let blob_hash = entry.oid.to_string();
                        manifest.insert(normalized_path, blob_hash);
                    }
                }

                Ok(manifest)
            }
            Err(e) => Err(anyhow::anyhow!(
                "Failed to discover git repository from '{}': {}",
                self.git_repo_path,
                e
            )),
        }
    }

    /// Fallback callers search when not in git repository
    async fn find_callers_non_git_aware(&self, target_function: &str) -> Result<Vec<FunctionInfo>> {
        tracing::info!(
            "Performing non-git-aware callers search for: {}",
            target_function
        );

        let all_callers = self.get_function_callers(target_function).await?;
        if all_callers.is_empty() {
            return Ok(Vec::new());
        }

        let caller_functions = self.function_store.get_by_names(&all_callers).await?;
        let callers_vec: Vec<FunctionInfo> = caller_functions.into_values().collect();

        tracing::info!(
            "Found {} callers for '{}' (non-git-aware)",
            callers_vec.len(),
            target_function
        );
        Ok(callers_vec)
    }

    // Content operations for deduplication

    /// Store content and return the blake3 hash
    pub async fn store_content(&self, content: &str) -> Result<String> {
        self.content_store.store_content(content).await
    }

    /// Store content and return hex hash
    pub async fn store_content_with_hex_hash(&self, content: &str) -> Result<String> {
        self.content_store
            .store_content_with_hex_hash(content)
            .await
    }

    /// Get content by blake3 hash
    pub async fn get_content(&self, blake3_hash: &str) -> Result<Option<String>> {
        self.content_store.get_content(blake3_hash).await
    }

    /// Get content by blake3 hash hex string
    pub async fn get_content_by_hex(&self, blake3_hash_hex: &str) -> Result<Option<String>> {
        self.content_store.get_content_by_hex(blake3_hash_hex).await
    }

    /// Bulk fetch content for multiple hashes - optimized for dump operations
    pub async fn get_content_bulk(
        &self,
        hashes: &[String],
    ) -> Result<std::collections::HashMap<String, String>> {
        self.content_store.get_content_bulk(hashes).await
    }

    /// Check if content exists by hash
    pub async fn content_exists(&self, blake3_hash: &str) -> Result<bool> {
        self.content_store.content_exists(blake3_hash).await
    }

    /// Insert a batch of content items
    pub async fn insert_content_batch(&self, content_items: Vec<ContentInfo>) -> Result<()> {
        self.content_store.insert_batch(content_items).await
    }

    /// Insert a batch of content items, but only insert items that don't already exist
    pub async fn insert_content_batch_deduplicated(
        &self,
        content_items: Vec<ContentInfo>,
    ) -> Result<()> {
        self.content_store.insert_batch(content_items).await
    }

    /// Get all content (for debugging/analysis)
    pub async fn get_all_content(&self) -> Result<Vec<ContentInfo>> {
        self.content_store.get_all().await
    }

    /// Get statistics about content storage
    pub async fn get_content_stats(&self) -> Result<crate::database::content::ContentStats> {
        self.content_store.get_stats().await
    }

    // ============================================================================
    // Git Manifest-based optimization methods for bulk operations
    // ============================================================================

    /// Check if a function exists at git commit using pre-generated manifest (fast)
    async fn function_exists_in_manifest(
        &self,
        function_name: &str,
        git_manifest: &std::collections::HashMap<String, String>,
    ) -> Result<bool> {
        // Get all functions with this name (non-git-aware, fast database query)
        let all_functions = self
            .function_store
            .find_all_by_name_unfiltered(function_name)
            .await?;

        // Check if any function exists in the git manifest (fast HashMap lookup)
        for func in &all_functions {
            if let Some(expected_hash) = git_manifest.get(&func.file_path) {
                if &func.git_file_hash == expected_hash {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Check if a macro exists at git commit using pre-generated manifest (fast)
    async fn macro_exists_in_manifest(
        &self,
        macro_name: &str,
        git_manifest: &std::collections::HashMap<String, String>,
    ) -> Result<bool> {
        // Get all macros with this name (non-git-aware, fast database query)
        let all_macros = self.macro_store.find_all_by_name(macro_name).await?;

        // Check if any macro exists in the git manifest (fast HashMap lookup)
        for mac in &all_macros {
            if let Some(expected_hash) = git_manifest.get(&mac.file_path) {
                if &mac.git_file_hash == expected_hash {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Get function callees using pre-generated manifest (fast)
    async fn get_function_callees_with_manifest(
        &self,
        function_name: &str,
        git_manifest: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>> {
        // Get all functions with this name (non-git-aware, fast database query)
        let all_matches = self
            .function_store
            .find_all_by_name_unfiltered(function_name)
            .await?;

        // Filter to functions that exist in git manifest (fast HashMap lookups)
        let mut manifest_matches = Vec::new();
        for func in &all_matches {
            if let Some(expected_hash) = git_manifest.get(&func.file_path) {
                if &func.git_file_hash == expected_hash {
                    manifest_matches.push(func.clone());
                }
            }
        }

        if manifest_matches.is_empty() {
            return Ok(Vec::new());
        }

        // Use the same smart selection logic as the original method
        let best_match = self.select_best_function_match(manifest_matches);

        // Get the calls from the best match
        if let Some(ref calls_list) = best_match.calls {
            return Ok(calls_list.clone());
        }

        Ok(Vec::new())
    }

    /// Get function callers using pre-generated manifest (fast)
    async fn get_function_callers_with_manifest(
        &self,
        function_name: &str,
        git_manifest: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>> {
        // Use efficient filtering: find functions whose calls JSON contains the target function name
        let escaped_name = function_name.replace("'", "''"); // SQL escape
        let table = self.connection.open_table("functions").execute().await?;

        // Filter for functions whose calls column contains the target function name
        let filter = format!("calls IS NOT NULL AND calls LIKE '%\\\"{escaped_name}\\\"%%'");
        let results = table
            .query()
            .only_if(filter)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut callers = Vec::new();

        for batch in results {
            if batch.num_rows() > 0 {
                let name_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let file_path_array = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let git_file_hash_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                // Find the calls column
                let calls_column_idx = batch
                    .schema()
                    .fields()
                    .iter()
                    .position(|f| f.name() == "calls")
                    .ok_or_else(|| anyhow::anyhow!("calls column not found in functions table"))?;
                let calls_array = batch
                    .column(calls_column_idx)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    let caller_name = name_array.value(i);
                    let file_path = file_path_array.value(i);
                    let git_file_hash = git_file_hash_array.value(i).to_string();

                    // Fast manifest lookup instead of expensive git resolution
                    if let Some(expected_hash) = git_manifest.get(file_path) {
                        if &git_file_hash == expected_hash {
                            // This function exists at the git SHA, verify it actually calls our target
                            if !calls_array.is_null(i) {
                                let calls_json = calls_array.value(i);
                                if let Ok(calls_list) =
                                    serde_json::from_str::<Vec<String>>(calls_json)
                                {
                                    if calls_list.contains(&function_name.to_string()) {
                                        callers.push(caller_name.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(callers)
    }
}
