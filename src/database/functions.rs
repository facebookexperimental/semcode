// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use arrow::array::{Array, ArrayRef, Int64Builder, RecordBatch, StringArray, StringBuilder};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatchIterator;
use futures::TryStreamExt;
use lancedb::connection::Connection;
use lancedb::query::{ExecutableQuery, QueryBase};
use std::sync::Arc;

use crate::database::connection::OPTIMAL_BATCH_SIZE;
use crate::database::content::ContentStore;
use crate::types::{FunctionInfo, ParameterInfo};

#[derive(Debug, Clone)]
struct FunctionMetadata {
    pub name: String,
    pub file_path: String,
    pub git_file_hash: String,
    pub line_start: u32,
    pub line_end: u32,
    pub return_type: String,
    pub parameters: Vec<ParameterInfo>,
    pub body_hash: Option<String>,
    pub calls: Option<Vec<String>>,
    pub types: Option<Vec<String>>,
}

pub struct FunctionStore {
    connection: Connection,
    content_store: ContentStore,
}

impl FunctionStore {
    pub fn new(connection: Connection) -> Self {
        let content_store = ContentStore::new(connection.clone());
        Self {
            connection,
            content_store,
        }
    }

    pub async fn insert_batch(&self, functions: Vec<FunctionInfo>) -> Result<()> {
        if functions.is_empty() {
            return Ok(());
        }

        // Check for extremely large functions that might cause issues
        let max_body_size = 10 * 1024 * 1024; // 10MB limit per function
        let filtered_functions: Vec<FunctionInfo> = functions
            .into_iter()
            .map(|mut func| {
                if func.body.len() > max_body_size {
                    tracing::warn!(
                        "Function {} has very large body ({} bytes), truncating to {}MB",
                        func.name,
                        func.body.len(),
                        max_body_size / 1024 / 1024
                    );
                    func.body.truncate(max_body_size);
                }
                func
            })
            .collect();

        let table = self.connection.open_table("functions").execute().await?;

        // Process in optimal batch sizes
        for chunk in filtered_functions.chunks(OPTIMAL_BATCH_SIZE) {
            self.insert_chunk(&table, chunk).await?;
        }

        Ok(())
    }

    pub async fn insert_metadata_only(&self, functions: Vec<FunctionInfo>) -> Result<()> {
        if functions.is_empty() {
            return Ok(());
        }

        let table = self.connection.open_table("functions").execute().await?;

        // Process in optimal batch sizes
        for chunk in functions.chunks(OPTIMAL_BATCH_SIZE) {
            self.insert_metadata_chunk(&table, chunk).await?;
        }

        Ok(())
    }

    async fn insert_chunk(
        &self,
        table: &lancedb::table::Table,
        functions: &[FunctionInfo],
    ) -> Result<()> {
        // First, store function bodies in content table and collect their hashes
        let mut content_items = Vec::new();
        for func in functions {
            if !func.body.is_empty() {
                content_items.push(crate::database::content::ContentInfo {
                    blake3_hash: crate::hash::compute_blake3_hash(&func.body),
                    content: func.body.clone(),
                });
            }
        }

        // Store content items without deduplication (for performance testing)
        if !content_items.is_empty() {
            self.content_store.insert_batch(content_items).await?;
        }

        // Build arrow arrays
        let mut name_builder = StringBuilder::new();
        let mut file_path_builder = StringBuilder::new();
        let mut line_start_builder = Int64Builder::new();
        let mut line_end_builder = Int64Builder::new();
        let mut return_type_builder = StringBuilder::new();
        let mut parameters_builder = StringBuilder::new();
        let mut calls_builder = StringBuilder::new();
        let mut types_builder = StringBuilder::new();

        for func in functions {
            name_builder.append_value(&func.name);
            file_path_builder.append_value(&func.file_path);

            line_start_builder.append_value(func.line_start as i64);
            line_end_builder.append_value(func.line_end as i64);
            return_type_builder.append_value(&func.return_type);
            parameters_builder.append_value(serde_json::to_string(&func.parameters)?);

            // Serialize calls and types to JSON strings (nullable)
            if let Some(ref calls) = func.calls {
                calls_builder.append_value(serde_json::to_string(calls)?);
            } else {
                calls_builder.append_null();
            }

            if let Some(ref types) = func.types {
                types_builder.append_value(serde_json::to_string(types)?);
            } else {
                types_builder.append_null();
            }
        }

        // Create body_hash StringArray (nullable for empty bodies)
        let mut body_hash_builder = StringBuilder::new();
        for func in functions {
            if func.body.is_empty() {
                body_hash_builder.append_null();
            } else {
                body_hash_builder.append_value(crate::hash::compute_blake3_hash(&func.body));
            }
        }
        let body_hash_array = body_hash_builder.finish();

        // Create git_file_hash StringArray (non-nullable)
        let mut git_file_hash_builder = StringBuilder::new();
        for func in functions {
            git_file_hash_builder.append_value(&func.git_file_hash);
        }
        let git_file_hash_array = git_file_hash_builder.finish();

        let schema = self.get_schema();

        let batch = RecordBatch::try_from_iter(vec![
            ("name", Arc::new(name_builder.finish()) as ArrayRef),
            (
                "file_path",
                Arc::new(file_path_builder.finish()) as ArrayRef,
            ),
            ("git_file_hash", Arc::new(git_file_hash_array) as ArrayRef),
            (
                "line_start",
                Arc::new(line_start_builder.finish()) as ArrayRef,
            ),
            ("line_end", Arc::new(line_end_builder.finish()) as ArrayRef),
            (
                "return_type",
                Arc::new(return_type_builder.finish()) as ArrayRef,
            ),
            (
                "parameters",
                Arc::new(parameters_builder.finish()) as ArrayRef,
            ),
            ("body_hash", Arc::new(body_hash_array) as ArrayRef),
            ("calls", Arc::new(calls_builder.finish()) as ArrayRef),
            ("types", Arc::new(types_builder.finish()) as ArrayRef),
        ])?;

        let batches = vec![Ok(batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);
        table.add(batch_iterator).execute().await?;

        Ok(())
    }

    async fn insert_metadata_chunk(
        &self,
        table: &lancedb::table::Table,
        functions: &[FunctionInfo],
    ) -> Result<()> {
        // Skip content storage, just build metadata arrays
        let mut name_builder = StringBuilder::new();
        let mut file_path_builder = StringBuilder::new();
        let mut line_start_builder = arrow::array::Int64Builder::new();
        let mut line_end_builder = arrow::array::Int64Builder::new();
        let mut return_type_builder = StringBuilder::new();
        let mut parameters_builder = StringBuilder::new();
        let mut calls_builder = StringBuilder::new();
        let mut types_builder = StringBuilder::new();

        for func in functions {
            name_builder.append_value(&func.name);
            file_path_builder.append_value(&func.file_path);
            line_start_builder.append_value(func.line_start as i64);
            line_end_builder.append_value(func.line_end as i64);
            return_type_builder.append_value(&func.return_type);

            // Serialize parameters to JSON
            let parameters_json = serde_json::to_string(&func.parameters).unwrap_or_default();
            parameters_builder.append_value(&parameters_json);

            // Handle calls and types as JSON arrays
            let calls_json = func
                .calls
                .as_ref()
                .map(|calls| serde_json::to_string(calls).unwrap_or_default())
                .unwrap_or_default();
            calls_builder.append_value(&calls_json);

            let types_json = func
                .types
                .as_ref()
                .map(|types| serde_json::to_string(types).unwrap_or_default())
                .unwrap_or_default();
            types_builder.append_value(&types_json);
        }

        // Create body_hash StringArray (non-nullable for metadata-only)
        let mut body_hash_builder = StringBuilder::new();
        for func in functions {
            if !func.body.is_empty() {
                body_hash_builder.append_value(crate::hash::compute_blake3_hash(&func.body));
            } else {
                body_hash_builder.append_value(""); // Empty hash for empty body
            }
        }
        let body_hash_array = body_hash_builder.finish();

        // Create git_file_hash StringArray (non-nullable)
        let mut git_file_hash_builder = StringBuilder::new();
        for func in functions {
            git_file_hash_builder.append_value(&func.git_file_hash);
        }
        let git_file_hash_array = git_file_hash_builder.finish();

        let schema = self.get_schema();
        let batch = RecordBatch::try_from_iter(vec![
            ("name", Arc::new(name_builder.finish()) as ArrayRef),
            (
                "file_path",
                Arc::new(file_path_builder.finish()) as ArrayRef,
            ),
            ("git_file_hash", Arc::new(git_file_hash_array) as ArrayRef),
            (
                "line_start",
                Arc::new(line_start_builder.finish()) as ArrayRef,
            ),
            ("line_end", Arc::new(line_end_builder.finish()) as ArrayRef),
            (
                "return_type",
                Arc::new(return_type_builder.finish()) as ArrayRef,
            ),
            (
                "parameters",
                Arc::new(parameters_builder.finish()) as ArrayRef,
            ),
            ("body_hash", Arc::new(body_hash_array) as ArrayRef),
            ("calls", Arc::new(calls_builder.finish()) as ArrayRef),
            ("types", Arc::new(types_builder.finish()) as ArrayRef),
        ])?;

        let batches = vec![Ok(batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);
        table.add(batch_iterator).execute().await?;

        Ok(())
    }

    pub async fn find_all_by_name(&self, name: &str) -> Result<Vec<FunctionInfo>> {
        let table = self.connection.open_table("functions").execute().await?;
        let escaped_name = name.replace("'", "''");

        let results = table
            .query()
            .only_if(format!("name = '{escaped_name}'"))
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        if results.is_empty() || results[0].num_rows() == 0 {
            return Ok(Vec::new());
        }

        let batch = &results[0];
        let mut candidates = Vec::new();

        // Extract all matching functions
        for i in 0..batch.num_rows() {
            if let Some(func) = self.extract_function_from_batch(batch, i).await? {
                candidates.push(func);
            }
        }

        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        // Filter and prioritize: prefer definitions over declarations
        let mut definitions = Vec::new();
        let mut declarations = Vec::new();

        for func in candidates {
            // Classify as definition or declaration
            let span = func.line_end.saturating_sub(func.line_start);
            let has_body = func.body.len() > 100 && span > 0; // Simple heuristic

            if has_body {
                definitions.push(func);
            } else {
                declarations.push(func);
            }
        }

        // Return definitions if we have any, otherwise return declarations
        if !definitions.is_empty() {
            Ok(definitions)
        } else {
            Ok(declarations)
        }
    }

    /// Find ALL functions by name without any filtering - needed for git-aware lookups
    pub async fn find_all_by_name_unfiltered(&self, name: &str) -> Result<Vec<FunctionInfo>> {
        let table = self.connection.open_table("functions").execute().await?;
        let escaped_name = name.replace("'", "''");

        let results = table
            .query()
            .only_if(format!("name = '{escaped_name}'"))
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut all_functions = Vec::new();

        for batch in &results {
            // Extract ALL matching functions without any filtering
            for i in 0..batch.num_rows() {
                if let Some(func) = self.extract_function_from_batch(batch, i).await? {
                    all_functions.push(func);
                }
            }
        }

        Ok(all_functions)
    }

    /// Find function by name, file path, and exact git file hash - for targeted git-aware lookups
    pub async fn find_by_name_file_and_hash(
        &self,
        name: &str,
        file_path: &str,
        git_file_hash: &str,
    ) -> Result<Option<FunctionInfo>> {
        let table = self.connection.open_table("functions").execute().await?;
        let escaped_name = name.replace("'", "''");
        let escaped_file_path = file_path.replace("'", "''");

        // Git hashes are now stored as hex strings directly without padding
        let git_hash_to_match = git_file_hash;

        let results = table
            .query()
            .only_if(format!(
                "name = '{escaped_name}' AND file_path = '{escaped_file_path}'"
            ))
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        // Search through all batches for the exact hash match using padded hash
        for batch in &results {
            for i in 0..batch.num_rows() {
                if let Some(func) = self.extract_function_from_batch(batch, i).await? {
                    if func.git_file_hash == git_hash_to_match {
                        tracing::debug!(
                            "Found exact match for '{}' in '{}' with git hash '{}'",
                            name,
                            file_path,
                            git_file_hash
                        );
                        return Ok(Some(func));
                    }
                }
            }
        }

        Ok(None)
    }

    pub async fn get_all(&self) -> Result<Vec<FunctionInfo>> {
        // Use optimized bulk retrieval for better performance
        self.get_all_bulk_optimized().await
    }

    /// Count all functions without resolving content - much faster for counts
    pub async fn count_all(&self) -> Result<usize> {
        let table = self.connection.open_table("functions").execute().await?;
        Ok(table.count_rows(None).await?)
    }

    /// Get all functions without resolving content hashes - much faster for dumps
    pub async fn get_all_metadata_only(&self) -> Result<Vec<FunctionInfo>> {
        let table = self.connection.open_table("functions").execute().await?;
        let mut all_functions = Vec::new();
        let batch_size = 10000;
        let mut offset = 0;

        loop {
            let results = table
                .query()
                .limit(batch_size)
                .offset(offset)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            if results.is_empty() {
                break;
            }

            for batch in &results {
                for i in 0..batch.num_rows() {
                    if let Ok(Some(func_data)) = self.extract_function_metadata_from_batch(batch, i)
                    {
                        // Create FunctionInfo with hash placeholder instead of resolving content
                        let body = match func_data.body_hash {
                            Some(ref hash) => format!("[blake3:{}]", hex::encode(hash)),
                            None => String::new(),
                        };

                        all_functions.push(FunctionInfo {
                            name: func_data.name,
                            file_path: func_data.file_path,
                            git_file_hash: func_data.git_file_hash,
                            line_start: func_data.line_start,
                            line_end: func_data.line_end,
                            return_type: func_data.return_type,
                            parameters: func_data.parameters,
                            body,
                            calls: func_data.calls,
                            types: func_data.types,
                        });
                    }
                }
            }

            offset += batch_size;
            let total_rows: usize = results.iter().map(|b| b.num_rows()).sum();
            if total_rows < batch_size {
                break;
            }
        }

        Ok(all_functions)
    }

    /// Optimized bulk retrieval that minimizes content table queries
    pub async fn get_all_bulk_optimized(&self) -> Result<Vec<FunctionInfo>> {
        let table = self.connection.open_table("functions").execute().await?;
        let mut all_function_data = Vec::new();
        let mut all_body_hashes = std::collections::HashSet::new();
        let batch_size = 10000;
        let mut offset = 0;

        // Step 1: Fetch all function metadata and collect unique body hashes
        loop {
            let results = table
                .query()
                .limit(batch_size)
                .offset(offset)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            if results.is_empty() {
                break;
            }

            for batch in &results {
                for i in 0..batch.num_rows() {
                    if let Ok(Some(func_data)) = self.extract_function_metadata_from_batch(batch, i)
                    {
                        // Collect body hash if not null
                        if let Some(ref body_hash) = func_data.body_hash {
                            all_body_hashes.insert(body_hash.clone());
                        }
                        all_function_data.push(func_data);
                    }
                }
            }

            offset += batch_size;
            let total_rows: usize = results.iter().map(|b| b.num_rows()).sum();
            if total_rows < batch_size {
                break;
            }
        }

        // Step 2: Bulk fetch all content for the collected hashes
        let content_map = if !all_body_hashes.is_empty() {
            let hash_vec: Vec<String> = all_body_hashes.into_iter().collect();
            self.bulk_get_content(&hash_vec).await?
        } else {
            std::collections::HashMap::new()
        };

        // Step 3: Reconstruct FunctionInfo objects with content
        let mut all_functions = Vec::new();
        for func_data in all_function_data {
            let body = match func_data.body_hash {
                Some(hash) => content_map.get(&hash).cloned().unwrap_or_default(),
                None => String::new(),
            };

            all_functions.push(FunctionInfo {
                name: func_data.name,
                file_path: func_data.file_path,
                git_file_hash: func_data.git_file_hash,
                line_start: func_data.line_start,
                line_end: func_data.line_end,
                return_type: func_data.return_type,
                parameters: func_data.parameters,
                body,
                calls: func_data.calls,
                types: func_data.types,
            });
        }

        Ok(all_functions)
    }

    /// Extract function metadata from batch without content lookup
    fn extract_function_metadata_from_batch(
        &self,
        batch: &RecordBatch,
        row: usize,
    ) -> Result<Option<FunctionMetadata>> {
        let name_array = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let file_path_array = batch
            .column(1)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let git_file_hash_array = batch
            .column(2)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let line_start_array = batch
            .column(3)
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .unwrap();
        let line_end_array = batch
            .column(4)
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .unwrap();
        let return_type_array = batch
            .column(5)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let parameters_array = batch
            .column(6)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let body_hash_array = batch
            .column(7)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let calls_array = batch
            .column(8)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let types_array = batch
            .column(9)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();

        let parameters: Vec<ParameterInfo> =
            serde_json::from_str::<Vec<ParameterInfo>>(parameters_array.value(row))?;

        // Get body hash if not null
        let body_hash = if body_hash_array.is_null(row) {
            None
        } else {
            Some(body_hash_array.value(row).to_string())
        };

        // Parse calls and types from JSON (they're nullable)
        let calls = if calls_array.is_null(row) {
            None
        } else {
            serde_json::from_str::<Vec<String>>(calls_array.value(row)).ok()
        };

        let types = if types_array.is_null(row) {
            None
        } else {
            serde_json::from_str::<Vec<String>>(types_array.value(row)).ok()
        };

        Ok(Some(FunctionMetadata {
            name: name_array.value(row).to_string(),
            file_path: file_path_array.value(row).to_string(),
            git_file_hash: git_file_hash_array.value(row).to_string(),
            line_start: line_start_array.value(row) as u32,
            line_end: line_end_array.value(row) as u32,
            return_type: return_type_array.value(row).to_string(),
            parameters,
            body_hash,
            calls,
            types,
        }))
    }

    /// Bulk fetch content for multiple hashes
    async fn bulk_get_content(
        &self,
        hashes: &[String],
    ) -> Result<std::collections::HashMap<String, String>> {
        self.content_store.get_content_bulk(hashes).await
    }

    /// Get functions by a list of names (batch lookup) - optimized to minimize content queries
    pub async fn get_by_names(
        &self,
        names: &[String],
    ) -> Result<std::collections::HashMap<String, FunctionInfo>> {
        if names.is_empty() {
            return Ok(std::collections::HashMap::new());
        }

        let table = self.connection.open_table("functions").execute().await?;
        let mut all_function_data = Vec::new();
        let mut all_body_hashes = std::collections::HashSet::new();

        // Step 1: Fetch all function metadata and collect unique body hashes
        for chunk in names.chunks(100) {
            let name_list = chunk
                .iter()
                .map(|name| format!("'{}'", name.replace("'", "''")))
                .collect::<Vec<_>>()
                .join(",");

            let filter = format!("name IN ({name_list})");

            let results = table
                .query()
                .only_if(filter)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            for batch in &results {
                for i in 0..batch.num_rows() {
                    if let Ok(Some(func_data)) = self.extract_function_metadata_from_batch(batch, i)
                    {
                        // Collect body hash if not null
                        if let Some(ref body_hash) = func_data.body_hash {
                            all_body_hashes.insert(body_hash.clone());
                        }
                        all_function_data.push(func_data);
                    }
                }
            }
        }

        // Step 2: Bulk fetch all content for the collected hashes
        let content_map = if !all_body_hashes.is_empty() {
            let hash_vec: Vec<String> = all_body_hashes.into_iter().collect();
            self.bulk_get_content(&hash_vec).await?
        } else {
            std::collections::HashMap::new()
        };

        // Step 3: Reconstruct FunctionInfo objects with content
        let mut result = std::collections::HashMap::new();
        for func_data in all_function_data {
            let body = match func_data.body_hash {
                Some(hash) => content_map.get(&hash).cloned().unwrap_or_default(),
                None => String::new(),
            };

            let function_info = FunctionInfo {
                name: func_data.name.clone(),
                file_path: func_data.file_path,
                git_file_hash: func_data.git_file_hash,
                line_start: func_data.line_start,
                line_end: func_data.line_end,
                return_type: func_data.return_type,
                parameters: func_data.parameters,
                body,
                calls: func_data.calls,
                types: func_data.types,
            };

            result.insert(func_data.name, function_info);
        }

        Ok(result)
    }

    pub async fn extract_function_from_batch(
        &self,
        batch: &RecordBatch,
        row: usize,
    ) -> Result<Option<FunctionInfo>> {
        let name_array = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let file_path_array = batch
            .column(1)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let git_file_hash_array = batch
            .column(2)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let line_start_array = batch
            .column(3)
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .unwrap();
        let line_end_array = batch
            .column(4)
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .unwrap();
        let return_type_array = batch
            .column(5)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let parameters_array = batch
            .column(6)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let body_hash_array = batch
            .column(7)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let calls_array = batch
            .column(8)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let types_array = batch
            .column(9)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();

        let parameters: Vec<ParameterInfo> =
            serde_json::from_str::<Vec<ParameterInfo>>(parameters_array.value(row))?;

        // Get function body from content table using hash (if not null)
        let body = if body_hash_array.is_null(row) {
            String::new() // Empty body for null hash
        } else {
            let hash_hex = body_hash_array.value(row);
            tracing::info!(
                "Retrieving function body for '{}' with hash: {}",
                name_array.value(row),
                hash_hex
            );
            match self.content_store.get_content(hash_hex).await? {
                Some(content) => {
                    tracing::info!(
                        "Successfully retrieved content for '{}', size: {} bytes",
                        name_array.value(row),
                        content.len()
                    );
                    content
                }
                None => {
                    tracing::error!(
                        "Body content not found for function '{}' with hash: {} - this indicates a database consistency issue",
                        name_array.value(row),
                        hash_hex
                    );
                    // Check if content exists with a different lookup
                    match self.content_store.content_exists(hash_hex).await {
                        Ok(true) => {
                            tracing::error!("Content exists check returned true but get_content returned None - possible race condition");
                        }
                        Ok(false) => {
                            tracing::error!("Content definitely does not exist in content store");
                        }
                        Err(e) => {
                            tracing::error!("Error checking content existence: {}", e);
                        }
                    }
                    String::new() // Fallback to empty body if content not found
                }
            }
        };

        // Parse calls and types from JSON (they're nullable)
        let calls = if calls_array.is_null(row) {
            None
        } else {
            serde_json::from_str::<Vec<String>>(calls_array.value(row)).ok()
        };

        let types = if types_array.is_null(row) {
            None
        } else {
            serde_json::from_str::<Vec<String>>(types_array.value(row)).ok()
        };

        Ok(Some(FunctionInfo {
            name: name_array.value(row).to_string(),
            file_path: file_path_array.value(row).to_string(),
            git_file_hash: git_file_hash_array.value(row).to_string(),
            line_start: line_start_array.value(row) as u32,
            line_end: line_end_array.value(row) as u32,
            return_type: return_type_array.value(row).to_string(),
            parameters,
            body,
            calls,
            types,
        }))
    }

    fn get_schema(&self) -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            Field::new("name", DataType::Utf8, false),
            Field::new("file_path", DataType::Utf8, false),
            Field::new("git_file_hash", DataType::Utf8, false), // Git file hash as hex string
            Field::new("line_start", DataType::Int64, false),
            Field::new("line_end", DataType::Int64, false),
            Field::new("return_type", DataType::Utf8, false),
            Field::new("parameters", DataType::Utf8, false),
            Field::new("body_hash", DataType::Utf8, true), // Blake3 hash referencing content table as hex string (nullable for empty bodies)
            Field::new("calls", DataType::Utf8, true), // JSON array of function names called (nullable)
            Field::new("types", DataType::Utf8, true), // JSON array of type names used (nullable)
        ]))
    }
}
