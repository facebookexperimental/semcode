// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use arrow::array::{
    Array, ArrayRef, BooleanBuilder, Int64Builder, RecordBatch, StringArray, StringBuilder,
};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatchIterator;
use futures::TryStreamExt;
use lancedb::connection::Connection;
use lancedb::query::{ExecutableQuery, QueryBase};
use std::sync::Arc;

use crate::database::connection::OPTIMAL_BATCH_SIZE;
use crate::database::content::ContentStore;
use crate::types::{FieldInfo, MacroInfo, TypeInfo, TypedefInfo};
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct TypeMetadata {
    pub name: String,
    pub file_path: String,
    pub git_file_hash: String,
    pub line_start: u32,
    pub kind: String,
    pub size: Option<u64>,
    pub members: Vec<FieldInfo>,
    pub definition_hash: Option<String>,
    pub types: Option<Vec<String>>,
}

pub struct TypeStore {
    connection: Connection,
    content_store: ContentStore,
}

impl TypeStore {
    pub fn new(connection: Connection) -> Self {
        let content_store = ContentStore::new(connection.clone());
        Self {
            connection,
            content_store,
        }
    }

    pub async fn insert_batch(&self, types: Vec<TypeInfo>) -> Result<()> {
        if types.is_empty() {
            return Ok(());
        }

        let max_definition_size = 10 * 1024 * 1024; // 10MB limit
        let filtered_types: Vec<TypeInfo> = types
            .into_iter()
            .map(|mut type_info| {
                if type_info.definition.len() > max_definition_size {
                    tracing::warn!(
                        "Type {} has very large definition ({} bytes), truncating",
                        type_info.name,
                        type_info.definition.len()
                    );
                    type_info.definition.truncate(max_definition_size);
                }
                type_info
            })
            .collect();

        let table = self.connection.open_table("types").execute().await?;

        // Process in optimal batch sizes
        for chunk in filtered_types.chunks(OPTIMAL_BATCH_SIZE) {
            self.insert_chunk(&table, chunk).await?;
        }

        Ok(())
    }

    pub async fn insert_metadata_only(&self, types: Vec<TypeInfo>) -> Result<()> {
        if types.is_empty() {
            return Ok(());
        }

        let table = self.connection.open_table("types").execute().await?;

        // Process in optimal batch sizes
        for chunk in types.chunks(OPTIMAL_BATCH_SIZE) {
            self.insert_metadata_chunk(&table, chunk).await?;
        }

        Ok(())
    }

    async fn insert_chunk(&self, table: &lancedb::table::Table, types: &[TypeInfo]) -> Result<()> {
        // First, store type definitions in content table and collect their hashes
        let mut content_items = Vec::new();
        for type_info in types {
            if !type_info.definition.is_empty() {
                content_items.push(crate::database::content::ContentInfo {
                    blake3_hash: crate::hash::compute_blake3_hash(&type_info.definition),
                    content: type_info.definition.clone(),
                });
            }
        }

        // Store content items without deduplication (for performance testing)
        if !content_items.is_empty() {
            self.content_store.insert_batch(content_items).await?;
        }

        let mut name_builder = StringBuilder::new();
        let mut file_path_builder = StringBuilder::new();
        let mut line_builder = Int64Builder::new();
        let mut kind_builder = StringBuilder::new();
        let mut size_builder = Int64Builder::new();
        let mut fields_builder = StringBuilder::new();
        let mut types_builder = StringBuilder::new();

        for type_info in types {
            name_builder.append_value(&type_info.name);
            file_path_builder.append_value(&type_info.file_path);

            line_builder.append_value(type_info.line_start as i64);
            kind_builder.append_value(&type_info.kind);

            if let Some(size) = type_info.size {
                size_builder.append_value(size as i64);
            } else {
                size_builder.append_null();
            }

            fields_builder.append_value(serde_json::to_string(&type_info.members)?);

            // Serialize types to JSON strings (nullable)
            if let Some(ref types_list) = type_info.types {
                types_builder.append_value(serde_json::to_string(types_list)?);
            } else {
                types_builder.append_null();
            }
        }

        // Create definition_hash strings (nullable for empty definitions) - unused, keeping for documentation
        let _definition_hash_strings: Vec<Option<String>> = types
            .iter()
            .map(|type_info| {
                if type_info.definition.is_empty() {
                    None
                } else {
                    Some(crate::hash::compute_blake3_hash(&type_info.definition))
                }
            })
            .collect();

        let mut definition_hash_builder = StringBuilder::new();
        for item in types {
            if item.definition.is_empty() {
                definition_hash_builder.append_null();
            } else {
                definition_hash_builder
                    .append_value(crate::hash::compute_blake3_hash(&item.definition));
            }
        }
        let definition_hash_array = definition_hash_builder.finish();

        let mut git_file_hash_builder = StringBuilder::new();
        for item in types {
            git_file_hash_builder.append_value(&item.git_file_hash);
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
            ("line", Arc::new(line_builder.finish()) as ArrayRef),
            ("kind", Arc::new(kind_builder.finish()) as ArrayRef),
            ("size", Arc::new(size_builder.finish()) as ArrayRef),
            ("fields", Arc::new(fields_builder.finish()) as ArrayRef),
            (
                "definition_hash",
                Arc::new(definition_hash_array) as ArrayRef,
            ),
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
        types: &[TypeInfo],
    ) -> Result<()> {
        // Skip content storage, just build metadata arrays
        let mut name_builder = StringBuilder::new();
        let mut file_path_builder = StringBuilder::new();
        let mut line_builder = Int64Builder::new();
        let mut kind_builder = StringBuilder::new();
        let mut size_builder = Int64Builder::new();
        let mut fields_builder = StringBuilder::new();
        let mut types_builder = StringBuilder::new();

        for type_info in types {
            name_builder.append_value(&type_info.name);
            file_path_builder.append_value(&type_info.file_path);
            line_builder.append_value(type_info.line_start as i64);
            kind_builder.append_value(&type_info.kind);
            size_builder.append_value(type_info.size.unwrap_or(0) as i64);

            // Serialize members to JSON
            let fields_json = serde_json::to_string(&type_info.members).unwrap_or_default();
            fields_builder.append_value(&fields_json);

            // Handle types as JSON array
            let types_json = type_info
                .types
                .as_ref()
                .map(|ts| serde_json::to_string(ts).unwrap_or_default())
                .unwrap_or_default();
            types_builder.append_value(&types_json);
        }

        let mut definition_hash_builder = StringBuilder::new();
        for item in types {
            if !item.definition.is_empty() {
                definition_hash_builder
                    .append_value(crate::hash::compute_blake3_hash(&item.definition));
            } else {
                definition_hash_builder.append_value(""); // Empty hash for empty definition
            }
        }
        let definition_hash_array = definition_hash_builder.finish();

        let mut git_file_hash_builder = StringBuilder::new();
        for item in types {
            git_file_hash_builder.append_value(&item.git_file_hash);
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
            ("line", Arc::new(line_builder.finish()) as ArrayRef),
            ("kind", Arc::new(kind_builder.finish()) as ArrayRef),
            ("size", Arc::new(size_builder.finish()) as ArrayRef),
            ("fields", Arc::new(fields_builder.finish()) as ArrayRef),
            (
                "definition_hash",
                Arc::new(definition_hash_array) as ArrayRef,
            ),
            ("types", Arc::new(types_builder.finish()) as ArrayRef),
        ])?;

        let batches = vec![Ok(batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);
        table.add(batch_iterator).execute().await?;

        Ok(())
    }

    pub async fn find_by_name(&self, name: &str) -> Result<Option<TypeInfo>> {
        let table = self.connection.open_table("types").execute().await?;
        let escaped_name = name.replace("'", "''");

        let results = table
            .query()
            .only_if(format!("name = '{escaped_name}'"))
            .limit(1)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        if results.is_empty() || results[0].num_rows() == 0 {
            return Ok(None);
        }

        let batch = &results[0];
        self.extract_type_from_batch(batch, 0).await
    }

    pub async fn exists(&self, name: &str, kind: &str, file_path: &str) -> Result<bool> {
        let table = self.connection.open_table("types").execute().await?;
        let escaped_name = name.replace("'", "''");
        let escaped_kind = kind.replace("'", "''");
        let escaped_path = file_path.replace("'", "''");

        let results = table
            .query()
            .only_if(format!(
                "name = '{escaped_name}' AND kind = '{escaped_kind}' AND file_path = '{escaped_path}'"
            ))
            .limit(1)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        Ok(!results.is_empty() && results[0].num_rows() > 0)
    }

    pub async fn get_all(&self) -> Result<Vec<TypeInfo>> {
        // Use optimized bulk retrieval for better performance
        self.get_all_bulk_optimized().await
    }

    /// Get all types without resolving content hashes - much faster for dumps
    pub async fn get_all_metadata_only(&self) -> Result<Vec<TypeInfo>> {
        let table = self.connection.open_table("types").execute().await?;
        let mut all_types = Vec::new();
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
                    if let Ok(Some(type_data)) = self.extract_type_metadata_from_batch(batch, i) {
                        // Create TypeInfo with hash placeholder instead of resolving content
                        let definition = match type_data.definition_hash {
                            Some(ref hash) => format!("[blake3:{}]", hex::encode(hash)),
                            None => String::new(),
                        };

                        all_types.push(TypeInfo {
                            name: type_data.name,
                            file_path: type_data.file_path,
                            git_file_hash: type_data.git_file_hash,
                            line_start: type_data.line_start,
                            kind: type_data.kind,
                            size: type_data.size,
                            members: type_data.members,
                            definition,
                            types: type_data.types,
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

        Ok(all_types)
    }

    /// Count all types without resolving content - much faster for counts
    pub async fn count_all(&self) -> Result<usize> {
        let table = self.connection.open_table("types").execute().await?;
        Ok(table.count_rows(None).await?)
    }

    /// Optimized bulk retrieval that minimizes content table queries
    pub async fn get_all_bulk_optimized(&self) -> Result<Vec<TypeInfo>> {
        let table = self.connection.open_table("types").execute().await?;
        let mut all_type_data = Vec::new();
        let mut all_definition_hashes = std::collections::HashSet::new();
        let batch_size = 10000;
        let mut offset = 0;

        // Step 1: Fetch all type metadata and collect unique definition hashes
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
                    if let Ok(Some(type_data)) = self.extract_type_metadata_from_batch(batch, i) {
                        // Collect definition hash if not null
                        if let Some(ref definition_hash) = type_data.definition_hash {
                            all_definition_hashes.insert(definition_hash.clone());
                        }
                        all_type_data.push(type_data);
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
        let content_map = if !all_definition_hashes.is_empty() {
            let hash_vec: Vec<String> = all_definition_hashes.into_iter().collect();
            self.bulk_get_content(&hash_vec).await?
        } else {
            std::collections::HashMap::new()
        };

        // Step 3: Reconstruct TypeInfo objects with content
        let mut all_types = Vec::new();
        for type_data in all_type_data {
            let definition = match type_data.definition_hash {
                Some(hash) => content_map.get(&hash).cloned().unwrap_or_default(),
                None => String::new(),
            };

            all_types.push(TypeInfo {
                name: type_data.name,
                file_path: type_data.file_path,
                git_file_hash: type_data.git_file_hash,
                line_start: type_data.line_start,
                kind: type_data.kind,
                size: type_data.size,
                members: type_data.members,
                definition,
                types: type_data.types,
            });
        }

        Ok(all_types)
    }

    /// Extract type metadata from batch without content lookup
    fn extract_type_metadata_from_batch(
        &self,
        batch: &RecordBatch,
        row: usize,
    ) -> Result<Option<TypeMetadata>> {
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
        let line_array = batch
            .column(3)
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .unwrap();
        let kind_array = batch
            .column(4)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let size_array = batch
            .column(5)
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .unwrap();
        let fields_array = batch
            .column(6)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let definition_hash_array = batch
            .column(7)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let types_array = batch
            .column(8)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();

        let fields: Vec<FieldInfo> = serde_json::from_str(fields_array.value(row))?;
        let size = if size_array.is_null(row) {
            None
        } else {
            Some(size_array.value(row) as u64)
        };

        // Get definition hash if not null
        let definition_hash = if definition_hash_array.is_null(row) {
            None
        } else {
            Some(definition_hash_array.value(row).to_string())
        };

        // Parse types from JSON (nullable)
        let types = if types_array.is_null(row) {
            None
        } else {
            serde_json::from_str::<Vec<String>>(types_array.value(row)).ok()
        };

        Ok(Some(TypeMetadata {
            name: name_array.value(row).to_string(),
            file_path: file_path_array.value(row).to_string(),
            git_file_hash: git_file_hash_array.value(row).to_string(),
            line_start: line_array.value(row) as u32,
            kind: kind_array.value(row).to_string(),
            size,
            members: fields,
            definition_hash,
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

    /// Get types by a list of names (batch lookup) - optimized to minimize content queries
    pub async fn get_by_names(
        &self,
        names: &[String],
    ) -> Result<std::collections::HashMap<String, TypeInfo>> {
        if names.is_empty() {
            return Ok(std::collections::HashMap::new());
        }

        let table = self.connection.open_table("types").execute().await?;
        let mut all_type_data = Vec::new();
        let mut all_definition_hashes = std::collections::HashSet::new();

        // Step 1: Fetch all type metadata and collect unique definition hashes
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
                    if let Ok(Some(type_data)) = self.extract_type_metadata_from_batch(batch, i) {
                        // Collect definition hash if not null
                        if let Some(ref definition_hash) = type_data.definition_hash {
                            all_definition_hashes.insert(definition_hash.clone());
                        }
                        all_type_data.push(type_data);
                    }
                }
            }
        }

        // Step 2: Bulk fetch all content for the collected hashes
        let content_map = if !all_definition_hashes.is_empty() {
            let hash_vec: Vec<String> = all_definition_hashes.into_iter().collect();
            self.bulk_get_content(&hash_vec).await?
        } else {
            std::collections::HashMap::new()
        };

        // Step 3: Reconstruct TypeInfo objects with content
        let mut result = std::collections::HashMap::new();
        for type_data in all_type_data {
            let definition = match type_data.definition_hash {
                Some(hash) => content_map.get(&hash).cloned().unwrap_or_default(),
                None => String::new(),
            };

            let type_info = TypeInfo {
                name: type_data.name.clone(),
                file_path: type_data.file_path,
                git_file_hash: type_data.git_file_hash,
                line_start: type_data.line_start,
                kind: type_data.kind,
                size: type_data.size,
                members: type_data.members,
                definition,
                types: type_data.types,
            };

            result.insert(type_data.name, type_info);
        }

        Ok(result)
    }

    /// Git-aware type lookup by name: two-phase resolution
    pub async fn find_by_name_git_aware(
        &self,
        name: &str,
        git_sha: &str,
        git_repo_path: &str,
    ) -> Result<Option<TypeInfo>> {
        // Phase 1: Search by name to get file paths
        let table = self.connection.open_table("types").execute().await?;
        let escaped_name = name.replace("'", "''");

        let initial_results = table
            .query()
            .only_if(format!("name = '{escaped_name}'"))
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        if initial_results.is_empty() || initial_results[0].num_rows() == 0 {
            return Ok(None);
        }

        // Extract unique file paths
        let mut file_paths = std::collections::HashSet::new();
        for batch in &initial_results {
            let file_path_array = batch
                .column(1)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            for i in 0..batch.num_rows() {
                let file_path = file_path_array.value(i).to_string();
                file_paths.insert(file_path);
            }
        }

        // Phase 2: Resolve file paths to git_file_hashes
        let file_paths_vec: Vec<String> = file_paths.into_iter().collect();
        let resolved_hashes = self
            .resolve_git_file_hashes(&file_paths_vec, git_sha, git_repo_path)
            .await?;

        if resolved_hashes.is_empty() {
            return Ok(None);
        }

        // Phase 3: Query with specific git_file_hashes
        let hash_values: Vec<String> = resolved_hashes.values().cloned().collect();
        let types = self
            .find_by_git_hashes(&hash_values, Some(&escaped_name), None)
            .await?;

        Ok(types.into_iter().next())
    }

    /// Helper function to resolve git file hashes using gitoxide
    async fn resolve_git_file_hashes(
        &self,
        file_paths: &[String],
        git_sha: &str,
        git_repo_path: &str,
    ) -> Result<HashMap<String, String>> {
        // Use the passed git repository path instead of hardcoding "."
        tracing::debug!(
            "resolve_git_file_hashes: Looking for {} file paths at git SHA {}",
            file_paths.len(),
            git_sha
        );

        match crate::git::resolve_files_at_commit(git_repo_path, git_sha, file_paths) {
            Ok(resolved_hashes) => {
                tracing::debug!(
                    "resolve_git_file_hashes: Successfully resolved {} out of {} file paths",
                    resolved_hashes.len(),
                    file_paths.len()
                );
                Ok(resolved_hashes)
            }
            Err(e) => {
                tracing::warn!(
                    "resolve_git_file_hashes: Failed to resolve git files: {}",
                    e
                );
                Ok(HashMap::new()) // Return empty map instead of failing, let caller handle
            }
        }
    }

    /// Helper function to find types by git_file_hashes with optional filters
    async fn find_by_git_hashes(
        &self,
        git_hashes: &[String],
        name_filter: Option<&str>,
        kind_filter: Option<&str>,
    ) -> Result<Vec<TypeInfo>> {
        let table = self.connection.open_table("types").execute().await?;
        let mut types = Vec::new();

        // Process in chunks to avoid query size limits
        for chunk in git_hashes.chunks(100) {
            let hash_conditions: Vec<String> = chunk
                .iter()
                .map(|hash| format!("git_file_hash = '{hash}'"))
                .collect();
            let mut filter = hash_conditions.join(" OR ");

            if let Some(name) = name_filter {
                filter = format!("({}) AND name = '{}'", filter, name.replace("'", "''"));
            }

            if let Some(kind) = kind_filter {
                filter = format!("({}) AND kind = '{}'", filter, kind.replace("'", "''"));
            }

            let results = table
                .query()
                .only_if(filter)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            for batch in &results {
                for i in 0..batch.num_rows() {
                    if let Some(type_info) = self.extract_type_from_batch(batch, i).await? {
                        types.push(type_info);
                    }
                }
            }
        }

        Ok(types)
    }

    pub async fn extract_type_from_batch(
        &self,
        batch: &RecordBatch,
        row: usize,
    ) -> Result<Option<TypeInfo>> {
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
        let line_array = batch
            .column(3)
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .unwrap();
        let kind_array = batch
            .column(4)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let size_array = batch
            .column(5)
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .unwrap();
        let fields_array = batch
            .column(6)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let definition_hash_array = batch
            .column(7)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let types_array = batch
            .column(8)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();

        let fields: Vec<FieldInfo> = serde_json::from_str(fields_array.value(row))?;
        let size = if size_array.is_null(row) {
            None
        } else {
            Some(size_array.value(row) as u64)
        };

        // Get type definition from content table using hash (if not null)
        let definition = if definition_hash_array.is_null(row) {
            String::new() // Empty definition for null hash
        } else {
            let definition_hash = definition_hash_array.value(row);
            match self.content_store.get_content(definition_hash).await? {
                Some(content) => content,
                None => {
                    tracing::warn!(
                        "Definition content not found for hash: {}",
                        definition_hash.to_string()
                    );
                    String::new() // Fallback to empty definition if content not found
                }
            }
        };

        // Parse types from JSON (nullable)
        let types = if types_array.is_null(row) {
            None
        } else {
            serde_json::from_str::<Vec<String>>(types_array.value(row)).ok()
        };

        Ok(Some(TypeInfo {
            name: name_array.value(row).to_string(),
            file_path: file_path_array.value(row).to_string(),
            git_file_hash: git_file_hash_array.value(row).to_string(),
            line_start: line_array.value(row) as u32,
            kind: kind_array.value(row).to_string(),
            size,
            members: fields,
            definition,
            types,
        }))
    }

    fn get_schema(&self) -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            Field::new("name", DataType::Utf8, false),
            Field::new("file_path", DataType::Utf8, false),
            Field::new("git_file_hash", DataType::Utf8, false), // Git file hash as hex string
            Field::new("line", DataType::Int64, false),
            Field::new("kind", DataType::Utf8, false),
            Field::new("size", DataType::Int64, true),
            Field::new("fields", DataType::Utf8, false),
            Field::new("definition_hash", DataType::Utf8, true), // Blake3 hash referencing content table as hex string (nullable for empty definitions)
            Field::new("types", DataType::Utf8, true), // JSON array of type names referenced by this type
        ]))
    }
}

pub struct TypedefStore {
    connection: Connection,
}

impl TypedefStore {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    pub async fn insert_batch(&self, typedefs: Vec<TypedefInfo>) -> Result<()> {
        if typedefs.is_empty() {
            return Ok(());
        }

        // Convert TypedefInfo to TypeInfo with kind="typedef"
        let types: Vec<TypeInfo> = typedefs
            .into_iter()
            .map(|typedef| {
                let full_definition = format!(
                    "// Underlying type: {}\n{}",
                    typedef.underlying_type, typedef.definition
                );

                TypeInfo {
                    name: typedef.name,
                    file_path: typedef.file_path,
                    git_file_hash: typedef.git_file_hash,
                    line_start: typedef.line_start,
                    kind: "typedef".to_string(),
                    size: None,
                    members: Vec::new(),
                    definition: full_definition,
                    types: None, // Typedefs don't reference other types directly
                }
            })
            .collect();

        // Use TypeStore to insert these as types
        let type_store = TypeStore::new(self.connection.clone());
        type_store.insert_batch(types).await?;

        Ok(())
    }

    pub async fn find_by_name(&self, name: &str) -> Result<Option<TypedefInfo>> {
        let table = self.connection.open_table("types").execute().await?;
        let escaped_name = name.replace("'", "''");

        let results = table
            .query()
            .only_if(format!("name = '{escaped_name}' AND kind = 'typedef'"))
            .limit(1)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        if results.is_empty() || results[0].num_rows() == 0 {
            return Ok(None);
        }

        let batch = &results[0];
        self.extract_typedef_from_batch(batch, 0).await
    }

    pub async fn exists(&self, name: &str, file_path: &str) -> Result<bool> {
        let table = self.connection.open_table("types").execute().await?;
        let escaped_name = name.replace("'", "''");
        let escaped_path = file_path.replace("'", "''");

        let results = table
            .query()
            .only_if(format!(
                "name = '{escaped_name}' AND file_path = '{escaped_path}' AND kind = 'typedef'"
            ))
            .limit(1)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        Ok(!results.is_empty() && results[0].num_rows() > 0)
    }

    pub async fn get_all(&self) -> Result<Vec<TypedefInfo>> {
        let table = self.connection.open_table("types").execute().await?;
        let mut all_typedefs = Vec::new();
        let batch_size = 10000;
        let mut offset = 0;

        loop {
            let results = table
                .query()
                .only_if("kind = 'typedef'")
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
                    if let Ok(Some(typedef)) = self.extract_typedef_from_batch(batch, i).await {
                        all_typedefs.push(typedef);
                    }
                }
            }

            offset += batch_size;
            let total_rows: usize = results.iter().map(|b| b.num_rows()).sum();
            if total_rows < batch_size {
                break;
            }
        }

        Ok(all_typedefs)
    }

    /// Count all typedefs without resolving content - much faster for counts
    pub async fn count_all(&self) -> Result<usize> {
        let table = self.connection.open_table("types").execute().await?;
        Ok(table
            .count_rows(Some("kind = 'typedef'".to_string()))
            .await?)
    }

    /// Get typedefs by a list of names (batch lookup)
    pub async fn get_by_names(
        &self,
        names: &[String],
    ) -> Result<std::collections::HashMap<String, TypedefInfo>> {
        if names.is_empty() {
            return Ok(std::collections::HashMap::new());
        }

        let table = self.connection.open_table("types").execute().await?;
        let mut result = std::collections::HashMap::new();

        // Process in smaller batches to avoid query size limits
        for chunk in names.chunks(100) {
            let name_list = chunk
                .iter()
                .map(|name| format!("'{}'", name.replace("'", "''")))
                .collect::<Vec<_>>()
                .join(",");

            let filter = format!("name IN ({name_list}) AND kind = 'typedef'");

            let results = table
                .query()
                .only_if(filter)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            for batch in &results {
                for i in 0..batch.num_rows() {
                    if let Ok(Some(typedef_info)) = self.extract_typedef_from_batch(batch, i).await
                    {
                        result.insert(typedef_info.name.clone(), typedef_info);
                    }
                }
            }
        }

        Ok(result)
    }

    /// Git-aware typedef lookup by name: two-phase resolution
    pub async fn find_by_name_git_aware(
        &self,
        name: &str,
        git_sha: &str,
        git_repo_path: &str,
    ) -> Result<Option<TypedefInfo>> {
        // Phase 1: Search by name to get file paths
        let table = self.connection.open_table("types").execute().await?;
        let escaped_name = name.replace("'", "''");

        let initial_results = table
            .query()
            .only_if(format!("name = '{escaped_name}' AND kind = 'typedef'"))
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        if initial_results.is_empty() || initial_results[0].num_rows() == 0 {
            return Ok(None);
        }

        // Extract unique file paths
        let mut file_paths = std::collections::HashSet::new();
        for batch in &initial_results {
            let file_path_array = batch
                .column(1)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            for i in 0..batch.num_rows() {
                file_paths.insert(file_path_array.value(i).to_string());
            }
        }

        // Phase 2: Resolve file paths to git_file_hashes
        let file_paths_vec: Vec<String> = file_paths.into_iter().collect();
        let resolved_hashes = self
            .resolve_git_file_hashes(&file_paths_vec, git_sha, git_repo_path)
            .await?;

        if resolved_hashes.is_empty() {
            return Ok(None);
        }

        // Phase 3: Query with specific git_file_hashes
        let hash_values: Vec<String> = resolved_hashes.values().cloned().collect();
        let typedefs = self
            .find_by_git_hashes(&hash_values, Some(&escaped_name))
            .await?;

        Ok(typedefs.into_iter().next())
    }

    /// Helper function to resolve git file hashes using gitoxide
    async fn resolve_git_file_hashes(
        &self,
        file_paths: &[String],
        git_sha: &str,
        git_repo_path: &str,
    ) -> Result<HashMap<String, String>> {
        // Use the passed git repository path instead of hardcoding "."
        tracing::debug!(
            "resolve_git_file_hashes: Looking for {} file paths at git SHA {}",
            file_paths.len(),
            git_sha
        );

        match crate::git::resolve_files_at_commit(git_repo_path, git_sha, file_paths) {
            Ok(resolved_hashes) => {
                tracing::debug!(
                    "resolve_git_file_hashes: Successfully resolved {} out of {} file paths",
                    resolved_hashes.len(),
                    file_paths.len()
                );
                Ok(resolved_hashes)
            }
            Err(e) => {
                tracing::warn!(
                    "resolve_git_file_hashes: Failed to resolve git files: {}",
                    e
                );
                Ok(HashMap::new()) // Return empty map instead of failing, let caller handle
            }
        }
    }

    /// Helper function to find typedefs by git_file_hashes with optional name filter
    async fn find_by_git_hashes(
        &self,
        git_hashes: &[String],
        name_filter: Option<&str>,
    ) -> Result<Vec<TypedefInfo>> {
        let table = self.connection.open_table("types").execute().await?;
        let mut typedefs = Vec::new();

        // Process in chunks to avoid query size limits
        for chunk in git_hashes.chunks(100) {
            let hash_conditions: Vec<String> = chunk
                .iter()
                .map(|hash| format!("git_file_hash = '{hash}'"))
                .collect();
            let mut filter = format!("({}) AND kind = 'typedef'", hash_conditions.join(" OR "));

            if let Some(name) = name_filter {
                filter = format!("{} AND name = '{}'", filter, name.replace("'", "''"));
            }

            let results = table
                .query()
                .only_if(filter)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            for batch in &results {
                for i in 0..batch.num_rows() {
                    if let Some(typedef) = self.extract_typedef_from_batch(batch, i).await? {
                        typedefs.push(typedef);
                    }
                }
            }
        }

        Ok(typedefs)
    }

    async fn extract_typedef_from_batch(
        &self,
        batch: &RecordBatch,
        row: usize,
    ) -> Result<Option<TypedefInfo>> {
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
        let line_array = batch
            .column(3)
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .unwrap();
        // Column 4 is 'kind', column 5 is 'size', column 6 is 'fields', column 7 is 'definition_hash'
        let definition_hash_array = batch
            .column(7)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();

        // Get definition from content table using hash (if not null)
        let definition = if definition_hash_array.is_null(row) {
            String::new() // Empty definition for null hash
        } else {
            let definition_hash = definition_hash_array.value(row);
            // Create a type store to access the content store
            let type_store = TypeStore::new(self.connection.clone());
            match type_store
                .content_store
                .get_content(definition_hash)
                .await?
            {
                Some(content) => content,
                None => {
                    tracing::warn!(
                        "Definition content not found for hash: {}",
                        definition_hash.to_string()
                    );
                    String::new() // Fallback to empty definition if content not found
                }
            }
        };

        // Extract underlying type from definition field
        let (underlying_type, actual_definition) = if definition.starts_with("// Underlying type: ")
        {
            if let Some(newline_pos) = definition.find('\n') {
                let underlying_line = &definition[20..newline_pos]; // Skip "// Underlying type: "
                let actual_def = &definition[newline_pos + 1..];
                (underlying_line.to_string(), actual_def.to_string())
            } else {
                // Fallback if format is unexpected
                ("unknown".to_string(), definition.to_string())
            }
        } else {
            // No underlying type info embedded, use definition as-is
            ("unknown".to_string(), definition.to_string())
        };

        Ok(Some(TypedefInfo {
            name: name_array.value(row).to_string(),
            file_path: file_path_array.value(row).to_string(),
            git_file_hash: git_file_hash_array.value(row).to_string(),
            line_start: line_array.value(row) as u32,
            underlying_type,
            definition: actual_definition,
        }))
    }
}

#[derive(Debug, Clone)]
struct MacroMetadata {
    pub name: String,
    pub file_path: String,
    pub git_file_hash: String,
    pub line_start: u32,
    pub is_function_like: bool,
    pub parameters: Option<Vec<String>>,
    pub definition_hash: Option<String>,
    pub calls: Option<Vec<String>>,
    pub types: Option<Vec<String>>,
}

pub struct MacroStore {
    connection: Connection,
    content_store: ContentStore,
}

impl MacroStore {
    pub fn new(connection: Connection) -> Self {
        let content_store = ContentStore::new(connection.clone());
        Self {
            connection,
            content_store,
        }
    }

    pub async fn insert_batch(&self, macros: Vec<MacroInfo>) -> Result<()> {
        if macros.is_empty() {
            return Ok(());
        }

        let table = self.connection.open_table("macros").execute().await?;

        // Process in optimal batch sizes
        for chunk in macros.chunks(OPTIMAL_BATCH_SIZE) {
            self.insert_chunk(&table, chunk).await?;
        }

        Ok(())
    }

    pub async fn insert_metadata_only(&self, macros: Vec<MacroInfo>) -> Result<()> {
        if macros.is_empty() {
            return Ok(());
        }

        let table = self.connection.open_table("macros").execute().await?;

        // Process in optimal batch sizes
        for chunk in macros.chunks(OPTIMAL_BATCH_SIZE) {
            self.insert_metadata_chunk(&table, chunk).await?;
        }

        Ok(())
    }

    async fn insert_chunk(
        &self,
        table: &lancedb::table::Table,
        macros: &[MacroInfo],
    ) -> Result<()> {
        // First, store macro definitions in content table and collect their hashes
        let mut content_items = Vec::new();
        for macro_info in macros {
            if !macro_info.definition.is_empty() {
                content_items.push(crate::database::content::ContentInfo {
                    blake3_hash: crate::hash::compute_blake3_hash(&macro_info.definition),
                    content: macro_info.definition.clone(),
                });
            }
        }

        // Store content items without deduplication (for performance testing)
        if !content_items.is_empty() {
            self.content_store.insert_batch(content_items).await?;
        }

        let mut name_builder = StringBuilder::new();
        let mut file_path_builder = StringBuilder::new();
        let mut line_builder = Int64Builder::new();
        let mut is_function_like_builder = BooleanBuilder::new();
        let mut parameters_builder = StringBuilder::new();
        let mut calls_builder = StringBuilder::new();
        let mut types_builder = StringBuilder::new();

        for macro_info in macros {
            name_builder.append_value(&macro_info.name);
            file_path_builder.append_value(&macro_info.file_path);

            line_builder.append_value(macro_info.line_start as i64);
            is_function_like_builder.append_value(macro_info.is_function_like);

            if let Some(params) = &macro_info.parameters {
                parameters_builder.append_value(serde_json::to_string(params)?);
            } else {
                parameters_builder.append_null();
            }

            // Serialize calls to JSON strings (nullable)
            if let Some(ref calls_list) = macro_info.calls {
                calls_builder.append_value(serde_json::to_string(calls_list)?);
            } else {
                calls_builder.append_null();
            }

            // Serialize types to JSON strings (nullable)
            if let Some(ref types_list) = macro_info.types {
                types_builder.append_value(serde_json::to_string(types_list)?);
            } else {
                types_builder.append_null();
            }
        }

        // Create definition_hash strings (nullable for empty definitions) - unused, keeping for documentation
        let _definition_hash_strings: Vec<Option<String>> = macros
            .iter()
            .map(|macro_info| {
                if macro_info.definition.is_empty() {
                    None
                } else {
                    Some(crate::hash::compute_blake3_hash(&macro_info.definition))
                }
            })
            .collect();

        let mut definition_hash_builder = StringBuilder::new();
        for item in macros {
            if item.definition.is_empty() {
                definition_hash_builder.append_null();
            } else {
                definition_hash_builder
                    .append_value(crate::hash::compute_blake3_hash(&item.definition));
            }
        }
        let definition_hash_array = definition_hash_builder.finish();

        let mut git_file_hash_builder = StringBuilder::new();
        for item in macros {
            git_file_hash_builder.append_value(&item.git_file_hash);
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
            ("line", Arc::new(line_builder.finish()) as ArrayRef),
            (
                "is_function_like",
                Arc::new(is_function_like_builder.finish()) as ArrayRef,
            ),
            (
                "parameters",
                Arc::new(parameters_builder.finish()) as ArrayRef,
            ),
            (
                "definition_hash",
                Arc::new(definition_hash_array) as ArrayRef,
            ),
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
        macros: &[MacroInfo],
    ) -> Result<()> {
        // Skip content storage, just build metadata arrays
        let mut name_builder = StringBuilder::new();
        let mut file_path_builder = StringBuilder::new();
        let mut line_builder = Int64Builder::new();
        let mut is_function_like_builder = BooleanBuilder::new();
        let mut parameters_builder = StringBuilder::new();
        let mut calls_builder = StringBuilder::new();
        let mut types_builder = StringBuilder::new();

        for macro_info in macros {
            name_builder.append_value(&macro_info.name);
            file_path_builder.append_value(&macro_info.file_path);
            line_builder.append_value(macro_info.line_start as i64);

            is_function_like_builder.append_value(macro_info.is_function_like);

            // Serialize parameters to JSON
            let parameters_json = serde_json::to_string(&macro_info.parameters).unwrap_or_default();
            parameters_builder.append_value(&parameters_json);

            // Handle calls and types as JSON arrays
            let calls_json = macro_info
                .calls
                .as_ref()
                .map(|calls| serde_json::to_string(calls).unwrap_or_default())
                .unwrap_or_default();
            calls_builder.append_value(&calls_json);

            let types_json = macro_info
                .types
                .as_ref()
                .map(|types| serde_json::to_string(types).unwrap_or_default())
                .unwrap_or_default();
            types_builder.append_value(&types_json);
        }

        // Create definition_hash strings - unused, keeping for documentation
        let _definition_hash_strings: Vec<String> = macros
            .iter()
            .map(|macro_info| {
                if !macro_info.definition.is_empty() {
                    crate::hash::compute_blake3_hash(&macro_info.definition)
                } else {
                    String::new() // Empty hash for empty definition
                }
            })
            .collect();
        let mut definition_hash_builder = StringBuilder::new();
        for item in macros {
            if !item.definition.is_empty() {
                definition_hash_builder
                    .append_value(crate::hash::compute_blake3_hash(&item.definition));
            } else {
                definition_hash_builder.append_value(""); // Empty hash for empty definition
            }
        }
        let definition_hash_array = definition_hash_builder.finish();

        let mut git_file_hash_builder = StringBuilder::new();
        for item in macros {
            git_file_hash_builder.append_value(&item.git_file_hash);
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
            ("line", Arc::new(line_builder.finish()) as ArrayRef),
            (
                "is_function_like",
                Arc::new(is_function_like_builder.finish()) as ArrayRef,
            ),
            (
                "parameters",
                Arc::new(parameters_builder.finish()) as ArrayRef,
            ),
            (
                "definition_hash",
                Arc::new(definition_hash_array) as ArrayRef,
            ),
            ("calls", Arc::new(calls_builder.finish()) as ArrayRef),
            ("types", Arc::new(types_builder.finish()) as ArrayRef),
        ])?;

        let batches = vec![Ok(batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);
        table.add(batch_iterator).execute().await?;

        Ok(())
    }

    pub async fn find_by_name(&self, name: &str) -> Result<Option<MacroInfo>> {
        let table = self.connection.open_table("macros").execute().await?;
        let escaped_name = name.replace("'", "''");

        let results = table
            .query()
            .only_if(format!("name = '{escaped_name}'"))
            .limit(1)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        if results.is_empty() || results[0].num_rows() == 0 {
            return Ok(None);
        }

        let batch = &results[0];
        self.extract_macro_from_batch(batch, 0).await
    }

    pub async fn find_all_by_name(&self, name: &str) -> Result<Vec<MacroInfo>> {
        let table = self.connection.open_table("macros").execute().await?;
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

        let mut all_macros = Vec::new();
        for batch in &results {
            for i in 0..batch.num_rows() {
                if let Ok(Some(mac)) = self.extract_macro_from_batch(batch, i).await {
                    all_macros.push(mac);
                }
            }
        }

        Ok(all_macros)
    }

    pub async fn exists(&self, name: &str, file_path: &str) -> Result<bool> {
        let table = self.connection.open_table("macros").execute().await?;
        let escaped_name = name.replace("'", "''");
        let escaped_path = file_path.replace("'", "''");

        let results = table
            .query()
            .only_if(format!(
                "name = '{escaped_name}' AND file_path = '{escaped_path}'"
            ))
            .limit(1)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        Ok(!results.is_empty() && results[0].num_rows() > 0)
    }

    pub async fn get_all(&self) -> Result<Vec<MacroInfo>> {
        let table = self.connection.open_table("macros").execute().await?;
        let mut all_macros = Vec::new();
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
                    if let Ok(Some(macro_info)) = self.extract_macro_from_batch(batch, i).await {
                        all_macros.push(macro_info);
                    }
                }
            }

            offset += batch_size;
            let total_rows: usize = results.iter().map(|b| b.num_rows()).sum();
            if total_rows < batch_size {
                break;
            }
        }

        Ok(all_macros)
    }

    /// Count all macros without resolving content - much faster for counts
    pub async fn count_all(&self) -> Result<usize> {
        let table = self.connection.open_table("macros").execute().await?;
        Ok(table.count_rows(None).await?)
    }

    /// Get all macros without resolving content hashes - much faster for dumps
    pub async fn get_all_metadata_only(&self) -> Result<Vec<MacroInfo>> {
        let table = self.connection.open_table("macros").execute().await?;
        let mut all_macros = Vec::new();
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
                    if let Ok(Some(macro_data)) = self.extract_macro_metadata_from_batch(batch, i) {
                        // Create MacroInfo with hash placeholder instead of resolving content
                        let definition = match macro_data.definition_hash {
                            Some(ref hash) => format!("[blake3:{}]", hex::encode(hash)),
                            None => String::new(),
                        };

                        all_macros.push(MacroInfo {
                            name: macro_data.name,
                            file_path: macro_data.file_path,
                            git_file_hash: macro_data.git_file_hash,
                            line_start: macro_data.line_start,
                            is_function_like: macro_data.is_function_like,
                            parameters: macro_data.parameters,
                            definition,
                            calls: macro_data.calls,
                            types: macro_data.types,
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

        Ok(all_macros)
    }

    /// Get macros by a list of names (batch lookup)
    pub async fn get_by_names(
        &self,
        names: &[String],
    ) -> Result<std::collections::HashMap<String, MacroInfo>> {
        if names.is_empty() {
            return Ok(std::collections::HashMap::new());
        }

        let table = self.connection.open_table("macros").execute().await?;
        let mut result = std::collections::HashMap::new();

        // Process in smaller batches to avoid query size limits
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
                    if let Ok(Some(macro_info)) = self.extract_macro_from_batch(batch, i).await {
                        result.insert(macro_info.name.clone(), macro_info);
                    }
                }
            }
        }

        Ok(result)
    }

    async fn extract_macro_from_batch(
        &self,
        batch: &RecordBatch,
        row: usize,
    ) -> Result<Option<MacroInfo>> {
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
        let line_array = batch
            .column(3)
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .unwrap();
        let is_function_like_array = batch
            .column(4)
            .as_any()
            .downcast_ref::<arrow::array::BooleanArray>()
            .unwrap();
        let parameters_array = batch
            .column(5)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let definition_hash_array = batch
            .column(6)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let calls_array = batch
            .column(7)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let types_array = batch
            .column(8)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();

        let parameters = if parameters_array.is_null(row) {
            None
        } else {
            serde_json::from_str(parameters_array.value(row)).ok()
        };

        // Get macro definition from content table using hash (if not null)
        let definition = if definition_hash_array.is_null(row) {
            String::new() // Empty definition for null hash
        } else {
            let definition_hash = definition_hash_array.value(row);
            match self.content_store.get_content(definition_hash).await? {
                Some(content) => content,
                None => {
                    tracing::warn!(
                        "Definition content not found for hash: {}",
                        definition_hash.to_string()
                    );
                    String::new() // Fallback to empty definition if content not found
                }
            }
        };

        // Parse calls from JSON (nullable)
        let calls = if calls_array.is_null(row) {
            None
        } else {
            serde_json::from_str::<Vec<String>>(calls_array.value(row)).ok()
        };

        // Parse types from JSON (nullable)
        let types = if types_array.is_null(row) {
            None
        } else {
            serde_json::from_str::<Vec<String>>(types_array.value(row)).ok()
        };

        Ok(Some(MacroInfo {
            name: name_array.value(row).to_string(),
            file_path: file_path_array.value(row).to_string(),
            git_file_hash: git_file_hash_array.value(row).to_string(),
            line_start: line_array.value(row) as u32,
            is_function_like: is_function_like_array.value(row),
            parameters,
            definition,
            calls,
            types,
        }))
    }

    /// Extract macro metadata from batch without content lookup
    fn extract_macro_metadata_from_batch(
        &self,
        batch: &RecordBatch,
        row: usize,
    ) -> Result<Option<MacroMetadata>> {
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
        let line_array = batch
            .column(3)
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .unwrap();
        let is_function_like_array = batch
            .column(4)
            .as_any()
            .downcast_ref::<arrow::array::BooleanArray>()
            .unwrap();
        let parameters_array = batch
            .column(5)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let definition_hash_array = batch
            .column(6)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let calls_array = batch
            .column(7)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let types_array = batch
            .column(8)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();

        let parameters = if parameters_array.is_null(row) {
            None
        } else {
            serde_json::from_str(parameters_array.value(row)).ok()
        };

        // Get definition hash if not null
        let definition_hash = if definition_hash_array.is_null(row) {
            None
        } else {
            Some(definition_hash_array.value(row).to_string())
        };

        // Parse calls from JSON (nullable)
        let calls = if calls_array.is_null(row) {
            None
        } else {
            serde_json::from_str::<Vec<String>>(calls_array.value(row)).ok()
        };

        // Parse types from JSON (nullable)
        let types = if types_array.is_null(row) {
            None
        } else {
            serde_json::from_str::<Vec<String>>(types_array.value(row)).ok()
        };

        Ok(Some(MacroMetadata {
            name: name_array.value(row).to_string(),
            file_path: file_path_array.value(row).to_string(),
            git_file_hash: git_file_hash_array.value(row).to_string(),
            line_start: line_array.value(row) as u32,
            is_function_like: is_function_like_array.value(row),
            parameters,
            definition_hash,
            calls,
            types,
        }))
    }

    fn get_schema(&self) -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            Field::new("name", DataType::Utf8, false),
            Field::new("file_path", DataType::Utf8, false),
            Field::new("git_file_hash", DataType::Utf8, false), // Git file hash as hex string
            Field::new("line", DataType::Int64, false),
            Field::new("is_function_like", DataType::Boolean, false),
            Field::new("parameters", DataType::Utf8, true),
            Field::new("definition_hash", DataType::Utf8, true), // Blake3 hash referencing content table as hex string (nullable for empty definitions)
            Field::new("calls", DataType::Utf8, true), // JSON array of function names called by this macro
            Field::new("types", DataType::Utf8, true), // JSON array of type names used by this macro
        ]))
    }
}
