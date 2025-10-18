// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use arrow::array::{Array, StringArray};
use futures::TryStreamExt;
use lancedb::connection::Connection;
use lancedb::index::{vector::IvfPqIndexBuilder, Index as LanceIndex};
use lancedb::query::{ExecutableQuery, QueryBase};
use lancedb::DistanceType;

use crate::database::content::ContentStore;
use crate::types::{FieldInfo, FunctionInfo, MacroInfo, ParameterInfo, TypeInfo, TypedefInfo};
use crate::vectorizer::CodeVectorizer;
use std::collections::HashMap;

#[derive(Debug)]
pub struct FunctionMatch {
    pub function: FunctionInfo,
    pub similarity_score: f32, // Higher is more similar (1.0 = identical, 0.0 = orthogonal)
}

pub struct SearchManager {
    connection: Connection,
    git_repo_path: String,
    content_store: ContentStore,
}

impl SearchManager {
    pub fn new(connection: Connection, git_repo_path: String) -> Self {
        let content_store = ContentStore::new(connection.clone());
        Self {
            connection,
            git_repo_path,
            content_store,
        }
    }

    /// Generic git resolution function: maps file_path + git_sha → git_file_hash
    /// This is the core function for two-phase git-aware resolution
    async fn resolve_git_file_hashes(
        &self,
        file_paths: &[String],
        git_sha: &str,
    ) -> Result<HashMap<String, String>> {
        // Use the proper gitoxide-based resolution from git.rs
        tracing::debug!(
            "resolve_git_file_hashes: Looking for {} file paths at git SHA {}",
            file_paths.len(),
            git_sha
        );

        match crate::git::resolve_files_at_commit(&self.git_repo_path, git_sha, file_paths) {
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

    /// Helper method to resolve definition hash to actual content
    async fn resolve_definition(
        &self,
        definition_hash_array: &StringArray,
        row: usize,
    ) -> Result<String> {
        if definition_hash_array.is_null(row) {
            Ok(String::new())
        } else {
            let definition_hash = definition_hash_array.value(row);
            match self.content_store.get_content(definition_hash).await? {
                Some(content) => Ok(content),
                None => {
                    tracing::warn!("Definition content not found for hash: {}", definition_hash);
                    Ok(String::new()) // Fallback to empty definition if content not found
                }
            }
        }
    }

    pub async fn search_functions_fuzzy(&self, pattern: &str) -> Result<Vec<FunctionInfo>> {
        let table = self.connection.open_table("functions").execute().await?;
        let escaped_pattern = pattern.replace("'", "''");

        // First try exact match
        let exact_results = table
            .query()
            .only_if(format!("name = '{escaped_pattern}'"))
            .limit(100)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        // If exact matches found, use them; otherwise fall back to fuzzy search
        let results = if exact_results.iter().any(|batch| batch.num_rows() > 0) {
            exact_results
        } else {
            table
                .query()
                .only_if(format!("name LIKE '%{escaped_pattern}%'"))
                .limit(100)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?
        };

        let mut functions = Vec::new();
        for batch in &results {
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
            let git_hash_array = batch
                .column(2)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
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

            for i in 0..batch.num_rows() {
                let parameters: Vec<ParameterInfo> =
                    serde_json::from_str(parameters_array.value(i))?;

                // Get function body from content table using hash (if not null)
                let body = if body_hash_array.is_null(i) {
                    String::new()
                } else {
                    let body_hash = body_hash_array.value(i);
                    match self.content_store.get_content(body_hash).await? {
                        Some(content) => content,
                        None => {
                            tracing::warn!("Body content not found for hash: {}", body_hash);
                            String::new() // Fallback to empty body if content not found
                        }
                    }
                };

                functions.push(FunctionInfo {
                    name: name_array.value(i).to_string(),
                    file_path: file_path_array.value(i).to_string(),
                    git_file_hash: git_hash_array.value(i).to_string(),
                    line_start: line_start_array.value(i) as u32,
                    line_end: line_end_array.value(i) as u32,
                    return_type: return_type_array.value(i).to_string(),
                    parameters,
                    body,
                    calls: None, // Not populated in search results
                    types: None, // Not populated in search results
                });
            }
        }

        Ok(functions)
    }

    /// Git-aware function search: two-phase resolution with exact match priority
    /// 1. Search by name to get file paths
    /// 2. Resolve file paths to git_file_hashes for the specified git_sha
    /// 3. Query again with specific git_file_hashes
    pub async fn search_functions_fuzzy_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<FunctionInfo>> {
        // Phase 1: Search by name to get file paths
        let table = self.connection.open_table("functions").execute().await?;
        let escaped_pattern = pattern.replace("'", "''");

        // First try exact match
        let exact_results = table
            .query()
            .only_if(format!("name = '{escaped_pattern}'"))
            .limit(1000)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        // If exact matches found, use them; otherwise fall back to fuzzy search
        let initial_results = if exact_results.iter().any(|batch| batch.num_rows() > 0) {
            exact_results
        } else {
            table
                .query()
                .only_if(format!("name LIKE '%{escaped_pattern}%'"))
                .limit(1000) // Get more initially to account for filtering
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?
        };

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

        if file_paths.is_empty() {
            return Ok(Vec::new());
        }

        // Phase 2: Resolve file paths to git_file_hashes
        let file_paths_vec: Vec<String> = file_paths.into_iter().collect();
        let resolved_hashes = self
            .resolve_git_file_hashes(&file_paths_vec, git_sha)
            .await?;

        if resolved_hashes.is_empty() {
            return Ok(Vec::new());
        }

        // Phase 3: Query with specific git_file_hashes
        let hash_values: Vec<String> = resolved_hashes.values().cloned().collect();
        self.search_functions_by_git_hashes(&hash_values, Some(&escaped_pattern))
            .await
    }

    /// Helper function to search functions by git_file_hashes with optional name filter
    async fn search_functions_by_git_hashes(
        &self,
        git_hashes: &[String],
        name_filter: Option<&str>,
    ) -> Result<Vec<FunctionInfo>> {
        let table = self.connection.open_table("functions").execute().await?;
        let mut functions = Vec::new();

        // Process in chunks to avoid query size limits
        for chunk in git_hashes.chunks(100) {
            let hash_conditions: Vec<String> = chunk
                .iter()
                .map(|hash| format!("git_file_hash = '{hash}'"))
                .collect();
            let mut filter = hash_conditions.join(" OR ");

            if let Some(pattern) = name_filter {
                filter = format!("({filter}) AND name LIKE '%{pattern}%'");
            }

            let results = table
                .query()
                .only_if(filter)
                .limit(100)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            for batch in &results {
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
                let git_hash_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
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

                for i in 0..batch.num_rows() {
                    let parameters: Vec<ParameterInfo> =
                        serde_json::from_str(parameters_array.value(i))?;

                    // Get function body from content table using hash (if not null)
                    let body = if body_hash_array.is_null(i) {
                        String::new()
                    } else {
                        let body_hash = body_hash_array.value(i);
                        match self.content_store.get_content(body_hash).await? {
                            Some(content) => content,
                            None => {
                                tracing::warn!("Body content not found for hash: {}", body_hash);
                                String::new() // Fallback to empty body if content not found
                            }
                        }
                    };

                    functions.push(FunctionInfo {
                        name: name_array.value(i).to_string(),
                        file_path: file_path_array.value(i).to_string(),
                        git_file_hash: git_hash_array.value(i).to_string(),
                        line_start: line_start_array.value(i) as u32,
                        line_end: line_end_array.value(i) as u32,
                        return_type: return_type_array.value(i).to_string(),
                        parameters,
                        body,
                        calls: None, // Not populated in search results
                        types: None, // Not populated in search results
                    });
                }
            }
        }

        Ok(functions)
    }

    pub async fn search_types_fuzzy(&self, pattern: &str) -> Result<Vec<TypeInfo>> {
        let table = self.connection.open_table("types").execute().await?;
        let escaped_pattern = pattern.replace("'", "''");

        // First try exact match
        let exact_results = table
            .query()
            .only_if(format!("name = '{escaped_pattern}'"))
            .limit(100)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        // If exact matches found, use them; otherwise fall back to fuzzy search
        let results = if exact_results.iter().any(|batch| batch.num_rows() > 0) {
            exact_results
        } else {
            table
                .query()
                .only_if(format!("name LIKE '%{escaped_pattern}%'"))
                .limit(100)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?
        };

        let mut types = Vec::new();
        for batch in &results {
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
            let git_hash_array = batch
                .column(2)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
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
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap();

            for i in 0..batch.num_rows() {
                let fields: Vec<FieldInfo> = serde_json::from_str(fields_array.value(i))?;
                let size = if size_array.is_null(i) {
                    None
                } else {
                    Some(size_array.value(i) as u64)
                };

                // Resolve definition hash to actual content
                let definition = self.resolve_definition(definition_hash_array, i).await?;

                types.push(TypeInfo {
                    name: name_array.value(i).to_string(),
                    file_path: file_path_array.value(i).to_string(),
                    git_file_hash: git_hash_array.value(i).to_string(),
                    line_start: line_array.value(i) as u32,
                    kind: kind_array.value(i).to_string(),
                    size,
                    members: fields,
                    definition,
                    types: None, // Not populated in search results
                });
            }
        }

        Ok(types)
    }

    /// Git-aware types search: two-phase resolution with exact match priority
    pub async fn search_types_fuzzy_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<TypeInfo>> {
        // Phase 1: Search by name to get file paths
        let table = self.connection.open_table("types").execute().await?;
        let escaped_pattern = pattern.replace("'", "''");

        // First try exact match
        let exact_results = table
            .query()
            .only_if(format!("name = '{escaped_pattern}'"))
            .limit(1000)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        // If exact matches found, use them; otherwise fall back to fuzzy search
        let initial_results = if exact_results.iter().any(|batch| batch.num_rows() > 0) {
            exact_results
        } else {
            table
                .query()
                .only_if(format!("name LIKE '%{escaped_pattern}%'"))
                .limit(1000)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?
        };

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

        if file_paths.is_empty() {
            return Ok(Vec::new());
        }

        // Phase 2: Resolve file paths to git_file_hashes
        let file_paths_vec: Vec<String> = file_paths.into_iter().collect();
        let resolved_hashes = self
            .resolve_git_file_hashes(&file_paths_vec, git_sha)
            .await?;

        if resolved_hashes.is_empty() {
            return Ok(Vec::new());
        }

        // Phase 3: Query with specific git_file_hashes
        let hash_values: Vec<String> = resolved_hashes.values().cloned().collect();
        self.search_types_by_git_hashes(&hash_values, Some(&escaped_pattern), None)
            .await
    }

    /// Helper function to search types by git_file_hashes with optional filters
    async fn search_types_by_git_hashes(
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

            if let Some(pattern) = name_filter {
                filter = format!("({filter}) AND name LIKE '%{pattern}%'");
            }

            if let Some(kind) = kind_filter {
                filter = format!("({}) AND kind = '{}'", filter, kind.replace("'", "''"));
            }

            let results = table
                .query()
                .only_if(filter)
                .limit(100)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            for batch in &results {
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
                let git_hash_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
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
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    let fields: Vec<FieldInfo> = serde_json::from_str(fields_array.value(i))?;
                    let size = if size_array.is_null(i) {
                        None
                    } else {
                        Some(size_array.value(i) as u64)
                    };

                    // Resolve definition hash to actual content
                    let definition = self.resolve_definition(definition_hash_array, i).await?;

                    types.push(TypeInfo {
                        name: name_array.value(i).to_string(),
                        file_path: file_path_array.value(i).to_string(),
                        git_file_hash: git_hash_array.value(i).to_string(),
                        line_start: line_array.value(i) as u32,
                        kind: kind_array.value(i).to_string(),
                        size,
                        members: fields,
                        definition,
                        types: None, // Not populated in search results
                    });
                }
            }
        }

        Ok(types)
    }

    pub async fn search_types_by_kind(&self, kind: &str) -> Result<Vec<TypeInfo>> {
        let table = self.connection.open_table("types").execute().await?;
        let escaped_kind = kind.replace("'", "''");

        let results = table
            .query()
            .only_if(format!("kind = '{escaped_kind}'"))
            .limit(100)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut types = Vec::new();
        for batch in &results {
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
            let git_hash_array = batch
                .column(2)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
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
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap();

            for i in 0..batch.num_rows() {
                let fields: Vec<FieldInfo> = serde_json::from_str(fields_array.value(i))?;
                let size = if size_array.is_null(i) {
                    None
                } else {
                    Some(size_array.value(i) as u64)
                };

                // Resolve definition hash to actual content
                let definition = self.resolve_definition(definition_hash_array, i).await?;

                types.push(TypeInfo {
                    name: name_array.value(i).to_string(),
                    file_path: file_path_array.value(i).to_string(),
                    git_file_hash: git_hash_array.value(i).to_string(),
                    line_start: line_array.value(i) as u32,
                    kind: kind_array.value(i).to_string(),
                    size,
                    members: fields,
                    definition,
                    types: None, // Not populated in search results
                });
            }
        }

        Ok(types)
    }

    pub async fn search_typedefs_fuzzy(&self, pattern: &str) -> Result<Vec<TypedefInfo>> {
        let table = self.connection.open_table("types").execute().await?;
        let escaped_pattern = pattern.replace("'", "''");

        // First try exact match
        let exact_results = table
            .query()
            .only_if(format!("name = '{escaped_pattern}' AND kind = 'typedef'"))
            .limit(100)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        // If exact matches found, use them; otherwise fall back to fuzzy search
        let results = if exact_results.iter().any(|batch| batch.num_rows() > 0) {
            exact_results
        } else {
            table
                .query()
                .only_if(format!(
                    "name LIKE '%{escaped_pattern}%' AND kind = 'typedef'"
                ))
                .limit(100)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?
        };

        let mut typedefs = Vec::new();
        for batch in &results {
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
            let git_hash_array = batch
                .column(2)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
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
            let definition_hash_array = batch
                .column(7)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap(); // definition_hash is column 7

            for i in 0..batch.num_rows() {
                let kind = kind_array.value(i);

                // Filter to only include typedefs
                if kind != "typedef" {
                    continue;
                }
                // Resolve definition hash to actual content
                let definition = self.resolve_definition(definition_hash_array, i).await?;

                // Extract underlying type from definition field
                let (underlying_type, actual_definition) =
                    if definition.starts_with("// Underlying type: ") {
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

                typedefs.push(TypedefInfo {
                    name: name_array.value(i).to_string(),
                    file_path: file_path_array.value(i).to_string(),
                    git_file_hash: git_hash_array.value(i).to_string(),
                    line_start: line_array.value(i) as u32,
                    underlying_type,
                    definition: actual_definition,
                });
            }
        }

        Ok(typedefs)
    }

    pub async fn search_macros_fuzzy(&self, pattern: &str) -> Result<Vec<MacroInfo>> {
        let table = self.connection.open_table("macros").execute().await?;
        let escaped_pattern = pattern.replace("'", "''");

        // First try exact match
        let exact_results = table
            .query()
            .only_if(format!("name = '{escaped_pattern}'"))
            .limit(100)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        // If exact matches found, use them; otherwise fall back to fuzzy search
        let results = if exact_results.iter().any(|batch| batch.num_rows() > 0) {
            exact_results
        } else {
            table
                .query()
                .only_if(format!("name LIKE '%{escaped_pattern}%'"))
                .limit(100)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?
        };

        let mut macros = Vec::new();
        for batch in &results {
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
            let git_hash_array = batch
                .column(2)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
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
            let definition_array = batch
                .column(6)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();

            for i in 0..batch.num_rows() {
                // Extract git_sha (nullable)

                let parameters = if parameters_array.is_null(i) {
                    None
                } else {
                    serde_json::from_str::<Vec<String>>(parameters_array.value(i)).ok()
                };

                macros.push(MacroInfo {
                    name: name_array.value(i).to_string(),
                    file_path: file_path_array.value(i).to_string(),
                    git_file_hash: git_hash_array.value(i).to_string(),
                    line_start: line_array.value(i) as u32,
                    is_function_like: is_function_like_array.value(i),
                    parameters,
                    definition: definition_array.value(i).to_string(),
                    calls: None, // Not populated in search results
                    types: None, // Not populated in search results
                });
            }
        }

        Ok(macros)
    }

    /// Git-aware typedef search: two-phase resolution with exact match priority
    pub async fn search_typedefs_fuzzy_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<TypedefInfo>> {
        // Phase 1: Search by name to get file paths
        let table = self.connection.open_table("types").execute().await?;
        let escaped_pattern = pattern.replace("'", "''");

        // First try exact match
        let exact_results = table
            .query()
            .only_if(format!("name = '{escaped_pattern}' AND kind = 'typedef'"))
            .limit(1000)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        // If exact matches found, use them; otherwise fall back to fuzzy search
        let initial_results = if exact_results.iter().any(|batch| batch.num_rows() > 0) {
            exact_results
        } else {
            table
                .query()
                .only_if(format!(
                    "name LIKE '%{escaped_pattern}%' AND kind = 'typedef'"
                ))
                .limit(1000)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?
        };

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

        if file_paths.is_empty() {
            return Ok(Vec::new());
        }

        // Phase 2: Resolve file paths to git_file_hashes
        let file_paths_vec: Vec<String> = file_paths.into_iter().collect();
        let resolved_hashes = self
            .resolve_git_file_hashes(&file_paths_vec, git_sha)
            .await?;

        if resolved_hashes.is_empty() {
            return Ok(Vec::new());
        }

        // Phase 3: Query with specific git_file_hashes
        let hash_values: Vec<String> = resolved_hashes.values().cloned().collect();
        self.search_typedefs_by_git_hashes(&hash_values, Some(&escaped_pattern))
            .await
    }

    /// Git-aware macro search: two-phase resolution with exact match priority
    pub async fn search_macros_fuzzy_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<MacroInfo>> {
        // Phase 1: Search by name to get file paths
        let table = self.connection.open_table("macros").execute().await?;
        let escaped_pattern = pattern.replace("'", "''");

        // First try exact match
        let exact_results = table
            .query()
            .only_if(format!("name = '{escaped_pattern}'"))
            .limit(1000)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        // If exact matches found, use them; otherwise fall back to fuzzy search
        let initial_results = if exact_results.iter().any(|batch| batch.num_rows() > 0) {
            exact_results
        } else {
            table
                .query()
                .only_if(format!("name LIKE '%{escaped_pattern}%'"))
                .limit(1000)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?
        };

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

        if file_paths.is_empty() {
            return Ok(Vec::new());
        }

        // Phase 2: Resolve file paths to git_file_hashes
        let file_paths_vec: Vec<String> = file_paths.into_iter().collect();
        let resolved_hashes = self
            .resolve_git_file_hashes(&file_paths_vec, git_sha)
            .await?;

        if resolved_hashes.is_empty() {
            return Ok(Vec::new());
        }

        // Phase 3: Query with specific git_file_hashes
        let hash_values: Vec<String> = resolved_hashes.values().cloned().collect();
        self.search_macros_by_git_hashes(&hash_values, Some(&escaped_pattern))
            .await
    }

    /// Helper function to search typedefs by git_file_hashes with optional name filter
    async fn search_typedefs_by_git_hashes(
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

            if let Some(pattern) = name_filter {
                filter = format!("{filter} AND name LIKE '%{pattern}%'");
            }

            let results = table
                .query()
                .only_if(filter)
                .limit(100)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            for batch in &results {
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
                let git_hash_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let line_array = batch
                    .column(3)
                    .as_any()
                    .downcast_ref::<arrow::array::Int64Array>()
                    .unwrap();
                let definition_hash_array = batch
                    .column(7)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap(); // definition_hash is column 7

                for i in 0..batch.num_rows() {
                    // Resolve definition hash to actual content
                    let definition = self.resolve_definition(definition_hash_array, i).await?;

                    // Extract underlying type from definition field
                    let (underlying_type, actual_definition) =
                        if definition.starts_with("// Underlying type: ") {
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

                    typedefs.push(TypedefInfo {
                        name: name_array.value(i).to_string(),
                        file_path: file_path_array.value(i).to_string(),
                        git_file_hash: git_hash_array.value(i).to_string(),
                        line_start: line_array.value(i) as u32,
                        underlying_type,
                        definition: actual_definition,
                    });
                }
            }
        }

        Ok(typedefs)
    }

    /// Helper function to search macros by git_file_hashes with optional name filter
    async fn search_macros_by_git_hashes(
        &self,
        git_hashes: &[String],
        name_filter: Option<&str>,
    ) -> Result<Vec<MacroInfo>> {
        let table = self.connection.open_table("macros").execute().await?;
        let mut macros = Vec::new();

        // Process in chunks to avoid query size limits
        for chunk in git_hashes.chunks(100) {
            let hash_conditions: Vec<String> = chunk
                .iter()
                .map(|hash| format!("git_file_hash = '{hash}'"))
                .collect();
            let mut filter = hash_conditions.join(" OR ");

            if let Some(pattern) = name_filter {
                filter = format!("({filter}) AND name LIKE '%{pattern}%'");
            }

            let results = table
                .query()
                .only_if(filter)
                .limit(100)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            for batch in &results {
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
                let git_hash_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
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
                let definition_array = batch
                    .column(6)
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    let parameters = if parameters_array.is_null(i) {
                        None
                    } else {
                        serde_json::from_str::<Vec<String>>(parameters_array.value(i)).ok()
                    };

                    macros.push(MacroInfo {
                        name: name_array.value(i).to_string(),
                        file_path: file_path_array.value(i).to_string(),
                        git_file_hash: git_hash_array.value(i).to_string(),
                        line_start: line_array.value(i) as u32,
                        is_function_like: is_function_like_array.value(i),
                        parameters,
                        definition: definition_array.value(i).to_string(),
                        calls: None, // Not populated in search results
                        types: None, // Not populated in search results
                    });
                }
            }
        }

        Ok(macros)
    }

    /// Search types using regex patterns on the name column
    pub async fn search_types_regex(&self, pattern: &str) -> Result<Vec<TypeInfo>> {
        let table = self.connection.open_table("types").execute().await?;

        // Only escape single quotes for SQL string literal - preserve backslashes for regex
        let escaped_pattern = pattern.replace("'", "''");

        let where_clause = format!("regexp_match(name, '{escaped_pattern}')");
        let results = table
            .query()
            .only_if(&where_clause)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut types = Vec::new();
        for batch in &results {
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
            let git_hash_array = batch
                .column(2)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
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
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap();

            for i in 0..batch.num_rows() {
                let kind = kind_array.value(i);

                // Filter out typedefs
                if kind == "typedef" {
                    continue;
                }

                let fields: Vec<FieldInfo> = serde_json::from_str(fields_array.value(i))?;
                let size = if size_array.is_null(i) {
                    None
                } else {
                    Some(size_array.value(i) as u64)
                };

                // Resolve definition hash to actual content
                let definition = self.resolve_definition(definition_hash_array, i).await?;

                types.push(TypeInfo {
                    name: name_array.value(i).to_string(),
                    file_path: file_path_array.value(i).to_string(),
                    git_file_hash: git_hash_array.value(i).to_string(),
                    line_start: line_array.value(i) as u32,
                    kind: kind.to_string(),
                    size,
                    members: fields,
                    definition,
                    types: None, // Not populated in search results
                });
            }
        }

        Ok(types)
    }

    /// Search types using regex patterns on the name column (git-aware)
    pub async fn search_types_regex_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<TypeInfo>> {
        let table = self.connection.open_table("types").execute().await?;
        let escaped_pattern = pattern.replace("'", "''");

        let where_clause = format!("regexp_match(name, '{escaped_pattern}')");
        let initial_results = table
            .query()
            .only_if(&where_clause)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        if initial_results.is_empty() {
            return Ok(Vec::new());
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

        if file_paths.is_empty() {
            return Ok(Vec::new());
        }

        // Resolve file paths to git_file_hashes
        let file_paths_vec: Vec<String> = file_paths.into_iter().collect();
        let resolved_hashes = self
            .resolve_git_file_hashes(&file_paths_vec, git_sha)
            .await?;

        if resolved_hashes.is_empty() {
            return Ok(Vec::new());
        }

        // Query with specific git_file_hashes using regexp_match
        let hash_values: Vec<String> = resolved_hashes.values().cloned().collect();

        // Compile regex once before processing batches (performance optimization)
        let regex = regex::Regex::new(pattern)?;

        let mut types = Vec::new();
        for chunk in hash_values.chunks(100) {
            let hash_conditions: Vec<String> = chunk
                .iter()
                .map(|hash| format!("git_file_hash = '{hash}'"))
                .collect();
            let hash_filter = hash_conditions.join(" OR ");
            let filter = hash_filter; // Just use git hash filter

            let results = table
                .query()
                .only_if(filter)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            for batch in &results {
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
                let git_hash_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
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
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    let kind = kind_array.value(i);
                    let name = name_array.value(i);

                    // Filter out typedefs
                    if kind == "typedef" {
                        continue;
                    }

                    // Apply regex matching in code since LanceDB has issues with combined conditions
                    if !regex.is_match(name) {
                        continue;
                    }

                    let fields: Vec<FieldInfo> = serde_json::from_str(fields_array.value(i))?;
                    let size = if size_array.is_null(i) {
                        None
                    } else {
                        Some(size_array.value(i) as u64)
                    };

                    let definition = self.resolve_definition(definition_hash_array, i).await?;

                    types.push(TypeInfo {
                        name: name_array.value(i).to_string(),
                        file_path: file_path_array.value(i).to_string(),
                        git_file_hash: git_hash_array.value(i).to_string(),
                        line_start: line_array.value(i) as u32,
                        kind: kind.to_string(),
                        size,
                        members: fields,
                        definition,
                        types: None,
                    });
                }
            }
        }

        Ok(types)
    }

    /// Search typedefs using regex patterns on the name column
    pub async fn search_typedefs_regex(&self, pattern: &str) -> Result<Vec<TypedefInfo>> {
        let table = self.connection.open_table("types").execute().await?;

        // Only escape single quotes for SQL string literal - preserve backslashes for regex
        let escaped_pattern = pattern.replace("'", "''");

        let where_clause = format!("regexp_match(name, '{escaped_pattern}')");
        let results = table
            .query()
            .only_if(&where_clause)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut typedefs = Vec::new();
        for batch in &results {
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
            let git_hash_array = batch
                .column(2)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
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
            let definition_hash_array = batch
                .column(7)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap(); // definition_hash is column 7

            for i in 0..batch.num_rows() {
                let kind = kind_array.value(i);

                // Filter to only include typedefs
                if kind != "typedef" {
                    continue;
                }
                // Resolve definition hash to actual content
                let definition = self.resolve_definition(definition_hash_array, i).await?;

                // Extract underlying type from definition field
                let (underlying_type, actual_definition) =
                    if definition.starts_with("// Underlying type: ") {
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

                typedefs.push(TypedefInfo {
                    name: name_array.value(i).to_string(),
                    file_path: file_path_array.value(i).to_string(),
                    git_file_hash: git_hash_array.value(i).to_string(),
                    line_start: line_array.value(i) as u32,
                    underlying_type,
                    definition: actual_definition,
                });
            }
        }

        Ok(typedefs)
    }

    /// Search typedefs using regex patterns on the name column (git-aware)
    pub async fn search_typedefs_regex_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<TypedefInfo>> {
        let table = self.connection.open_table("types").execute().await?;
        let escaped_pattern = pattern.replace("'", "''");

        let where_clause = format!("regexp_match(name, '{escaped_pattern}')");
        let initial_results = table
            .query()
            .only_if(&where_clause)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        if initial_results.is_empty() {
            return Ok(Vec::new());
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

        if file_paths.is_empty() {
            return Ok(Vec::new());
        }

        // Resolve file paths to git_file_hashes
        let file_paths_vec: Vec<String> = file_paths.into_iter().collect();
        let resolved_hashes = self
            .resolve_git_file_hashes(&file_paths_vec, git_sha)
            .await?;

        if resolved_hashes.is_empty() {
            return Ok(Vec::new());
        }

        // Query with specific git_file_hashes using regexp_match for typedefs
        let hash_values: Vec<String> = resolved_hashes.values().cloned().collect();

        // Compile regex once before processing batches (performance optimization)
        let regex = regex::Regex::new(pattern)?;

        let mut typedefs = Vec::new();
        for chunk in hash_values.chunks(100) {
            let hash_conditions: Vec<String> = chunk
                .iter()
                .map(|hash| format!("git_file_hash = '{hash}'"))
                .collect();
            let hash_filter = hash_conditions.join(" OR ");
            let filter = hash_filter; // Just use git hash filter

            let results = table
                .query()
                .only_if(filter)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            for batch in &results {
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
                let git_hash_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
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
                let definition_hash_array = batch
                    .column(7)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    let kind = kind_array.value(i);
                    let name = name_array.value(i);

                    // Filter to only include typedefs
                    if kind != "typedef" {
                        continue;
                    }

                    // Apply regex matching in code since LanceDB has issues with combined conditions
                    if !regex.is_match(name) {
                        continue;
                    }

                    let definition = self.resolve_definition(definition_hash_array, i).await?;

                    let underlying_type = "unknown".to_string();
                    let actual_definition = definition;

                    typedefs.push(TypedefInfo {
                        name: name_array.value(i).to_string(),
                        file_path: file_path_array.value(i).to_string(),
                        git_file_hash: git_hash_array.value(i).to_string(),
                        line_start: line_array.value(i) as u32,
                        underlying_type,
                        definition: actual_definition,
                    });
                }
            }
        }

        Ok(typedefs)
    }

    /// Search functions using regex patterns on the name column
    pub async fn search_functions_regex(&self, pattern: &str) -> Result<Vec<FunctionInfo>> {
        let table = self.connection.open_table("functions").execute().await?;

        // Only escape single quotes for SQL string literal - preserve backslashes for regex
        let escaped_pattern = pattern.replace("'", "''");

        let where_clause = format!("regexp_match(name, '{escaped_pattern}')");
        let results = table
            .query()
            .only_if(&where_clause)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        // Apply regex matching in code since LanceDB has issues with combined conditions
        let regex = match regex::Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()), // Return empty for invalid regex patterns
        };

        let mut functions = Vec::new();
        for batch in &results {
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
            let git_hash_array = batch
                .column(2)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
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
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap();

            for i in 0..batch.num_rows() {
                let name = name_array.value(i);

                if !regex.is_match(name) {
                    continue;
                }

                let parameters: Vec<ParameterInfo> =
                    serde_json::from_str(parameters_array.value(i))?;

                // Get function body from content table using hash (if not null)
                let body = if body_hash_array.is_null(i) {
                    String::new()
                } else {
                    let body_hash = body_hash_array.value(i);
                    match self.content_store.get_content(body_hash).await? {
                        Some(content) => content,
                        None => {
                            tracing::warn!(
                                "Body content not found for hash: {}",
                                body_hash.to_string()
                            );
                            String::new() // Fallback to empty body if content not found
                        }
                    }
                };

                functions.push(FunctionInfo {
                    name: name.to_string(),
                    file_path: file_path_array.value(i).to_string(),
                    git_file_hash: git_hash_array.value(i).to_string(),
                    line_start: line_start_array.value(i) as u32,
                    line_end: line_end_array.value(i) as u32,
                    return_type: return_type_array.value(i).to_string(),
                    parameters,
                    body,
                    calls: None, // Not populated in search results
                    types: None, // Not populated in search results
                });
            }
        }

        Ok(functions)
    }

    /// Search functions using regex patterns on the name column (git-aware)
    pub async fn search_functions_regex_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<FunctionInfo>> {
        let table = self.connection.open_table("functions").execute().await?;
        let escaped_pattern = pattern.replace("'", "''");

        let where_clause = format!("regexp_match(name, '{escaped_pattern}')");
        let initial_results = table
            .query()
            .only_if(&where_clause)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        if initial_results.is_empty() {
            return Ok(Vec::new());
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

        if file_paths.is_empty() {
            return Ok(Vec::new());
        }

        // Resolve file paths to git_file_hashes
        let file_paths_vec: Vec<String> = file_paths.into_iter().collect();
        let resolved_hashes = self
            .resolve_git_file_hashes(&file_paths_vec, git_sha)
            .await?;

        if resolved_hashes.is_empty() {
            return Ok(Vec::new());
        }

        // Query with specific git_file_hashes using regex filtering in code
        let hash_values: Vec<String> = resolved_hashes.values().cloned().collect();

        // Apply regex matching in code
        let regex = match regex::Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()), // Return empty for invalid regex patterns
        };

        let mut functions = Vec::new();
        for chunk in hash_values.chunks(100) {
            let hash_conditions: Vec<String> = chunk
                .iter()
                .map(|hash| format!("git_file_hash = '{hash}'"))
                .collect();
            let filter = hash_conditions.join(" OR ");

            let results = table
                .query()
                .only_if(filter)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            for batch in &results {
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
                let git_hash_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
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
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    let name = name_array.value(i);

                    if !regex.is_match(name) {
                        continue;
                    }

                    let parameters: Vec<ParameterInfo> =
                        serde_json::from_str(parameters_array.value(i))?;

                    // Get function body from content table using hash (if not null)
                    let body = if body_hash_array.is_null(i) {
                        String::new()
                    } else {
                        let body_hash = body_hash_array.value(i);
                        match self.content_store.get_content(body_hash).await? {
                            Some(content) => content,
                            None => {
                                tracing::warn!(
                                    "Body content not found for hash: {}",
                                    body_hash.to_string()
                                );
                                String::new() // Fallback to empty body if content not found
                            }
                        }
                    };

                    functions.push(FunctionInfo {
                        name: name.to_string(),
                        file_path: file_path_array.value(i).to_string(),
                        git_file_hash: git_hash_array.value(i).to_string(),
                        line_start: line_start_array.value(i) as u32,
                        line_end: line_end_array.value(i) as u32,
                        return_type: return_type_array.value(i).to_string(),
                        parameters,
                        body,
                        calls: None,
                        types: None,
                    });
                }
            }
        }

        Ok(functions)
    }

    /// Search macros using regex patterns on the name column
    pub async fn search_macros_regex(&self, pattern: &str) -> Result<Vec<MacroInfo>> {
        let table = self.connection.open_table("macros").execute().await?;

        let escaped_pattern = pattern.replace("'", "''");

        let where_clause = format!("regexp_match(name, '{escaped_pattern}')");
        let results = table
            .query()
            .only_if(&where_clause)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        // Compile regex once before processing batches (performance optimization)
        let regex = regex::Regex::new(pattern)?;

        let mut macros = Vec::new();
        for batch in &results {
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
            let git_hash_array = batch
                .column(2)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
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
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap();

            for i in 0..batch.num_rows() {
                let name = name_array.value(i);

                // Apply regex matching in code
                if !regex.is_match(name) {
                    continue;
                }

                let parameters = if parameters_array.is_null(i) {
                    None
                } else {
                    let param_list: Vec<String> = serde_json::from_str(parameters_array.value(i))?;
                    if param_list.is_empty() {
                        None
                    } else {
                        Some(param_list)
                    }
                };

                let definition = if definition_hash_array.is_null(i) {
                    String::new()
                } else {
                    let definition_hash = definition_hash_array.value(i);
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

                macros.push(MacroInfo {
                    name: name.to_string(),
                    file_path: file_path_array.value(i).to_string(),
                    git_file_hash: git_hash_array.value(i).to_string(),
                    line_start: line_array.value(i) as u32,
                    is_function_like: is_function_like_array.value(i),
                    parameters,
                    definition,
                    calls: None,
                    types: None,
                });
            }
        }

        Ok(macros)
    }

    /// Search macros using regex patterns on the name column (git-aware)
    pub async fn search_macros_regex_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<MacroInfo>> {
        let table = self.connection.open_table("macros").execute().await?;
        let escaped_pattern = pattern.replace("'", "''");

        let where_clause = format!("regexp_match(name, '{escaped_pattern}')");
        let initial_results = table
            .query()
            .only_if(&where_clause)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        if initial_results.is_empty() {
            return Ok(Vec::new());
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

        if file_paths.is_empty() {
            return Ok(Vec::new());
        }

        // Resolve file paths to git_file_hashes
        let file_paths_vec: Vec<String> = file_paths.into_iter().collect();
        let resolved_hashes = self
            .resolve_git_file_hashes(&file_paths_vec, git_sha)
            .await?;

        if resolved_hashes.is_empty() {
            return Ok(Vec::new());
        }

        // Query with specific git_file_hashes using regex filtering in code
        let hash_values: Vec<String> = resolved_hashes.values().cloned().collect();

        let mut macros = Vec::new();
        for chunk in hash_values.chunks(100) {
            let hash_conditions: Vec<String> = chunk
                .iter()
                .map(|hash| format!("git_file_hash = '{hash}'"))
                .collect();
            let filter = hash_conditions.join(" OR ");

            let results = table
                .query()
                .only_if(filter)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            for batch in &results {
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
                let git_hash_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
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
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    let name = name_array.value(i);

                    // Apply regex matching in code
                    let regex = match regex::Regex::new(pattern) {
                        Ok(r) => r,
                        Err(_) => continue,
                    };
                    if !regex.is_match(name) {
                        continue;
                    }

                    let parameters = if parameters_array.is_null(i) {
                        None
                    } else {
                        let param_list: Vec<String> =
                            serde_json::from_str(parameters_array.value(i))?;
                        if param_list.is_empty() {
                            None
                        } else {
                            Some(param_list)
                        }
                    };

                    let definition = if definition_hash_array.is_null(i) {
                        String::new()
                    } else {
                        let definition_hash = definition_hash_array.value(i);
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

                    macros.push(MacroInfo {
                        name: name.to_string(),
                        file_path: file_path_array.value(i).to_string(),
                        git_file_hash: git_hash_array.value(i).to_string(),
                        line_start: line_array.value(i) as u32,
                        is_function_like: is_function_like_array.value(i),
                        parameters,
                        definition,
                        calls: None,
                        types: None,
                    });
                }
            }
        }

        Ok(macros)
    }
}

pub struct VectorSearchManager {
    connection: Connection,
    content_store: ContentStore,
}

impl VectorSearchManager {
    pub fn new(connection: Connection) -> Self {
        let content_store = ContentStore::new(connection.clone());
        Self {
            connection,
            content_store,
        }
    }

    pub async fn create_vector_index(&self) -> Result<()> {
        let table = self.connection.open_table("vectors").execute().await?;

        // Check how many vectors are available
        let vector_count = table
            .query()
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>();

        if vector_count < 10 {
            tracing::warn!(
                "Not enough vectors to create vector index: {} vectors found, need at least 10",
                vector_count
            );
            return Ok(());
        }

        // Adjust parameters based on the number of vectors
        let num_partitions = if vector_count < 256 {
            // For small datasets, use fewer partitions
            ((vector_count as f64).sqrt() as usize)
                .max(2)
                .min(vector_count)
        } else {
            ((vector_count as f64).sqrt() as usize).max(256).min(1024)
        };

        tracing::info!(
            "Creating vector index for {} vectors (using {} partitions)",
            vector_count,
            num_partitions
        );

        // Create IVF-PQ index optimized for code search
        let index_builder = IvfPqIndexBuilder::default()
            .distance_type(DistanceType::Cosine)
            .num_partitions(num_partitions as u32)
            .num_sub_vectors(8) // 256/32 for model2vec, will adjust dynamically if needed
            .num_bits(8)
            .sample_rate(256.min(vector_count) as u32)
            .max_iterations(50);

        table
            .create_index(&["vector"], LanceIndex::IvfPq(index_builder))
            .execute()
            .await?;

        tracing::info!("Created vector index for {} vectors", vector_count);
        Ok(())
    }

    pub async fn search_similar_functions_with_scores(
        &self,
        query_vector: &[f32],
        limit: usize,
        filter: Option<String>,
    ) -> Result<Vec<FunctionMatch>> {
        // First, search for similar vectors in the vectors table
        let vectors_table = self.connection.open_table("vectors").execute().await?;

        let mut vector_query = vectors_table
            .query()
            .nearest_to(query_vector)?
            .refine_factor(5)
            .nprobes(10)
            .limit(limit);

        // Apply additional filter if provided
        if let Some(additional_filter) = filter {
            vector_query = vector_query.only_if(additional_filter);
        }

        let vector_results = vector_query
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        // Extract content_hashes and distances from vector search results
        let mut content_hash_scores = Vec::new();
        for batch in &vector_results {
            let content_hash_array = batch
                .column(0)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap();
            let distance_array = batch
                .column(2) // LanceDB puts distance in column 2
                .as_any()
                .downcast_ref::<arrow::array::Float32Array>()
                .unwrap();

            for i in 0..batch.num_rows() {
                let hash = content_hash_array.value(i).to_string();
                let distance = distance_array.value(i);
                // Convert cosine distance to similarity score (1.0 - distance)
                // Cosine distance: 0.0 = identical, 2.0 = opposite
                let similarity = (1.0 - distance / 2.0).max(0.0);
                content_hash_scores.push((hash, similarity));
            }
        }

        let content_hashes: Vec<String> =
            content_hash_scores.iter().map(|(h, _)| h.clone()).collect();

        if content_hashes.is_empty() {
            return Ok(Vec::new());
        }

        // Create a map from content hash to similarity score
        let score_map: HashMap<String, f32> = content_hash_scores.into_iter().collect();

        // Now query the functions table for these content hashes (in body_hash field)
        let functions_table = self.connection.open_table("functions").execute().await?;

        // Process in chunks to avoid query size limits
        let mut function_matches = Vec::new();
        for chunk in content_hashes.chunks(100) {
            let hash_conditions: Vec<String> = chunk
                .iter()
                .map(|hash| format!("body_hash = '{hash}'"))
                .collect();
            let hash_filter = hash_conditions.join(" OR ");

            let function_results = functions_table
                .query()
                .only_if(hash_filter)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            for batch in &function_results {
                // Get body_hash column to look up similarity scores
                let body_hash_array = batch
                    .column(7) // body_hash is column 7 in functions table
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    if let Ok(Some(func)) = self
                        .extract_function_from_batch(batch, i, &self.content_store)
                        .await
                    {
                        // Get the similarity score for this function's body hash
                        let similarity_score = if body_hash_array.is_null(i) {
                            0.0 // Default score for functions without body hash
                        } else {
                            let body_hash = body_hash_array.value(i);
                            score_map.get(body_hash).copied().unwrap_or(0.0)
                        };

                        function_matches.push(FunctionMatch {
                            function: func,
                            similarity_score,
                        });
                    }
                }
            }
        }

        // Sort by similarity score (highest first) to show most relevant matches first
        function_matches.sort_by(|a, b| {
            b.similarity_score
                .partial_cmp(&a.similarity_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(function_matches)
    }

    pub async fn search_similar_functions(
        &self,
        query_vector: &[f32],
        limit: usize,
        filter: Option<String>,
    ) -> Result<Vec<FunctionInfo>> {
        let matches = self
            .search_similar_functions_with_scores(query_vector, limit, filter)
            .await?;
        Ok(matches.into_iter().map(|m| m.function).collect())
    }

    // Helper method to extract function data from a batch - similar to the one in functions.rs
    async fn extract_function_from_batch(
        &self,
        batch: &arrow::record_batch::RecordBatch,
        row: usize,
        content_store: &ContentStore,
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
        let git_hash_array = batch
            .column(2)
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
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

        let parameters: Vec<ParameterInfo> = serde_json::from_str(parameters_array.value(row))?;

        // Get function body from content table using hash (if not null)
        let body = if body_hash_array.is_null(row) {
            String::new()
        } else {
            let body_hash = body_hash_array.value(row);
            match content_store.get_content(body_hash).await? {
                Some(content) => content,
                None => {
                    tracing::warn!("Body content not found for hash: {}", body_hash);
                    String::new() // Fallback to empty body if content not found
                }
            }
        };

        Ok(Some(FunctionInfo {
            name: name_array.value(row).to_string(),
            file_path: file_path_array.value(row).to_string(),
            git_file_hash: git_hash_array.value(row).to_string(),
            line_start: line_start_array.value(row) as u32,
            line_end: line_end_array.value(row) as u32,
            return_type: return_type_array.value(row).to_string(),
            parameters,
            body,
            calls: None, // Not populated from database extraction helper
            types: None, // Not populated from database extraction helper
        }))
    }

    pub async fn search_similar_by_name(
        &self,
        vectorizer: &CodeVectorizer,
        name: &str,
        limit: usize,
    ) -> Result<Vec<FunctionInfo>> {
        // Create a synthetic code snippet from the function name
        let code_snippet = format!("void {name}() {{}}");
        let vector = vectorizer.vectorize_code(&code_snippet)?;

        self.search_similar_functions(&vector, limit, None).await
    }

    pub async fn update_vectors(&self, vectorizer: &CodeVectorizer) -> Result<()> {
        use crate::database::vectors::{VectorEntry, VectorStore};
        use indicatif::{ProgressBar, ProgressStyle};
        use rayon::prelude::*;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let vector_store = VectorStore::new(self.connection.clone());
        let existing_vectors = vector_store.get_stats().await?;

        tracing::info!(
            "Found {} existing vectors, checking for missing ones in content tables",
            existing_vectors
        );

        // First count total entries for progress bar
        let mut total_entries = 0;
        for shard in 0..16u8 {
            let table_name = format!("content_{shard}");
            if let Ok(content_table) = self.connection.open_table(&table_name).execute().await {
                let count_results = content_table
                    .query()
                    .execute()
                    .await?
                    .try_collect::<Vec<_>>()
                    .await?;
                total_entries += count_results
                    .iter()
                    .map(|batch| batch.num_rows())
                    .sum::<usize>();
            }
        }

        if total_entries == 0 {
            println!("No content found in database");
            return Ok(());
        }

        let pb = ProgressBar::new(total_entries as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({percent}%) {msg} [{eta}]",
            )?
            .progress_chars("##-"),
        );

        let processed_count = Arc::new(AtomicUsize::new(0));
        let new_vectors_count = Arc::new(AtomicUsize::new(0));

        // Memory-bounded chunk size (process ~10k entries at a time in memory)
        let memory_chunk_size = 10000;

        // Process each shard concurrently
        let shard_tasks: Vec<_> = (0..16u8)
            .map(|shard| {
                let connection = self.connection.clone();
                let vector_store = VectorStore::new(connection.clone());
                let vectorizer = vectorizer.clone();
                let pb = pb.clone();
                let processed_counter = Arc::clone(&processed_count);
                let new_vectors_counter = Arc::clone(&new_vectors_count);

                tokio::spawn(async move {
                    let table_name = format!("content_{shard}");
                    let content_table = match connection.open_table(&table_name).execute().await {
                        Ok(table) => table,
                        Err(_) => return Ok::<(), anyhow::Error>(()), // Skip missing shards
                    };

                    let mut offset = 0;
                    loop {
                        // Get a memory-bounded chunk from this shard
                        let results = content_table
                            .query()
                            .limit(memory_chunk_size)
                            .offset(offset)
                            .execute()
                            .await?
                            .try_collect::<Vec<_>>()
                            .await?;

                        if results.is_empty() || results.iter().all(|b| b.num_rows() == 0) {
                            break; // No more data in this shard
                        }

                        // Extract content from database results
                        let mut chunk_content = Vec::new();
                        for batch in &results {
                            let blake3_hash_array = batch
                                .column(0)
                                .as_any()
                                .downcast_ref::<arrow::array::StringArray>()
                                .unwrap();
                            let content_array = batch
                                .column(1)
                                .as_any()
                                .downcast_ref::<arrow::array::StringArray>()
                                .unwrap();

                            for i in 0..batch.num_rows() {
                                let content_hash = blake3_hash_array.value(i).to_string();
                                let content = content_array.value(i).to_string();

                                if !content.trim().is_empty() {
                                    chunk_content.push((content_hash, content));
                                }
                            }
                        }

                        if !chunk_content.is_empty() {
                            // Check which entries need vectors
                            let hashes: Vec<String> =
                                chunk_content.iter().map(|(h, _)| h.clone()).collect();
                            let existing = vector_store.get_vectors_batch(&hashes).await?;

                            let new_content: Vec<(String, String)> = chunk_content
                                .into_iter()
                                .filter(|(hash, _)| !existing.contains_key(hash))
                                .collect();

                            if !new_content.is_empty() {
                                // Use rayon for CPU parallelism within this chunk
                                let cpu_chunk_size = (new_content.len() / num_cpus::get()).max(10);

                                let chunk_results: Result<Vec<Vec<VectorEntry>>> = new_content
                                    .par_chunks(cpu_chunk_size)
                                    .map(|cpu_chunk| -> Result<Vec<VectorEntry>> {
                                        let content_texts: Vec<&str> = cpu_chunk
                                            .iter()
                                            .map(|(_, content)| content.as_str())
                                            .collect();

                                        let vectors = vectorizer.vectorize_batch(&content_texts)?;

                                        let vector_entries: Vec<VectorEntry> = cpu_chunk
                                            .iter()
                                            .zip(vectors)
                                            .map(|((content_hash, _), vector)| VectorEntry {
                                                content_hash: content_hash.clone(),
                                                vector,
                                            })
                                            .collect();

                                        Ok(vector_entries)
                                    })
                                    .collect();

                                let all_vectors: Vec<VectorEntry> =
                                    chunk_results?.into_iter().flatten().collect();

                                // Insert vectors
                                if !all_vectors.is_empty() {
                                    vector_store.insert_batch(all_vectors.clone()).await?;
                                    let new_count = new_vectors_counter
                                        .fetch_add(all_vectors.len(), Ordering::Relaxed)
                                        + all_vectors.len();
                                    pb.set_message(format!("Generated {new_count} vectors"));
                                }
                            }
                        }

                        // Update progress for all entries processed (not just new ones)
                        let entries_in_chunk =
                            results.iter().map(|batch| batch.num_rows()).sum::<usize>();
                        let current = processed_counter
                            .fetch_add(entries_in_chunk, Ordering::Relaxed)
                            + entries_in_chunk;
                        pb.set_position(current as u64);

                        offset += memory_chunk_size;
                    }

                    Ok(())
                })
            })
            .collect();

        // Wait for all shards to complete
        for task in shard_tasks {
            task.await??;
        }

        let final_new_vectors = new_vectors_count.load(Ordering::Relaxed);
        let final_processed = processed_count.load(Ordering::Relaxed);

        pb.finish_with_message(format!(
            "Vectorization complete: {final_processed} entries processed, {final_new_vectors} new vectors generated"
        ));

        tracing::info!(
            "Successfully processed {} entries, generated {} new vectors",
            final_processed,
            final_new_vectors
        );
        Ok(())
    }
}
