// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use arrow::array::{Array, StringArray};
use futures::TryStreamExt;
use lancedb::connection::Connection;
use lancedb::index::scalar::FullTextSearchQuery;
use lancedb::index::{vector::IvfPqIndexBuilder, Index as LanceIndex};
use lancedb::query::{ExecutableQuery, QueryBase};
use lancedb::DistanceType;

use crate::database::content::ContentStore;
use crate::types::{FieldInfo, FunctionInfo, ParameterInfo, TypeInfo, TypedefInfo};
use crate::vectorizer::CodeVectorizer;
use std::collections::HashMap;

/// Filter patterns for lore email vector searches
#[derive(Debug, Clone, Default)]
pub struct LoreEmailFilters<'a> {
    pub from_patterns: Option<&'a [String]>,
    pub subject_patterns: Option<&'a [String]>,
    pub body_patterns: Option<&'a [String]>,
    pub symbols_patterns: Option<&'a [String]>,
    pub recipients_patterns: Option<&'a [String]>,
    pub since_date: Option<&'a str>,
    pub until_date: Option<&'a str>,
}

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

    /// Search types using regex patterns on the name column
    pub async fn search_types_regex(&self, pattern: &str) -> Result<Vec<TypeInfo>> {
        let table = self.connection.open_table("types").execute().await?;

        // Only escape single quotes for SQL string literal - preserve backslashes for regex
        let escaped_pattern = pattern.replace("'", "''");

        let where_clause = format!("regexp_like(name, '{escaped_pattern}')");
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

        let where_clause = format!("regexp_like(name, '{escaped_pattern}')");
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

        // Query with specific git_file_hashes using regexp_like
        let hash_values: Vec<String> = resolved_hashes.values().cloned().collect();

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
                    let regex = match regex::RegexBuilder::new(pattern)
                        .case_insensitive(true)
                        .build()
                    {
                        Ok(r) => r,
                        Err(_) => continue, // Skip invalid regex patterns
                    };
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

        let where_clause = format!("regexp_like(name, '{escaped_pattern}')");
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

        let where_clause = format!("regexp_like(name, '{escaped_pattern}')");
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

        // Query with specific git_file_hashes using regexp_like for typedefs
        let hash_values: Vec<String> = resolved_hashes.values().cloned().collect();

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
                    let regex = match regex::RegexBuilder::new(pattern)
                        .case_insensitive(true)
                        .build()
                    {
                        Ok(r) => r,
                        Err(_) => continue, // Skip invalid regex patterns
                    };
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

        let where_clause = format!("regexp_like(name, '{escaped_pattern}')");
        let results = table
            .query()
            .only_if(&where_clause)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        // Apply regex matching in code since LanceDB has issues with combined conditions
        let regex = match regex::RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
        {
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

        let where_clause = format!("regexp_like(name, '{escaped_pattern}')");
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
        let regex = match regex::RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
        {
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

    /// Helper to query lore by fields and return intersection of message_ids
    /// Optimized for large result sets with capacity pre-allocation
    async fn query_lore_fields_intersection(
        &self,
        from_patterns: Option<&[String]>,
        subject_patterns: Option<&[String]>,
        body_patterns: Option<&[String]>,
        symbols_patterns: Option<&[String]>,
        recipients_patterns: Option<&[String]>,
        search_limit: usize,
    ) -> Result<std::collections::HashSet<String>> {
        use std::collections::HashSet;

        let lore_table = self.connection.open_table("lore").execute().await?;
        let mut field_result_sets: Vec<HashSet<String>> = Vec::new();

        // Helper function to query a field using substring matching and collect message_ids efficiently
        async fn query_field_impl(
            lore_table: &lancedb::Table,
            field_name: String,
            pattern: String,
            search_limit: usize,
        ) -> Result<HashSet<String>> {
            let start = std::time::Instant::now();

            tracing::info!(
                "vlore filter query: field='{}' pattern='{}' limit={}",
                field_name,
                pattern,
                search_limit
            );

            // FTS uses simple tokenizer - normalize pattern by stripping special chars
            let fts_pattern = pattern
                .split(|c: char| !c.is_alphanumeric() && c != ' ')
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ");

            let fts_query =
                FullTextSearchQuery::new(fts_pattern).with_column(field_name.clone())?;
            let mut query = lore_table.query().full_text_search(fts_query).select(
                lancedb::query::Select::Columns(vec![
                    "message_id".to_string(),
                    "_score".to_string(),
                    field_name.clone(),
                ]),
            );

            // Apply limit - use large limit if search_limit is 0 (unlimited)
            // FTS has a default limit of 10, so we must explicitly set a large limit
            let effective_limit = if search_limit > 0 {
                search_limit
            } else {
                100000
            };
            query = query.limit(effective_limit);

            let results = query.execute().await?.try_collect::<Vec<_>>().await?;

            // Step 2: Post-filter results with regex in memory (small result set)
            let regex = regex::RegexBuilder::new(&pattern)
                .case_insensitive(true)
                .build()?;
            let mut message_ids = HashSet::new();

            for batch in &results {
                let msg_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let field_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    let field_value = field_array.value(i);
                    if regex.is_match(field_value) {
                        message_ids.insert(msg_array.value(i).to_string());
                    }
                }
            }

            tracing::info!(
                "vlore filter completed: FTS returned {} candidates, regex filtered to {} in {:?}",
                results.iter().map(|b| b.num_rows()).sum::<usize>(),
                message_ids.len(),
                start.elapsed()
            );

            Ok(message_ids)
        }

        // Query from field
        if let Some(patterns) = from_patterns {
            if !patterns.is_empty() {
                // FTS: join patterns with spaces for multi-keyword search
                let combined_pattern = patterns.join(" ");
                field_result_sets.push(
                    query_field_impl(
                        &lore_table,
                        "from".to_string(),
                        combined_pattern,
                        search_limit,
                    )
                    .await?,
                );
            }
        }

        // Query subject field
        if let Some(patterns) = subject_patterns {
            if !patterns.is_empty() {
                // FTS: join patterns with spaces for multi-keyword search
                let combined_pattern = patterns.join(" ");
                field_result_sets.push(
                    query_field_impl(
                        &lore_table,
                        "subject".to_string(),
                        combined_pattern,
                        search_limit,
                    )
                    .await?,
                );
            }
        }

        // Query body field
        if let Some(patterns) = body_patterns {
            if !patterns.is_empty() {
                // FTS: join patterns with spaces for multi-keyword search
                let combined_pattern = patterns.join(" ");
                field_result_sets.push(
                    query_field_impl(
                        &lore_table,
                        "body".to_string(),
                        combined_pattern,
                        search_limit,
                    )
                    .await?,
                );
            }
        }

        // Query symbols field
        if let Some(patterns) = symbols_patterns {
            if !patterns.is_empty() {
                // FTS: join patterns with spaces for multi-keyword search
                let combined_pattern = patterns.join(" ");
                field_result_sets.push(
                    query_field_impl(
                        &lore_table,
                        "symbols".to_string(),
                        combined_pattern,
                        search_limit,
                    )
                    .await?,
                );
            }
        }

        // Query recipients field
        if let Some(patterns) = recipients_patterns {
            if !patterns.is_empty() {
                // FTS: join patterns with spaces for multi-keyword search
                let combined_pattern = patterns.join(" ");
                field_result_sets.push(
                    query_field_impl(
                        &lore_table,
                        "recipients".to_string(),
                        combined_pattern,
                        search_limit,
                    )
                    .await?,
                );
            }
        }

        // Compute intersection efficiently
        if field_result_sets.is_empty() {
            return Ok(HashSet::new());
        }

        let intersection_start = std::time::Instant::now();

        // Start with the smallest set for faster intersection
        field_result_sets.sort_by_key(|s| s.len());

        tracing::info!(
            "vlore intersection: {} sets with sizes: {:?}",
            field_result_sets.len(),
            field_result_sets
                .iter()
                .map(|s| s.len())
                .collect::<Vec<_>>()
        );

        let mut intersection = field_result_sets[0].clone();
        for (idx, set) in field_result_sets.iter().enumerate().skip(1) {
            let before_size = intersection.len();
            // Use retain for in-place intersection (faster than creating new set)
            intersection.retain(|id| set.contains(id));
            tracing::info!(
                "vlore intersection step {}: {} -> {} results",
                idx,
                before_size,
                intersection.len()
            );

            // Early exit if intersection becomes empty
            if intersection.is_empty() {
                break;
            }
        }

        tracing::info!(
            "vlore intersection completed: {} final results in {:?}",
            intersection.len(),
            intersection_start.elapsed()
        );

        Ok(intersection)
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
            ((vector_count as f64).sqrt() as usize).clamp(256, 1024)
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

        tracing::info!("Starting function content vectorization");

        // Build hashset of all existing vector content_hashes upfront
        println!("Loading existing vectors into memory...");
        let vectors_table = self.connection.open_table("vectors").execute().await?;
        let existing_vector_results = vectors_table
            .query()
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut existing_content_hashes = std::collections::HashSet::new();
        for batch in &existing_vector_results {
            let hash_array = batch
                .column(0)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap();
            for i in 0..batch.num_rows() {
                existing_content_hashes.insert(hash_array.value(i).to_string());
            }
        }

        println!(
            "Loaded {} existing content hashes into memory",
            existing_content_hashes.len()
        );

        tracing::info!(
            "Found {} existing vectors, checking for missing ones in content tables",
            existing_content_hashes.len()
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

        // Share the hashset across all shard tasks
        let existing_content_hashes = Arc::new(existing_content_hashes);

        // Process each shard concurrently
        let shard_tasks: Vec<_> = (0..16u8)
            .map(|shard| {
                let connection = self.connection.clone();
                let vector_store = VectorStore::new(connection.clone());
                let vectorizer = vectorizer.clone();
                let pb = pb.clone();
                let processed_counter = Arc::clone(&processed_count);
                let new_vectors_counter = Arc::clone(&new_vectors_count);
                let existing_hashes = Arc::clone(&existing_content_hashes);

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
                            // Filter out already-vectorized content using the shared hashset
                            let new_content: Vec<(String, String)> = chunk_content
                                .into_iter()
                                .filter(|(hash, _)| !existing_hashes.contains(hash))
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

        // Hashset is automatically freed here when function returns
        drop(existing_content_hashes);
        println!("Function vectorization complete, memory freed");

        Ok(())
    }

    pub async fn update_commit_vectors(&self, vectorizer: &CodeVectorizer) -> Result<()> {
        use crate::database::vectors::VectorEntry;
        use indicatif::{ProgressBar, ProgressStyle};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        tracing::info!("Starting commit vectorization");

        // Open git_commits table
        let commits_table = self.connection.open_table("git_commits").execute().await?;

        // Get all commits
        let commit_results = commits_table
            .query()
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let total_commits: usize = commit_results.iter().map(|batch| batch.num_rows()).sum();

        if total_commits == 0 {
            println!("No commits found in database");
            return Ok(());
        }

        println!("Found {} commits to vectorize", total_commits);

        // Check which commits already have vectors
        let commit_vectors_table = self
            .connection
            .open_table("commit_vectors")
            .execute()
            .await?;
        let existing_vector_results = commit_vectors_table
            .query()
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut existing_commit_shas = std::collections::HashSet::new();
        for batch in &existing_vector_results {
            let sha_array = batch
                .column(0)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap();
            for i in 0..batch.num_rows() {
                existing_commit_shas.insert(sha_array.value(i).to_string());
            }
        }

        tracing::info!(
            "Found {} existing commit vectors, {} new commits to vectorize",
            existing_commit_shas.len(),
            total_commits - existing_commit_shas.len()
        );

        // Extract commit data (git_sha, message, diff)
        let mut commits_to_vectorize = Vec::new();
        for batch in &commit_results {
            let git_sha_array = batch
                .column(0)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap();
            let message_array = batch
                .column(4) // message is column 4
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap();
            let diff_array = batch
                .column(6) // diff is column 6
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap();

            for i in 0..batch.num_rows() {
                let git_sha = git_sha_array.value(i).to_string();

                // Skip if already vectorized
                if existing_commit_shas.contains(&git_sha) {
                    continue;
                }

                let message = message_array.value(i).to_string();
                let diff = diff_array.value(i).to_string();

                // Combine message and diff
                let combined_text = format!("{}\n\n{}", message, diff);

                commits_to_vectorize.push((git_sha, combined_text));
            }
        }

        if commits_to_vectorize.is_empty() {
            println!("All commits already have vectors");
            return Ok(());
        }

        // Free the hashset now that we've filtered commits
        drop(existing_commit_shas);
        println!(
            "Commit hashset freed, {} commits to vectorize",
            commits_to_vectorize.len()
        );

        let pb = ProgressBar::new(commits_to_vectorize.len() as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({percent}%) {msg} [{eta}]",
            )?
            .progress_chars("##-"),
        );

        let processed_count = Arc::new(AtomicUsize::new(0));

        // Open commit_vectors table once and cache it for all insertions
        let commit_vectors_table = self
            .connection
            .open_table("commit_vectors")
            .execute()
            .await?;

        // Process commits in streaming batches for better progress feedback
        // Larger batch size (500) reduces database insertion overhead while still providing
        // visible progress updates every 10-15 seconds
        let streaming_batch_size = 500;
        let total_to_process = commits_to_vectorize.len();

        for batch_start in (0..total_to_process).step_by(streaming_batch_size) {
            let batch_end = (batch_start + streaming_batch_size).min(total_to_process);
            let batch = &commits_to_vectorize[batch_start..batch_end];

            // Vectorize all texts in one call - vectorizer handles internal batching and
            // parallelism optimally (model2vec-rs uses num_cpus * 128 batch size internally)
            let texts: Vec<&str> = batch.iter().map(|(_, text)| text.as_str()).collect();
            let vectors = vectorizer.vectorize_batch(&texts)?;

            let batch_vectors: Vec<VectorEntry> = batch
                .iter()
                .zip(vectors)
                .map(|((git_sha, _), vector)| VectorEntry {
                    content_hash: git_sha.clone(), // Using git_commit_sha as the key
                    vector,
                })
                .collect();

            // Insert this batch immediately using cached table
            if !batch_vectors.is_empty() {
                Self::insert_commit_vectors_batch_with_table(&commit_vectors_table, &batch_vectors)
                    .await?;

                let count = processed_count.fetch_add(batch_vectors.len(), Ordering::Relaxed)
                    + batch_vectors.len();
                pb.set_position(count as u64);
                pb.set_message(format!("Inserted {} vectors", count));
            }
        }

        let total_generated = processed_count.load(Ordering::Relaxed);
        pb.finish_with_message(format!(
            "Commit vectorization complete: {} vectors generated",
            total_generated
        ));

        tracing::info!("Successfully vectorized {} commits", total_generated);
        Ok(())
    }

    /// Helper to insert commit vectors into commit_vectors table with cached table handle
    async fn insert_commit_vectors_batch_with_table(
        commit_vectors_table: &lancedb::table::Table,
        vectors: &[crate::database::vectors::VectorEntry],
    ) -> Result<()> {
        use arrow::array::{ArrayRef, FixedSizeListArray, StringBuilder};
        use arrow::datatypes::{DataType, Field, Float32Type, Schema};
        use arrow::record_batch::RecordBatchIterator;
        use std::sync::Arc;

        if vectors.is_empty() {
            return Ok(());
        }

        // Get vector dimension from first entry
        let vector_dim = vectors[0].vector.len();

        // Create git_commit_sha StringArray
        let mut sha_builder = StringBuilder::new();
        for entry in vectors {
            sha_builder.append_value(&entry.content_hash); // content_hash field contains git_commit_sha
        }
        let sha_array = sha_builder.finish();

        // Create vector array
        let vector_array = FixedSizeListArray::from_iter_primitive::<Float32Type, _, _>(
            vectors
                .iter()
                .map(|entry| Some(entry.vector.iter().map(|&v| Some(v)))),
            vector_dim as i32,
        );

        let schema = Arc::new(Schema::new(vec![
            Field::new("git_commit_sha", DataType::Utf8, false),
            Field::new(
                "vector",
                DataType::FixedSizeList(
                    Arc::new(Field::new("item", DataType::Float32, true)),
                    vector_dim as i32,
                ),
                false,
            ),
        ]));

        let batch = arrow::record_batch::RecordBatch::try_from_iter(vec![
            ("git_commit_sha", Arc::new(sha_array) as ArrayRef),
            ("vector", Arc::new(vector_array) as ArrayRef),
        ])?;

        let batches = vec![Ok(batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);
        commit_vectors_table.add(batch_iterator).execute().await?;

        Ok(())
    }

    pub async fn update_lore_vectors(&self, vectorizer: &CodeVectorizer) -> Result<()> {
        use crate::database::vectors::VectorEntry;
        use indicatif::{ProgressBar, ProgressStyle};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        tracing::info!("Starting lore email vectorization");

        // Open lore table
        let lore_table = self.connection.open_table("lore").execute().await?;

        // Load existing vector message_ids into a HashSet for fast lookup
        let mut existing_message_ids = std::collections::HashSet::new();
        match self.connection.open_table("lore_vectors").execute().await {
            Ok(lore_vectors_table) => {
                let mut existing_stream = lore_vectors_table.query().execute().await?;
                while let Some(batch) = existing_stream.try_next().await? {
                    let message_id_array = batch
                        .column(0)
                        .as_any()
                        .downcast_ref::<arrow::array::StringArray>()
                        .unwrap();
                    for i in 0..batch.num_rows() {
                        existing_message_ids.insert(message_id_array.value(i).to_string());
                    }
                }
                println!(
                    "Loaded {} existing lore message IDs into memory",
                    existing_message_ids.len()
                );
            }
            Err(_) => {
                println!("No existing lore vectors found (first run)");
            }
        }

        // Share hashset via Arc to avoid cloning for every worker
        let existing_message_ids = Arc::new(existing_message_ids);

        // Count total for progress bar
        println!("Counting lore emails...");
        let mut total_emails = 0;
        let mut emails_needing_vectors = 0;

        // Quick scan to count
        let mut temp_stream = lore_table.query().execute().await?;
        while let Some(batch) = temp_stream.try_next().await? {
            total_emails += batch.num_rows();
            let message_id_array = batch
                .column(3)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap();
            for i in 0..batch.num_rows() {
                if !existing_message_ids.contains(message_id_array.value(i)) {
                    emails_needing_vectors += 1;
                }
            }
        }

        if emails_needing_vectors == 0 {
            println!("All {} lore emails already have vectors", total_emails);
            return Ok(());
        }

        println!(
            "Found {} total lore emails, {} need vectorization",
            total_emails, emails_needing_vectors
        );

        let pb = ProgressBar::new(emails_needing_vectors as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({percent}%) {msg} [{eta}]",
            )?
            .progress_chars("##-"),
        );

        let processed_count = Arc::new(AtomicUsize::new(0));

        // Create parallel pipeline with multiple stages running concurrently:
        // 1. Reader task: streams RecordBatches from DB and sends to work queue
        // 2. Multiple extraction+vectorization workers: extract emails and vectorize in parallel
        // 3. Insertion task: collects vectors and inserts to DB
        use tokio::sync::mpsc;

        // Work queue: reader -> workers (sends RecordBatches with ~1024 rows each)
        let (work_tx, work_rx) = mpsc::channel::<arrow::record_batch::RecordBatch>(32);
        // Results queue: workers -> insertion task
        let (result_tx, mut result_rx) = mpsc::channel::<Vec<VectorEntry>>(32);

        let num_vectorization_workers = num_cpus::get().max(4); // At least 4 workers
        tracing::info!(
            "Starting parallel pipeline: 1 reader, {} vectorization workers, 1 inserter",
            num_vectorization_workers
        );

        // Clone for tasks
        let pb_clone = pb.clone();
        let processed_clone = processed_count.clone();
        let connection_clone = self.connection.clone();

        // Spawn database insertion task that consumes results
        let insertion_task = tokio::spawn(async move {
            // Open the table ONCE and reuse it for all insertions
            let lore_vectors_table = connection_clone
                .open_table("lore_vectors")
                .execute()
                .await?;

            let mut total_inserted = 0;
            while let Some(batch_vectors) = result_rx.recv().await {
                if let Err(e) =
                    insert_lore_vectors_batch_with_table(&lore_vectors_table, &batch_vectors).await
                {
                    tracing::error!("Failed to insert lore vectors batch: {}", e);
                    return Err(e);
                }

                total_inserted += batch_vectors.len();
                let count = processed_clone.fetch_add(batch_vectors.len(), Ordering::Relaxed)
                    + batch_vectors.len();
                pb_clone.set_position(count as u64);
                pb_clone.set_message(format!("Inserted {} vectors", count));
            }
            Ok::<_, anyhow::Error>(total_inserted)
        });

        // Spawn multiple extraction+vectorization workers
        // Workers extract emails from RecordBatches and vectorize in parallel
        let vectorizer_clone = vectorizer.clone();
        let mut worker_handles = Vec::new();

        // Share receiver via mutex for work distribution
        let work_rx = Arc::new(tokio::sync::Mutex::new(work_rx));

        for worker_id in 0..num_vectorization_workers {
            let work_rx_clone = work_rx.clone();
            let result_tx_clone = result_tx.clone();
            let vectorizer_worker = vectorizer_clone.clone();
            let existing_ids_worker = Arc::clone(&existing_message_ids); // Cheap Arc clone, not HashSet clone

            let worker = tokio::spawn(async move {
                let mut batches_processed = 0;
                loop {
                    // Get RecordBatch from queue
                    let record_batch = {
                        let mut rx = work_rx_clone.lock().await;
                        rx.recv().await
                    };

                    match record_batch {
                        Some(record_batch) => {
                            // Extract and vectorize emails in spawn_blocking (CPU-intensive)
                            let vectorizer_for_batch = vectorizer_worker.clone();
                            let existing_ids_for_batch = existing_ids_worker.clone();

                            let vectors =
                                tokio::task::spawn_blocking(move || -> Result<Vec<VectorEntry>> {
                                    // Extract email data from RecordBatch
                                    let message_id_array = record_batch
                                        .column(3)
                                        .as_any()
                                        .downcast_ref::<arrow::array::StringArray>()
                                        .unwrap();
                                    let from_array = record_batch
                                        .column(1)
                                        .as_any()
                                        .downcast_ref::<arrow::array::StringArray>()
                                        .unwrap();
                                    let subject_array = record_batch
                                        .column(5)
                                        .as_any()
                                        .downcast_ref::<arrow::array::StringArray>()
                                        .unwrap();
                                    let recipients_array = record_batch
                                        .column(7)
                                        .as_any()
                                        .downcast_ref::<arrow::array::StringArray>()
                                        .unwrap();
                                    let body_array = record_batch
                                        .column(9)
                                        .as_any()
                                        .downcast_ref::<arrow::array::StringArray>()
                                        .unwrap();

                                    // Extract emails that need vectorization
                                    let mut emails_to_vectorize = Vec::new();
                                    for i in 0..record_batch.num_rows() {
                                        let message_id = message_id_array.value(i).to_string();

                                        // Skip if already vectorized
                                        if existing_ids_for_batch.contains(&message_id) {
                                            continue;
                                        }

                                        let from = from_array.value(i);
                                        let subject = subject_array.value(i);
                                        let recipients = recipients_array.value(i);
                                        let body = body_array.value(i);

                                        let combined_text = format!(
                                            "From: {}\nTo/Cc: {}\nSubject: {}\n\n{}",
                                            from, recipients, subject, body
                                        );

                                        emails_to_vectorize.push((message_id, combined_text));
                                    }

                                    if emails_to_vectorize.is_empty() {
                                        return Ok(Vec::new());
                                    }

                                    // Vectorize all emails in this batch
                                    let texts: Vec<&str> = emails_to_vectorize
                                        .iter()
                                        .map(|(_, text)| text.as_str())
                                        .collect();

                                    let vector_results =
                                        vectorizer_for_batch.vectorize_batch(&texts)?;

                                    // Combine with message IDs
                                    let entries: Vec<VectorEntry> = emails_to_vectorize
                                        .iter()
                                        .zip(vector_results.into_iter())
                                        .map(|((message_id, _), vector)| VectorEntry {
                                            content_hash: message_id.clone(),
                                            vector,
                                        })
                                        .collect();

                                    Ok(entries)
                                })
                                .await??;

                            // Send results to insertion task
                            if !vectors.is_empty() {
                                result_tx_clone.send(vectors).await?;
                            }
                            batches_processed += 1;
                        }
                        None => {
                            // Channel closed, worker done
                            tracing::info!(
                                "Worker {} processed {} RecordBatches",
                                worker_id,
                                batches_processed
                            );
                            break;
                        }
                    }
                }
                Ok::<_, anyhow::Error>(())
            });

            worker_handles.push(worker);
        }

        // Spawn reader task that streams RecordBatches from DB and distributes to workers
        let lore_table_clone = lore_table.clone();
        let reader_task = tokio::spawn(async move {
            // Stream lore emails from database (LanceDB uses default batch size)
            let mut lore_stream = lore_table_clone.query().execute().await?;

            let mut total_batches_sent = 0;

            // Simply stream RecordBatches to workers - they'll extract emails in parallel
            while let Some(record_batch) = lore_stream.try_next().await? {
                work_tx.send(record_batch).await?;
                total_batches_sent += 1;
            }

            drop(work_tx); // Signal completion to workers
            tracing::info!(
                "Reader complete: sent {} RecordBatches to workers",
                total_batches_sent
            );
            Ok::<_, anyhow::Error>(())
        });

        // Let reader, workers, and inserter run concurrently!
        // Don't wait for reader - let it stream in parallel with workers processing

        // Reader will finish and close work_tx when done
        // Workers will finish when work_rx is closed and they've processed all batches
        // Inserter will finish when result_rx is closed and all results are inserted

        // Just wait for workers to complete (reader runs in parallel)
        tokio::spawn(reader_task);

        // Wait for all workers to finish processing
        for handle in worker_handles {
            handle.await??;
        }

        // Drop result_tx to signal completion to insertion task
        drop(result_tx);

        // Wait for all insertions to complete
        let total_inserted = insertion_task.await??;

        tracing::info!("Pipeline complete: {} vectors inserted", total_inserted);

        let total_generated = processed_count.load(Ordering::Relaxed);
        pb.finish_with_message(format!(
            "Lore email vectorization complete: {} vectors generated",
            total_generated
        ));

        tracing::info!("Successfully vectorized {} lore emails", total_generated);

        // Hashset is automatically freed here when function returns
        drop(existing_message_ids);
        println!("Lore vectorization complete, memory freed");

        Ok(())
    }
}

/// Static helper for inserting lore vectors with a cached table handle
async fn insert_lore_vectors_batch_with_table(
    lore_vectors_table: &lancedb::table::Table,
    vectors: &[crate::database::vectors::VectorEntry],
) -> Result<()> {
    use arrow::array::{ArrayRef, FixedSizeListArray, StringBuilder};
    use arrow::datatypes::{DataType, Field, Float32Type, Schema};
    use arrow::record_batch::RecordBatchIterator;
    use std::sync::Arc;

    if vectors.is_empty() {
        return Ok(());
    }

    // Get vector dimension from first entry
    let vector_dim = vectors[0].vector.len();

    // Create message_id StringArray
    let mut message_id_builder = StringBuilder::new();
    for entry in vectors {
        message_id_builder.append_value(&entry.content_hash); // content_hash field contains message_id
    }
    let message_id_array = message_id_builder.finish();

    // Create vector array
    let vector_array = FixedSizeListArray::from_iter_primitive::<Float32Type, _, _>(
        vectors
            .iter()
            .map(|entry| Some(entry.vector.iter().map(|&v| Some(v)))),
        vector_dim as i32,
    );

    let schema = Arc::new(Schema::new(vec![
        Field::new("message_id", DataType::Utf8, false),
        Field::new(
            "vector",
            DataType::FixedSizeList(
                Arc::new(Field::new("item", DataType::Float32, true)),
                vector_dim as i32,
            ),
            false,
        ),
    ]));

    let batch = arrow::record_batch::RecordBatch::try_from_iter(vec![
        ("message_id", Arc::new(message_id_array) as ArrayRef),
        ("vector", Arc::new(vector_array) as ArrayRef),
    ])?;

    let batches = vec![Ok(batch)];
    let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);
    lore_vectors_table.add(batch_iterator).execute().await?;

    Ok(())
}

impl VectorSearchManager {
    /// Search for similar commits based on vector similarity
    /// Returns commits sorted by similarity score (highest first)
    pub async fn search_similar_commits(
        &self,
        query_vector: &[f32],
        limit: usize,
    ) -> Result<Vec<(crate::types::GitCommitInfo, f32)>> {
        // Search for similar vectors in commit_vectors table
        let commit_vectors_table = self
            .connection
            .open_table("commit_vectors")
            .execute()
            .await?;

        let vector_results = commit_vectors_table
            .query()
            .nearest_to(query_vector)?
            .refine_factor(5)
            .nprobes(10)
            .limit(limit)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        // Extract git_commit_sha and distances from vector search results
        let mut sha_scores = Vec::new();
        for batch in &vector_results {
            let sha_array = batch
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
                let sha = sha_array.value(i).to_string();
                let distance = distance_array.value(i);
                // Convert cosine distance to similarity score (1.0 - distance/2.0)
                let similarity = (1.0 - distance / 2.0).max(0.0);
                sha_scores.push((sha, similarity));
            }
        }

        if sha_scores.is_empty() {
            return Ok(Vec::new());
        }

        // Create a map from git_sha to similarity score
        let score_map: HashMap<String, f32> = sha_scores.iter().cloned().collect();
        let shas: Vec<String> = sha_scores.into_iter().map(|(sha, _)| sha).collect();

        // Query git_commits table for these commit SHAs
        let commits_table = self.connection.open_table("git_commits").execute().await?;

        let mut commit_results = Vec::new();
        for chunk in shas.chunks(100) {
            let sha_conditions: Vec<String> = chunk
                .iter()
                .map(|sha| format!("git_sha = '{}'", sha.replace("'", "''")))
                .collect();
            let sha_filter = sha_conditions.join(" OR ");

            let results = commits_table
                .query()
                .only_if(sha_filter)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            for batch in &results {
                let git_sha_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let parent_sha_array = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let author_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let subject_array = batch
                    .column(3)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let message_array = batch
                    .column(4)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let tags_array = batch
                    .column(5)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let diff_array = batch
                    .column(6)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let symbols_array = batch
                    .column(7)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let files_array = batch
                    .column(8)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    let git_sha = git_sha_array.value(i).to_string();
                    let similarity_score = score_map.get(&git_sha).copied().unwrap_or(0.0);

                    let parent_sha: Vec<String> = serde_json::from_str(parent_sha_array.value(i))?;
                    let tags: std::collections::HashMap<String, Vec<String>> =
                        serde_json::from_str(tags_array.value(i))?;
                    let symbols: Vec<String> = serde_json::from_str(symbols_array.value(i))?;
                    let files: Vec<String> = serde_json::from_str(files_array.value(i))?;

                    let commit_info = crate::types::GitCommitInfo {
                        git_sha,
                        parent_sha,
                        author: author_array.value(i).to_string(),
                        subject: subject_array.value(i).to_string(),
                        message: message_array.value(i).to_string(),
                        tags,
                        diff: diff_array.value(i).to_string(),
                        symbols,
                        files,
                    };

                    commit_results.push((commit_info, similarity_score));
                }
            }
        }

        // Sort by similarity score (highest first)
        commit_results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        Ok(commit_results)
    }

    pub async fn search_similar_lore_emails(
        &self,
        query_vector: &[f32],
        limit: usize,
        filters: &LoreEmailFilters<'_>,
    ) -> Result<Vec<(crate::types::LoreEmailInfo, f32)>> {
        tracing::info!(
            "vlore: search_similar_lore_emails called with since_date={:?}, until_date={:?}",
            filters.since_date,
            filters.until_date
        );

        // Separate field filters from date filters
        // Field filters affect which emails to search (FTS/regex), date filters affect final results
        let has_field_filters = filters.from_patterns.is_some()
            || filters.subject_patterns.is_some()
            || filters.body_patterns.is_some()
            || filters.symbols_patterns.is_some()
            || filters.recipients_patterns.is_some();

        let lore_vectors_table = self.connection.open_table("lore_vectors").execute().await?;
        let lore_table = self.connection.open_table("lore").execute().await?;

        // Build date filter clause if needed
        let date_filter = match (filters.since_date, filters.until_date) {
            (Some(since), Some(until)) => {
                let escaped_since = since.replace("'", "''");
                let escaped_until = until.replace("'", "''");
                Some(format!(
                    "date >= '{}' AND date <= '{}'",
                    escaped_since, escaped_until
                ))
            }
            (Some(since), None) => {
                let escaped_since = since.replace("'", "''");
                Some(format!("date >= '{}'", escaped_since))
            }
            (None, Some(until)) => {
                let escaped_until = until.replace("'", "''");
                Some(format!("date <= '{}'", escaped_until))
            }
            (None, None) => None,
        };

        if let Some(ref filter) = date_filter {
            tracing::info!(
                "vlore: Date filter will be applied during email fetch: {}",
                filter
            );
        }

        // No field filters (but may have date filter): simple vector search
        if !has_field_filters {
            // Note: LanceDB vector search on lore_vectors table doesn't have date column
            // We must fetch more candidates and filter in fetch_emails_by_ids
            let fetch_multiplier = if date_filter.is_some() {
                50 // Significantly increase to ensure we get enough results after date filtering
            } else {
                2
            };

            let vector_results = lore_vectors_table
                .query()
                .nearest_to(query_vector)?
                .refine_factor(5)
                .nprobes(10)
                .limit(limit * fetch_multiplier)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            let mut score_map = HashMap::new();
            let mut message_ids = Vec::new();

            for batch in &vector_results {
                let msg_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let dist_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::Float32Array>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    let msg_id = msg_array.value(i).to_string();
                    let similarity = (1.0 - dist_array.value(i) / 2.0).max(0.0);
                    score_map.insert(msg_id.clone(), similarity);
                    message_ids.push(msg_id);
                }
            }

            return self
                .fetch_emails_by_ids(
                    &message_ids,
                    &score_map,
                    lore_table,
                    limit,
                    filters.since_date,
                    filters.until_date,
                )
                .await;
        }

        // With filters: Use intersection strategy to avoid SQL AND issues
        // Query each field separately, then intersect in Rust
        // FTS is used for fast keyword search on all fields

        // Incremental search: start small, expand if needed
        let search_limits = vec![1_000, 10_000, 50_000, 100_000];
        let mut final_results = Vec::new();

        for search_limit in search_limits {
            let loop_start = std::time::Instant::now();
            tracing::info!("vlore search iteration: search_limit={}", search_limit);

            if final_results.len() >= limit {
                break;
            }

            // 1. Query fields and get intersection using helper
            let regex_start = std::time::Instant::now();
            let regex_message_ids = self
                .query_lore_fields_intersection(
                    filters.from_patterns,
                    filters.subject_patterns,
                    filters.body_patterns,
                    filters.symbols_patterns,
                    filters.recipients_patterns,
                    search_limit,
                )
                .await?;

            if regex_message_ids.is_empty() {
                tracing::info!(
                    "vlore: No filter matches at limit {}, trying larger limit",
                    search_limit
                );
                continue; // No matches in intersection at this limit, try larger limit
            }

            tracing::info!(
                "vlore regex phase: {} emails in {:?}",
                regex_message_ids.len(),
                regex_start.elapsed()
            );

            // 2. Get vector search results
            let vector_start = std::time::Instant::now();
            let vector_results = lore_vectors_table
                .query()
                .nearest_to(query_vector)?
                .refine_factor(5)
                .nprobes(10)
                .limit(search_limit)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            // 3. Build score map from vector results
            let mut score_map = HashMap::new();
            for batch in &vector_results {
                let message_id_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let distance_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::Float32Array>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    let message_id = message_id_array.value(i).to_string();
                    let distance = distance_array.value(i);
                    let similarity = (1.0 - distance / 2.0).max(0.0);
                    score_map.insert(message_id, similarity);
                }
            }

            tracing::info!(
                "vlore vector phase: {} candidates in {:?}",
                score_map.len(),
                vector_start.elapsed()
            );

            // 4. Find intersection: message_ids that match BOTH regex AND have good vector similarity
            let final_intersection_start = std::time::Instant::now();
            let mut intersection_ids: Vec<(String, f32)> = regex_message_ids
                .into_iter()
                .filter_map(|msg_id| score_map.get(&msg_id).map(|&score| (msg_id, score)))
                .collect();

            // Sort by similarity score (highest first)
            intersection_ids
                .sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

            tracing::info!(
                "vlore final intersection: {} results in {:?}",
                intersection_ids.len(),
                final_intersection_start.elapsed()
            );

            if intersection_ids.is_empty() {
                continue; // Try larger search if no intersection found
            }

            // 5. Fetch full email data for intersection (only what we need, up to limit)
            let ids_to_fetch: Vec<String> = intersection_ids
                .iter()
                .take(limit)
                .map(|(id, _)| id.clone())
                .collect();

            let fetched_emails = self
                .fetch_emails_by_ids(
                    &ids_to_fetch,
                    &score_map,
                    lore_table.clone(),
                    limit,
                    filters.since_date,
                    filters.until_date,
                )
                .await?;

            final_results.extend(fetched_emails);

            tracing::info!(
                "vlore iteration completed in {:?}, total results so far: {}",
                loop_start.elapsed(),
                final_results.len()
            );

            // If we found enough results, stop
            if final_results.len() >= limit {
                break;
            }
        }

        // Deduplicate results by message_id (keep highest score for each message)
        let mut seen_ids = std::collections::HashSet::new();
        final_results.retain(|(email, _score)| seen_ids.insert(email.message_id.clone()));

        // Sort by similarity score and truncate
        final_results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        final_results.truncate(limit);

        Ok(final_results)
    }

    /// Helper to fetch full email data given message IDs
    async fn fetch_emails_by_ids(
        &self,
        message_ids: &[String],
        score_map: &HashMap<String, f32>,
        lore_table: lancedb::Table,
        limit: usize,
        since_date: Option<&str>,
        until_date: Option<&str>,
    ) -> Result<Vec<(crate::types::LoreEmailInfo, f32)>> {
        let mut results = Vec::new();
        let chunk_size = 500;

        // Parse filter dates once (they're in RFC 2822 format)
        let since_datetime = since_date
            .and_then(|d| chrono::DateTime::parse_from_rfc2822(d).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));
        let until_datetime = until_date
            .and_then(|d| chrono::DateTime::parse_from_rfc2822(d).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));

        tracing::info!(
            "fetch_emails_by_ids: Processing {} message_ids, limit={}, since={:?}, until={:?}",
            message_ids.len(),
            limit,
            since_datetime,
            until_datetime
        );

        for chunk in message_ids.chunks(chunk_size) {
            if results.len() >= limit {
                break;
            }

            let conditions: Vec<String> = chunk
                .iter()
                .map(|id| format!("message_id = '{}'", id.replace("'", "''")))
                .collect();
            let filter = format!("({})", conditions.join(" OR "));

            // Note: We do NOT use SQL date filtering because RFC 2822 dates are not
            // comparable as strings. We'll filter in Rust after fetching.
            tracing::info!("vlore: Fetching emails with filter: {}", filter);

            let batches = lore_table
                .query()
                .only_if(filter)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            for batch in &batches {
                let git_commit_sha_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let from_array = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let date_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let message_id_array = batch
                    .column(3)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let in_reply_to_array = batch
                    .column(4)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let subject_array = batch
                    .column(5)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let references_array = batch
                    .column(6)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let recipients_array = batch
                    .column(7)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let headers_array = batch
                    .column(8)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let body_array = batch
                    .column(9)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let symbols_array = batch
                    .column(10)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    if results.len() >= limit {
                        break;
                    }

                    let message_id = message_id_array.value(i).to_string();
                    let email_date_str = date_array.value(i).to_string();
                    let similarity = score_map.get(&message_id).copied().unwrap_or(0.0);

                    // Parse email date for filtering (dates are in RFC 2822 format)
                    let email_datetime = match chrono::DateTime::parse_from_rfc2822(&email_date_str)
                    {
                        Ok(dt) => dt.with_timezone(&chrono::Utc),
                        Err(e) => {
                            tracing::warn!(
                                "Failed to parse email date '{}': {}, skipping",
                                email_date_str,
                                e
                            );
                            continue;
                        }
                    };

                    // Apply date filtering in Rust (proper temporal comparison)
                    if let Some(since) = since_datetime {
                        if email_datetime < since {
                            tracing::debug!(
                                "Email {} dated {} is before since filter {}, skipping",
                                message_id,
                                email_datetime,
                                since
                            );
                            continue;
                        }
                    }
                    if let Some(until) = until_datetime {
                        if email_datetime > until {
                            tracing::debug!(
                                "Email {} dated {} is after until filter {}, skipping",
                                message_id,
                                email_datetime,
                                until
                            );
                            continue;
                        }
                    }

                    tracing::info!(
                        "vlore: Including email message_id={} date={} similarity={}",
                        message_id,
                        email_date_str,
                        similarity
                    );

                    // Parse JSON symbols array
                    let symbols_json = symbols_array.value(i);
                    let symbols: Vec<String> =
                        serde_json::from_str(symbols_json).unwrap_or_default();

                    results.push((
                        crate::types::LoreEmailInfo {
                            git_commit_sha: git_commit_sha_array.value(i).to_string(),
                            message_id,
                            from: from_array.value(i).to_string(),
                            date: email_date_str,
                            subject: subject_array.value(i).to_string(),
                            in_reply_to: if in_reply_to_array.is_null(i) {
                                None
                            } else {
                                Some(in_reply_to_array.value(i).to_string())
                            },
                            references: if references_array.is_null(i) {
                                None
                            } else {
                                Some(references_array.value(i).to_string())
                            },
                            recipients: recipients_array.value(i).to_string(),
                            headers: headers_array.value(i).to_string(),
                            body: body_array.value(i).to_string(),
                            symbols,
                        },
                        similarity,
                    ));
                }
            }
        }

        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        Ok(results)
    }
}
