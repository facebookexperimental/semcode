// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use arrow::array::{Array, ArrayRef, RecordBatch, StringArray, StringBuilder};
use futures::TryStreamExt;
use lancedb::connection::Connection;
use lancedb::query::{ExecutableQuery, QueryBase};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ProcessedFileRecord {
    pub file: String,
    pub git_sha: Option<String>, // Store as hex string
    pub git_file_sha: String,
    /// The extractor that read it, absent when the row predates the column.
    pub extractor_version: Option<u32>,
}

// Separate struct for JSON serialization with hex strings
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessedFileRecordJson {
    pub file: String,
    pub git_sha: Option<String>, // Display as hex string
    pub git_file_sha: String,    // Display as hex string
}

impl From<ProcessedFileRecord> for ProcessedFileRecordJson {
    fn from(record: ProcessedFileRecord) -> Self {
        ProcessedFileRecordJson {
            file: record.file,
            git_sha: record.git_sha,           // Already hex string
            git_file_sha: record.git_file_sha, // Already hex string
        }
    }
}

pub struct ProcessedFileStore {
    connection: Connection,
}

impl ProcessedFileStore {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    /// Insert a batch of processed file records
    pub async fn insert_batch(&self, records: Vec<ProcessedFileRecord>) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        let table = self
            .connection
            .open_table("processed_files")
            .execute()
            .await?;

        // Build arrays for each column
        let mut file_builder = StringBuilder::new();

        for record in &records {
            file_builder.append_value(&record.file);
        }

        // Handle nullable git_sha as hex string
        let mut git_sha_builder = StringBuilder::new();
        for record in &records {
            match &record.git_sha {
                Some(sha) => git_sha_builder.append_value(sha),
                None => git_sha_builder.append_null(),
            }
        }
        let git_sha_array = git_sha_builder.finish();

        let mut extractor_version_builder = arrow::array::Int64Builder::new();
        for record in &records {
            extractor_version_builder.append_option(record.extractor_version.map(|v| v as i64));
        }
        let extractor_version_array = extractor_version_builder.finish();

        // Create git_file_sha StringArray (non-nullable)
        let mut git_file_sha_builder = StringBuilder::new();
        for record in &records {
            git_file_sha_builder.append_value(&record.git_file_sha);
        }
        let git_file_sha_array = git_file_sha_builder.finish();

        let batch = RecordBatch::try_from_iter(vec![
            ("file", Arc::new(file_builder.finish()) as ArrayRef),
            ("git_sha", Arc::new(git_sha_array) as ArrayRef),
            ("git_file_sha", Arc::new(git_file_sha_array) as ArrayRef),
            (
                "extractor_version",
                Arc::new(extractor_version_array) as ArrayRef,
            ),
        ])?;

        // Replace any earlier row for the same file content rather than
        // adding a second one: re-indexing a tree otherwise grows this table
        // by a row per file per run.
        let mut merge = table.merge_insert(&["file", "git_file_sha"]);
        merge
            .when_matched_update_all(None)
            .when_not_matched_insert_all();
        let schema = batch.schema();
        merge
            .execute(Box::new(arrow::record_batch::RecordBatchIterator::new(
                vec![Ok(batch)],
                schema,
            )))
            .await?;

        Ok(())
    }

    /// Insert a single processed file record
    pub async fn insert(&self, record: ProcessedFileRecord) -> Result<()> {
        self.insert_batch(vec![record]).await
    }

    /// Check if a file with the given git_sha and git_file_sha has been processed
    pub async fn is_processed(&self, git_file_sha: &str) -> Result<bool> {
        let table = self
            .connection
            .open_table("processed_files")
            .execute()
            .await?;

        let git_file_sha_hex = git_file_sha;

        let filter = format!("git_file_sha = '{git_file_sha_hex}'");

        let results = table
            .query()
            .only_if(filter)
            .limit(1)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        Ok(!results.is_empty() && results[0].num_rows() > 0)
    }

    /// Get all processed files for a specific git_sha
    pub async fn get_processed_files_for_git_sha(
        &self,
        git_sha: Option<&str>,
    ) -> Result<Vec<ProcessedFileRecord>> {
        let table = self
            .connection
            .open_table("processed_files")
            .execute()
            .await?;

        let filter = if let Some(sha) = git_sha {
            // Convert git_sha string to hex for binary comparison
            let git_sha_hex = hex::encode(hex::decode(sha).unwrap_or_default());
            format!("git_sha = X'{git_sha_hex}'")
        } else {
            "git_sha IS NULL".to_string()
        };

        let results = table
            .query()
            .only_if(filter)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut records = Vec::new();
        for batch in &results {
            for i in 0..batch.num_rows() {
                if let Some(record) = self.extract_record_from_batch(batch, i)? {
                    records.push(record);
                }
            }
        }

        Ok(records)
    }

    /// Remove processed file records for a specific git_sha (e.g., when git commit changes)
    /// Forget files read by an older extractor.
    ///
    /// Called once the whole tree has been read: a row still carrying an
    /// older version at that point describes content that is not in the tree,
    /// usually an earlier revision of a file the last commit touched. Keeping
    /// it makes the index answer "older than this build" forever, so
    /// re-indexing never clears the refusal it is supposed to clear. Losing
    /// the row costs a re-read if that content ever comes back.
    pub async fn forget_older_than(&self, version: u32) -> Result<usize> {
        let table = self
            .connection
            .open_table("processed_files")
            .execute()
            .await?;
        let before = table.count_rows(None).await?;
        table
            .delete(&format!(
                "extractor_version IS NULL OR extractor_version < {version}"
            ))
            .await?;
        Ok(before - table.count_rows(None).await?)
    }

    pub async fn remove_for_git_sha(&self, git_sha: Option<&str>) -> Result<()> {
        let table = self
            .connection
            .open_table("processed_files")
            .execute()
            .await?;

        let filter = if let Some(sha) = git_sha {
            let escaped_sha = sha.replace("'", "''");
            format!("git_sha = '{escaped_sha}'")
        } else {
            "git_sha IS NULL".to_string()
        };

        table.delete(&filter).await?;
        Ok(())
    }

    /// Remove a specific processed file record
    pub async fn remove_file(
        &self,
        file: &str,
        git_sha: Option<&str>,
        git_file_sha: &str,
    ) -> Result<()> {
        let table = self
            .connection
            .open_table("processed_files")
            .execute()
            .await?;

        let escaped_file = file.replace("'", "''");
        let escaped_git_file_sha = git_file_sha.replace("'", "''");

        let filter = if let Some(sha) = git_sha {
            let escaped_sha = sha.replace("'", "''");
            format!(
                "file = '{escaped_file}' AND git_sha = '{escaped_sha}' AND git_file_sha = '{escaped_git_file_sha}'"
            )
        } else {
            format!(
                "file = '{escaped_file}' AND git_sha IS NULL AND git_file_sha = '{escaped_git_file_sha}'"
            )
        };

        table.delete(&filter).await?;
        Ok(())
    }

    /// Get total count of processed files
    pub async fn count(&self) -> Result<usize> {
        let table = self
            .connection
            .open_table("processed_files")
            .execute()
            .await?;
        Ok(table.count_rows(None).await?)
    }

    /// Get all processed file records with progress reporting for large datasets
    pub async fn get_all(&self) -> Result<Vec<ProcessedFileRecord>> {
        use futures::TryStreamExt;

        let table = self
            .connection
            .open_table("processed_files")
            .execute()
            .await?;

        // Check count first to see if we're dealing with a large dataset
        let total_count = table.count_rows(None).await?;
        if total_count > 100000 {
            tracing::info!("Loading {} processed file records from database (this may take a moment for large repositories)", total_count);
        }

        // Load all results (but with progress reporting for large datasets)
        let results = table
            .query()
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut records = Vec::new();
        let mut processed_count = 0;

        for batch in &results {
            for i in 0..batch.num_rows() {
                if let Some(record) = self.extract_record_from_batch(batch, i)? {
                    records.push(record);
                    processed_count += 1;

                    // Log progress for large operations
                    if total_count > 100000 && processed_count % 100000 == 0 {
                        tracing::info!(
                            "Processed {}/{} file records from database",
                            processed_count,
                            total_count
                        );
                    }
                }
            }
        }

        if total_count > 100000 {
            tracing::info!(
                "Completed loading {} processed file records from database",
                records.len()
            );
        }
        Ok(records)
    }

    /// Paths of indexed files that sit under a directory named `arch`.
    ///
    /// The vocabulary a reader's architecture pin is checked against has to
    /// come from the tree that was indexed, not from a list compiled into
    /// the binary: a list says every tree has architectures, and a tree that
    /// has none would accept a pin and filter nothing.
    ///
    /// Only the path column, and only the rows that can name an
    /// architecture, so this is not a scan of the table.
    pub async fn files_under_an_arch_directory(&self) -> Result<Vec<String>> {
        let table = self
            .connection
            .open_table("processed_files")
            .execute()
            .await?;

        let results = table
            .query()
            .only_if("file LIKE 'arch/%' OR file LIKE '%/arch/%'")
            .select(lancedb::query::Select::Columns(vec!["file".to_string()]))
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut paths = Vec::new();
        for batch in &results {
            let Some(column) = batch.column_by_name("file") else {
                continue;
            };
            let Some(files) = column.as_any().downcast_ref::<StringArray>() else {
                continue;
            };
            for i in 0..files.len() {
                if !files.is_null(i) {
                    paths.push(files.value(i).to_string());
                }
            }
        }
        Ok(paths)
    }

    /// Get only git file SHAs for efficient deduplication (much faster than loading full records)
    pub async fn get_all_git_file_shas(&self) -> Result<std::collections::HashSet<String>> {
        use futures::TryStreamExt;

        let table = self
            .connection
            .open_table("processed_files")
            .execute()
            .await?;

        // Check count first for progress reporting
        let total_count = table.count_rows(None).await?;
        if total_count > 100000 {
            tracing::info!("Loading git file SHAs for {} processed files (optimized: only loading git_file_sha column)", total_count);
        }

        // Use select to only fetch the git_file_sha column for better performance
        let results = table
            .query()
            .select(lancedb::query::Select::Columns(vec![
                "git_file_sha".to_string()
            ]))
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut sha_set = std::collections::HashSet::new();
        let mut processed_count = 0;

        for batch in &results {
            if let Some(git_file_sha_array) = batch.column_by_name("git_file_sha") {
                let git_file_sha_array = git_file_sha_array
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..git_file_sha_array.len() {
                    if !git_file_sha_array.is_null(i) {
                        sha_set.insert(git_file_sha_array.value(i).to_string());
                        processed_count += 1;

                        // Log progress for large operations
                        if total_count > 100000 && processed_count % 200000 == 0 {
                            tracing::info!(
                                "Processed {}/{} git file SHAs from database",
                                processed_count,
                                total_count
                            );
                        }
                    }
                }
            }
        }

        if total_count > 100000 {
            tracing::info!(
                "Loaded {} unique git file SHAs from database",
                sha_set.len()
            );
        }
        Ok(sha_set)
    }

    /// Get file/git_file_sha pairs for pipeline deduplication (optimized for large datasets)
    pub async fn get_all_file_git_sha_pairs(
        &self,
    ) -> Result<std::collections::HashSet<(String, String)>> {
        use futures::TryStreamExt;

        let table = self
            .connection
            .open_table("processed_files")
            .execute()
            .await?;

        // Check count first for progress reporting
        let total_count = table.count_rows(None).await?;
        if total_count > 100000 {
            tracing::info!("Loading file/git_sha pairs for {} processed files (optimized: only loading file and git_file_sha columns)", total_count);
        }

        // Use select to only fetch the needed columns for better performance
        let results = table
            .query()
            .select(lancedb::query::Select::Columns(vec![
                "file".to_string(),
                "git_file_sha".to_string(),
            ]))
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut pair_set = std::collections::HashSet::new();
        let mut processed_count = 0;

        for batch in &results {
            if let (Some(file_array), Some(git_file_sha_array)) = (
                batch.column_by_name("file"),
                batch.column_by_name("git_file_sha"),
            ) {
                let file_array = file_array
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let git_file_sha_array = git_file_sha_array
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..file_array.len() {
                    if !file_array.is_null(i) && !git_file_sha_array.is_null(i) {
                        let file_path = file_array.value(i).to_string();
                        let git_file_sha = git_file_sha_array.value(i).to_string();
                        pair_set.insert((file_path, git_file_sha));
                        processed_count += 1;

                        // Log progress for large operations
                        if total_count > 100000 && processed_count % 150000 == 0 {
                            tracing::info!(
                                "Processed {}/{} file/git_sha pairs from database",
                                processed_count,
                                total_count
                            );
                        }
                    }
                }
            }
        }

        if total_count > 100000 {
            tracing::info!(
                "Loaded {} unique file/git_sha pairs from database",
                pair_set.len()
            );
        }
        Ok(pair_set)
    }

    /// Revisions that contain a given file content (by its blob hash).
    ///
    /// Reads `processed_files` where `git_file_sha` matches, so a caller can
    /// say where a row's content lives without walking git. Returns distinct
    /// `git_sha` values, sorted for deterministic output.
    pub async fn get_revisions_for_file_hash(&self, git_file_sha: &str) -> Result<Vec<String>> {
        let table = self
            .connection
            .open_table("processed_files")
            .execute()
            .await?;
        let escaped = git_file_sha.replace('\'', "''");
        let filter = format!("git_file_sha = '{escaped}'");
        let results = table
            .query()
            .only_if(filter)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;
        let mut revs = std::collections::HashSet::new();
        for batch in &results {
            let git_sha_array = batch
                .column_by_name("git_sha")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                .ok_or_else(|| anyhow::anyhow!("Missing git_sha column"))?;
            for i in 0..batch.num_rows() {
                if !git_sha_array.is_null(i) {
                    revs.insert(git_sha_array.value(i).to_string());
                }
            }
        }
        let mut out: Vec<String> = revs.into_iter().collect();
        out.sort();
        Ok(out)
    }

    /// Extract a ProcessedFileRecord from a batch at the given row index
    fn extract_record_from_batch(
        &self,
        batch: &RecordBatch,
        row: usize,
    ) -> Result<Option<ProcessedFileRecord>> {
        let file_array = batch
            .column(0)
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .unwrap();
        let git_sha_array = batch
            .column(1)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap(); // Now binary
        let git_file_sha_array = batch
            .column(2)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();

        let file = file_array.value(row).to_string();

        let git_sha = if git_sha_array.is_null(row) {
            None
        } else {
            Some(git_sha_array.value(row).to_string()) // Store as hex string
        };

        let git_file_sha = git_file_sha_array.value(row).to_string();

        // Absent in rows written before the column existed, which is exactly
        // the population that has to be read again.
        let extractor_version = batch
            .column_by_name("extractor_version")
            .and_then(|column| column.as_any().downcast_ref::<arrow::array::Int64Array>())
            .filter(|versions| versions.is_valid(row))
            .map(|versions| versions.value(row) as u32);

        Ok(Some(ProcessedFileRecord {
            file,
            git_sha,
            git_file_sha,
            extractor_version,
        }))
    }
}
