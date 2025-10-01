// src/database/functions.rs
use anyhow::Result;
use arrow::array::{
    ArrayRef, RecordBatch, StringBuilder, TimestampMillisecondBuilder, 
};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use arrow::record_batch::RecordBatchIterator;
use futures::TryStreamExt;
use lancedb::connection::Connection;
use lancedb::query::{ExecutableQuery, QueryBase};
use std::sync::Arc;

use crate::database::connection::OPTIMAL_BATCH_SIZE;

#[derive(Debug, Clone)]
pub struct GitLoad {
    pub current_sha: String,
    pub parent_sha: Option<String>,
    pub load_type: LoadType,
    pub timestamp: i64,              // Unix timestamp in milliseconds
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LoadType {
    Full,
    Delta,
}

impl GitLoad {
    /// Create a new GitLoad with current timestamp
    pub fn new(current_sha: String, parent_sha: Option<String>, load_type: LoadType, description: Option<String>) -> Self {
        Self {
            current_sha,
            parent_sha,
            load_type,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64,
            description,
        }
    }

    /// Create a new full load
    pub fn new_full_load(current_sha: String, description: Option<String>) -> Self {
        Self::new(current_sha, None, LoadType::Full, description)
    }

    /// Create a new delta load
    pub fn new_delta_load(current_sha: String, parent_sha: String, description: Option<String>) -> Self {
        Self::new(current_sha, Some(parent_sha), LoadType::Delta, description)
    }
}

impl LoadType {
    pub fn as_str(&self) -> &str {
        match self {
            LoadType::Full => "full",
            LoadType::Delta => "delta",
        }
    }

    pub fn from_str(s: &str) -> Result<LoadType> {
        match s {
            "full" => Ok(LoadType::Full),
            "delta" => Ok(LoadType::Delta),
            _ => Err(anyhow::anyhow!("Invalid load type: {}", s)),
        }
    }
}

pub struct GitStore {
    connection: Connection,
}

impl GitStore {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    /// Record a new git load
    pub async fn record_load(&self, git_load: GitLoad) -> Result<()> {
        let loads = vec![git_load];
        self.insert_batch(loads).await
    }

    /// Insert multiple git load records
    pub async fn insert_batch(&self, loads: Vec<GitLoad>) -> Result<()> {
        if loads.is_empty() {
            return Ok(());
        }

        let table = self.connection.open_table("git").execute().await?;

        // Process in optimal batch sizes
        for chunk in loads.chunks(OPTIMAL_BATCH_SIZE) {
            self.insert_chunk(&table, chunk).await?;
        }

        Ok(())
    }

    async fn insert_chunk(&self, table: &lancedb::table::Table, loads: &[GitLoad]) -> Result<()> {
        let mut current_sha_builder = StringBuilder::new();
        let mut parent_sha_builder = StringBuilder::new();
        let mut load_type_builder = StringBuilder::new();
        let mut timestamp_builder = TimestampMillisecondBuilder::new();
        let mut description_builder = StringBuilder::new();

        for load in loads {
            current_sha_builder.append_value(&load.current_sha);
            
            if let Some(ref parent_sha) = load.parent_sha {
                parent_sha_builder.append_value(parent_sha);
            } else {
                parent_sha_builder.append_null();
            }
            
            load_type_builder.append_value(load.load_type.as_str());
            timestamp_builder.append_value(load.timestamp);
            
            if let Some(ref description) = load.description {
                description_builder.append_value(description);
            } else {
                description_builder.append_null();
            }
        }

        let schema = self.get_schema();

        let batch = RecordBatch::try_from_iter(vec![
            ("current_sha", Arc::new(current_sha_builder.finish()) as ArrayRef),
            ("parent_sha", Arc::new(parent_sha_builder.finish()) as ArrayRef),
            ("load_type", Arc::new(load_type_builder.finish()) as ArrayRef),
            ("timestamp", Arc::new(timestamp_builder.finish()) as ArrayRef),
            ("description", Arc::new(description_builder.finish()) as ArrayRef),
        ])?;

        let batches = vec![Ok(batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);
        table.add(batch_iterator).execute().await?;

        Ok(())
    }

    /// Get a git load by current SHA
    pub async fn get_load_by_sha(&self, current_sha: &str) -> Result<Option<GitLoad>> {
        let table = self.connection.open_table("git").execute().await?;
        let escaped_sha = current_sha.replace("'", "''");

        let results = table
            .query()
            .only_if(format!("current_sha = '{}'", escaped_sha))
            .limit(1)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        if results.is_empty() || results[0].num_rows() == 0 {
            return Ok(None);
        }

        let batch = &results[0];
        self.extract_git_load_from_batch(batch, 0)
    }

    /// Get all git loads ordered by timestamp (newest first)
    pub async fn get_all_loads(&self) -> Result<Vec<GitLoad>> {
        let table = self.connection.open_table("git").execute().await?;
        let mut all_loads = Vec::new();
        let batch_size = 1000;
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
                    if let Ok(Some(load)) = self.extract_git_load_from_batch(batch, i) {
                        all_loads.push(load);
                    }
                }
            }

            offset += batch_size;
            let total_rows: usize = results.iter().map(|b| b.num_rows()).sum();
            if total_rows < batch_size {
                break;
            }
        }

        // Sort by timestamp (newest first)
        all_loads.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(all_loads)
    }

    /// Get all delta loads that are children of a given SHA
    pub async fn get_children_loads(&self, parent_sha: &str) -> Result<Vec<GitLoad>> {
        let table = self.connection.open_table("git").execute().await?;
        let escaped_sha = parent_sha.replace("'", "''");

        let results = table
            .query()
            .only_if(format!("parent_sha = '{}'", escaped_sha))
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut loads = Vec::new();
        for batch in &results {
            for i in 0..batch.num_rows() {
                if let Ok(Some(load)) = self.extract_git_load_from_batch(batch, i) {
                    loads.push(load);
                }
            }
        }

        // Sort by timestamp (newest first)
        loads.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(loads)
    }

    /// Get the most recent full load
    pub async fn get_latest_full_load(&self) -> Result<Option<GitLoad>> {
        let table = self.connection.open_table("git").execute().await?;

        let results = table
            .query()
            .only_if("load_type = 'full'")
            .limit(1)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        if results.is_empty() || results[0].num_rows() == 0 {
            return Ok(None);
        }

        let batch = &results[0];
        self.extract_git_load_from_batch(batch, 0)
    }

    /// Check if a git SHA has already been loaded
    pub async fn is_sha_loaded(&self, sha: &str) -> Result<bool> {
        let table = self.connection.open_table("git").execute().await?;
        let escaped_sha = sha.replace("'", "''");

        let results = table
            .query()
            .only_if(format!("current_sha = '{}'", escaped_sha))
            .limit(1)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        Ok(!results.is_empty() && results[0].num_rows() > 0)
    }

    /// Get load history (chain of loads from a given SHA back to the root)
    pub async fn get_load_chain(&self, start_sha: &str) -> Result<Vec<GitLoad>> {
        let mut chain = Vec::new();
        let mut current_sha = start_sha.to_string();

        loop {
            if let Some(load) = self.get_load_by_sha(&current_sha).await? {
                let parent_sha = load.parent_sha.clone();
                chain.push(load);
                
                if let Some(parent) = parent_sha {
                    current_sha = parent;
                } else {
                    // Reached the root (full load with no parent)
                    break;
                }
            } else {
                // SHA not found in database
                break;
            }
        }

        Ok(chain)
    }

    fn extract_git_load_from_batch(&self, batch: &RecordBatch, row: usize) -> Result<Option<GitLoad>> {
        let current_sha_array = batch.column(0).as_any().downcast_ref::<arrow::array::StringArray>().unwrap();
        let parent_sha_array = batch.column(1).as_any().downcast_ref::<arrow::array::StringArray>().unwrap();
        let load_type_array = batch.column(2).as_any().downcast_ref::<arrow::array::StringArray>().unwrap();
        let timestamp_array = batch.column(3).as_any().downcast_ref::<arrow::array::TimestampMillisecondArray>().unwrap();
        let description_array = batch.column(4).as_any().downcast_ref::<arrow::array::StringArray>().unwrap();

        let parent_sha = if parent_sha_array.is_null(row) {
            None
        } else {
            Some(parent_sha_array.value(row).to_string())
        };

        let description = if description_array.is_null(row) {
            None
        } else {
            Some(description_array.value(row).to_string())
        };

        let load_type = LoadType::from_str(load_type_array.value(row))?;

        Ok(Some(GitLoad {
            current_sha: current_sha_array.value(row).to_string(),
            parent_sha,
            load_type,
            timestamp: timestamp_array.value(row),
            description,
        }))
    }

    fn get_schema(&self) -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            Field::new("current_sha", DataType::Utf8, false),
            Field::new("parent_sha", DataType::Utf8, true),
            Field::new("load_type", DataType::Utf8, false),
            Field::new("timestamp", DataType::Timestamp(TimeUnit::Millisecond, None), false),
            Field::new("description", DataType::Utf8, true),
        ]))
    }
}
