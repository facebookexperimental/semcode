// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use arrow::array::{Array, ArrayRef, RecordBatch, StringArray, StringBuilder};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatchIterator;
use futures::TryStreamExt;
use gxhash::{HashMap, HashMapExt};
use lancedb::connection::Connection;
use lancedb::query::{ExecutableQuery, QueryBase};
use std::sync::Arc;

use crate::database::connection::OPTIMAL_BATCH_SIZE;
use crate::hash;

// Number of shards for the content store
const NUM_SHARDS: u8 = 16;

#[derive(Debug, Clone)]
pub struct ContentInfo {
    pub gxhash: String,
    pub content: String,
}

pub struct ContentStore {
    connection: Connection,
}

impl ContentStore {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    /// Determine which shard an gxhash128 hash belongs to based on its first hex character
    fn get_shard_number(gxhash: &str) -> u8 {
        if gxhash.is_empty() {
            0
        } else {
            // Use the first hex character to determine shard (0-15)
            gxhash
                .chars()
                .next()
                .and_then(|c| c.to_digit(16))
                .unwrap_or(0) as u8
                % NUM_SHARDS
        }
    }

    /// Get the table name for a specific shard
    fn get_shard_table_name(shard: u8) -> String {
        format!("content_{shard}")
    }

    /// Get the table name for an gxhash128 hash
    fn get_table_name_for_hash(gxhash: &str) -> String {
        let shard = Self::get_shard_number(gxhash);
        Self::get_shard_table_name(shard)
    }

    /// Insert content and return the gxhash128 hash - uses upsert
    pub async fn store_content(&self, content: &str) -> Result<String> {
        let gxhash = hash::compute_gxhash(content);

        let content_info = ContentInfo {
            gxhash: gxhash.clone(),
            content: content.to_string(),
        };

        // Use upsert operation instead of manual existence checking
        self.insert_batch(vec![content_info]).await?;
        Ok(gxhash)
    }

    /// Insert a batch of content items using upsert - handles duplicates gracefully
    pub async fn insert_batch(&self, content_items: Vec<ContentInfo>) -> Result<()> {
        if content_items.is_empty() {
            return Ok(());
        }

        // Deduplicate content items by Gxhash within the batch
        let mut dedup_map: HashMap<String, ContentInfo> = HashMap::new();
        for item in content_items {
            dedup_map.insert(item.gxhash.clone(), item);
        }
        let deduplicated_items: Vec<ContentInfo> = dedup_map.into_values().collect();

        // Group content items by shard
        let mut shard_groups: HashMap<u8, Vec<ContentInfo>> = HashMap::new();
        for item in deduplicated_items {
            let shard = Self::get_shard_number(&item.gxhash);
            shard_groups.entry(shard).or_default().push(item);
        }

        // Process each shard in parallel using tokio::spawn
        // This maximizes database throughput by writing to multiple shards concurrently
        let mut handles = Vec::new();

        for (shard, items) in shard_groups {
            let table_name = Self::get_shard_table_name(shard);
            let connection = self.connection.clone();

            let handle = tokio::spawn(async move {
                let table = connection.open_table(&table_name).execute().await?;

                // Process in optimal batch sizes within this shard
                for chunk in items.chunks(OPTIMAL_BATCH_SIZE) {
                    Self::insert_chunk_static(&table, chunk).await?;
                }

                Ok::<(), anyhow::Error>(())
            });

            handles.push(handle);
        }

        // Wait for all shard writes to complete
        for handle in handles {
            handle.await??;
        }

        Ok(())
    }

    async fn insert_chunk_static(
        table: &lancedb::table::Table,
        content_items: &[ContentInfo],
    ) -> Result<()> {
        // Build arrow arrays
        let mut content_builder = StringBuilder::new();

        for item in content_items {
            content_builder.append_value(&item.content);
        }

        // Create gxhash StringArray (non-nullable)
        let mut gxhash_builder = StringBuilder::new();
        for item in content_items {
            gxhash_builder.append_value(&item.gxhash);
        }
        let gxhash_array = gxhash_builder.finish();

        let schema = Self::get_schema_static();

        let batch = RecordBatch::try_from_iter(vec![
            ("gxhash", Arc::new(gxhash_array) as ArrayRef),
            ("content", Arc::new(content_builder.finish()) as ArrayRef),
        ])?;

        let batches = vec![Ok(batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);

        // Use merge_insert for upsert functionality
        let mut merge_insert = table.merge_insert(&["gxhash"]);
        merge_insert
            .when_matched_update_all(None)
            .when_not_matched_insert_all();
        merge_insert.execute(Box::new(batch_iterator)).await?;

        Ok(())
    }

    /// Check if content exists by hash - uses indexed lookup
    pub async fn content_exists(&self, gxhash: &str) -> Result<bool> {
        let table_name = Self::get_table_name_for_hash(gxhash);
        let table = self.connection.open_table(&table_name).execute().await?;

        // Use indexed lookup with hex string
        let results = table
            .query()
            .only_if(format!("gxhash = '{gxhash}'"))
            .limit(1)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        // Check if we found any results
        Ok(!results.is_empty() && results[0].num_rows() > 0)
    }

    /// Get content by gxhash128 hash - uses indexed lookup
    pub async fn get_content(&self, gxhash: &str) -> Result<Option<String>> {
        let table_name = Self::get_table_name_for_hash(gxhash);
        let table = self.connection.open_table(&table_name).execute().await?;

        // Use indexed lookup with hex string
        let results = table
            .query()
            .only_if(format!("gxhash = '{gxhash}'"))
            .limit(1)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        for batch in &results {
            if batch.num_rows() > 0 {
                let content_array = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .unwrap();
                return Ok(Some(content_array.value(0).to_string()));
            }
        }

        Ok(None)
    }

    /// Get content by gxhash128 hash hex string (now redundant since get_content takes hex strings directly)
    pub async fn get_content_by_hex(&self, gxhash_hex: &str) -> Result<Option<String>> {
        self.get_content(gxhash_hex).await
    }

    /// Bulk fetch content for multiple hashes - uses indexed lookup
    pub async fn get_content_bulk(&self, hashes: &[String]) -> Result<HashMap<String, String>> {
        if hashes.is_empty() {
            return Ok(HashMap::new());
        }

        let mut content_map = HashMap::new();

        // Group hashes by shard
        let mut shard_groups: HashMap<u8, Vec<&String>> = HashMap::new();
        for hash in hashes {
            let shard = Self::get_shard_number(hash);
            shard_groups.entry(shard).or_default().push(hash);
        }

        let shard_count = shard_groups.len();

        // Process each shard separately
        for (shard, shard_hashes) in shard_groups {
            let table_name = Self::get_shard_table_name(shard);
            let table = self.connection.open_table(&table_name).execute().await?;

            // Process in chunks to avoid query size limits
            let chunk_size = 100; // Reasonable chunk size for IN clauses

            for chunk in shard_hashes.chunks(chunk_size) {
                // Build WHERE IN clause with hex strings
                let hash_list: Vec<String> = chunk.iter().map(|hash| format!("'{hash}'")).collect();

                let in_clause = hash_list.join(", ");
                let filter = format!("gxhash IN ({in_clause})");

                // Use indexed lookup with WHERE IN clause
                let results = table
                    .query()
                    .only_if(filter)
                    .execute()
                    .await?
                    .try_collect::<Vec<_>>()
                    .await?;

                // Collect the content from results
                for batch in &results {
                    let gxhash_array = batch
                        .column(0)
                        .as_any()
                        .downcast_ref::<StringArray>()
                        .unwrap();
                    let content_array = batch
                        .column(1)
                        .as_any()
                        .downcast_ref::<StringArray>()
                        .unwrap();

                    for i in 0..batch.num_rows() {
                        let hash = gxhash_array.value(i).to_string();
                        let content = content_array.value(i).to_string();
                        content_map.insert(hash, content);
                    }
                }
            }
        }

        tracing::debug!(
            "Bulk content lookup: requested {} hashes across {} shards, found {} entries",
            hashes.len(),
            shard_count,
            content_map.len()
        );

        Ok(content_map)
    }

    /// Store content and return hex hash (now same as store_content since it returns hex)
    pub async fn store_content_with_hex_hash(&self, content: &str) -> Result<String> {
        self.store_content(content).await
    }

    /// Get all content (for debugging/analysis)
    pub async fn get_all(&self) -> Result<Vec<ContentInfo>> {
        let mut all_content = Vec::new();
        let batch_size = 10000;

        // Query all shards
        for shard in 0..NUM_SHARDS {
            let table_name = Self::get_shard_table_name(shard);
            let table = self.connection.open_table(&table_name).execute().await?;
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
                        if let Ok(Some(content_info)) = self.extract_content_from_batch(batch, i) {
                            all_content.push(content_info);
                        }
                    }
                }

                offset += batch_size;
                let total_rows: usize = results.iter().map(|b| b.num_rows()).sum();
                if total_rows < batch_size {
                    break;
                }
            }
        }

        Ok(all_content)
    }

    fn extract_content_from_batch(
        &self,
        batch: &RecordBatch,
        row: usize,
    ) -> Result<Option<ContentInfo>> {
        let gxhash_array = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let content_array = batch
            .column(1)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();

        Ok(Some(ContentInfo {
            gxhash: gxhash_array.value(row).to_string(),
            content: content_array.value(row).to_string(),
        }))
    }

    fn get_schema_static() -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            Field::new("gxhash", DataType::Utf8, false), // gxhash128 hash as hex string
            Field::new("content", DataType::Utf8, false), // The actual content
        ]))
    }

    /// Get statistics about content storage
    pub async fn get_stats(&self) -> Result<ContentStats> {
        let mut total_count = 0i64;
        let mut total_content_size = 0;
        let mut sample_count = 0;

        // Aggregate statistics from all shards
        for shard in 0..NUM_SHARDS {
            let table_name = Self::get_shard_table_name(shard);
            let table = self.connection.open_table(&table_name).execute().await?;
            let count = table.count_rows(None).await?;
            total_count += count as i64;

            // Sample content size from each shard (proportional sampling)
            let sample_size = std::cmp::min(1000, count.div_ceil(NUM_SHARDS as usize));
            if sample_size > 0 {
                let sample_results = table
                    .query()
                    .limit(sample_size)
                    .execute()
                    .await?
                    .try_collect::<Vec<_>>()
                    .await?;

                for batch in &sample_results {
                    let content_array = batch
                        .column(1)
                        .as_any()
                        .downcast_ref::<StringArray>()
                        .unwrap();
                    for i in 0..batch.num_rows() {
                        total_content_size += content_array.value(i).len();
                        sample_count += 1;
                    }
                }
            }
        }

        let avg_content_size = if sample_count > 0 {
            total_content_size / sample_count
        } else {
            0
        };

        Ok(ContentStats {
            total_entries: total_count,
            estimated_total_size: avg_content_size * total_count as usize,
            average_content_size: avg_content_size,
        })
    }
}

#[derive(Debug)]
pub struct ContentStats {
    pub total_entries: i64,
    pub estimated_total_size: usize,
    pub average_content_size: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ContentInfoJson {
    pub gxhash: String, // Hex string for JSON
    pub content: String,
}

impl From<ContentInfo> for ContentInfoJson {
    fn from(content_info: ContentInfo) -> Self {
        Self {
            gxhash: content_info.gxhash, // Already a hex string
            content: content_info.content,
        }
    }
}
