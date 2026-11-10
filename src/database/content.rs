// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use arrow::array::{Array, ArrayRef, RecordBatch, RecordBatchIterator, StringArray, StringBuilder};
use futures::TryStreamExt;
use lancedb::connection::Connection;
use lancedb::query::{ExecutableQuery, QueryBase};
use once_cell::sync::Lazy;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::database::connection::OPTIMAL_BATCH_SIZE;
use crate::hash;

// Number of shards for the content store
const NUM_SHARDS: u8 = 16;

/// Process-global locks serializing same-shard content upserts.
///
/// Two inserters can upsert the same new hash into one shard at the same
/// time: both open the table at the same version, both miss, both insert,
/// and the hash keeps two rows. The locks must be process-global because
/// several ContentStore instances share one database (connection, functions,
/// types and search each hold one), so a per-instance lock would not
/// serialize them. Only commits to the same shard wait on each other, and
/// content upserts are a small part of insert time.
static CONTENT_SHARD_LOCKS: Lazy<[Mutex<()>; NUM_SHARDS as usize]> =
    Lazy::new(|| std::array::from_fn(|_| Mutex::new(())));

#[derive(Debug, Clone)]
pub struct ContentInfo {
    pub blake3_hash: String,
    pub content: String,
}

pub struct ContentStore {
    connection: Connection,
}

impl ContentStore {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    /// Determine which shard a blake3 hash belongs to based on its first hex character
    fn get_shard_number(blake3_hash: &str) -> u8 {
        if blake3_hash.is_empty() {
            0
        } else {
            // Use the first hex character to determine shard (0-15)
            blake3_hash
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

    /// Get the table name for a blake3 hash
    fn get_table_name_for_hash(blake3_hash: &str) -> String {
        let shard = Self::get_shard_number(blake3_hash);
        Self::get_shard_table_name(shard)
    }

    /// Insert content and return the blake3 hash - uses upsert
    pub async fn store_content(&self, content: &str) -> Result<String> {
        let blake3_hash = hash::compute_blake3_hash(content);

        let content_info = ContentInfo {
            blake3_hash: blake3_hash.clone(),
            content: content.to_string(),
        };

        // Use upsert operation instead of manual existence checking
        self.insert_batch(vec![content_info]).await?;
        Ok(blake3_hash)
    }

    /// Insert a batch of content items using upsert - handles duplicates gracefully
    pub async fn insert_batch(&self, content_items: Vec<ContentInfo>) -> Result<()> {
        if content_items.is_empty() {
            return Ok(());
        }

        // Deduplicate content items by blake3_hash within the batch
        let mut dedup_map: std::collections::HashMap<String, ContentInfo> =
            std::collections::HashMap::new();
        for item in content_items {
            dedup_map.insert(item.blake3_hash.clone(), item);
        }
        let deduplicated_items: Vec<ContentInfo> = dedup_map.into_values().collect();

        // Group content items by shard
        let mut shard_groups: std::collections::HashMap<u8, Vec<ContentInfo>> =
            std::collections::HashMap::new();
        for item in deduplicated_items {
            let shard = Self::get_shard_number(&item.blake3_hash);
            shard_groups.entry(shard).or_default().push(item);
        }

        // Process each shard
        for (shard, items) in shard_groups {
            // Serialize same-shard upserts across all ContentStore instances:
            // without this, two inserters upserting the same new hash race
            // and the shard keeps a duplicate row. Held across open_table +
            // merge_insert + commit, which is the whole shard write below.
            let _shard_guard = CONTENT_SHARD_LOCKS[shard as usize].lock().await;
            let table_name = Self::get_shard_table_name(shard);
            let table = self.connection.open_table(&table_name).execute().await?;

            // Process in optimal batch sizes
            for chunk in items.chunks(OPTIMAL_BATCH_SIZE) {
                self.insert_chunk(&table, chunk).await?;
            }
        }

        Ok(())
    }

    async fn insert_chunk(
        &self,
        table: &lancedb::table::Table,
        content_items: &[ContentInfo],
    ) -> Result<()> {
        // Build arrow arrays
        let mut content_builder = StringBuilder::new();

        for item in content_items {
            content_builder.append_value(&item.content);
        }

        // Create blake3_hash StringArray (non-nullable)
        let mut blake3_hash_builder = StringBuilder::new();
        for item in content_items {
            blake3_hash_builder.append_value(&item.blake3_hash);
        }
        let blake3_hash_array = blake3_hash_builder.finish();

        let batch = RecordBatch::try_from_iter(vec![
            ("blake3_hash", Arc::new(blake3_hash_array) as ArrayRef),
            ("content", Arc::new(content_builder.finish()) as ArrayRef),
        ])?;

        // Use merge_insert for upsert functionality
        let mut merge_insert = table.merge_insert(&["blake3_hash"]);
        merge_insert
            .when_matched_update_all(None)
            .when_not_matched_insert_all();
        let schema = batch.schema();
        let batch_reader = RecordBatchIterator::new(vec![Ok(batch)], schema);
        merge_insert.execute(Box::new(batch_reader)).await?;

        Ok(())
    }

    /// Check if content exists by hash - uses indexed lookup
    pub async fn content_exists(&self, blake3_hash: &str) -> Result<bool> {
        let table_name = Self::get_table_name_for_hash(blake3_hash);
        let table = self.connection.open_table(&table_name).execute().await?;

        // Use indexed lookup with hex string
        let results = table
            .query()
            .only_if(format!("blake3_hash = '{blake3_hash}'"))
            .limit(1)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        // Check if we found any results
        Ok(!results.is_empty() && results[0].num_rows() > 0)
    }

    /// Get content by blake3 hash - uses indexed lookup
    pub async fn get_content(&self, blake3_hash: &str) -> Result<Option<String>> {
        let table_name = Self::get_table_name_for_hash(blake3_hash);
        let table = self.connection.open_table(&table_name).execute().await?;

        // Use indexed lookup with hex string
        let results = table
            .query()
            .only_if(format!("blake3_hash = '{blake3_hash}'"))
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

    /// Get content by blake3 hash hex string (now redundant since get_content takes hex strings directly)
    pub async fn get_content_by_hex(&self, blake3_hash_hex: &str) -> Result<Option<String>> {
        self.get_content(blake3_hash_hex).await
    }

    /// Bulk fetch content for multiple hashes - uses indexed lookup
    pub async fn get_content_bulk(
        &self,
        hashes: &[String],
    ) -> Result<std::collections::HashMap<String, String>> {
        if hashes.is_empty() {
            return Ok(std::collections::HashMap::new());
        }

        let mut content_map = std::collections::HashMap::new();

        // Group hashes by shard
        let mut shard_groups: std::collections::HashMap<u8, Vec<&String>> =
            std::collections::HashMap::new();
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
                let filter = format!("blake3_hash IN ({in_clause})");

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
                    let blake3_hash_array = batch
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
                        let hash = blake3_hash_array.value(i).to_string();
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
        let blake3_hash_array = batch
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
            blake3_hash: blake3_hash_array.value(row).to_string(),
            content: content_array.value(row).to_string(),
        }))
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

        let avg_content_size = total_content_size.checked_div(sample_count).unwrap_or(0);

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
    pub blake3_hash: String, // Hex string for JSON
    pub content: String,
}

impl From<ContentInfo> for ContentInfoJson {
    fn from(content_info: ContentInfo) -> Self {
        Self {
            blake3_hash: content_info.blake3_hash, // Already a hex string
            content: content_info.content,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lancedb::connection::LanceFileVersion;
    use lancedb::database::listing::ListingDatabaseOptions;

    async fn fresh_store() -> (tempfile::TempDir, ContentStore) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("content-race.lancedb");
        let options = ListingDatabaseOptions::builder()
            .data_storage_version(LanceFileVersion::V2_2)
            .build();
        let connection = lancedb::connect(db_path.to_str().unwrap())
            .database_options(&options)
            .execute()
            .await
            .unwrap();
        crate::database::schema::SchemaManager::new(connection.clone())
            .create_all_tables()
            .await
            .unwrap();
        (dir, ContentStore::new(connection))
    }

    /// One body hashing into `shard`, distinct for every (round, item).
    fn body_for_shard(shard: u8, round: u32, item: u32) -> ContentInfo {
        let mut nonce = 0u32;
        loop {
            let content = format!("race body round {round} item {item} nonce {nonce}");
            let blake3_hash = crate::hash::compute_blake3_hash(&content);
            if ContentStore::get_shard_number(&blake3_hash) == shard {
                return ContentInfo {
                    blake3_hash,
                    content,
                };
            }
            nonce += 1;
        }
    }

    /// Two concurrent insert_batch calls with overlapping new hashes must not
    /// leave duplicate rows: without the per-shard lock both commits miss
    /// and both insert. Fresh hashes every round so one lucky round cannot
    /// hide the race; everything lands in one shard for maximum overlap.
    #[tokio::test]
    async fn concurrent_same_shard_upserts_leave_no_duplicates() {
        const ROUNDS: u32 = 40;
        const PER_ROUND: u32 = 64;

        let (_dir, store) = fresh_store().await;
        let store = Arc::new(store);
        let mut unique_hashes = std::collections::HashSet::new();

        for round in 0..ROUNDS {
            let items: Vec<ContentInfo> = (0..PER_ROUND)
                .map(|item| body_for_shard(0, round, item))
                .collect();
            unique_hashes.extend(items.iter().map(|item| item.blake3_hash.clone()));

            let (first, second) =
                tokio::join!(store.insert_batch(items.clone()), store.insert_batch(items),);
            first.unwrap();
            second.unwrap();
        }

        assert_eq!(
            unique_hashes.len(),
            (ROUNDS * PER_ROUND) as usize,
            "test bodies must hash distinctly"
        );
        let rows = store.get_all().await.unwrap();
        assert_eq!(
            rows.len(),
            unique_hashes.len(),
            "concurrent upserts of the same new hashes left duplicate rows"
        );
    }
}
