// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use arrow::array::{ArrayRef, RecordBatch, RecordBatchIterator, StringBuilder};
use futures::TryStreamExt;
use lancedb::connection::Connection;
use lancedb::query::{ExecutableQuery, QueryBase};
use once_cell::sync::Lazy;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::database::connection::OPTIMAL_BATCH_SIZE;

/// Process-global lock serializing symbol_filename upserts.
///
/// One batch's functions and types inserts both upsert into this table
/// concurrently, and several inserters run at once. Two merge_inserts of the
/// same new (symbol, filename) pair both open the table at the same version,
/// both miss, and both insert, so the pair keeps two rows. The lock is
/// process-global rather than per instance so that it also serializes stores
/// belonging to different DatabaseManagers opened on one database.
static SYMBOL_FILENAME_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

/// Stores (symbol_name, filename) pairs for fast lookups of functions, macros, types, and typedefs
pub struct SymbolFilenameStore {
    connection: Connection,
}

impl SymbolFilenameStore {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    /// Insert a batch of (symbol_name, filename) pairs
    pub async fn insert_batch(&self, pairs: Vec<(String, String)>) -> Result<()> {
        if pairs.is_empty() {
            return Ok(());
        }

        // Taken before open_table and held across every chunk: a handle
        // opened earlier reads a version without the other writer's rows,
        // and its merge_insert inserts them again.
        let _guard = SYMBOL_FILENAME_LOCK.lock().await;
        let table = self
            .connection
            .open_table("symbol_filename")
            .execute()
            .await?;

        // Process in optimal batch sizes
        for chunk in pairs.chunks(OPTIMAL_BATCH_SIZE) {
            self.insert_chunk(&table, chunk).await?;
        }

        Ok(())
    }

    async fn insert_chunk(
        &self,
        table: &lancedb::table::Table,
        pairs: &[(String, String)],
    ) -> Result<()> {
        // Deduplicate pairs in memory before sending to database
        // This significantly reduces the workload on LanceDB's merge_insert
        use std::collections::HashSet;

        let mut seen_keys = HashSet::new();
        let mut unique_pairs = Vec::new();

        for (symbol_name, file_path) in pairs {
            // Create combined key for deduplication: "filename:symbol"
            let key = format!("{}:{}", file_path, symbol_name);

            // Only add if we haven't seen this key before
            if seen_keys.insert(key) {
                unique_pairs.push((symbol_name.clone(), file_path.clone()));
            }
        }

        // If all pairs were duplicates, return early
        if unique_pairs.is_empty() {
            return Ok(());
        }

        // Build arrow arrays from deduplicated data (no separate key column)
        let mut symbol_builder = StringBuilder::new();
        let mut filename_builder = StringBuilder::new();

        for (symbol_name, file_path) in &unique_pairs {
            symbol_builder.append_value(symbol_name);
            filename_builder.append_value(file_path);
        }

        let batch = RecordBatch::try_from_iter(vec![
            ("symbol", Arc::new(symbol_builder.finish()) as ArrayRef),
            ("filename", Arc::new(filename_builder.finish()) as ArrayRef),
        ])?;

        // Use merge_insert with composite key (symbol, filename) for deduplication
        let mut merge_insert = table.merge_insert(&["symbol", "filename"]);
        merge_insert
            .when_matched_update_all(None) // Update existing rows with same composite key
            .when_not_matched_insert_all(); // Insert new rows
        let schema = batch.schema();
        let batch_reader = RecordBatchIterator::new(vec![Ok(batch)], schema);
        merge_insert.execute(Box::new(batch_reader)).await?;

        Ok(())
    }

    /// Get all filenames where a symbol (function/macro/type/typedef) is defined
    /// This is optimized for git-aware lookups - returns unique file paths
    pub async fn get_filenames_for_symbol(&self, symbol_name: &str) -> Result<Vec<String>> {
        let table = self
            .connection
            .open_table("symbol_filename")
            .execute()
            .await?;

        let escaped_name = symbol_name.replace("'", "''");
        let filter = format!("symbol = '{escaped_name}'");

        let results = table
            .query()
            .only_if(filter)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut filenames = Vec::new();

        for batch in &results {
            if batch.num_rows() == 0 {
                continue;
            }

            // Column 1 is filename (column 0 is symbol)
            let filename_array = batch
                .column(1)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap();

            for i in 0..batch.num_rows() {
                filenames.push(filename_array.value(i).to_string());
            }
        }

        // Deduplicate filenames (same symbol may appear multiple times if indexed at different git commits)
        let unique_filenames: Vec<String> = filenames
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        Ok(unique_filenames)
    }

    /// Get all symbol-filename pairs
    pub async fn get_all(&self) -> Result<Vec<(String, String)>> {
        let table = self
            .connection
            .open_table("symbol_filename")
            .execute()
            .await?;

        let results = table
            .query()
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut pairs = Vec::new();

        for batch in &results {
            if batch.num_rows() == 0 {
                continue;
            }

            // Column 0 is symbol, column 1 is filename
            let symbol_array = batch
                .column(0)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap();
            let filename_array = batch
                .column(1)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap();

            for i in 0..batch.num_rows() {
                let symbol = symbol_array.value(i).to_string();
                let filename = filename_array.value(i).to_string();
                pairs.push((symbol, filename));
            }
        }

        Ok(pairs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lancedb::connection::LanceFileVersion;
    use lancedb::database::listing::ListingDatabaseOptions;

    async fn fresh_store() -> (tempfile::TempDir, SymbolFilenameStore) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("symbol-filename-race.lancedb");
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
        (dir, SymbolFilenameStore::new(connection))
    }

    /// Two concurrent insert_batch calls with the same new pairs must not
    /// leave duplicate rows: without the lock both merge_inserts miss and
    /// both insert. Fresh pairs every round so one lucky round cannot hide
    /// the race.
    #[tokio::test]
    async fn concurrent_upserts_of_same_pairs_leave_no_duplicates() {
        const ROUNDS: u32 = 40;
        const PER_ROUND: u32 = 64;

        let (_dir, store) = fresh_store().await;
        let store = Arc::new(store);
        let mut unique_pairs = std::collections::HashSet::new();

        for round in 0..ROUNDS {
            let pairs: Vec<(String, String)> = (0..PER_ROUND)
                .map(|item| (format!("sym_{round}_{item}"), format!("dir/file_{item}.c")))
                .collect();
            unique_pairs.extend(pairs.iter().cloned());

            let (first, second) =
                tokio::join!(store.insert_batch(pairs.clone()), store.insert_batch(pairs));
            first.unwrap();
            second.unwrap();
        }

        let rows = store.get_all().await.unwrap();
        assert_eq!(
            rows.len(),
            unique_pairs.len(),
            "concurrent upserts of the same new pairs left duplicate rows"
        );
    }
}
