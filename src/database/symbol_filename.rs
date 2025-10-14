// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use arrow::array::{ArrayRef, RecordBatch, StringBuilder};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatchIterator;
use futures::TryStreamExt;
use lancedb::connection::Connection;
use lancedb::query::{ExecutableQuery, QueryBase};
use std::sync::Arc;

use crate::database::connection::OPTIMAL_BATCH_SIZE;

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
        // Build arrow arrays
        let mut symbol_builder = StringBuilder::new();
        let mut filename_builder = StringBuilder::new();

        for (symbol_name, file_path) in pairs {
            symbol_builder.append_value(symbol_name);
            filename_builder.append_value(file_path);
        }

        let schema = self.get_schema();

        let batch = RecordBatch::try_from_iter(vec![
            ("symbol", Arc::new(symbol_builder.finish()) as ArrayRef),
            ("filename", Arc::new(filename_builder.finish()) as ArrayRef),
        ])?;

        let batches = vec![Ok(batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);
        table.add(batch_iterator).execute().await?;

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

    fn get_schema(&self) -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            Field::new("symbol", DataType::Utf8, false),
            Field::new("filename", DataType::Utf8, false),
        ]))
    }
}
