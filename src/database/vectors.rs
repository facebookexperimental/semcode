// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use arrow::array::{Array, ArrayRef, FixedSizeListArray, RecordBatch, StringArray, StringBuilder};
use arrow::datatypes::{DataType, Field, Float32Type, Schema};
use arrow::record_batch::RecordBatchIterator;
use futures::TryStreamExt;
use gxhash::{HashMap, HashMapExt};
use lancedb::connection::Connection;
use lancedb::query::{ExecutableQuery, QueryBase};
use std::sync::Arc;

use crate::database::connection::OPTIMAL_BATCH_SIZE;

#[derive(Debug, Clone)]
pub struct VectorEntry {
    pub content_hash: String, // gxhash128 hash of the content
    pub vector: Vec<f32>,     // Variable-dimensional vector
}

pub struct VectorStore {
    connection: Connection,
}

impl VectorStore {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    pub async fn insert_batch(&self, vectors: Vec<VectorEntry>) -> Result<()> {
        if vectors.is_empty() {
            return Ok(());
        }

        let table = self.connection.open_table("vectors").execute().await?;

        // Process in optimal batch sizes
        for chunk in vectors.chunks(OPTIMAL_BATCH_SIZE) {
            self.insert_chunk(&table, chunk).await?;
        }

        Ok(())
    }

    async fn insert_chunk(
        &self,
        table: &lancedb::table::Table,
        vectors: &[VectorEntry],
    ) -> Result<()> {
        if vectors.is_empty() {
            return Ok(());
        }

        // Get vector dimension from first entry
        let vector_dim = vectors[0].vector.len();

        // Validate all vectors have the same dimension
        for (i, entry) in vectors.iter().enumerate() {
            if entry.vector.len() != vector_dim {
                return Err(anyhow::anyhow!(
                    "Vector dimension mismatch at entry {}: expected {}, got {}",
                    i,
                    vector_dim,
                    entry.vector.len()
                ));
            }
        }

        // Create content_hash StringArray (non-nullable)
        let mut content_hash_builder = StringBuilder::new();
        for entry in vectors {
            content_hash_builder.append_value(&entry.content_hash);
        }
        let content_hash_array = content_hash_builder.finish();

        // Create vector array with dynamic dimension
        let vector_array = FixedSizeListArray::from_iter_primitive::<Float32Type, _, _>(
            vectors
                .iter()
                .map(|entry| Some(entry.vector.iter().map(|&v| Some(v)))),
            vector_dim as i32,
        );

        let schema = self.get_schema(vector_dim);

        let batch = RecordBatch::try_from_iter(vec![
            ("content_hash", Arc::new(content_hash_array) as ArrayRef),
            ("vector", Arc::new(vector_array) as ArrayRef),
        ])?;

        let batches = vec![Ok(batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);
        table.add(batch_iterator).execute().await?;

        Ok(())
    }

    /// Get vectors for multiple content hashes (batch lookup)
    pub async fn get_vectors_batch(
        &self,
        content_hashes: &[String],
    ) -> Result<HashMap<String, Vec<f32>>> {
        if content_hashes.is_empty() {
            return Ok(HashMap::new());
        }

        let table = self.connection.open_table("vectors").execute().await?;
        let mut result = HashMap::new();

        // Process in chunks to avoid query size limits
        for chunk in content_hashes.chunks(100) {
            let conditions: Vec<String> = chunk
                .iter()
                .map(|hash| {
                    let escaped_hash = hash.replace("'", "''");
                    format!("content_hash = '{escaped_hash}'")
                })
                .collect();

            let filter = conditions.join(" OR ");

            let results = table
                .query()
                .only_if(filter)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            for batch in &results {
                for i in 0..batch.num_rows() {
                    if let Some((hash, vector)) = self.extract_vector_from_batch(batch, i)? {
                        result.insert(hash, vector);
                    }
                }
            }
        }

        Ok(result)
    }

    fn extract_vector_from_batch(
        &self,
        batch: &RecordBatch,
        row: usize,
    ) -> Result<Option<(String, Vec<f32>)>> {
        let content_hash_array = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let vector_array = batch
            .column(1)
            .as_any()
            .downcast_ref::<FixedSizeListArray>()
            .unwrap();

        let hash = content_hash_array.value(row).to_string();

        if vector_array.is_null(row) {
            return Ok(None);
        }

        let vector_values = vector_array.value(row);
        if let Some(float_array) = vector_values
            .as_any()
            .downcast_ref::<arrow::array::Float32Array>()
        {
            let vector: Vec<f32> = (0..float_array.len())
                .map(|i| float_array.value(i))
                .collect();
            Ok(Some((hash, vector)))
        } else {
            Ok(None)
        }
    }

    fn get_schema(&self, vector_dim: usize) -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            Field::new("content_hash", DataType::Utf8, false), // gxhash128 content hash as hex string
            Field::new(
                "vector",
                DataType::FixedSizeList(
                    Arc::new(Field::new("item", DataType::Float32, true)),
                    vector_dim as i32,
                ),
                false, // Non-nullable - we only store entries that have vectors
            ),
        ]))
    }

    /// Verify the dimension of vectors stored in the database
    pub async fn verify_vector_dimension(&self) -> Result<usize> {
        let table = self.connection.open_table("vectors").execute().await?;

        // Get schema information
        let schema = table.schema().await?;

        // Find the vector column
        if let Some((_, field)) = schema.column_with_name("vector") {
            match field.data_type() {
                arrow::datatypes::DataType::FixedSizeList(_, size) => {
                    let dimension = *size as usize;
                    tracing::info!(
                        "Database vectors table configured for {} dimensions",
                        dimension
                    );
                    Ok(dimension)
                }
                _ => Err(anyhow::anyhow!("Vector column has unexpected data type")),
            }
        } else {
            Err(anyhow::anyhow!("No vector column found in vectors table"))
        }
    }

    /// Get statistics about vector storage
    pub async fn get_stats(&self) -> Result<usize> {
        let table = self.connection.open_table("vectors").execute().await?;

        let results = table
            .query()
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let total_count = results.iter().map(|batch| batch.num_rows()).sum();

        Ok(total_count)
    }
}
