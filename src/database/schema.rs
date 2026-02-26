// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use arrow::datatypes::{DataType, Field, Schema};
use arrow::error::ArrowError;
use arrow::record_batch::{RecordBatch, RecordBatchIterator};
use futures::{stream, StreamExt, TryStreamExt};
use lancedb::connection::Connection;
use lancedb::index::{scalar::BTreeIndexBuilder, scalar::FtsIndexBuilder, Index as LanceIndex};
use lancedb::query::{ExecutableQuery, QueryBase};
use lancedb::table::OptimizeAction;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Outcome of a single table optimization operation.
pub enum OptimizeOutcome {
    /// Table was successfully optimized (all operations completed)
    Optimized,
    /// Table was skipped (too small to benefit from optimization)
    Skipped,
    /// Optimization was attempted but one or more operations failed
    PartialFailure,
}

pub struct SchemaManager {
    connection: Connection,
}

impl SchemaManager {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    pub async fn create_all_tables(&self) -> Result<()> {
        let table_names = self.connection.table_names().execute().await?;

        if !table_names.iter().any(|n| n == "functions") {
            self.create_functions_table().await?;
        }

        if !table_names.iter().any(|n| n == "types") {
            self.create_types_table().await?;
        }

        if !table_names.iter().any(|n| n == "vectors") {
            self.create_vectors_table().await?;
        }

        if !table_names.iter().any(|n| n == "processed_files") {
            self.create_processed_files_table().await?;
        }

        if !table_names.iter().any(|n| n == "symbol_filename") {
            self.create_symbol_filename_table().await?;
        }

        if !table_names.iter().any(|n| n == "git_commits") {
            self.create_git_commits_table().await?;
        }

        if !table_names.iter().any(|n| n == "commit_vectors") {
            self.create_commit_vectors_table().await?;
        }

        if !table_names.iter().any(|n| n == "lore") {
            self.create_lore_table().await?;
        }

        if !table_names.iter().any(|n| n == "lore_indexed_commits") {
            self.create_lore_indexed_commits_table().await?;
        }

        if !table_names.iter().any(|n| n == "lore_vectors") {
            self.create_lore_vectors_table().await?;
        }

        if !table_names.iter().any(|n| n == "indexed_branches") {
            self.create_indexed_branches_table().await?;
        }

        // Check and create content shard tables (content_0 through content_15)
        self.create_content_shard_tables().await?;

        Ok(())
    }

    pub async fn create_functions_table(&self) -> Result<()> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("name", DataType::Utf8, false),
            Field::new("file_path", DataType::Utf8, false),
            Field::new("git_file_hash", DataType::Utf8, false), // Git hash of file content as hex string
            Field::new("line_start", DataType::Int64, false),
            Field::new("line_end", DataType::Int64, false),
            Field::new("return_type", DataType::Utf8, false),
            Field::new("parameters", DataType::Utf8, false),
            Field::new("body_hash", DataType::Utf8, true), // Blake3 hash referencing content table as hex string (nullable for empty bodies)
            Field::new("calls", DataType::Utf8, true), // JSON array of function names called by this function
            Field::new("types", DataType::Utf8, true), // JSON array of type names used by this function
        ]));

        let empty_batch = RecordBatch::new_empty(schema.clone());
        let batches = vec![Ok(empty_batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);

        self.connection
            .create_table("functions", batch_iterator)
            .execute()
            .await?;

        Ok(())
    }

    pub async fn create_types_table(&self) -> Result<()> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("name", DataType::Utf8, false),
            Field::new("file_path", DataType::Utf8, false),
            Field::new("git_file_hash", DataType::Utf8, false), // Git hash of file content as hex string
            Field::new("line", DataType::Int64, false),
            Field::new("kind", DataType::Utf8, false),
            Field::new("size", DataType::Int64, true),
            Field::new("fields", DataType::Utf8, false),
            Field::new("definition_hash", DataType::Utf8, true), // Blake3 hash referencing content table as hex string (nullable for empty definitions)
            Field::new("types", DataType::Utf8, true), // JSON array of type names referenced by this type
        ]));

        let empty_batch = RecordBatch::new_empty(schema.clone());
        let batches = vec![Ok(empty_batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);

        self.connection
            .create_table("types", batch_iterator)
            .execute()
            .await?;

        Ok(())
    }

    async fn create_vectors_table(&self) -> Result<()> {
        // Create vectors table with 256 dimensions
        let schema = Arc::new(Schema::new(vec![
            Field::new("content_hash", DataType::Utf8, false), // Blake3 content hash as hex string
            Field::new(
                "vector",
                DataType::FixedSizeList(Arc::new(Field::new("item", DataType::Float32, true)), 256),
                false, // Non-nullable - we only store entries that have vectors
            ),
        ]));

        let empty_batch = RecordBatch::new_empty(schema.clone());
        let batches = vec![Ok(empty_batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);

        self.connection
            .create_table("vectors", batch_iterator)
            .execute()
            .await?;

        tracing::info!("Created vectors table with 256 dimensions");
        Ok(())
    }

    async fn create_commit_vectors_table(&self) -> Result<()> {
        // Create commit_vectors table with 256 dimensions
        let schema = Arc::new(Schema::new(vec![
            Field::new("git_commit_sha", DataType::Utf8, false), // Git commit SHA
            Field::new(
                "vector",
                DataType::FixedSizeList(Arc::new(Field::new("item", DataType::Float32, true)), 256),
                false, // Non-nullable - we only store entries that have vectors
            ),
        ]));

        let empty_batch = RecordBatch::new_empty(schema.clone());
        let batches = vec![Ok(empty_batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);

        self.connection
            .create_table("commit_vectors", batch_iterator)
            .execute()
            .await?;

        tracing::info!("Created commit_vectors table with 256 dimensions");
        Ok(())
    }

    async fn create_lore_vectors_table(&self) -> Result<()> {
        // Create lore_vectors table with 256 dimensions, indexed by message_id
        let schema = Arc::new(Schema::new(vec![
            Field::new("message_id", DataType::Utf8, false), // Email message-id
            Field::new(
                "vector",
                DataType::FixedSizeList(Arc::new(Field::new("item", DataType::Float32, true)), 256),
                false, // Non-nullable - we only store entries that have vectors
            ),
        ]));

        let empty_batch = RecordBatch::new_empty(schema.clone());
        let batches = vec![Ok(empty_batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);

        self.connection
            .create_table("lore_vectors", batch_iterator)
            .execute()
            .await?;

        tracing::info!("Created lore_vectors table with 256 dimensions");
        Ok(())
    }

    async fn create_processed_files_table(&self) -> Result<()> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("file", DataType::Utf8, false),   // File path
            Field::new("git_sha", DataType::Utf8, true), // Current git head SHA as hex string (nullable)
            Field::new("git_file_sha", DataType::Utf8, false), // SHA of specific file content as hex string
        ]));

        let empty_batch = RecordBatch::new_empty(schema.clone());
        let batches = vec![Ok(empty_batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);

        self.connection
            .create_table("processed_files", batch_iterator)
            .execute()
            .await?;

        Ok(())
    }

    async fn create_symbol_filename_table(&self) -> Result<()> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("symbol", DataType::Utf8, false), // Symbol name (function, macro, type, or typedef)
            Field::new("filename", DataType::Utf8, false), // File path where symbol is defined
        ]));

        let empty_batch = RecordBatch::new_empty(schema.clone());
        let batches = vec![Ok(empty_batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);

        self.connection
            .create_table("symbol_filename", batch_iterator)
            .execute()
            .await?;

        Ok(())
    }

    async fn create_git_commits_table(&self) -> Result<()> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("git_sha", DataType::Utf8, false), // Commit SHA
            Field::new("parent_sha", DataType::Utf8, false), // Parent commit SHAs (JSON array)
            Field::new("author", DataType::Utf8, false),  // Author name and email
            Field::new("subject", DataType::Utf8, false), // Single line commit title
            Field::new("message", DataType::Utf8, false), // Full commit message
            Field::new("tags", DataType::Utf8, false),    // JSON object of tags
            Field::new("diff", DataType::Utf8, false),    // Full unified diff
            Field::new("symbols", DataType::Utf8, false), // JSON array of changed symbols
            Field::new("files", DataType::Utf8, false),   // JSON array of changed files
        ]));

        let empty_batch = RecordBatch::new_empty(schema.clone());
        let batches = vec![Ok(empty_batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);

        self.connection
            .create_table("git_commits", batch_iterator)
            .execute()
            .await?;

        Ok(())
    }

    async fn create_lore_table(&self) -> Result<()> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("git_commit_sha", DataType::Utf8, false), // Git commit SHA containing this email
            Field::new("from", DataType::Utf8, false),           // From header in the email
            Field::new("date", DataType::Utf8, false),           // Date field
            Field::new("message_id", DataType::Utf8, false),     // Message-ID header
            Field::new("in_reply_to", DataType::Utf8, true),     // In-Reply-To header (nullable)
            Field::new("subject", DataType::Utf8, false),        // Subject line
            Field::new("references", DataType::Utf8, true), // Full list of references (nullable)
            Field::new("recipients", DataType::Utf8, false), // Full list of cc/to recipients
            Field::new("headers", DataType::Utf8, false), // Email headers (everything before first blank line)
            Field::new("body", DataType::Utf8, false), // Email body (everything after first blank line)
            Field::new("symbols", DataType::Utf8, false), // JSON array of symbols referenced in email
        ]));

        let empty_batch = RecordBatch::new_empty(schema.clone());
        let batches = vec![Ok(empty_batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);

        self.connection
            .create_table("lore", batch_iterator)
            .execute()
            .await?;

        tracing::info!("Created lore table for email archive indexing");
        Ok(())
    }

    async fn create_lore_indexed_commits_table(&self) -> Result<()> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("git_commit_sha", DataType::Utf8, false),
        ]));

        let empty_batch = RecordBatch::new_empty(schema.clone());
        let batches = vec![Ok(empty_batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);

        self.connection
            .create_table("lore_indexed_commits", batch_iterator)
            .execute()
            .await?;

        tracing::info!("Created lore_indexed_commits table");
        Ok(())
    }

    async fn create_indexed_branches_table(&self) -> Result<()> {
        use crate::database::branches::IndexedBranchStore;

        let schema = IndexedBranchStore::get_schema();
        let empty_batch = RecordBatch::new_empty(schema.clone());
        let batches = vec![Ok(empty_batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);

        self.connection
            .create_table("indexed_branches", batch_iterator)
            .execute()
            .await?;

        tracing::info!("Created indexed_branches table for multi-branch support");
        Ok(())
    }

    async fn create_content_table(&self) -> Result<()> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("blake3_hash", DataType::Utf8, false), // Blake3 hash of content as hex string
            Field::new("content", DataType::Utf8, false), // The actual content (function body, etc.)
        ]));

        let empty_batch = RecordBatch::new_empty(schema.clone());
        let batches = vec![Ok(empty_batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);

        self.connection
            .create_table("content", batch_iterator)
            .execute()
            .await?;

        Ok(())
    }

    /// Create all 16 content shard tables (content_0 through content_15)
    async fn create_content_shard_tables(&self) -> Result<()> {
        let table_names = self.connection.table_names().execute().await?;
        let schema = Arc::new(Schema::new(vec![
            Field::new("blake3_hash", DataType::Utf8, false), // Blake3 hash of content as hex string
            Field::new("content", DataType::Utf8, false), // The actual content (function body, etc.)
        ]));

        // Create each shard table if it doesn't exist
        for shard in 0..16u8 {
            let table_name = format!("content_{shard}");

            if !table_names.iter().any(|n| n == &table_name) {
                let empty_batch = RecordBatch::new_empty(schema.clone());
                let batches = vec![Ok(empty_batch)];
                let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema.clone());

                self.connection
                    .create_table(&table_name, batch_iterator)
                    .execute()
                    .await?;

                tracing::info!("Created content shard table: {}", table_name);
            }
        }

        Ok(())
    }

    pub async fn create_scalar_indices(&self) -> Result<()> {
        let table_names = self.connection.table_names().execute().await?;

        // Check if database already has data (skip index creation if it does - likely already indexed)
        // This significantly speeds up startup time from 12+ seconds to milliseconds
        // Check both functions and lore tables
        if let Ok(table) = self.connection.open_table("functions").execute().await {
            if let Ok(count) = table.count_rows(None).await {
                if count > 100 {
                    tracing::debug!(
                        "Skipping index creation - functions table has {} rows (likely already indexed)",
                        count
                    );
                    return Ok(());
                }
            }
        }

        if let Ok(table) = self.connection.open_table("lore").execute().await {
            if let Ok(count) = table.count_rows(None).await {
                if count > 100 {
                    tracing::debug!(
                        "Skipping index creation - lore table has {} rows (likely already indexed)",
                        count
                    );
                    return Ok(());
                }
            }
        }

        tracing::info!("Creating database indices (first time or small database)...");

        // Create indices for functions table
        if table_names.iter().any(|n| n == "functions") {
            let table = self.connection.open_table("functions").execute().await?;

            // Index on name for exact matches
            self.try_create_index(&table, &["name"], "BTree index on functions.name")
                .await;

            // Index on git_file_hash for content-based lookups
            self.try_create_index(
                &table,
                &["git_file_hash"],
                "BTree index on functions.git_file_hash",
            )
            .await;

            // Index on file_path for file-based queries
            self.try_create_index(&table, &["file_path"], "BTree index on functions.file_path")
                .await;

            // Index on body_hash for content reference lookups
            self.try_create_index(&table, &["body_hash"], "BTree index on functions.body_hash")
                .await;

            // Index on line_start for line-based queries and sorting
            self.try_create_index(
                &table,
                &["line_start"],
                "BTree index on functions.line_start",
            )
            .await;

            // Index on line_end for range-based queries
            self.try_create_index(&table, &["line_end"], "BTree index on functions.line_end")
                .await;

            // Composite index for duplicate checking with content hash
            self.try_create_index(
                &table,
                &["name", "git_file_hash"],
                "Composite index on functions.(name,git_file_hash)",
            )
            .await;
        }

        // Create indices for types table
        if table_names.iter().any(|n| n == "types") {
            let table = self.connection.open_table("types").execute().await?;

            // Index on name
            self.try_create_index(&table, &["name"], "BTree index on types.name")
                .await;

            // Index on git_file_hash for content-based lookups
            self.try_create_index(
                &table,
                &["git_file_hash"],
                "BTree index on types.git_file_hash",
            )
            .await;

            // Index on kind
            self.try_create_index(&table, &["kind"], "BTree index on types.kind")
                .await;

            // Index on file_path for file-based queries
            self.try_create_index(&table, &["file_path"], "BTree index on types.file_path")
                .await;

            // Index on definition_hash for content reference lookups
            self.try_create_index(
                &table,
                &["definition_hash"],
                "BTree index on types.definition_hash",
            )
            .await;

            // Composite index for duplicate checking with content hash
            self.try_create_index(
                &table,
                &["name", "kind", "git_file_hash"],
                "Composite index on types.(name,kind,git_file_hash)",
            )
            .await;
        }

        // Create indices for vectors table
        if table_names.iter().any(|n| n == "vectors") {
            let table = self.connection.open_table("vectors").execute().await?;

            // Primary index on content_hash for fast lookups
            self.try_create_index(
                &table,
                &["content_hash"],
                "BTree index on vectors.content_hash",
            )
            .await;
        }

        // Create indices for commit_vectors table
        if table_names.iter().any(|n| n == "commit_vectors") {
            let table = self
                .connection
                .open_table("commit_vectors")
                .execute()
                .await?;

            // Primary index on git_commit_sha for fast lookups
            self.try_create_index(
                &table,
                &["git_commit_sha"],
                "BTree index on commit_vectors.git_commit_sha",
            )
            .await;
        }

        // Create indices for lore_vectors table
        if table_names.iter().any(|n| n == "lore_vectors") {
            let table = self.connection.open_table("lore_vectors").execute().await?;

            // Primary index on message_id for fast lookups
            self.try_create_index(
                &table,
                &["message_id"],
                "BTree index on lore_vectors.message_id",
            )
            .await;
        }

        // Create indices for lore table
        if table_names.iter().any(|n| n == "lore") {
            let table = self.connection.open_table("lore").execute().await?;

            // Index on message_id for fast lookups and joins
            self.try_create_index(&table, &["message_id"], "BTree index on lore.message_id")
                .await;

            // Index on from field for email sender queries
            self.try_create_index(&table, &["from"], "BTree index on lore.from")
                .await;

            // Index on subject for subject-based searches
            self.try_create_index(&table, &["subject"], "BTree index on lore.subject")
                .await;

            // Index on git_commit_sha for commit-based lookups
            self.try_create_index(
                &table,
                &["git_commit_sha"],
                "BTree index on lore.git_commit_sha",
            )
            .await;

            // Index on date for chronological queries
            self.try_create_index(&table, &["date"], "BTree index on lore.date")
                .await;

            // Index on in_reply_to for threading queries
            self.try_create_index(&table, &["in_reply_to"], "BTree index on lore.in_reply_to")
                .await;

            // Index on references for threading
            self.try_create_index(&table, &["references"], "BTree index on lore.references")
                .await;

            // Note: FTS indices for lore table are created separately after data is inserted
            // via create_lore_fts_indices() - see process_lore_commits_pipeline completion
            // BTree indices on body, recipients, and symbols removed - FTS indices used instead
        }

        // Create indices for processed_files table
        if table_names.iter().any(|n| n == "processed_files") {
            let table = self
                .connection
                .open_table("processed_files")
                .execute()
                .await?;

            // Index on file for file-based lookups
            self.try_create_index(&table, &["file"], "BTree index on processed_files.file")
                .await;

            // Index on git_sha for git commit-based lookups
            self.try_create_index(
                &table,
                &["git_sha"],
                "BTree index on processed_files.git_sha",
            )
            .await;

            // Index on git_file_sha for file content-based lookups
            self.try_create_index(
                &table,
                &["git_file_sha"],
                "BTree index on processed_files.git_file_sha",
            )
            .await;

            // Composite index for efficient file + git_sha lookups
            self.try_create_index(
                &table,
                &["file", "git_sha"],
                "Composite index on processed_files.(file,git_sha)",
            )
            .await;
        }

        // Create indices for symbol_filename table
        if table_names.iter().any(|n| n == "symbol_filename") {
            let table = self
                .connection
                .open_table("symbol_filename")
                .execute()
                .await?;

            // Index on symbol for symbol name-based lookups
            self.try_create_index(&table, &["symbol"], "BTree index on symbol_filename.symbol")
                .await;

            // Index on filename for file-based lookups
            self.try_create_index(
                &table,
                &["filename"],
                "BTree index on symbol_filename.filename",
            )
            .await;

            // Composite index on (symbol, filename) for fast deduplication
            self.try_create_index(
                &table,
                &["symbol", "filename"],
                "Composite index on symbol_filename.(symbol,filename)",
            )
            .await;
        }

        // Create indices for git_commits table
        if table_names.iter().any(|n| n == "git_commits") {
            let table = self.connection.open_table("git_commits").execute().await?;

            // Index on git_sha for commit lookups
            self.try_create_index(&table, &["git_sha"], "BTree index on git_commits.git_sha")
                .await;

            // Index on parent_sha for parent commit lookups
            self.try_create_index(
                &table,
                &["parent_sha"],
                "BTree index on git_commits.parent_sha",
            )
            .await;

            // Index on author for author-based queries
            self.try_create_index(&table, &["author"], "BTree index on git_commits.author")
                .await;

            // Index on subject for subject searches
            self.try_create_index(&table, &["subject"], "BTree index on git_commits.subject")
                .await;
        }

        // Create indices for lore table
        if table_names.iter().any(|n| n == "lore") {
            let table = self.connection.open_table("lore").execute().await?;

            // Index on git_commit_sha for commit-based queries
            self.try_create_index(
                &table,
                &["git_commit_sha"],
                "BTree index on lore.git_commit_sha",
            )
            .await;

            // Index on message_id for unique message lookups
            self.try_create_index(&table, &["message_id"], "BTree index on lore.message_id")
                .await;

            // Index on from for sender-based queries
            self.try_create_index(&table, &["from"], "BTree index on lore.from")
                .await;

            // Index on date for date-based queries and sorting
            self.try_create_index(&table, &["date"], "BTree index on lore.date")
                .await;

            // Index on in_reply_to for threading
            self.try_create_index(&table, &["in_reply_to"], "BTree index on lore.in_reply_to")
                .await;

            // Index on subject for subject searches
            self.try_create_index(&table, &["subject"], "BTree index on lore.subject")
                .await;

            // Index on references for threading
            self.try_create_index(&table, &["references"], "BTree index on lore.references")
                .await;

            // Note: BTree indices on body, recipients, and symbols removed - FTS used instead
        }

        // Create indices for indexed_branches table
        if table_names.iter().any(|n| n == "indexed_branches") {
            let table = self
                .connection
                .open_table("indexed_branches")
                .execute()
                .await?;

            // Primary index on branch_name for fast branch lookups
            self.try_create_index(
                &table,
                &["branch_name"],
                "BTree index on indexed_branches.branch_name",
            )
            .await;

            // Index on tip_commit for finding branches at specific commits
            self.try_create_index(
                &table,
                &["tip_commit"],
                "BTree index on indexed_branches.tip_commit",
            )
            .await;

            // Index on remote for remote-based queries
            self.try_create_index(
                &table,
                &["remote"],
                "BTree index on indexed_branches.remote",
            )
            .await;
        }

        // Create indices for all content shard tables
        for shard in 0..16u8 {
            let table_name = format!("content_{shard}");
            if table_names.iter().any(|n| n == &table_name) {
                let table = self.connection.open_table(&table_name).execute().await?;

                // Primary index on blake3_hash for deduplication and fast lookups
                self.try_create_index(
                    &table,
                    &["blake3_hash"],
                    &format!("BTree index on {table_name}.blake3_hash"),
                )
                .await;
            }
        }

        Ok(())
    }

    async fn try_create_index(
        &self,
        table: &lancedb::table::Table,
        columns: &[&str],
        description: &str,
    ) {
        match table
            .create_index(columns, LanceIndex::BTree(BTreeIndexBuilder::default()))
            .execute()
            .await
        {
            Ok(_) => tracing::info!("Created {}", description),
            Err(e) => tracing::debug!("{} may already exist: {}", description, e),
        }
    }

    async fn try_create_fts_index(
        &self,
        table: &lancedb::table::Table,
        columns: &[&str],
        description: &str,
    ) {
        // Configure FTS index optimized for source code and technical docs
        let fts_config = FtsIndexBuilder::default()
            .with_position(false) // Enable phrase queries for exact code snippets
            .base_tokenizer("simple".to_string())
            .lower_case(true) // Case-insensitive search for better matching
            .stem(false) // No stemming (run != running in code)
            .remove_stop_words(false) // Keep all tokens (if, for, while are keywords)
            .ascii_folding(true) // Preserve exact characters
            .max_token_length(Some(100)); // Allow long identifiers/symbols

        tracing::info!("Starting {}", description);
        match table
            .create_index(columns, LanceIndex::FTS(fts_config))
            .execute()
            .await
        {
            Ok(_) => tracing::info!("✓ Completed {}", description),
            Err(e) => tracing::debug!("{} may already exist: {}", description, e),
        }
    }

    /// Create FTS indices for lore table (must be called after data is inserted)
    /// Only creates indices if they don't already exist
    pub async fn create_lore_fts_indices(&self) -> Result<()> {
        let table = self.connection.open_table("lore").execute().await?;

        // Check if FTS indices already exist by trying to list them
        let indices: Vec<lancedb::index::IndexConfig> =
            (table.list_indices().await).unwrap_or_default();

        // Check if FTS indices already exist (index_type must be FTS)
        use lancedb::index::IndexType;
        let has_fts_indices = indices.iter().any(|idx| {
            idx.index_type == IndexType::FTS
                && (idx.columns.contains(&"from".to_string())
                    || idx.columns.contains(&"subject".to_string())
                    || idx.columns.contains(&"body".to_string())
                    || idx.columns.contains(&"recipients".to_string())
                    || idx.columns.contains(&"symbols".to_string()))
        });

        if has_fts_indices {
            tracing::info!("FTS indices already exist for lore table, skipping creation");
            return Ok(());
        }

        // Create FTS indices for text search on all searchable fields in parallel
        let start_time = std::time::Instant::now();
        tracing::info!("Creating 5 FTS indices for lore table in parallel (from, subject, body, recipients, symbols)...");

        // Create all 5 indices concurrently for faster indexing
        tokio::join!(
            self.try_create_fts_index(&table, &["from"], "FTS index on lore.from"),
            self.try_create_fts_index(&table, &["subject"], "FTS index on lore.subject"),
            self.try_create_fts_index(&table, &["body"], "FTS index on lore.body"),
            self.try_create_fts_index(&table, &["recipients"], "FTS index on lore.recipients"),
            self.try_create_fts_index(&table, &["symbols"], "FTS index on lore.symbols"),
        );

        let elapsed = start_time.elapsed();
        tracing::info!(
            "Completed creating 5 FTS indices in {:.1}s",
            elapsed.as_secs_f64()
        );
        Ok(())
    }

    pub async fn rebuild_indices(&self) -> Result<()> {
        // Rebuild vector index if needed
        let table_names = self.connection.table_names().execute().await?;

        // Check if we have vectors to index in the separate vectors table
        if table_names.iter().any(|n| n == "vectors") {
            let vectors_table = self.connection.open_table("vectors").execute().await?;

            let vector_count = vectors_table
                .query()
                .limit(1)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?
                .iter()
                .map(|batch| batch.num_rows())
                .sum::<usize>();

            if vector_count > 0 {
                tracing::info!(
                    "Found {} vectors, vector index creation is handled separately",
                    vector_count
                );
                // Vector index creation is handled separately by VectorSearchManager
            }
        }

        // Ensure scalar indices exist
        self.create_scalar_indices().await?;

        Ok(())
    }

    pub async fn optimize_tables(&self) -> Result<()> {
        // LanceDB handles optimization automatically
        tracing::info!("Database optimization is handled automatically by LanceDB");
        Ok(())
    }

    pub async fn compact_and_cleanup(&self) -> Result<()> {
        tracing::info!("Running database compaction and cleanup...");

        let table_names = self.connection.table_names().execute().await?;

        let mut tables_to_compact: Vec<String> = vec![
            "functions".to_string(),
            "types".to_string(),
            "vectors".to_string(),
            "commit_vectors".to_string(),
            "lore_vectors".to_string(),
            "processed_files".to_string(),
            "symbol_filename".to_string(),
            "git_commits".to_string(),
            "lore".to_string(),
            "indexed_branches".to_string(),
            "lore_indexed_commits".to_string(),
        ];

        // Add all content shard tables
        for shard in 0..16u8 {
            tables_to_compact.push(format!("content_{shard}"));
        }

        // Filter to only existing tables
        let tables_to_compact: Vec<String> = tables_to_compact
            .into_iter()
            .filter(|name| table_names.iter().any(|n| n == name))
            .collect();

        let total_tables = tables_to_compact.len();
        let tables_optimized = Arc::new(AtomicUsize::new(0));
        let tables_skipped = Arc::new(AtomicUsize::new(0));
        let tables_failed = Arc::new(AtomicUsize::new(0));
        let tables_processed = Arc::new(AtomicUsize::new(0));

        // Process tables in parallel with bounded concurrency
        const PARALLEL_TABLES: usize = 8;

        stream::iter(tables_to_compact)
            .map(|table_name| {
                let connection = self.connection.clone();
                let optimized = Arc::clone(&tables_optimized);
                let skipped = Arc::clone(&tables_skipped);
                let failed = Arc::clone(&tables_failed);
                let processed = Arc::clone(&tables_processed);

                async move {
                    let result = Self::optimize_single_table(&connection, &table_name).await;
                    let done = processed.fetch_add(1, Ordering::Relaxed) + 1;
                    tracing::info!("Processed table {}/{}: {}", done, total_tables, table_name);
                    match result {
                        Ok(OptimizeOutcome::Optimized) => {
                            optimized.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(OptimizeOutcome::PartialFailure) => {
                            failed.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(OptimizeOutcome::Skipped) => {
                            skipped.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to optimize table {}: {}", table_name, e);
                            failed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            })
            .buffer_unordered(PARALLEL_TABLES)
            .collect::<Vec<()>>()
            .await;

        let optimized = tables_optimized.load(Ordering::Relaxed);
        let skipped = tables_skipped.load(Ordering::Relaxed);
        let failed = tables_failed.load(Ordering::Relaxed);

        println!(
            "    Optimized {} tables{}{}",
            optimized,
            if skipped > 0 {
                format!(", {} skipped", skipped)
            } else {
                String::new()
            },
            if failed > 0 {
                format!(", {} failed", failed)
            } else {
                String::new()
            }
        );

        Ok(())
    }

    /// Optimize a single table - runs compact, prune, and index operations
    ///
    /// Tables with fewer than 1000 rows are skipped since the overhead of
    /// optimization exceeds any benefit for small tables.
    async fn optimize_single_table(
        connection: &Connection,
        table_name: &str,
    ) -> Result<OptimizeOutcome> {
        // Minimum row count for optimization to be worthwhile
        const MIN_ROWS_FOR_OPTIMIZATION: usize = 1000;

        let table = connection.open_table(table_name).execute().await?;

        let count = table.count_rows(None).await?;

        // Skip optimization for small tables - overhead exceeds benefit
        if count < MIN_ROWS_FOR_OPTIMIZATION {
            tracing::info!(
                "Skipping optimization for table {} ({} rows < {} threshold)",
                table_name,
                count,
                MIN_ROWS_FOR_OPTIMIZATION
            );
            return Ok(OptimizeOutcome::Skipped);
        }

        tracing::info!("Optimizing table {} ({} rows)", table_name, count);

        let mut success = true;

        // 1. Compact files
        if let Err(e) = table
            .optimize(OptimizeAction::Compact {
                options: Default::default(),
                remap_options: None,
            })
            .await
        {
            tracing::warn!("Failed to compact table {}: {}", table_name, e);
            success = false;
        }

        // 2. Prune ALL old versions
        if let Err(e) = table
            .optimize(OptimizeAction::Prune {
                older_than: Some(lancedb::table::Duration::try_seconds(0).expect("valid duration")),
                delete_unverified: Some(true),
                error_if_tagged_old_versions: Some(false),
            })
            .await
        {
            tracing::warn!(
                "Failed to prune old versions from table {}: {}",
                table_name,
                e
            );
            success = false;
        }

        // 3. Optimize indices
        if let Err(e) = table
            .optimize(OptimizeAction::Index(Default::default()))
            .await
        {
            tracing::warn!("Failed to optimize indices for table {}: {}", table_name, e);
            success = false;
        }

        // 4. Checkout latest version to release old handles
        if let Err(e) = table.checkout_latest().await {
            tracing::warn!(
                "Failed to checkout latest version for table {}: {}",
                table_name,
                e
            );
        }

        Ok(if success {
            OptimizeOutcome::Optimized
        } else {
            OptimizeOutcome::PartialFailure
        })
    }

    /// Drop and recreate tables for maximum space savings
    /// This is more aggressive than compaction and guarantees space reclamation
    pub async fn drop_and_recreate_tables(&self) -> Result<()> {
        tracing::info!("Starting drop and recreate operation for space savings...");

        let table_names = self.connection.table_names().execute().await?;

        let mut tables_to_recreate = vec![
            "functions",
            "types",
            "vectors",
            "commit_vectors",
            "lore_vectors",
            "processed_files",
            "symbol_filename",
            "git_commits",
            "lore",
            "indexed_branches",
            "lore_indexed_commits",
        ];

        // Add all content shard tables
        for shard in 0..16u8 {
            tables_to_recreate.push(Box::leak(format!("content_{shard}").into_boxed_str()));
        }

        for table_name in &tables_to_recreate {
            if table_names.iter().any(|n| n == table_name) {
                tracing::info!("Drop and recreate for table: {}", table_name);

                // Step 1: Export all data from the table
                let exported_data = self.export_table_data(table_name).await?;
                let row_count = exported_data.len();
                tracing::info!("Exported {} rows from table {}", row_count, table_name);

                if row_count == 0 {
                    tracing::info!("Table {} is empty, skipping drop/recreate", table_name);
                    continue;
                }

                // Step 2: Drop the table
                match self.connection.drop_table(table_name, &[]).await {
                    Ok(_) => {
                        tracing::info!("Successfully dropped table {}", table_name);
                    }
                    Err(e) => {
                        tracing::error!("Failed to drop table {}: {}", table_name, e);
                        return Err(e.into());
                    }
                }

                // Step 3: Recreate the table with fresh schema
                if *table_name == "vectors" {
                    // Always create vectors table with 256 dimensions
                    tracing::info!("Recreating vectors table with 256 dimensions");
                    match self.create_vectors_table().await {
                        Ok(_) => {
                            tracing::info!("Successfully recreated vectors table");
                        }
                        Err(e) => {
                            tracing::error!("Failed to recreate vectors table: {}", e);
                            return Err(e);
                        }
                    }
                } else if *table_name == "commit_vectors" {
                    // Always create commit_vectors table with 256 dimensions
                    tracing::info!("Recreating commit_vectors table with 256 dimensions");
                    match self.create_commit_vectors_table().await {
                        Ok(_) => {
                            tracing::info!("Successfully recreated commit_vectors table");
                        }
                        Err(e) => {
                            tracing::error!("Failed to recreate commit_vectors table: {}", e);
                            return Err(e);
                        }
                    }
                } else if *table_name == "lore_vectors" {
                    // Always create lore_vectors table with 256 dimensions
                    tracing::info!("Recreating lore_vectors table with 256 dimensions");
                    match self.create_lore_vectors_table().await {
                        Ok(_) => {
                            tracing::info!("Successfully recreated lore_vectors table");
                        }
                        Err(e) => {
                            tracing::error!("Failed to recreate lore_vectors table: {}", e);
                            return Err(e);
                        }
                    }
                } else {
                    // Normal table recreation
                    match self.create_table_by_name(table_name).await {
                        Ok(_) => {
                            tracing::info!("Successfully recreated table {}", table_name);
                        }
                        Err(e) => {
                            tracing::error!("Failed to recreate table {}: {}", table_name, e);
                            return Err(e);
                        }
                    }
                }

                // Step 4: Re-import the data
                match self.import_table_data(table_name, exported_data).await {
                    Ok(_) => {
                        tracing::info!(
                            "Successfully imported {} rows back to table {}",
                            row_count,
                            table_name
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to import data back to table {}: {}",
                            table_name,
                            e
                        );
                        return Err(e);
                    }
                }

                tracing::info!(
                    "Drop and recreate complete for table {} ({} rows)",
                    table_name,
                    row_count
                );
            }
        }

        // Recreate indices after all tables are reconstructed
        tracing::info!("Recreating indices after drop/recreate...");
        self.create_scalar_indices().await?;

        // Recreate FTS indices for lore table if it has data
        if table_names.iter().any(|n| n == "lore") {
            tracing::info!("Recreating FTS indices for lore table...");
            if let Err(e) = self.create_lore_fts_indices().await {
                tracing::warn!("Failed to create lore FTS indices: {}", e);
            }
        }

        tracing::info!("Drop and recreate operation complete - maximum space reclaimed!");
        Ok(())
    }

    /// Export all data from a table to memory
    async fn export_table_data(&self, table_name: &str) -> Result<Vec<RecordBatch>> {
        let table = self.connection.open_table(table_name).execute().await?;

        // Query all data
        let stream = table.query().execute().await?;

        // Collect all batches
        let batches = stream.try_collect::<Vec<_>>().await?;
        Ok(batches)
    }

    /// Import data back into a table
    async fn import_table_data(&self, table_name: &str, batches: Vec<RecordBatch>) -> Result<()> {
        if batches.is_empty() {
            return Ok(());
        }

        let table = self.connection.open_table(table_name).execute().await?;

        // Create a RecordBatchIterator from the batches
        if let Some(first_batch) = batches.first() {
            let schema = first_batch.schema();
            let batch_results: Vec<Result<RecordBatch, ArrowError>> =
                batches.into_iter().map(Ok).collect();
            let batch_iterator = RecordBatchIterator::new(batch_results.into_iter(), schema);

            // Add all batches at once using the iterator
            table.add(batch_iterator).execute().await?;
        }

        Ok(())
    }

    /// Create a specific table by name
    async fn create_table_by_name(&self, table_name: &str) -> Result<()> {
        match table_name {
            "functions" => self.create_functions_table().await,
            "types" => self.create_types_table().await,
            "vectors" => self.create_vectors_table().await,
            "commit_vectors" => self.create_commit_vectors_table().await,
            "lore_vectors" => self.create_lore_vectors_table().await,
            "processed_files" => self.create_processed_files_table().await,
            "symbol_filename" => self.create_symbol_filename_table().await,
            "git_commits" => self.create_git_commits_table().await,
            "lore" => self.create_lore_table().await,
            "lore_indexed_commits" => self.create_lore_indexed_commits_table().await,
            "indexed_branches" => self.create_indexed_branches_table().await,
            "content" => self.create_content_table().await,
            name if name.starts_with("content_") => {
                // Handle content shard tables
                self.create_single_content_shard_table(name).await
            }
            _ => Err(anyhow::anyhow!("Unknown table name: {}", table_name)),
        }
    }

    /// Create a single content shard table
    async fn create_single_content_shard_table(&self, table_name: &str) -> Result<()> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("blake3_hash", DataType::Utf8, false), // Blake3 hash of content as hex string
            Field::new("content", DataType::Utf8, false), // The actual content (function body, etc.)
        ]));

        let empty_batch = RecordBatch::new_empty(schema.clone());
        let batches = vec![Ok(empty_batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);

        self.connection
            .create_table(table_name, batch_iterator)
            .execute()
            .await?;

        Ok(())
    }

    /// Drop and recreate a specific table
    pub async fn drop_and_recreate_table(&self, table_name: &str) -> Result<()> {
        tracing::info!("Drop and recreate for single table: {}", table_name);

        let table_names = self.connection.table_names().execute().await?;

        if !table_names.iter().any(|n| n == table_name) {
            return Err(anyhow::anyhow!("Table {} does not exist", table_name));
        }

        // Step 1: Export all data
        let exported_data = self.export_table_data(table_name).await?;
        let row_count = exported_data.len();
        tracing::info!("Exported {} rows from table {}", row_count, table_name);

        if row_count == 0 {
            tracing::info!("Table {} is empty, skipping drop/recreate", table_name);
            return Ok(());
        }

        // Step 2: Drop table
        self.connection.drop_table(table_name, &[]).await?;
        tracing::info!("Dropped table {}", table_name);

        // Step 3: Recreate table
        if table_name == "vectors" {
            // Always create vectors table with 256 dimensions
            tracing::info!("Recreating vectors table with 256 dimensions");
            self.create_vectors_table().await?;
            tracing::info!("Recreated vectors table");
        } else if table_name == "commit_vectors" {
            // Always create commit_vectors table with 256 dimensions
            tracing::info!("Recreating commit_vectors table with 256 dimensions");
            self.create_commit_vectors_table().await?;
            tracing::info!("Recreated commit_vectors table");
        } else if table_name == "lore_vectors" {
            // Always create lore_vectors table with 256 dimensions
            tracing::info!("Recreating lore_vectors table with 256 dimensions");
            self.create_lore_vectors_table().await?;
            tracing::info!("Recreated lore_vectors table");
        } else {
            // Normal table recreation
            self.create_table_by_name(table_name).await?;
            tracing::info!("Recreated table {}", table_name);
        }

        // Step 4: Import data
        self.import_table_data(table_name, exported_data).await?;
        tracing::info!("Imported {} rows back to table {}", row_count, table_name);

        // Step 5: Recreate indices for this table
        self.create_scalar_indices().await?;

        // Step 6: Recreate FTS indices for lore table if applicable
        if table_name == "lore" {
            tracing::info!("Recreating FTS indices for lore table...");
            if let Err(e) = self.create_lore_fts_indices().await {
                tracing::warn!("Failed to create lore FTS indices: {}", e);
            }
        }

        tracing::info!("Drop and recreate complete for table {}", table_name);
        Ok(())
    }
}
