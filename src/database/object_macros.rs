// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Object-like macros, kept with what they expand to.
//
// A declaration cannot be read without them: `struct { ... } __packed;` and
// `struct { ... } lru_gen;` are the same shape to the grammar, and only the
// expansion says that the first names no member. The expansion lives in
// another file, so the question is asked of the whole set at once, here.
use anyhow::Result;
use arrow::array::{Array, ArrayRef, RecordBatch, RecordBatchIterator, StringArray, StringBuilder};
use futures::TryStreamExt;
use lancedb::connection::Connection;
use lancedb::query::ExecutableQuery;
use std::collections::HashMap;
use std::sync::Arc;

pub struct ObjectMacroStore {
    connection: Connection,
}

/// A macro and what it stands for.
#[derive(Debug, Clone)]
pub struct ObjectMacro {
    pub name: String,
    pub expansion: String,
    pub file_path: String,
    pub git_file_hash: String,
    /// The preprocessor arm holding this definition, as the file writes it.
    /// Empty at file scope. Part of the merge key, so never null.
    pub guard: String,
}

impl ObjectMacroStore {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    pub async fn insert_batch(&self, macros: Vec<ObjectMacro>) -> Result<()> {
        if macros.is_empty() {
            return Ok(());
        }
        let macros = crate::database::one_row_per_key(macros, |row| {
            (
                row.name.clone(),
                row.file_path.clone(),
                row.git_file_hash.clone(),
                row.guard.clone(),
            )
        });

        let mut names = StringBuilder::new();
        let mut expansions = StringBuilder::new();
        let mut files = StringBuilder::new();
        let mut hashes = StringBuilder::new();
        let mut guards = StringBuilder::new();
        for entry in &macros {
            names.append_value(&entry.name);
            expansions.append_value(&entry.expansion);
            files.append_value(&entry.file_path);
            hashes.append_value(&entry.git_file_hash);
            guards.append_value(&entry.guard);
        }

        let batch = RecordBatch::try_from_iter(vec![
            ("name", Arc::new(names.finish()) as ArrayRef),
            ("expansion", Arc::new(expansions.finish()) as ArrayRef),
            ("file_path", Arc::new(files.finish()) as ArrayRef),
            ("git_file_hash", Arc::new(hashes.finish()) as ArrayRef),
            ("guard", Arc::new(guards.finish()) as ArrayRef),
        ])?;

        let table = self
            .connection
            .open_table("object_macros")
            .execute()
            .await?;
        // One row per definition: re-reading a file it already holds stores
        // the same row rather than a second copy.
        let mut merge_insert = table.merge_insert(&["name", "file_path", "git_file_hash", "guard"]);
        merge_insert
            .when_matched_update_all(None)
            .when_not_matched_insert_all();
        let schema = batch.schema();
        merge_insert
            .execute(Box::new(RecordBatchIterator::new(vec![Ok(batch)], schema)))
            .await?;

        Ok(())
    }

    /// Every macro, by name, with what it expands to.
    ///
    /// The whole table is read: the caller needs the closure over aliases, and
    /// the set is small — a Linux tree has some tens of thousands, against
    /// six million `#define`s that cannot lead to an attribute and are not
    /// stored.
    pub async fn all(&self) -> Result<HashMap<String, String>> {
        let table = match self.connection.open_table("object_macros").execute().await {
            Ok(table) => table,
            // An index written before this table existed. The version check
            // asks for a re-index; until then there is nothing to read, and
            // saying so is better than reading 159,455 bodies to find out.
            Err(_) => return Ok(HashMap::new()),
        };

        let batches: Vec<RecordBatch> = table.query().execute().await?.try_collect().await?;

        let mut macros = HashMap::new();
        for batch in &batches {
            let column = |i: usize| {
                batch
                    .column(i)
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .expect("string column")
            };
            let (names, expansions) = (column(0), column(1));
            for row in 0..batch.num_rows() {
                // A macro defined in several files under one name: the first
                // wins, and a disagreement between them is not a question a
                // declaration can answer anyway.
                macros
                    .entry(names.value(row).to_string())
                    .or_insert_with(|| expansions.value(row).to_string());
            }
        }

        Ok(macros)
    }
}
