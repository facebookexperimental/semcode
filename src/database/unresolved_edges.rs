// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Storage for edges the index cannot record. A row says what is known, what
// mechanism blocks the edge, and where to look for the other side; a consumer
// that has to derive the location itself will derive it differently.
use anyhow::Result;
use arrow::array::StringBuilder;
use arrow::array::{ArrayRef, Int64Builder, RecordBatch, RecordBatchIterator, StringArray};
use futures::TryStreamExt;
use lancedb::connection::Connection;
use lancedb::query::{ExecutableQuery, QueryBase};
use std::sync::Arc;

use crate::database::get_column;
use crate::types::{EdgeLocation, UnresolvedEdge};

pub struct UnresolvedEdgeStore {
    connection: Connection,
}

impl UnresolvedEdgeStore {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    pub async fn insert_batch(&self, edges: Vec<UnresolvedEdge>) -> Result<()> {
        if edges.is_empty() {
            return Ok(());
        }
        // A batch spanning commits holds the same file at the same hash twice,
        // and merge_insert refuses a batch with two source rows for one target.
        // The store keeps one row per kind at a place in a file.
        let edges = crate::database::one_row_per_key(edges, |row| {
            (
                row.file_path.clone(),
                row.git_file_hash.clone(),
                row.line,
                row.name.clone(),
                row.direction.clone(),
                row.kind.clone(),
            )
        });
        let table = self
            .connection
            .open_table("unresolved_edges")
            .execute()
            .await?;

        let mut name = StringBuilder::new();
        let mut direction = StringBuilder::new();
        let mut kind = StringBuilder::new();
        let mut evidence = StringBuilder::new();
        let mut locations = StringBuilder::new();
        let mut file_path = StringBuilder::new();
        let mut git_file_hash = StringBuilder::new();
        let mut line = Int64Builder::new();

        for edge in &edges {
            name.append_value(&edge.name);
            direction.append_value(&edge.direction);
            kind.append_value(&edge.kind);
            evidence.append_value(&edge.evidence);
            locations.append_value(serde_json::to_string(&edge.locations)?);
            file_path.append_value(&edge.file_path);
            git_file_hash.append_value(&edge.git_file_hash);
            line.append_value(edge.line as i64);
        }

        let batch = RecordBatch::try_from_iter(vec![
            ("name", Arc::new(name.finish()) as ArrayRef),
            ("direction", Arc::new(direction.finish()) as ArrayRef),
            ("kind", Arc::new(kind.finish()) as ArrayRef),
            ("evidence", Arc::new(evidence.finish()) as ArrayRef),
            ("locations", Arc::new(locations.finish()) as ArrayRef),
            ("file_path", Arc::new(file_path.finish()) as ArrayRef),
            (
                "git_file_hash",
                Arc::new(git_file_hash.finish()) as ArrayRef,
            ),
            ("line", Arc::new(line.finish()) as ArrayRef),
        ])?;

        // One row per unresolved edge at a place in a file, so re-indexing
        // unchanged content rewrites the row rather than adding a second.
        let mut merge_insert = table.merge_insert(&[
            "file_path",
            "git_file_hash",
            "line",
            "name",
            "direction",
            "kind",
        ]);
        merge_insert
            .when_matched_update_all(None)
            .when_not_matched_insert_all();
        let schema = batch.schema();
        merge_insert
            .execute(Box::new(RecordBatchIterator::new(vec![Ok(batch)], schema)))
            .await?;
        Ok(())
    }

    /// What is unresolved about this name, from either direction.
    pub async fn find_by_name(&self, name: &str) -> Result<Vec<UnresolvedEdge>> {
        let table = self
            .connection
            .open_table("unresolved_edges")
            .execute()
            .await?;
        let escaped = name.replace('\'', "''");
        let batches = table
            .query()
            .only_if(format!("name = '{escaped}'"))
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut out = Vec::new();
        for batch in &batches {
            let name = get_column::<StringArray>(batch, "name")?;
            let direction = get_column::<StringArray>(batch, "direction")?;
            let kind = get_column::<StringArray>(batch, "kind")?;
            let evidence = get_column::<StringArray>(batch, "evidence")?;
            let locations = get_column::<StringArray>(batch, "locations")?;
            let file_path = get_column::<StringArray>(batch, "file_path")?;
            let git_file_hash = get_column::<StringArray>(batch, "git_file_hash")?;
            let line = get_column::<arrow::array::Int64Array>(batch, "line")?;
            for row in 0..batch.num_rows() {
                out.push(UnresolvedEdge {
                    name: name.value(row).to_string(),
                    direction: direction.value(row).to_string(),
                    kind: kind.value(row).to_string(),
                    evidence: evidence.value(row).to_string(),
                    locations: serde_json::from_str::<Vec<EdgeLocation>>(locations.value(row))
                        .unwrap_or_default(),
                    file_path: file_path.value(row).to_string(),
                    git_file_hash: git_file_hash.value(row).to_string(),
                    line: line.value(row) as u32,
                });
            }
        }
        Ok(out)
    }
}
