// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Normalized call edges: one row per (caller, callee) pair parsed from a
// function's calls, so reverse lookup is an indexed equality on `callee`
// instead of a full-column LIKE scan over serialized calls JSON.
//
// The functions.calls JSON stays the source of truth for forward reads;
// this table is a derived acceleration structure holding the same facts.
// Every row carries the caller's file hash so readers apply the same
// manifest check the LIKE path applies, and stale rows from older file
// versions stay invisible. Lifecycle follows the functions table: edges
// are deleted per file and rewritten whenever that file's functions are
// inserted, so a removed call's row cannot outlive its function row.
use anyhow::Result;
use arrow::array::{Array, ArrayRef, Int64Builder, RecordBatch, StringArray, StringBuilder};
use futures::TryStreamExt;
use lancedb::connection::Connection;
use lancedb::query::{ExecutableQuery, QueryBase};
use std::sync::Arc;

use crate::database::get_column;
use crate::types::{CallEdge, FunctionInfo};

pub struct CallEdgeStore {
    connection: Connection,
}

/// One normalized edge row, ready to insert.
pub struct StoredEdge {
    pub caller_name: String,
    pub caller_file: String,
    pub caller_line: i64,
    pub caller_file_hash: String,
    pub callee: String,
    pub owner: Option<String>,
    pub kind: &'static str,
}

/// One function's parsed calls, borrowed for edge extraction without
/// moving the function itself.
pub struct EdgeSource<'a> {
    pub name: &'a str,
    pub file: &'a str,
    pub line: u32,
    pub hash: &'a str,
    pub calls: Option<Vec<CallEdge>>,
}

impl CallEdgeStore {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    /// Edge rows for a batch of functions: one per parsed call edge,
    /// deduplicated on the full tuple (a function row contributes at most
    /// one entry per distinct edge, mirroring the `.any()` check the LIKE
    /// path applies per row).
    pub fn edges_for(functions: &[FunctionInfo]) -> Vec<StoredEdge> {
        let sources: Vec<EdgeSource> = functions
            .iter()
            .map(|func| EdgeSource {
                name: &func.name,
                file: &func.file_path,
                line: func.line_start,
                hash: &func.git_file_hash,
                calls: func.calls.clone(),
            })
            .collect();
        Self::edges_for_sources(&sources)
    }

    fn edges_for_sources(sources: &[EdgeSource]) -> Vec<StoredEdge> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for src in sources {
            let Some(calls) = src.calls.as_ref() else {
                continue;
            };
            for edge in calls {
                let (callee, owner, kind) = match edge {
                    CallEdge::Plain(callee) => (callee.clone(), None, "plain"),
                    CallEdge::Tagged { call, owner } => {
                        (call.clone(), Some(owner.clone()), "tagged")
                    }
                };
                let key = (
                    src.name.to_string(),
                    src.file.to_string(),
                    src.line,
                    src.hash.to_string(),
                    callee.clone(),
                    owner.clone(),
                    kind,
                );
                if seen.insert(key) {
                    out.push(StoredEdge {
                        caller_name: src.name.to_string(),
                        caller_file: src.file.to_string(),
                        caller_line: src.line as i64,
                        caller_file_hash: src.hash.to_string(),
                        callee,
                        owner,
                        kind,
                    });
                }
            }
        }
        out
    }

    /// Exact lifecycle: drop every edge credited to these files, then write
    /// the fresh set. A removed call's row cannot survive its file's
    /// re-index, and unchanged files are never touched.
    pub async fn sync_for_files(&self, files: &[String], edges: Vec<StoredEdge>) -> Result<()> {
        let table = self.connection.open_table("call_edges").execute().await?;
        if !files.is_empty() {
            let list: Vec<String> = files
                .iter()
                .map(|f| format!("'{}'", f.replace('\'', "''")))
                .collect();
            // File paths come from the index itself, not user input.
            table
                .delete(&format!("caller_file IN ({})", list.join(", ")))
                .await?;
        }
        if edges.is_empty() {
            return Ok(());
        }
        let mut caller_name = StringBuilder::new();
        let mut caller_file = StringBuilder::new();
        let mut caller_line = Int64Builder::new();
        let mut caller_file_hash = StringBuilder::new();
        let mut callee = StringBuilder::new();
        let mut owner = StringBuilder::new();
        let mut kind = StringBuilder::new();
        for edge in &edges {
            caller_name.append_value(&edge.caller_name);
            caller_file.append_value(&edge.caller_file);
            caller_line.append_value(edge.caller_line);
            caller_file_hash.append_value(&edge.caller_file_hash);
            callee.append_value(&edge.callee);
            owner.append_value(edge.owner.as_deref().unwrap_or(""));
            kind.append_value(edge.kind);
        }
        let batch = RecordBatch::try_from_iter(vec![
            ("caller_name", Arc::new(caller_name.finish()) as ArrayRef),
            ("caller_file", Arc::new(caller_file.finish()) as ArrayRef),
            ("caller_line", Arc::new(caller_line.finish()) as ArrayRef),
            (
                "caller_file_hash",
                Arc::new(caller_file_hash.finish()) as ArrayRef,
            ),
            ("callee", Arc::new(callee.finish()) as ArrayRef),
            ("owner", Arc::new(owner.finish()) as ArrayRef),
            ("kind", Arc::new(kind.finish()) as ArrayRef),
        ])?;
        table.add(vec![batch]).execute().await?;
        Ok(())
    }

    /// One-shot migration for indexes written before this table existed:
    /// rebuild every edge from the functions rows. The caller runs it only
    /// when the table is empty but functions are present, so a fresh index
    /// that already writes edges inline never pays it.
    pub async fn backfill_from_functions(&self) -> Result<usize> {
        let table = self.connection.open_table("functions").execute().await?;
        let batches = table
            .query()
            .only_if("calls IS NOT NULL")
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;
        let mut owned: Vec<(String, String, u32, String, Vec<CallEdge>)> = Vec::new();
        for batch in &batches {
            if batch.num_rows() == 0 {
                continue;
            }
            let name_col: &StringArray = get_column(batch, "name")?;
            let file_col: &StringArray = get_column(batch, "file_path")?;
            let line_col: &arrow::array::Int64Array = get_column(batch, "line_start")?;
            let hash_col: &StringArray = get_column(batch, "git_file_hash")?;
            let calls_col: &StringArray = get_column(batch, "calls")?;
            for i in 0..batch.num_rows() {
                if calls_col.is_null(i) {
                    continue;
                }
                let edges = crate::database::parse_call_edges(calls_col.value(i))?;
                owned.push((
                    name_col.value(i).to_string(),
                    file_col.value(i).to_string(),
                    line_col.value(i) as u32,
                    hash_col.value(i).to_string(),
                    edges,
                ));
            }
        }
        let sources: Vec<EdgeSource> = owned
            .iter()
            .map(|(name, file, line, hash, calls)| EdgeSource {
                name,
                file,
                line: *line,
                hash,
                calls: Some(calls.clone()),
            })
            .collect();
        let mut files: Vec<String> = sources.iter().map(|s| s.file.to_string()).collect();
        files.sort();
        files.dedup();
        let edges = Self::edges_for_sources(&sources);
        let n = edges.len();
        self.sync_for_files(&files, edges).await?;
        Ok(n)
    }

    /// Rows naming any of these callees: the indexed candidate set for one
    /// reverse lookup. The caller applies the exact match rule and the
    /// manifest check; this only bounds the scan to matching rows.
    /// Returns (caller_name, caller_file, caller_file_hash, callee, owner, kind).
    pub async fn rows_for_callees(
        &self,
        callees: &[String],
    ) -> Result<Vec<(String, String, String, String, String, String)>> {
        let table = self.connection.open_table("call_edges").execute().await?;
        let list: Vec<String> = callees
            .iter()
            .map(|c| format!("'{}'", c.replace('\'', "''")))
            .collect();
        let batches = table
            .query()
            .only_if(format!("callee IN ({})", list.join(", ")))
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;
        let mut out = Vec::new();
        for batch in batches {
            if batch.num_rows() == 0 {
                continue;
            }
            let col = |name: &str| -> Result<&StringArray> { get_column(&batch, name) };
            let caller_name = col("caller_name")?;
            let caller_file = col("caller_file")?;
            let caller_file_hash = col("caller_file_hash")?;
            let callee_col = col("callee")?;
            let owner = col("owner")?;
            let kind = col("kind")?;
            for i in 0..batch.num_rows() {
                out.push((
                    caller_name.value(i).to_string(),
                    caller_file.value(i).to_string(),
                    caller_file_hash.value(i).to_string(),
                    callee_col.value(i).to_string(),
                    owner.value(i).to_string(),
                    kind.value(i).to_string(),
                ));
            }
        }
        Ok(out)
    }
}
