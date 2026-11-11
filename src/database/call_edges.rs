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
// versions stay invisible. Lifecycle follows the functions table: a file
// version's edges are deleted and rewritten whenever that version's
// functions are inserted, so a removed call's row cannot outlive its
// function row. Rows of the same path at other versions stay, and the
// manifest check hides them from revisions that do not hold that version.
use anyhow::Result;
use arrow::array::{Array, ArrayRef, Int64Builder, RecordBatch, StringArray, StringBuilder};
use futures::TryStreamExt;
use lancedb::connection::Connection;
use lancedb::query::{ExecutableQuery, QueryBase};
use once_cell::sync::Lazy;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::database::get_column;
use crate::types::{CallEdge, FunctionInfo};

/// Process-global lock serializing every write to `call_edges`.
///
/// Inserters write the table concurrently. Two deletes on it conflict and
/// retry, and a delete racing an append of the same file version can leave
/// that version's rows twice. Process-global because several
/// `CallEdgeStore` instances share one database, so a per-instance lock
/// would not serialize them.
static CALL_EDGE_WRITE_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

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

    /// The (caller_file, caller_file_hash) pairs a batch of functions
    /// covers, sorted and deduplicated: the file versions whose edges
    /// [`Self::sync_for_versions`] replaces.
    pub fn versions_of(functions: &[FunctionInfo]) -> Vec<(String, String)> {
        let mut versions: Vec<(String, String)> = functions
            .iter()
            .map(|func| (func.file_path.clone(), func.git_file_hash.clone()))
            .collect();
        versions.sort();
        versions.dedup();
        versions
    }

    /// Exact lifecycle per file version: drop every edge credited to these
    /// (caller_file, caller_file_hash) pairs, then write the fresh set. A
    /// removed call's row cannot survive its version's re-index, and the
    /// same path's rows at other versions are never touched.
    pub async fn sync_for_versions(
        &self,
        versions: &[(String, String)],
        edges: Vec<StoredEdge>,
    ) -> Result<()> {
        let _write_guard = CALL_EDGE_WRITE_LOCK.lock().await;
        let table = self.connection.open_table("call_edges").execute().await?;
        if !versions.is_empty() {
            // One IN list over a `hash:path` key: a single hash-set probe
            // per row, where an OR of per-version comparisons costs one
            // comparison per version per row. The key is exact because the
            // hash comes first and a git blob id holds no `:`, so the first
            // `:` splits every key the same way whatever the path holds.
            // File paths and hashes come from the index itself, not user
            // input.
            let keys: Vec<String> = versions
                .iter()
                .map(|(file, hash)| {
                    format!(
                        "'{}:{}'",
                        hash.replace('\'', "''"),
                        file.replace('\'', "''")
                    )
                })
                .collect();
            table
                .delete(&format!(
                    "concat(caller_file_hash, ':', caller_file) IN ({})",
                    keys.join(", ")
                ))
                .await?;
        }
        Self::append_edges(&table, edges).await
    }

    /// Append edge rows. The caller holds [`CALL_EDGE_WRITE_LOCK`].
    async fn append_edges(table: &lancedb::Table, edges: Vec<StoredEdge>) -> Result<()> {
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
        let edges = Self::edges_for_sources(&sources);
        let n = edges.len();
        // The table is empty, so there is nothing to delete first.
        let _write_guard = CALL_EDGE_WRITE_LOCK.lock().await;
        let edges_table = self.connection.open_table("call_edges").execute().await?;
        Self::append_edges(&edges_table, edges).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use lancedb::connection::LanceFileVersion;
    use lancedb::database::listing::ListingDatabaseOptions;

    async fn fresh_store() -> (tempfile::TempDir, CallEdgeStore) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("call-edges.lancedb");
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
        (dir, CallEdgeStore::new(connection))
    }

    /// One plain edge from `caller` in `file` at blob `hash` to `callee`.
    fn edge(file: &str, hash: &str, caller: &str, callee: &str) -> StoredEdge {
        StoredEdge {
            caller_name: caller.to_string(),
            caller_file: file.to_string(),
            caller_line: 1,
            caller_file_hash: hash.to_string(),
            callee: callee.to_string(),
            owner: None,
            kind: "plain",
        }
    }

    fn version(file: &str, hash: &str) -> (String, String) {
        (file.to_string(), hash.to_string())
    }

    /// Every row as (caller_file, caller_file_hash, caller_name, callee),
    /// sorted, duplicates kept.
    async fn all_rows(store: &CallEdgeStore) -> Vec<(String, String, String, String)> {
        let table = store
            .connection
            .open_table("call_edges")
            .execute()
            .await
            .unwrap();
        let batches = table
            .query()
            .execute()
            .await
            .unwrap()
            .try_collect::<Vec<_>>()
            .await
            .unwrap();
        let mut rows = Vec::new();
        for batch in &batches {
            let col = |name: &str| -> &StringArray { get_column(batch, name).unwrap() };
            let (file, hash, caller, callee) = (
                col("caller_file"),
                col("caller_file_hash"),
                col("caller_name"),
                col("callee"),
            );
            for i in 0..batch.num_rows() {
                rows.push((
                    file.value(i).to_string(),
                    hash.value(i).to_string(),
                    caller.value(i).to_string(),
                    callee.value(i).to_string(),
                ));
            }
        }
        rows.sort();
        rows
    }

    fn row(file: &str, hash: &str, caller: &str, callee: &str) -> (String, String, String, String) {
        (
            file.to_string(),
            hash.to_string(),
            caller.to_string(),
            callee.to_string(),
        )
    }

    #[tokio::test]
    async fn syncing_a_second_version_keeps_the_first() {
        let (_dir, store) = fresh_store().await;
        store
            .sync_for_versions(&[version("a.c", "h1")], vec![edge("a.c", "h1", "f", "g")])
            .await
            .unwrap();
        store
            .sync_for_versions(
                &[version("a.c", "h2")],
                vec![edge("a.c", "h2", "f", "g"), edge("a.c", "h2", "f", "h")],
            )
            .await
            .unwrap();

        assert_eq!(
            all_rows(&store).await,
            [
                row("a.c", "h1", "f", "g"),
                row("a.c", "h2", "f", "g"),
                row("a.c", "h2", "f", "h"),
            ]
        );
    }

    #[tokio::test]
    async fn resyncing_a_version_replaces_its_edges() {
        let (_dir, store) = fresh_store().await;
        store
            .sync_for_versions(
                &[version("a.c", "h1"), version("a.c", "h2")],
                vec![
                    edge("a.c", "h1", "f", "g"),
                    edge("a.c", "h1", "f", "h"),
                    edge("a.c", "h2", "f", "g"),
                ],
            )
            .await
            .unwrap();
        // h1 again, without its call to h.
        store
            .sync_for_versions(&[version("a.c", "h1")], vec![edge("a.c", "h1", "f", "g")])
            .await
            .unwrap();

        assert_eq!(
            all_rows(&store).await,
            [row("a.c", "h1", "f", "g"), row("a.c", "h2", "f", "g")]
        );
    }

    #[tokio::test]
    async fn same_blob_at_another_path_is_left_alone() {
        let (_dir, store) = fresh_store().await;
        store
            .sync_for_versions(
                &[version("a.c", "same"), version("b.c", "same")],
                vec![edge("a.c", "same", "f", "g"), edge("b.c", "same", "f", "g")],
            )
            .await
            .unwrap();
        // a.c's version loses its edges; b.c holds the same blob and keeps
        // its own.
        store
            .sync_for_versions(&[version("a.c", "same")], Vec::new())
            .await
            .unwrap();

        assert_eq!(all_rows(&store).await, [row("b.c", "same", "f", "g")]);
    }

    #[tokio::test]
    async fn paths_and_hashes_with_quotes_are_matched_literally() {
        let (_dir, store) = fresh_store().await;
        store
            .sync_for_versions(
                &[version("it's.c", "h'1"), version("its.c", "h1")],
                vec![
                    edge("it's.c", "h'1", "f", "g"),
                    edge("its.c", "h1", "f", "g"),
                ],
            )
            .await
            .unwrap();
        store
            .sync_for_versions(&[version("it's.c", "h'1")], Vec::new())
            .await
            .unwrap();

        assert_eq!(all_rows(&store).await, [row("its.c", "h1", "f", "g")]);
    }

    /// A `:` in a path cannot make one version's key match another's,
    /// because the hash before the first `:` holds none.
    #[tokio::test]
    async fn colons_in_paths_match_only_their_own_version() {
        let (_dir, store) = fresh_store().await;
        store
            .sync_for_versions(
                &[
                    version("a.c", "h1"),
                    version("dir:a.c", "h1"),
                    version("a.c:x", "h1"),
                ],
                vec![
                    edge("a.c", "h1", "f", "g"),
                    edge("dir:a.c", "h1", "f", "g"),
                    edge("a.c:x", "h1", "f", "g"),
                ],
            )
            .await
            .unwrap();
        store
            .sync_for_versions(&[version("dir:a.c", "h1")], Vec::new())
            .await
            .unwrap();

        assert_eq!(
            all_rows(&store).await,
            [row("a.c", "h1", "f", "g"), row("a.c:x", "h1", "f", "g")]
        );
    }

    #[tokio::test]
    async fn a_large_batch_of_versions_is_replaced_in_one_sync() {
        let (_dir, store) = fresh_store().await;
        // Past a `--git` batch's 512 files.
        let count = 1025;
        let versions: Vec<(String, String)> = (0..count)
            .map(|i| version(&format!("f{i:04}.c"), "h1"))
            .collect();
        let edges_to = |callee: &str| -> Vec<StoredEdge> {
            versions
                .iter()
                .map(|(file, hash)| edge(file, hash, "f", callee))
                .collect()
        };
        store
            .sync_for_versions(&versions, edges_to("old"))
            .await
            .unwrap();
        store
            .sync_for_versions(&versions, edges_to("new"))
            .await
            .unwrap();

        let rows = all_rows(&store).await;
        assert_eq!(rows.len(), count);
        assert!(rows.iter().all(|(_, _, _, callee)| callee == "new"));
    }

    #[test]
    fn versions_of_is_sorted_and_deduplicated() {
        let function = |file: &str, hash: &str, name: &str| FunctionInfo {
            name: name.to_string(),
            file_path: file.to_string(),
            git_file_hash: hash.to_string(),
            line_start: 1,
            line_end: 3,
            return_type: "int".to_string(),
            parameters: Vec::new(),
            body: String::new(),
            calls: None,
            types: None,
            guard: None,
            qualifier: None,
        };
        let versions = CallEdgeStore::versions_of(&[
            function("b.c", "h1", "x"),
            function("a.c", "h2", "y"),
            function("b.c", "h1", "z"),
            function("a.c", "h1", "w"),
        ]);
        assert_eq!(
            versions,
            [
                version("a.c", "h1"),
                version("a.c", "h2"),
                version("b.c", "h1")
            ]
        );
    }

    /// Two inserters syncing different versions of one path at once must
    /// leave both versions' rows, each exactly once. Fresh versions every
    /// round so one lucky interleaving cannot hide a lost or doubled row.
    #[tokio::test]
    async fn concurrent_syncs_of_different_versions_keep_every_row_once() {
        const ROUNDS: usize = 20;
        let (_dir, store) = fresh_store().await;
        let mut expected = Vec::new();
        for round in 0..ROUNDS {
            let (h1, h2) = (format!("r{round}a"), format!("r{round}b"));
            let edges = |hash: &str| vec![edge("a.c", hash, "f", "g"), edge("a.c", hash, "f", "h")];
            for hash in [&h1, &h2] {
                expected.push(row("a.c", hash, "f", "g"));
                expected.push(row("a.c", hash, "f", "h"));
            }
            let (v1, v2) = ([version("a.c", &h1)], [version("a.c", &h2)]);
            let (first, second) = tokio::join!(
                store.sync_for_versions(&v1, edges(&h1)),
                store.sync_for_versions(&v2, edges(&h2)),
            );
            first.unwrap();
            second.unwrap();
        }
        expected.sort();
        assert_eq!(all_rows(&store).await, expected);
    }

    /// Two syncs of the same version at once must leave its rows once.
    /// Indexing sends each blob once per run, so this holds the store to
    /// its own contract rather than relying on that: without the write
    /// lock both deletes run before either append and both appends land.
    #[tokio::test]
    async fn concurrent_syncs_of_one_version_leave_no_duplicates() {
        const ROUNDS: usize = 20;
        let (_dir, store) = fresh_store().await;
        let mut expected = Vec::new();
        for round in 0..ROUNDS {
            let hash = format!("r{round}");
            let edges = || vec![edge("a.c", &hash, "f", "g")];
            expected.push(row("a.c", &hash, "f", "g"));
            let versions = [version("a.c", &hash)];
            let (first, second) = tokio::join!(
                store.sync_for_versions(&versions, edges()),
                store.sync_for_versions(&versions, edges()),
            );
            first.unwrap();
            second.unwrap();
        }
        expected.sort();
        assert_eq!(all_rows(&store).await, expected);
    }
}
