// SPDX-License-Identifier: MIT OR Apache-2.0
//! Store for tracking indexed git branches.
//!
//! This module provides functionality to track which branches have been indexed,
//! their tip commits, and when they were last indexed. This enables efficient
//! multi-branch indexing by avoiding re-indexing branches that haven't changed.

use anyhow::Result;
use arrow::array::{Array, ArrayRef, Int64Array, RecordBatch, StringBuilder};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatchIterator;
use futures::TryStreamExt;
use lancedb::connection::Connection;
use lancedb::query::{ExecutableQuery, QueryBase};
use std::sync::Arc;

/// Information about an indexed branch
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedBranchInfo {
    /// Branch name (e.g., "main", "origin/develop")
    pub branch_name: String,
    /// The commit SHA at the tip of the branch when indexed
    pub tip_commit: String,
    /// Unix timestamp of when the branch was last indexed
    pub indexed_at: i64,
    /// Remote name if this is a remote-tracking branch (e.g., "origin")
    pub remote: Option<String>,
}

/// JSON-serializable version of IndexedBranchInfo
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IndexedBranchInfoJson {
    pub branch_name: String,
    pub tip_commit: String,
    pub indexed_at: i64,
    pub remote: Option<String>,
}

impl From<IndexedBranchInfo> for IndexedBranchInfoJson {
    fn from(info: IndexedBranchInfo) -> Self {
        IndexedBranchInfoJson {
            branch_name: info.branch_name,
            tip_commit: info.tip_commit,
            indexed_at: info.indexed_at,
            remote: info.remote,
        }
    }
}

impl From<IndexedBranchInfoJson> for IndexedBranchInfo {
    fn from(json: IndexedBranchInfoJson) -> Self {
        IndexedBranchInfo {
            branch_name: json.branch_name,
            tip_commit: json.tip_commit,
            indexed_at: json.indexed_at,
            remote: json.remote,
        }
    }
}

/// Store for managing indexed branch records
pub struct IndexedBranchStore {
    connection: Connection,
}

impl IndexedBranchStore {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    /// Get the Arrow schema for the indexed_branches table
    pub fn get_schema() -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            Field::new("branch_name", DataType::Utf8, false),
            Field::new("tip_commit", DataType::Utf8, false),
            Field::new("indexed_at", DataType::Int64, false),
            Field::new("remote", DataType::Utf8, true),
        ]))
    }

    /// Record that a branch has been indexed at a specific commit
    pub async fn record_branch_indexed(&self, info: &IndexedBranchInfo) -> Result<()> {
        // First, remove any existing record for this branch
        self.remove_branch(&info.branch_name).await?;

        let table = self
            .connection
            .open_table("indexed_branches")
            .execute()
            .await?;

        // Build arrays for each column
        let mut branch_name_builder = StringBuilder::new();
        let mut tip_commit_builder = StringBuilder::new();
        let mut indexed_at_builder = arrow::array::Int64Builder::new();
        let mut remote_builder = StringBuilder::new();

        branch_name_builder.append_value(&info.branch_name);
        tip_commit_builder.append_value(&info.tip_commit);
        indexed_at_builder.append_value(info.indexed_at);
        match &info.remote {
            Some(r) => remote_builder.append_value(r),
            None => remote_builder.append_null(),
        }

        let schema = Self::get_schema();

        let batch = RecordBatch::try_from_iter(vec![
            (
                "branch_name",
                Arc::new(branch_name_builder.finish()) as ArrayRef,
            ),
            (
                "tip_commit",
                Arc::new(tip_commit_builder.finish()) as ArrayRef,
            ),
            (
                "indexed_at",
                Arc::new(indexed_at_builder.finish()) as ArrayRef,
            ),
            ("remote", Arc::new(remote_builder.finish()) as ArrayRef),
        ])?;

        let batches = vec![Ok(batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);
        table.add(batch_iterator).execute().await?;

        Ok(())
    }

    /// Get the tip commit for a specific branch
    pub async fn get_branch_tip(&self, branch_name: &str) -> Result<Option<String>> {
        let info = self.get_branch_info(branch_name).await?;
        Ok(info.map(|i| i.tip_commit))
    }

    /// Get full information about a specific branch
    pub async fn get_branch_info(&self, branch_name: &str) -> Result<Option<IndexedBranchInfo>> {
        let table = self
            .connection
            .open_table("indexed_branches")
            .execute()
            .await?;

        let escaped_name = branch_name.replace("'", "''");
        let filter = format!("branch_name = '{escaped_name}'");

        let results = table
            .query()
            .only_if(filter)
            .limit(1)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        if results.is_empty() || results[0].num_rows() == 0 {
            return Ok(None);
        }

        self.extract_record_from_batch(&results[0], 0)
    }

    /// List all indexed branches
    pub async fn list_indexed_branches(&self) -> Result<Vec<IndexedBranchInfo>> {
        let table = self
            .connection
            .open_table("indexed_branches")
            .execute()
            .await?;

        let results = table
            .query()
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut branches = Vec::new();
        for batch in &results {
            for i in 0..batch.num_rows() {
                if let Some(info) = self.extract_record_from_batch(batch, i)? {
                    branches.push(info);
                }
            }
        }

        // Sort by branch name for consistent output
        branches.sort_by(|a, b| a.branch_name.cmp(&b.branch_name));

        Ok(branches)
    }

    /// Check if a branch is indexed at the current tip commit
    pub async fn is_branch_current(&self, branch_name: &str, current_tip: &str) -> Result<bool> {
        if let Some(info) = self.get_branch_info(branch_name).await? {
            Ok(info.tip_commit == current_tip)
        } else {
            Ok(false)
        }
    }

    /// Remove a branch record (used when branch is deleted or before updating)
    pub async fn remove_branch(&self, branch_name: &str) -> Result<()> {
        let table = self
            .connection
            .open_table("indexed_branches")
            .execute()
            .await?;

        let escaped_name = branch_name.replace("'", "''");
        let filter = format!("branch_name = '{escaped_name}'");

        table.delete(&filter).await?;
        Ok(())
    }

    /// Remove all branches that match a remote prefix (e.g., "origin/")
    pub async fn remove_branches_by_remote(&self, remote: &str) -> Result<usize> {
        let branches = self.list_indexed_branches().await?;
        let mut removed = 0;

        for branch in branches {
            if branch.remote.as_deref() == Some(remote) {
                self.remove_branch(&branch.branch_name).await?;
                removed += 1;
            }
        }

        Ok(removed)
    }

    /// Get all branches that point to a specific commit
    pub async fn get_branches_at_commit(&self, commit_sha: &str) -> Result<Vec<IndexedBranchInfo>> {
        let table = self
            .connection
            .open_table("indexed_branches")
            .execute()
            .await?;

        let escaped_sha = commit_sha.replace("'", "''");
        let filter = format!("tip_commit = '{escaped_sha}'");

        let results = table
            .query()
            .only_if(filter)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut branches = Vec::new();
        for batch in &results {
            for i in 0..batch.num_rows() {
                if let Some(info) = self.extract_record_from_batch(batch, i)? {
                    branches.push(info);
                }
            }
        }

        Ok(branches)
    }

    /// Get total count of indexed branches
    pub async fn count(&self) -> Result<usize> {
        let table = self
            .connection
            .open_table("indexed_branches")
            .execute()
            .await?;
        Ok(table.count_rows(None).await?)
    }

    /// Extract an IndexedBranchInfo from a batch at the given row index
    fn extract_record_from_batch(
        &self,
        batch: &RecordBatch,
        row: usize,
    ) -> Result<Option<IndexedBranchInfo>> {
        let branch_name_array = batch
            .column_by_name("branch_name")
            .ok_or_else(|| anyhow::anyhow!("Missing branch_name column"))?
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .ok_or_else(|| anyhow::anyhow!("Invalid branch_name column type"))?;

        let tip_commit_array = batch
            .column_by_name("tip_commit")
            .ok_or_else(|| anyhow::anyhow!("Missing tip_commit column"))?
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .ok_or_else(|| anyhow::anyhow!("Invalid tip_commit column type"))?;

        let indexed_at_array = batch
            .column_by_name("indexed_at")
            .ok_or_else(|| anyhow::anyhow!("Missing indexed_at column"))?
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or_else(|| anyhow::anyhow!("Invalid indexed_at column type"))?;

        let remote_array = batch
            .column_by_name("remote")
            .ok_or_else(|| anyhow::anyhow!("Missing remote column"))?
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .ok_or_else(|| anyhow::anyhow!("Invalid remote column type"))?;

        let branch_name = branch_name_array.value(row).to_string();
        let tip_commit = tip_commit_array.value(row).to_string();
        let indexed_at = indexed_at_array.value(row);
        let remote = if remote_array.is_null(row) {
            None
        } else {
            Some(remote_array.value(row).to_string())
        };

        Ok(Some(IndexedBranchInfo {
            branch_name,
            tip_commit,
            indexed_at,
            remote,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_store() -> (TempDir, IndexedBranchStore) {
        let tmpdir = TempDir::new().unwrap();
        let db_path = tmpdir.path().to_str().unwrap();
        let connection = lancedb::connect(db_path).execute().await.unwrap();

        // Create the table
        let schema = IndexedBranchStore::get_schema();
        let empty_batch = RecordBatch::new_empty(schema.clone());
        let batches = vec![Ok(empty_batch)];
        let batch_iterator = RecordBatchIterator::new(batches.into_iter(), schema);
        connection
            .create_table("indexed_branches", batch_iterator)
            .execute()
            .await
            .unwrap();

        let store = IndexedBranchStore::new(connection);
        (tmpdir, store)
    }

    #[tokio::test]
    async fn test_record_and_get_branch() {
        let (_tmpdir, store) = create_test_store().await;

        let info = IndexedBranchInfo {
            branch_name: "main".to_string(),
            tip_commit: "abc123def456".to_string(),
            indexed_at: 1699900000,
            remote: None,
        };

        store.record_branch_indexed(&info).await.unwrap();

        let retrieved = store.get_branch_info("main").await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.branch_name, "main");
        assert_eq!(retrieved.tip_commit, "abc123def456");
        assert_eq!(retrieved.indexed_at, 1699900000);
        assert!(retrieved.remote.is_none());
    }

    #[tokio::test]
    async fn test_record_remote_branch() {
        let (_tmpdir, store) = create_test_store().await;

        let info = IndexedBranchInfo {
            branch_name: "origin/develop".to_string(),
            tip_commit: "789abc123".to_string(),
            indexed_at: 1699900100,
            remote: Some("origin".to_string()),
        };

        store.record_branch_indexed(&info).await.unwrap();

        let retrieved = store.get_branch_info("origin/develop").await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.remote, Some("origin".to_string()));
    }

    #[tokio::test]
    async fn test_update_branch() {
        let (_tmpdir, store) = create_test_store().await;

        // Record initial version
        let info1 = IndexedBranchInfo {
            branch_name: "main".to_string(),
            tip_commit: "commit1".to_string(),
            indexed_at: 1699900000,
            remote: None,
        };
        store.record_branch_indexed(&info1).await.unwrap();

        // Update with new commit
        let info2 = IndexedBranchInfo {
            branch_name: "main".to_string(),
            tip_commit: "commit2".to_string(),
            indexed_at: 1699900100,
            remote: None,
        };
        store.record_branch_indexed(&info2).await.unwrap();

        // Should have only one record with the new commit
        let retrieved = store.get_branch_info("main").await.unwrap().unwrap();
        assert_eq!(retrieved.tip_commit, "commit2");
        assert_eq!(retrieved.indexed_at, 1699900100);

        // Count should be 1
        assert_eq!(store.count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_list_indexed_branches() {
        let (_tmpdir, store) = create_test_store().await;

        let branches = vec![
            IndexedBranchInfo {
                branch_name: "main".to_string(),
                tip_commit: "commit1".to_string(),
                indexed_at: 1699900000,
                remote: None,
            },
            IndexedBranchInfo {
                branch_name: "develop".to_string(),
                tip_commit: "commit2".to_string(),
                indexed_at: 1699900100,
                remote: None,
            },
            IndexedBranchInfo {
                branch_name: "origin/feature".to_string(),
                tip_commit: "commit3".to_string(),
                indexed_at: 1699900200,
                remote: Some("origin".to_string()),
            },
        ];

        for info in &branches {
            store.record_branch_indexed(info).await.unwrap();
        }

        let listed = store.list_indexed_branches().await.unwrap();
        assert_eq!(listed.len(), 3);

        // Should be sorted by name
        assert_eq!(listed[0].branch_name, "develop");
        assert_eq!(listed[1].branch_name, "main");
        assert_eq!(listed[2].branch_name, "origin/feature");
    }

    #[tokio::test]
    async fn test_is_branch_current() {
        let (_tmpdir, store) = create_test_store().await;

        let info = IndexedBranchInfo {
            branch_name: "main".to_string(),
            tip_commit: "abc123".to_string(),
            indexed_at: 1699900000,
            remote: None,
        };
        store.record_branch_indexed(&info).await.unwrap();

        assert!(store.is_branch_current("main", "abc123").await.unwrap());
        assert!(!store.is_branch_current("main", "def456").await.unwrap());
        assert!(!store
            .is_branch_current("nonexistent", "abc123")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_remove_branch() {
        let (_tmpdir, store) = create_test_store().await;

        let info = IndexedBranchInfo {
            branch_name: "feature".to_string(),
            tip_commit: "abc123".to_string(),
            indexed_at: 1699900000,
            remote: None,
        };
        store.record_branch_indexed(&info).await.unwrap();

        assert!(store.get_branch_info("feature").await.unwrap().is_some());

        store.remove_branch("feature").await.unwrap();

        assert!(store.get_branch_info("feature").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_remove_branches_by_remote() {
        let (_tmpdir, store) = create_test_store().await;

        let branches = vec![
            IndexedBranchInfo {
                branch_name: "main".to_string(),
                tip_commit: "commit1".to_string(),
                indexed_at: 1699900000,
                remote: None,
            },
            IndexedBranchInfo {
                branch_name: "origin/main".to_string(),
                tip_commit: "commit2".to_string(),
                indexed_at: 1699900100,
                remote: Some("origin".to_string()),
            },
            IndexedBranchInfo {
                branch_name: "origin/develop".to_string(),
                tip_commit: "commit3".to_string(),
                indexed_at: 1699900200,
                remote: Some("origin".to_string()),
            },
            IndexedBranchInfo {
                branch_name: "upstream/main".to_string(),
                tip_commit: "commit4".to_string(),
                indexed_at: 1699900300,
                remote: Some("upstream".to_string()),
            },
        ];

        for info in &branches {
            store.record_branch_indexed(info).await.unwrap();
        }

        let removed = store.remove_branches_by_remote("origin").await.unwrap();
        assert_eq!(removed, 2);

        let remaining = store.list_indexed_branches().await.unwrap();
        assert_eq!(remaining.len(), 2);
        assert!(remaining.iter().any(|b| b.branch_name == "main"));
        assert!(remaining.iter().any(|b| b.branch_name == "upstream/main"));
    }

    #[tokio::test]
    async fn test_get_branches_at_commit() {
        let (_tmpdir, store) = create_test_store().await;

        let shared_commit = "shared123";
        let branches = vec![
            IndexedBranchInfo {
                branch_name: "main".to_string(),
                tip_commit: shared_commit.to_string(),
                indexed_at: 1699900000,
                remote: None,
            },
            IndexedBranchInfo {
                branch_name: "release".to_string(),
                tip_commit: shared_commit.to_string(),
                indexed_at: 1699900100,
                remote: None,
            },
            IndexedBranchInfo {
                branch_name: "develop".to_string(),
                tip_commit: "different456".to_string(),
                indexed_at: 1699900200,
                remote: None,
            },
        ];

        for info in &branches {
            store.record_branch_indexed(info).await.unwrap();
        }

        let at_shared = store.get_branches_at_commit(shared_commit).await.unwrap();
        assert_eq!(at_shared.len(), 2);
        assert!(at_shared.iter().any(|b| b.branch_name == "main"));
        assert!(at_shared.iter().any(|b| b.branch_name == "release"));
    }

    #[tokio::test]
    async fn test_get_branch_tip() {
        let (_tmpdir, store) = create_test_store().await;

        let info = IndexedBranchInfo {
            branch_name: "main".to_string(),
            tip_commit: "abc123".to_string(),
            indexed_at: 1699900000,
            remote: None,
        };
        store.record_branch_indexed(&info).await.unwrap();

        assert_eq!(
            store.get_branch_tip("main").await.unwrap(),
            Some("abc123".to_string())
        );
        assert_eq!(store.get_branch_tip("nonexistent").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_branch_name_with_special_chars() {
        let (_tmpdir, store) = create_test_store().await;

        // Test branch names with characters that need escaping
        let info = IndexedBranchInfo {
            branch_name: "feature/user's-branch".to_string(),
            tip_commit: "abc123".to_string(),
            indexed_at: 1699900000,
            remote: None,
        };
        store.record_branch_indexed(&info).await.unwrap();

        let retrieved = store
            .get_branch_info("feature/user's-branch")
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().branch_name, "feature/user's-branch");
    }
}
