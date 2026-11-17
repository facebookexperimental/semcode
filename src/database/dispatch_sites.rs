// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Storage for dispatch sites: calls that go through a value rather than
// naming a function. A site carries no resolved target, so it is stored
// apart from the resolved call edges in the functions table and joined
// against installed targets at query time.
use anyhow::Result;
use arrow::array::{ArrayRef, Int64Builder, RecordBatch, RecordBatchIterator, StringBuilder};
use futures::TryStreamExt;
use lancedb::connection::Connection;
use lancedb::query::{ExecutableQuery, QueryBase};
use std::sync::Arc;

use crate::database::get_column;
use crate::types::{DispatchKind, DispatchSite};

pub struct DispatchSiteStore {
    connection: Connection,
}

impl DispatchSiteStore {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    /// Insert dispatch sites, replacing any already recorded for the same
    /// site. A site is identified by where it is and what it names, so
    /// reindexing unchanged content stores the same rows again rather than
    /// duplicating them.
    pub async fn insert_batch(&self, sites: Vec<DispatchSite>) -> Result<()> {
        if sites.is_empty() {
            return Ok(());
        }
        // A batch spanning commits holds the same file at the same hash twice,
        // and merge_insert refuses a batch with two source rows for one target.
        let sites = crate::database::one_row_per_key(sites, |site| {
            (
                site.file_path.clone(),
                site.git_file_hash.clone(),
                site.byte_start,
                site.target.clone(),
            )
        });

        let table = self
            .connection
            .open_table("dispatch_sites")
            .execute()
            .await?;

        let mut caller = StringBuilder::new();
        let mut file_path = StringBuilder::new();
        let mut git_file_hash = StringBuilder::new();
        let mut byte_start = Int64Builder::new();
        let mut line = Int64Builder::new();
        let mut member = StringBuilder::new();
        let mut receiver_expr = StringBuilder::new();
        let mut receiver_type = StringBuilder::new();
        let mut receiver_base_type = StringBuilder::new();
        let mut receiver_field = StringBuilder::new();
        let mut receiver_bound = StringBuilder::new();
        let mut kind = StringBuilder::new();
        let mut target = StringBuilder::new();

        for site in &sites {
            caller.append_value(&site.caller_name);
            file_path.append_value(&site.file_path);
            git_file_hash.append_value(&site.git_file_hash);
            byte_start.append_value(site.byte_start as i64);
            line.append_value(site.line as i64);
            member.append_value(&site.member);
            receiver_expr.append_option(site.receiver_expr.as_deref());
            receiver_type.append_option(site.receiver_type.as_deref());
            receiver_base_type.append_option(site.receiver_base_type.as_deref());
            receiver_field.append_option(site.receiver_field.as_deref());
            receiver_bound.append_option(site.receiver_bound.as_deref());
            kind.append_value(site.kind.as_str());
            target.append_value(site.target.as_deref().unwrap_or(""));
        }

        let batch = RecordBatch::try_from_iter(vec![
            ("caller_name", Arc::new(caller.finish()) as ArrayRef),
            ("file_path", Arc::new(file_path.finish()) as ArrayRef),
            (
                "git_file_hash",
                Arc::new(git_file_hash.finish()) as ArrayRef,
            ),
            ("byte_start", Arc::new(byte_start.finish()) as ArrayRef),
            ("line", Arc::new(line.finish()) as ArrayRef),
            ("member", Arc::new(member.finish()) as ArrayRef),
            (
                "receiver_expr",
                Arc::new(receiver_expr.finish()) as ArrayRef,
            ),
            (
                "receiver_type",
                Arc::new(receiver_type.finish()) as ArrayRef,
            ),
            (
                "receiver_base_type",
                Arc::new(receiver_base_type.finish()) as ArrayRef,
            ),
            (
                "receiver_field",
                Arc::new(receiver_field.finish()) as ArrayRef,
            ),
            (
                "receiver_bound",
                Arc::new(receiver_bound.finish()) as ArrayRef,
            ),
            ("kind", Arc::new(kind.finish()) as ArrayRef),
            ("target", Arc::new(target.finish()) as ArrayRef),
        ])?;

        let mut merge_insert =
            table.merge_insert(&["file_path", "git_file_hash", "byte_start", "target"]);
        merge_insert
            .when_matched_update_all(None)
            .when_not_matched_insert_all();
        let schema = batch.schema();
        merge_insert
            .execute(Box::new(RecordBatchIterator::new(vec![Ok(batch)], schema)))
            .await?;

        Ok(())
    }

    /// Every site dispatching through the named member.
    pub async fn find_by_member(&self, member: &str) -> Result<Vec<DispatchSite>> {
        let table = self
            .connection
            .open_table("dispatch_sites")
            .execute()
            .await?;
        let escaped = member.replace('\'', "''");
        let batches: Vec<RecordBatch> = table
            .query()
            .only_if(format!("member = '{escaped}'"))
            .execute()
            .await?
            .try_collect()
            .await?;

        let mut sites = Vec::new();
        for batch in &batches {
            for row in 0..batch.num_rows() {
                sites.push(Self::site_from_batch(batch, row)?);
            }
        }

        Ok(sites)
    }

    /// Every site that names this function as a candidate outright: an
    /// indirect-call macro's declared target, or a local pointer's
    /// initializer.
    pub async fn find_by_target(&self, target: &str) -> Result<Vec<DispatchSite>> {
        let table = self
            .connection
            .open_table("dispatch_sites")
            .execute()
            .await?;
        let escaped = target.replace('\'', "''");
        let batches: Vec<RecordBatch> = table
            .query()
            .only_if(format!("target = '{escaped}'"))
            .execute()
            .await?
            .try_collect()
            .await?;

        let mut sites = Vec::new();
        for batch in &batches {
            for row in 0..batch.num_rows() {
                sites.push(Self::site_from_batch(batch, row)?);
            }
        }

        Ok(sites)
    }

    /// Every site inside the named function.
    pub async fn find_by_caller(&self, caller_name: &str) -> Result<Vec<DispatchSite>> {
        let table = self
            .connection
            .open_table("dispatch_sites")
            .execute()
            .await?;
        let escaped = caller_name.replace('\'', "''");
        let batches: Vec<RecordBatch> = table
            .query()
            .only_if(format!("caller_name = '{escaped}'"))
            .execute()
            .await?
            .try_collect()
            .await?;

        let mut sites = Vec::new();
        for batch in &batches {
            for row in 0..batch.num_rows() {
                sites.push(Self::site_from_batch(batch, row)?);
            }
        }

        Ok(sites)
    }

    fn site_from_batch(batch: &RecordBatch, row: usize) -> Result<DispatchSite> {
        use arrow::array::{Array, Int64Array, StringArray};

        let text = |name: &str| -> Result<String> {
            Ok(get_column::<StringArray>(batch, name)?
                .value(row)
                .to_string())
        };
        let optional_text = |name: &str| -> Result<Option<String>> {
            let column = get_column::<StringArray>(batch, name)?;
            Ok(if column.is_null(row) {
                None
            } else {
                Some(column.value(row).to_string())
            })
        };

        let kind_text = text("kind")?;
        let kind = DispatchKind::from_column_value(&kind_text)
            .ok_or_else(|| anyhow::anyhow!("unknown dispatch kind '{kind_text}'"))?;

        Ok(DispatchSite {
            caller_name: text("caller_name")?,
            file_path: text("file_path")?,
            git_file_hash: text("git_file_hash")?,
            byte_start: get_column::<Int64Array>(batch, "byte_start")?.value(row) as u64,
            line: get_column::<Int64Array>(batch, "line")?.value(row) as u32,
            member: text("member")?,
            receiver_expr: optional_text("receiver_expr")?,
            receiver_type: optional_text("receiver_type")?,
            receiver_base_type: optional_text("receiver_base_type")?,
            receiver_field: optional_text("receiver_field")?,
            receiver_bound: optional_text("receiver_bound")?,
            kind,
            target: optional_text("target")?.filter(|t| !t.is_empty()),
        })
    }
}
