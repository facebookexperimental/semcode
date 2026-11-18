// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Storage for registrations: functions installed in struct members. These are
// the targets a dispatch site resolves to, joined on (container_type, member).
use anyhow::Result;
use arrow::array::Array;
use arrow::array::{ArrayRef, Int64Array, RecordBatch, RecordBatchIterator, StringArray};
use arrow::array::{Int64Builder, StringBuilder};
use futures::TryStreamExt;
use lancedb::connection::Connection;
use lancedb::query::{ExecutableQuery, QueryBase};
use std::sync::Arc;

use crate::database::get_column;
use crate::types::{Registration, RegistrationKind};

pub struct RegistrationStore {
    connection: Connection,
}

impl RegistrationStore {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    /// Insert registrations, replacing any already recorded for the same
    /// initializer. Reindexing unchanged content stores the same rows again
    /// rather than duplicating them.
    pub async fn insert_batch(&self, registrations: Vec<Registration>) -> Result<()> {
        if registrations.is_empty() {
            return Ok(());
        }
        // A batch spanning commits holds the same file at the same hash twice,
        // and merge_insert refuses a batch with two source rows for one target.
        let registrations = crate::database::one_row_per_key(registrations, |row| {
            (
                row.file_path.clone(),
                row.git_file_hash.clone(),
                row.byte_start,
                row.target.clone(),
            )
        });

        let table = self
            .connection
            .open_table("registrations")
            .execute()
            .await?;

        let mut container = StringBuilder::new();
        let mut container_base = StringBuilder::new();
        let mut container_field = StringBuilder::new();
        let mut member = StringBuilder::new();
        let mut target = StringBuilder::new();
        let mut file_path = StringBuilder::new();
        let mut git_file_hash = StringBuilder::new();
        let mut byte_start = Int64Builder::new();
        let mut line = Int64Builder::new();
        let mut enclosing = StringBuilder::new();
        let mut kind = StringBuilder::new();

        for r in &registrations {
            container.append_value(&r.container_type);
            container_base.append_option(r.container_base_type.as_deref());
            container_field.append_option(r.container_field.as_deref());
            member.append_value(&r.member);
            target.append_value(&r.target);
            file_path.append_value(&r.file_path);
            git_file_hash.append_value(&r.git_file_hash);
            byte_start.append_value(r.byte_start as i64);
            line.append_value(r.line as i64);
            enclosing.append_value(&r.enclosing_function);
            kind.append_value(r.kind.as_str());
        }

        let batch = RecordBatch::try_from_iter(vec![
            ("container_type", Arc::new(container.finish()) as ArrayRef),
            (
                "container_base_type",
                Arc::new(container_base.finish()) as ArrayRef,
            ),
            (
                "container_field",
                Arc::new(container_field.finish()) as ArrayRef,
            ),
            ("member", Arc::new(member.finish()) as ArrayRef),
            ("target", Arc::new(target.finish()) as ArrayRef),
            ("file_path", Arc::new(file_path.finish()) as ArrayRef),
            (
                "git_file_hash",
                Arc::new(git_file_hash.finish()) as ArrayRef,
            ),
            ("byte_start", Arc::new(byte_start.finish()) as ArrayRef),
            ("line", Arc::new(line.finish()) as ArrayRef),
            (
                "enclosing_function",
                Arc::new(enclosing.finish()) as ArrayRef,
            ),
            ("kind", Arc::new(kind.finish()) as ArrayRef),
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

    /// Everything installed in one member of one type.
    pub async fn find_by_slot(
        &self,
        container_type: &str,
        member: &str,
    ) -> Result<Vec<Registration>> {
        let filter = format!(
            "container_type = '{}' AND member = '{}'",
            container_type.replace('\'', "''"),
            member.replace('\'', "''")
        );
        self.query(&filter).await
    }

    /// Every place a function is installed.
    pub async fn find_by_target(&self, target: &str) -> Result<Vec<Registration>> {
        self.query(&format!("target = '{}'", target.replace('\'', "''")))
            .await
    }

    /// Everything installed in a member of this name, whatever the type.
    /// Weaker than find_by_slot, and the caller has to say it means that.
    /// Rows for a member that could still turn out to be this container's.
    ///
    /// A row made through a field does not know its container until it is
    /// resolved, so it has to be read; every other container's rows do not.
    /// Asking by member alone reads them all — `read` and `owner` match
    /// thousands across a kernel — and resolves each one before discarding it.
    pub async fn find_by_member_for_container(
        &self,
        container_type: &str,
        member: &str,
    ) -> Result<Vec<Registration>> {
        let quote = |v: &str| v.replace('\'', "''");
        self.query(&format!(
            "member = '{}' AND (container_type = '{}' OR container_type = '')",
            quote(member),
            quote(container_type)
        ))
        .await
    }

    pub async fn find_by_member(&self, member: &str) -> Result<Vec<Registration>> {
        self.query(&format!("member = '{}'", member.replace('\'', "''")))
            .await
    }

    /// Trait-impl installations of a member, narrowed by kind.
    pub async fn find_trait_impls_by_member(&self, member: &str) -> Result<Vec<Registration>> {
        self.query(&format!(
            "member = '{}' AND kind = 'trait_impl'",
            member.replace('\'', "''")
        ))
        .await
    }

    async fn query(&self, filter: &str) -> Result<Vec<Registration>> {
        let table = self
            .connection
            .open_table("registrations")
            .execute()
            .await?;
        let batches: Vec<RecordBatch> = table
            .query()
            .only_if(filter)
            .execute()
            .await?
            .try_collect()
            .await?;

        let mut out = Vec::new();
        for batch in &batches {
            for row in 0..batch.num_rows() {
                out.push(Self::from_batch(batch, row)?);
            }
        }

        Ok(out)
    }

    fn from_batch(batch: &RecordBatch, row: usize) -> Result<Registration> {
        let text = |name: &str| -> Result<String> {
            Ok(get_column::<StringArray>(batch, name)?
                .value(row)
                .to_string())
        };

        // Absent on a row whose container the file stated outright, and on
        // every row written before the columns existed.
        let optional = |name: &str| -> Option<String> {
            batch
                .column_by_name(name)
                .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                .filter(|values| values.is_valid(row) && !values.value(row).is_empty())
                .map(|values| values.value(row).to_string())
        };

        let kind_text = text("kind")?;
        let kind = RegistrationKind::from_column_value(&kind_text)
            .ok_or_else(|| anyhow::anyhow!("unknown registration kind '{kind_text}'"))?;

        Ok(Registration {
            container_type: text("container_type")?,
            member: text("member")?,
            target: text("target")?,
            file_path: text("file_path")?,
            git_file_hash: text("git_file_hash")?,
            byte_start: get_column::<Int64Array>(batch, "byte_start")?.value(row) as u64,
            line: get_column::<Int64Array>(batch, "line")?.value(row) as u32,
            enclosing_function: text("enclosing_function")?,
            kind,
            container_base_type: optional("container_base_type"),
            container_field: optional("container_field"),
        })
    }
}
