// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Storage for functions named as call arguments: what a callee was handed.
// A row records what one file proves. Whether the name belongs to a function
// is answered against the functions table, which is complete only once the
// tree has been indexed.
use anyhow::Result;
use arrow::array::{Array, RecordBatchIterator, StringArray};
use arrow::array::{ArrayRef, BooleanBuilder, Int64Builder, RecordBatch, StringBuilder};
use futures::TryStreamExt;
use lancedb::connection::Connection;
use lancedb::query::{ExecutableQuery, QueryBase};
use std::sync::Arc;

use crate::database::get_column;
use crate::types::ArgumentFunction;

pub struct ArgumentFunctionStore {
    connection: Connection,
}

impl ArgumentFunctionStore {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    /// Insert rows, replacing any already recorded for the same argument.
    /// Reindexing unchanged content stores the same rows rather than
    /// duplicating them.
    pub async fn insert_batch(&self, arguments: Vec<ArgumentFunction>) -> Result<()> {
        if arguments.is_empty() {
            return Ok(());
        }
        // A batch spanning commits holds the same file at the same hash twice,
        // and merge_insert refuses a batch with two source rows for one target.
        let arguments = crate::database::one_row_per_key(arguments, |row| {
            (
                row.file_path.clone(),
                row.git_file_hash.clone(),
                row.byte_start,
                row.target.clone(),
            )
        });

        let table = self
            .connection
            .open_table("argument_functions")
            .execute()
            .await?;

        let mut target = StringBuilder::new();
        let mut callee = StringBuilder::new();
        let mut argument_index = Int64Builder::new();
        let mut taken_address = BooleanBuilder::new();
        let mut subject_type = StringBuilder::new();
        let mut subject_member = StringBuilder::new();
        let mut file_path = StringBuilder::new();
        let mut git_file_hash = StringBuilder::new();
        let mut byte_start = Int64Builder::new();
        let mut line = Int64Builder::new();
        let mut enclosing = StringBuilder::new();

        for argument in &arguments {
            target.append_value(&argument.target);
            callee.append_value(&argument.callee);
            argument_index.append_value(argument.argument_index as i64);
            taken_address.append_value(argument.taken_address);
            subject_type.append_option(argument.subject_type.as_deref());
            subject_member.append_option(argument.subject_member.as_deref());
            file_path.append_value(&argument.file_path);
            git_file_hash.append_value(&argument.git_file_hash);
            byte_start.append_value(argument.byte_start as i64);
            line.append_value(argument.line as i64);
            enclosing.append_value(&argument.enclosing_function);
        }

        let batch = RecordBatch::try_from_iter(vec![
            ("target", Arc::new(target.finish()) as ArrayRef),
            ("callee", Arc::new(callee.finish()) as ArrayRef),
            (
                "argument_index",
                Arc::new(argument_index.finish()) as ArrayRef,
            ),
            (
                "taken_address",
                Arc::new(taken_address.finish()) as ArrayRef,
            ),
            ("subject_type", Arc::new(subject_type.finish()) as ArrayRef),
            (
                "subject_member",
                Arc::new(subject_member.finish()) as ArrayRef,
            ),
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
        ])?;

        // One row per argument occurrence: reindexing unchanged content
        // rewrites the same row rather than adding a second.
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

    /// Every row, for measurement over the whole table.
    pub async fn all(&self) -> Result<Vec<ArgumentFunction>> {
        let table = self
            .connection
            .open_table("argument_functions")
            .execute()
            .await?;
        let batches = table
            .query()
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;
        let mut out = Vec::new();
        for batch in &batches {
            let callee = get_column::<StringArray>(batch, "callee")?;
            let index = get_column::<arrow::array::Int64Array>(batch, "argument_index")?;
            let target = get_column::<StringArray>(batch, "target")?;
            for row in 0..batch.num_rows() {
                out.push(ArgumentFunction {
                    target: target.value(row).to_string(),
                    callee: callee.value(row).to_string(),
                    argument_index: index.value(row) as u32,
                    taken_address: false,
                    subject_type: None,
                    subject_member: None,
                    file_path: String::new(),
                    git_file_hash: String::new(),
                    byte_start: 0,
                    line: 0,
                    enclosing_function: String::new(),
                });
            }
        }
        Ok(out)
    }

    /// Every call that was handed this name.
    pub async fn find_by_target(&self, target: &str) -> Result<Vec<ArgumentFunction>> {
        let table = self
            .connection
            .open_table("argument_functions")
            .execute()
            .await?;
        let escaped = target.replace('\'', "''");
        let batches = table
            .query()
            .only_if(format!("target = '{escaped}'"))
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut out = Vec::new();
        for batch in &batches {
            let target = get_column::<StringArray>(batch, "target")?;
            let callee = get_column::<StringArray>(batch, "callee")?;
            let index = get_column::<arrow::array::Int64Array>(batch, "argument_index")?;
            let address = get_column::<arrow::array::BooleanArray>(batch, "taken_address")?;
            let file_path = get_column::<StringArray>(batch, "file_path")?;
            let git_file_hash = get_column::<StringArray>(batch, "git_file_hash")?;
            let byte_start = get_column::<arrow::array::Int64Array>(batch, "byte_start")?;
            let line = get_column::<arrow::array::Int64Array>(batch, "line")?;
            let enclosing = get_column::<StringArray>(batch, "enclosing_function")?;
            let subject_type = get_column::<StringArray>(batch, "subject_type")?;
            let subject_member = get_column::<StringArray>(batch, "subject_member")?;
            for row in 0..batch.num_rows() {
                out.push(ArgumentFunction {
                    target: target.value(row).to_string(),
                    callee: callee.value(row).to_string(),
                    argument_index: index.value(row) as u32,
                    taken_address: address.value(row),
                    subject_type: (!subject_type.is_null(row))
                        .then(|| subject_type.value(row).to_string()),
                    subject_member: (!subject_member.is_null(row))
                        .then(|| subject_member.value(row).to_string()),
                    file_path: file_path.value(row).to_string(),
                    git_file_hash: git_file_hash.value(row).to_string(),
                    byte_start: byte_start.value(row) as u64,
                    line: line.value(row) as u32,
                    enclosing_function: enclosing.value(row).to_string(),
                });
            }
        }
        Ok(out)
    }

    /// Every site that handed an argument to this callee: the forward
    /// handover leg. The `callee` column carries an index (schema.rs), so
    /// this is an indexed lookup, not a scan on `enclosing_function`.
    pub async fn find_by_callee(&self, callee: &str) -> Result<Vec<ArgumentFunction>> {
        let table = self
            .connection
            .open_table("argument_functions")
            .execute()
            .await?;
        let escaped = callee.replace('\'', "''");
        let batches = table
            .query()
            .only_if(format!("callee = '{escaped}'"))
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut out = Vec::new();
        for batch in &batches {
            let target = get_column::<StringArray>(batch, "target")?;
            let callee = get_column::<StringArray>(batch, "callee")?;
            let index = get_column::<arrow::array::Int64Array>(batch, "argument_index")?;
            let address = get_column::<arrow::array::BooleanArray>(batch, "taken_address")?;
            let file_path = get_column::<StringArray>(batch, "file_path")?;
            let git_file_hash = get_column::<StringArray>(batch, "git_file_hash")?;
            let byte_start = get_column::<arrow::array::Int64Array>(batch, "byte_start")?;
            let line = get_column::<arrow::array::Int64Array>(batch, "line")?;
            let enclosing = get_column::<StringArray>(batch, "enclosing_function")?;
            let subject_type = get_column::<StringArray>(batch, "subject_type")?;
            let subject_member = get_column::<StringArray>(batch, "subject_member")?;
            for row in 0..batch.num_rows() {
                out.push(ArgumentFunction {
                    target: target.value(row).to_string(),
                    callee: callee.value(row).to_string(),
                    argument_index: index.value(row) as u32,
                    taken_address: address.value(row),
                    subject_type: (!subject_type.is_null(row))
                        .then(|| subject_type.value(row).to_string()),
                    subject_member: (!subject_member.is_null(row))
                        .then(|| subject_member.value(row).to_string()),
                    file_path: file_path.value(row).to_string(),
                    git_file_hash: git_file_hash.value(row).to_string(),
                    byte_start: byte_start.value(row) as u64,
                    line: line.value(row) as u32,
                    enclosing_function: enclosing.value(row).to_string(),
                });
            }
        }
        Ok(out)
    }
}
