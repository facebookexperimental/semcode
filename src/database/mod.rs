// SPDX-License-Identifier: MIT OR Apache-2.0
pub mod branches;
pub mod calls;
mod connection;
pub mod content;
mod functions;
pub mod processed_files;
mod schema;
pub mod search;
mod symbol_filename;
mod types;
mod vectors;

pub use connection::DatabaseManager;

use anyhow::Result;
use arrow::array::RecordBatch;

/// Look up a column by name and downcast to the expected Arrow array type.
pub(crate) fn get_column<'a, T: 'static>(batch: &'a RecordBatch, name: &str) -> Result<&'a T> {
    batch
        .column_by_name(name)
        .ok_or_else(|| anyhow::anyhow!("missing column '{name}' in batch"))?
        .as_any()
        .downcast_ref::<T>()
        .ok_or_else(|| anyhow::anyhow!("column '{name}' has unexpected type"))
}
