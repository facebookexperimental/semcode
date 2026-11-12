// SPDX-License-Identifier: MIT OR Apache-2.0
pub mod argument_functions;
pub mod branches;
pub mod call_edges;
pub mod calls;
mod connection;
pub mod content;
pub mod dispatch_sites;
mod functions;
pub mod globals;
mod lore_date;
pub mod object_macros;
pub mod processed_files;
pub mod registrations;
pub mod resolution;
pub(crate) mod schema;
pub mod unresolved_edges;
pub use schema::SCHEMA_VERSION;
pub mod search;
mod symbol_filename;
mod types;
mod vectors;

pub use connection::{DatabaseManager, LoreIdState};

use anyhow::Result;
use arrow::array::RecordBatch;
use arrow::array::StringArray;

/// One row per merge key, keeping the last.
///
/// `merge_insert` refuses a batch in which two source rows match the same
/// target row, so a duplicate is not a duplicate row in the table: it is a
/// failed insert of everything batched alongside it, reported as
///
/// ```text
/// Ambiguous merge inserts are prohibited: multiple source rows match the
/// same target row on (file_path = "fs/aio.c", ...)
/// ```
///
/// A batch built from several commits holds the same file at the same content
/// hash more than once, since a file unchanged between two commits is analysed
/// under each. Those rows are identical, so which one is kept does not matter;
/// that one is kept does.
pub fn one_row_per_key<T, K: std::hash::Hash + Eq>(rows: Vec<T>, key: impl Fn(&T) -> K) -> Vec<T> {
    let mut seen: std::collections::HashMap<K, usize> = std::collections::HashMap::new();
    for (index, row) in rows.iter().enumerate() {
        seen.insert(key(row), index);
    }
    let mut keep: Vec<bool> = vec![false; rows.len()];
    for index in seen.into_values() {
        keep[index] = true;
    }
    rows.into_iter()
        .zip(keep)
        .filter_map(|(row, keep)| keep.then_some(row))
        .collect()
}

/// Look up an optional string column by name, tolerating tables written
/// before it existed. New columns are appended and read this way: existing
/// column order is frozen, and a missing column means an older row, not an
/// error.
pub(crate) fn optional_string_column(
    batch: &RecordBatch,
    row: usize,
    name: &str,
) -> Option<String> {
    batch
        .column_by_name(name)
        .and_then(|column| column.as_any().downcast_ref::<StringArray>())
        .map(|array| array.value(row).to_string())
        .filter(|value| !value.is_empty())
}

/// Look up a column by name and downcast to the expected Arrow array type.
pub(crate) fn get_column<'a, T: 'static>(batch: &'a RecordBatch, name: &str) -> Result<&'a T> {
    batch
        .column_by_name(name)
        .ok_or_else(|| anyhow::anyhow!("missing column '{name}' in batch"))?
        .as_any()
        .downcast_ref::<T>()
        .ok_or_else(|| anyhow::anyhow!("column '{name}' has unexpected type"))
}

/// Parse the `calls` column to callee names: a JSON array mixing plain
/// spellings and tagged edges. A tagged edge contributes its call text;
/// the owner beside it is for owner-aware lookup, read by
/// [`parse_call_edges`].
///
/// An unparsable value is an error rather than an empty list. Callers used to
/// discard the parse error, which turned a malformed or unrecognised value into
/// a function that appears to call nothing, indistinguishable from one that
/// really calls nothing.
pub(crate) fn parse_call_list(json: &str) -> Result<Vec<String>> {
    parse_call_edges(json).map(|edges| {
        edges
            .into_iter()
            .map(|edge| edge.callee().to_string())
            .collect()
    })
}

/// Parse the `calls` column to its edges, keeping the owner beside every
/// tagged member call. Plain spellings carry no owner.
pub(crate) fn parse_call_edges(json: &str) -> Result<Vec<crate::types::CallEdge>> {
    serde_json::from_str::<Vec<crate::types::CallEdge>>(json).map_err(|e| {
        let preview: String = json.chars().take(120).collect();
        anyhow::anyhow!("call list is not a JSON array of names ({e}): {preview}")
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_call_edges, parse_call_list};

    #[test]
    fn parses_a_list_of_names() {
        assert_eq!(
            parse_call_list(r#"["memcpy","kmalloc"]"#).unwrap(),
            vec!["memcpy".to_string(), "kmalloc".to_string()]
        );
        assert!(parse_call_list("[]").unwrap().is_empty());
    }

    #[test]
    fn rejects_values_that_are_not_a_list_of_names() {
        // Truncated, and an object where a list belongs.
        assert!(parse_call_list(r#"["memcpy""#).is_err());
        assert!(parse_call_list(r#"{"calls":["memcpy"]}"#).is_err());

        // A future encoding that carries more than a name. Silently reporting
        // no calls for these is exactly the failure this rejects.
        assert!(parse_call_list(r#"[{"name":"read","kind":"member"}]"#).is_err());

        // A tagged edge contributes its call text, and keeps its owner for
        // owner-aware lookup.
        assert_eq!(
            parse_call_list(r#"["memcpy",{"call":"get","owner":"ns::Box"}]"#).unwrap(),
            vec!["memcpy".to_string(), "get".to_string()]
        );
        let edges = parse_call_edges(r#"["memcpy",{"call":"get","owner":"ns::Box"}]"#).unwrap();
        assert_eq!(
            edges.iter().map(|edge| edge.owner()).collect::<Vec<_>>(),
            vec![None, Some("ns::Box")]
        );
    }

    #[test]
    fn error_names_the_offending_value() {
        let err = parse_call_list("not json").unwrap_err().to_string();
        assert!(err.contains("not json"), "unhelpful error: {err}");
    }
}
