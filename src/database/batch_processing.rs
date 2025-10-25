// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Batch processing utilities for database result extraction
//
// This module provides parallel batch processing functions for efficient
// extraction of data from Arrow RecordBatch results. The functions use
// rayon for parallelism with adaptive thresholds.

use arrow_array::RecordBatch;
use rayon::prelude::*;
use gxhash::{HashMap, HashMapExt};

use crate::consts::BATCH_PARALLEL_THRESHOLD;

/// Process batches by applying an extractor function to each row
///
/// This function processes all batches and applies the extractor function to each row,
/// collecting successful extractions into a Vec. Automatically uses parallel processing
/// for large result sets (>= 1000 rows) and sequential processing for smaller sets.
///
/// # Arguments
/// * `batches` - Slice of RecordBatch to process
/// * `extractor` - Function that extracts T from (batch, row_index)
///
/// # Returns
/// Vec of successfully extracted items
pub fn process_batches<T, F>(batches: &[RecordBatch], extractor: F) -> Vec<T>
where
    F: Fn(&RecordBatch, usize) -> Option<T> + Sync + Send,
    T: Send,
{
    let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();

    if total_rows < BATCH_PARALLEL_THRESHOLD {
        // Sequential processing for small result sets (better cache locality)
        batches
            .iter()
            .flat_map(|batch| (0..batch.num_rows()).filter_map(|i| extractor(batch, i)))
            .collect()
    } else {
        // Parallel processing for large result sets
        batches
            .par_iter()
            .flat_map(|batch| {
                (0..batch.num_rows())
                    .into_par_iter()
                    .filter_map(|i| extractor(batch, i))
            })
            .collect()
    }
}

/// Build a HashMap from two columns in batches
///
/// This function processes all batches and extracts key-value pairs from two columns,
/// collecting them into a HashMap. The key and value are extracted using provided
/// closures.
///
/// # Arguments
/// * `batches` - Slice of RecordBatch to process
/// * `key_extractor` - Function that extracts the key (K) from (batch, row_index)
/// * `value_extractor` - Function that extracts the value (V) from (batch, row_index)
///
/// # Returns
/// HashMap of extracted key-value pairs
pub fn build_map_from_batches<K, V, FK, FV>(
    batches: &[RecordBatch],
    key_extractor: FK,
    value_extractor: FV,
) -> HashMap<K, V>
where
    FK: Fn(&RecordBatch, usize) -> Option<K>,
    FV: Fn(&RecordBatch, usize) -> Option<V>,
    K: std::hash::Hash + Eq,
{
    let mut map = HashMap::new();

    for batch in batches {
        for i in 0..batch.num_rows() {
            if let (Some(key), Some(value)) = (key_extractor(batch, i), value_extractor(batch, i)) {
                map.insert(key, value);
            }
        }
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::{Int32Array, RecordBatch, StringArray};
    use arrow_schema::{DataType, Field, Schema};
    use std::sync::Arc;

    #[test]
    fn test_process_batches_empty() {
        let batches: Vec<RecordBatch> = vec![];
        let extractor = |_batch: &RecordBatch, _i: usize| Some(42);

        let result = process_batches(&batches, extractor);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_process_batches_single_batch() {
        // Create a simple RecordBatch with Int32 data
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("name", DataType::Utf8, false),
        ]));

        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(Int32Array::from(vec![1, 2, 3])),
                Arc::new(StringArray::from(vec!["a", "b", "c"])),
            ],
        )
        .unwrap();

        let batches = vec![batch];

        // Extract the ID from each row
        let extractor = |batch: &RecordBatch, i: usize| {
            let id_array = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap();
            Some(id_array.value(i))
        };

        let result = process_batches(&batches, extractor);
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn test_process_batches_multiple_batches() {
        let schema = Arc::new(Schema::new(vec![Field::new(
            "value",
            DataType::Int32,
            false,
        )]));

        let batch1 = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(Int32Array::from(vec![10, 20]))],
        )
        .unwrap();

        let batch2 = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(Int32Array::from(vec![30, 40, 50]))],
        )
        .unwrap();

        let batches = vec![batch1, batch2];

        let extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap();
            Some(array.value(i))
        };

        let result = process_batches(&batches, extractor);
        assert_eq!(result, vec![10, 20, 30, 40, 50]);
    }

    #[test]
    fn test_process_batches_with_filtering() {
        let schema = Arc::new(Schema::new(vec![Field::new(
            "value",
            DataType::Int32,
            false,
        )]));

        let batch = RecordBatch::try_new(
            schema,
            vec![Arc::new(Int32Array::from(vec![1, 2, 3, 4, 5]))],
        )
        .unwrap();

        let batches = vec![batch];

        // Only extract even numbers
        let extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap();
            let value = array.value(i);
            if value % 2 == 0 {
                Some(value)
            } else {
                None
            }
        };

        let result = process_batches(&batches, extractor);
        assert_eq!(result, vec![2, 4]);
    }

    #[test]
    fn test_process_batches_string_extraction() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("name", DataType::Utf8, false),
        ]));

        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(Int32Array::from(vec![1, 2, 3])),
                Arc::new(StringArray::from(vec!["foo", "bar", "baz"])),
            ],
        )
        .unwrap();

        let batches = vec![batch];

        // Extract names as Strings
        let extractor = |batch: &RecordBatch, i: usize| {
            let name_array = batch
                .column(1)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            Some(name_array.value(i).to_string())
        };

        let result = process_batches(&batches, extractor);
        assert_eq!(
            result,
            vec!["foo".to_string(), "bar".to_string(), "baz".to_string()]
        );
    }

    #[test]
    fn test_process_batches_empty_batch_in_sequence() {
        // Test handling of empty batches mixed with non-empty ones
        let schema = Arc::new(Schema::new(vec![Field::new(
            "value",
            DataType::Int32,
            false,
        )]));

        let batch1 =
            RecordBatch::try_new(schema.clone(), vec![Arc::new(Int32Array::from(vec![1, 2]))])
                .unwrap();

        let batch2 = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(Int32Array::from(Vec::<i32>::new()))],
        )
        .unwrap();

        let batch3 =
            RecordBatch::try_new(schema.clone(), vec![Arc::new(Int32Array::from(vec![3, 4]))])
                .unwrap();

        let batches = vec![batch1, batch2, batch3];

        let extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap();
            Some(array.value(i))
        };

        let result = process_batches(&batches, extractor);
        assert_eq!(result, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_process_batches_all_filtered_out() {
        // Test when all items are filtered (all None)
        let schema = Arc::new(Schema::new(vec![Field::new(
            "value",
            DataType::Int32,
            false,
        )]));

        let batch = RecordBatch::try_new(
            schema,
            vec![Arc::new(Int32Array::from(vec![1, 3, 5, 7, 9]))],
        )
        .unwrap();

        let batches = vec![batch];

        // Filter to only even numbers (none exist)
        let extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap();
            let value = array.value(i);
            if value % 2 == 0 {
                Some(value)
            } else {
                None
            }
        };

        let result = process_batches(&batches, extractor);
        assert_eq!(result, Vec::<i32>::new());
    }

    #[test]
    fn test_process_batches_large_batch() {
        // Test with a larger batch to ensure no performance issues
        let schema = Arc::new(Schema::new(vec![Field::new(
            "value",
            DataType::Int32,
            false,
        )]));

        let large_data: Vec<i32> = (0..10000).collect();
        let batch =
            RecordBatch::try_new(schema, vec![Arc::new(Int32Array::from(large_data.clone()))])
                .unwrap();

        let batches = vec![batch];

        let extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap();
            Some(array.value(i))
        };

        let result = process_batches(&batches, extractor);
        assert_eq!(result, large_data);
    }

    #[test]
    fn test_process_batches_complex_extraction() {
        // Test extracting a struct/tuple from multiple columns
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("name", DataType::Utf8, false),
            Field::new("score", DataType::Int32, false),
        ]));

        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(Int32Array::from(vec![1, 2, 3])),
                Arc::new(StringArray::from(vec!["alice", "bob", "charlie"])),
                Arc::new(Int32Array::from(vec![100, 200, 300])),
            ],
        )
        .unwrap();

        let batches = vec![batch];

        // Extract as tuples
        let extractor = |batch: &RecordBatch, i: usize| {
            let id_array = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap();
            let name_array = batch
                .column(1)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let score_array = batch
                .column(2)
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap();

            Some((
                id_array.value(i),
                name_array.value(i).to_string(),
                score_array.value(i),
            ))
        };

        let result = process_batches(&batches, extractor);
        assert_eq!(
            result,
            vec![
                (1, "alice".to_string(), 100),
                (2, "bob".to_string(), 200),
                (3, "charlie".to_string(), 300),
            ]
        );
    }

    #[test]
    fn test_process_batches_mixed_filtering() {
        // Test filtering that keeps some items from each batch
        let schema = Arc::new(Schema::new(vec![Field::new(
            "value",
            DataType::Int32,
            false,
        )]));

        let batch1 = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(Int32Array::from(vec![1, 2, 3, 4, 5]))],
        )
        .unwrap();

        let batch2 = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(Int32Array::from(vec![6, 7, 8, 9, 10]))],
        )
        .unwrap();

        let batches = vec![batch1, batch2];

        // Only keep values > 3 and < 9
        let extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap();
            let value = array.value(i);
            if value > 3 && value < 9 {
                Some(value)
            } else {
                None
            }
        };

        let result = process_batches(&batches, extractor);
        assert_eq!(result, vec![4, 5, 6, 7, 8]);
    }

    // Tests for build_map_from_batches

    #[test]
    fn test_build_map_empty() {
        let batches: Vec<RecordBatch> = vec![];
        let key_extractor = |_: &RecordBatch, _: usize| Some(42);
        let value_extractor = |_: &RecordBatch, _: usize| Some("test".to_string());

        let result: HashMap<i32, String> =
            build_map_from_batches(&batches, key_extractor, value_extractor);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_build_map_single_batch() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("name", DataType::Utf8, false),
        ]));

        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(Int32Array::from(vec![1, 2, 3])),
                Arc::new(StringArray::from(vec!["a", "b", "c"])),
            ],
        )
        .unwrap();

        let batches = vec![batch];

        let key_extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap();
            Some(array.value(i))
        };
        let value_extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(1)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            Some(array.value(i).to_string())
        };

        let result = build_map_from_batches(&batches, key_extractor, value_extractor);
        assert_eq!(result.len(), 3);
        assert_eq!(result.get(&1), Some(&"a".to_string()));
        assert_eq!(result.get(&2), Some(&"b".to_string()));
        assert_eq!(result.get(&3), Some(&"c".to_string()));
    }

    #[test]
    fn test_build_map_multiple_batches() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("key", DataType::Utf8, false),
            Field::new("value", DataType::Int32, false),
        ]));

        let batch1 = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(StringArray::from(vec!["a", "b"])),
                Arc::new(Int32Array::from(vec![10, 20])),
            ],
        )
        .unwrap();

        let batch2 = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(StringArray::from(vec!["c", "d"])),
                Arc::new(Int32Array::from(vec![30, 40])),
            ],
        )
        .unwrap();

        let batches = vec![batch1, batch2];

        let key_extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(0)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            Some(array.value(i).to_string())
        };
        let value_extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(1)
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap();
            Some(array.value(i))
        };

        let result = build_map_from_batches(&batches, key_extractor, value_extractor);
        assert_eq!(result.len(), 4);
        assert_eq!(result.get("a"), Some(&10));
        assert_eq!(result.get("b"), Some(&20));
        assert_eq!(result.get("c"), Some(&30));
        assert_eq!(result.get("d"), Some(&40));
    }

    #[test]
    fn test_build_map_with_duplicates() {
        // Later values should overwrite earlier ones
        let schema = Arc::new(Schema::new(vec![
            Field::new("key", DataType::Utf8, false),
            Field::new("value", DataType::Int32, false),
        ]));

        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(StringArray::from(vec!["a", "b", "a"])),
                Arc::new(Int32Array::from(vec![10, 20, 30])),
            ],
        )
        .unwrap();

        let batches = vec![batch];

        let key_extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(0)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            Some(array.value(i).to_string())
        };
        let value_extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(1)
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap();
            Some(array.value(i))
        };

        let result = build_map_from_batches(&batches, key_extractor, value_extractor);
        assert_eq!(result.len(), 2);
        assert_eq!(result.get("a"), Some(&30)); // Last value wins
        assert_eq!(result.get("b"), Some(&20));
    }

    #[test]
    fn test_build_map_with_none_values() {
        // Test handling of None from extractors
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("value", DataType::Int32, false),
        ]));

        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(Int32Array::from(vec![1, 2, 3, 4, 5])),
                Arc::new(Int32Array::from(vec![10, 20, 30, 40, 50])),
            ],
        )
        .unwrap();

        let batches = vec![batch];

        // Only include even keys
        let key_extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap();
            let key = array.value(i);
            if key % 2 == 0 {
                Some(key)
            } else {
                None
            }
        };
        let value_extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(1)
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap();
            Some(array.value(i))
        };

        let result = build_map_from_batches(&batches, key_extractor, value_extractor);
        assert_eq!(result.len(), 2);
        assert_eq!(result.get(&2), Some(&20));
        assert_eq!(result.get(&4), Some(&40));
    }

    #[test]
    fn test_build_map_large_batch() {
        // Test with 1000 items
        let schema = Arc::new(Schema::new(vec![
            Field::new("key", DataType::Int32, false),
            Field::new("value", DataType::Int32, false),
        ]));

        let keys: Vec<i32> = (0..1000).collect();
        let values: Vec<i32> = (0..1000).map(|i| i * 2).collect();

        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(Int32Array::from(keys.clone())),
                Arc::new(Int32Array::from(values.clone())),
            ],
        )
        .unwrap();

        let batches = vec![batch];

        let key_extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap();
            Some(array.value(i))
        };
        let value_extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(1)
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap();
            Some(array.value(i))
        };

        let result = build_map_from_batches(&batches, key_extractor, value_extractor);
        assert_eq!(result.len(), 1000);
        assert_eq!(result.get(&0), Some(&0));
        assert_eq!(result.get(&500), Some(&1000));
        assert_eq!(result.get(&999), Some(&1998));
    }

    #[test]
    fn test_build_map_string_to_string() {
        // Test typical content hash -> content pattern
        let schema = Arc::new(Schema::new(vec![
            Field::new("hash", DataType::Utf8, false),
            Field::new("content", DataType::Utf8, false),
        ]));

        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(StringArray::from(vec!["hash1", "hash2", "hash3"])),
                Arc::new(StringArray::from(vec!["content1", "content2", "content3"])),
            ],
        )
        .unwrap();

        let batches = vec![batch];

        let key_extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(0)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            Some(array.value(i).to_string())
        };
        let value_extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(1)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            Some(array.value(i).to_string())
        };

        let result = build_map_from_batches(&batches, key_extractor, value_extractor);
        assert_eq!(result.len(), 3);
        assert_eq!(result.get("hash1"), Some(&"content1".to_string()));
        assert_eq!(result.get("hash2"), Some(&"content2".to_string()));
        assert_eq!(result.get("hash3"), Some(&"content3".to_string()));
    }

    #[test]
    fn test_build_map_empty_batch_in_sequence() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("key", DataType::Int32, false),
            Field::new("value", DataType::Int32, false),
        ]));

        let batch1 = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![1, 2])),
                Arc::new(Int32Array::from(vec![10, 20])),
            ],
        )
        .unwrap();

        let batch2 = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(Vec::<i32>::new())),
                Arc::new(Int32Array::from(Vec::<i32>::new())),
            ],
        )
        .unwrap();

        let batch3 = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![3, 4])),
                Arc::new(Int32Array::from(vec![30, 40])),
            ],
        )
        .unwrap();

        let batches = vec![batch1, batch2, batch3];

        let key_extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap();
            Some(array.value(i))
        };
        let value_extractor = |batch: &RecordBatch, i: usize| {
            let array = batch
                .column(1)
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap();
            Some(array.value(i))
        };

        let result = build_map_from_batches(&batches, key_extractor, value_extractor);
        assert_eq!(result.len(), 4);
        assert_eq!(result.get(&1), Some(&10));
        assert_eq!(result.get(&2), Some(&20));
        assert_eq!(result.get(&3), Some(&30));
        assert_eq!(result.get(&4), Some(&40));
    }
}
