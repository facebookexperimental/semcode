// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Database operation performance benchmarks
//
// Run with: cargo bench --bench database_operations
// Note: These benchmarks require a temporary database and are heavier

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use semcode::types::{FunctionInfo, MacroInfo, TypeInfo};
use semcode::DatabaseManager;
use smallvec::SmallVec;
use tempfile::TempDir;
use tokio::runtime::Runtime;

// Helper to create test data matching real-world function patterns
// Parameters: Most functions have 0-5 params (SmallVec stays on stack)
// Bodies: Realistic length for C functions (~50-200 chars)
fn create_test_functions(count: usize) -> Vec<FunctionInfo> {
    (0..count)
        .map(|i| FunctionInfo {
            name: format!("test_function_{}", i),
            file_path: format!("/test/file_{}.c", i % 100),
            git_file_hash: format!("hash{}", i % 50),
            line_start: i as u32,
            line_end: (i + 10) as u32,
            return_type: "int".to_string(),
            parameters: SmallVec::new(),
            body: format!("void test_function_{}() {{ return {}; }}", i, i),
            calls: None,
            types: None,
        })
        .collect()
}

fn create_test_types(count: usize) -> Vec<TypeInfo> {
    (0..count)
        .map(|i| TypeInfo {
            name: format!("test_type_{}", i),
            file_path: format!("/test/file_{}.c", i % 100),
            git_file_hash: format!("hash{}", i % 50),
            line_start: i as u32,
            kind: "struct".to_string(),
            size: None,
            members: SmallVec::new(),
            definition: format!("struct test_type_{} {{ int field; }};", i),
            types: None,
        })
        .collect()
}

fn create_test_macros(count: usize) -> Vec<MacroInfo> {
    (0..count)
        .map(|i| MacroInfo {
            name: format!("TEST_MACRO_{}", i),
            file_path: format!("/test/file_{}.c", i % 100),
            git_file_hash: format!("hash{}", i % 50),
            line_start: i as u32,
            is_function_like: false,
            parameters: None,
            definition: format!("#define TEST_MACRO_{} {}", i, i),
            calls: None,
            types: None,
        })
        .collect()
}

// Benchmark batch insertion performance
fn bench_batch_insertion(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("batch_insertion");

    for batch_size in [100, 1000, 5000] {
        group.throughput(Throughput::Elements(batch_size as u64));

        group.bench_with_input(
            BenchmarkId::new("combined_insert", batch_size),
            &batch_size,
            |b, &size| {
                b.to_async(&rt).iter(|| async move {
                    let temp_dir = TempDir::new().unwrap();
                    let db_path = temp_dir.path().join("bench.db");
                    let db: DatabaseManager = DatabaseManager::new(
                        db_path.to_str().unwrap(),
                        temp_dir.path().to_string_lossy().to_string(),
                    )
                    .await
                    .unwrap();
                    db.create_tables().await.unwrap();

                    let functions = create_test_functions(size);
                    let types = create_test_types(size / 2);
                    let macros = create_test_macros(size / 4);

                    db.insert_batch_combined(
                        black_box(functions),
                        black_box(types),
                        black_box(macros),
                    )
                    .await
                    .unwrap();
                });
            },
        );
    }

    group.finish();
}

// Benchmark search operations
fn bench_search_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("search_operations");

    // Setup: create a database with test data
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("bench.db");

    rt.block_on(async {
        let db: DatabaseManager = DatabaseManager::new(
            db_path.to_str().unwrap(),
            temp_dir.path().to_string_lossy().to_string(),
        )
        .await
        .unwrap();
        db.create_tables().await.unwrap();

        // Insert 10,000 test functions
        let functions = create_test_functions(10000);
        let types = create_test_types(5000);
        let macros = create_test_macros(2500);

        db.insert_batch_combined(functions, types, macros)
            .await
            .unwrap();
    });

    group.throughput(Throughput::Elements(1));
    group.bench_function("search_functions_exact", |b| {
        b.to_async(&rt).iter(|| async {
            let db: DatabaseManager = DatabaseManager::new(
                db_path.to_str().unwrap(),
                temp_dir.path().to_string_lossy().to_string(),
            )
            .await
            .unwrap();

            db.search_functions_fuzzy(black_box("test_function_5000"))
                .await
                .unwrap()
        });
    });

    group.bench_function("search_functions_fuzzy", |b| {
        b.to_async(&rt).iter(|| async {
            let db: DatabaseManager = DatabaseManager::new(
                db_path.to_str().unwrap(),
                temp_dir.path().to_string_lossy().to_string(),
            )
            .await
            .unwrap();

            db.search_functions_fuzzy(black_box("test_function"))
                .await
                .unwrap()
        });
    });

    group.bench_function("find_function_git_aware", |b| {
        b.to_async(&rt).iter(|| async {
            let db: DatabaseManager = DatabaseManager::new(
                db_path.to_str().unwrap(),
                temp_dir.path().to_string_lossy().to_string(),
            )
            .await
            .unwrap();

            db.find_function_git_aware(black_box("test_function_5000"), black_box("test_commit"))
                .await
                .unwrap()
        });
    });

    group.finish();
}

// Benchmark content deduplication overhead
fn bench_content_deduplication(c: &mut Criterion) {
    use semcode::hash::compute_gxhash;

    let mut group = c.benchmark_group("content_deduplication");

    let bodies: Vec<String> = (0..1000)
        .map(|i| format!("void func_{}() {{ return {}; }}", i, i))
        .collect();

    group.throughput(Throughput::Elements(bodies.len() as u64));

    group.bench_function("hash_all_bodies", |b| {
        b.iter(|| {
            bodies
                .iter()
                .map(|body| compute_gxhash(black_box(body)))
                .collect::<Vec<_>>()
        })
    });

    group.finish();
}

// Benchmark batch result processing
fn bench_batch_processing(c: &mut Criterion) {
    use arrow_array::{Int32Array, RecordBatch, StringArray};
    use arrow_schema::{DataType, Field, Schema};
    use semcode::database::batch_processing::process_batches;
    use std::sync::Arc;

    let mut group = c.benchmark_group("batch_processing");

    // Create test batches with varying sizes
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int32, false),
        Field::new("name", DataType::Utf8, false),
        Field::new("value", DataType::Int32, false),
    ]));

    // Small batches (100 rows each, 10 batches = 1000 rows)
    let small_batches: Vec<RecordBatch> = (0..10)
        .map(|batch_idx| {
            let start = batch_idx * 100;
            RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(Int32Array::from((start..start + 100).collect::<Vec<_>>())),
                    Arc::new(StringArray::from(
                        (start..start + 100)
                            .map(|i| format!("item_{}", i))
                            .collect::<Vec<_>>(),
                    )),
                    Arc::new(Int32Array::from(
                        (start..start + 100).map(|i| i * 2).collect::<Vec<_>>(),
                    )),
                ],
            )
            .unwrap()
        })
        .collect();

    // Large batches (1000 rows each, 10 batches = 10000 rows)
    let large_batches: Vec<RecordBatch> = (0..10)
        .map(|batch_idx| {
            let start = batch_idx * 1000;
            RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(Int32Array::from((start..start + 1000).collect::<Vec<_>>())),
                    Arc::new(StringArray::from(
                        (start..start + 1000)
                            .map(|i| format!("item_{}", i))
                            .collect::<Vec<_>>(),
                    )),
                    Arc::new(Int32Array::from(
                        (start..start + 1000).map(|i| i * 2).collect::<Vec<_>>(),
                    )),
                ],
            )
            .unwrap()
        })
        .collect();

    // Benchmark small batches (1000 rows total)
    group.throughput(Throughput::Elements(1000));
    group.bench_function("small_batches_1000_rows", |b| {
        b.iter(|| {
            process_batches(black_box(&small_batches), |batch, i| {
                let id_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<Int32Array>()
                    .unwrap();
                Some(id_array.value(i))
            })
        })
    });

    // Benchmark large batches (10000 rows total)
    group.throughput(Throughput::Elements(10000));
    group.bench_function("large_batches_10000_rows", |b| {
        b.iter(|| {
            process_batches(black_box(&large_batches), |batch, i| {
                let id_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<Int32Array>()
                    .unwrap();
                Some(id_array.value(i))
            })
        })
    });

    // Benchmark with filtering (only even IDs)
    group.throughput(Throughput::Elements(10000));
    group.bench_function("large_batches_with_filter", |b| {
        b.iter(|| {
            process_batches(black_box(&large_batches), |batch, i| {
                let id_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<Int32Array>()
                    .unwrap();
                let id = id_array.value(i);
                if id % 2 == 0 {
                    Some(id)
                } else {
                    None
                }
            })
        })
    });

    group.finish();
}

// Benchmark SQL string formatting
fn bench_sql_string_formatting(c: &mut Criterion) {
    use semcode::database::sql_utils::format_sql_strings;

    let mut group = c.benchmark_group("sql_string_formatting");

    // Small batch (10 items)
    let small_items: Vec<String> = (0..10).map(|i| format!("hash_{}", i)).collect();
    group.throughput(Throughput::Elements(10));
    group.bench_function("format_10_strings", |b| {
        b.iter(|| format_sql_strings(black_box(&small_items)))
    });

    // Medium batch (100 items) - typical chunk size
    let medium_items: Vec<String> = (0..100).map(|i| format!("hash_{}", i)).collect();
    group.throughput(Throughput::Elements(100));
    group.bench_function("format_100_strings", |b| {
        b.iter(|| format_sql_strings(black_box(&medium_items)))
    });

    // Large batch (1000 items)
    let large_items: Vec<String> = (0..1000).map(|i| format!("hash_{}", i)).collect();
    group.throughput(Throughput::Elements(1000));
    group.bench_function("format_1000_strings", |b| {
        b.iter(|| format_sql_strings(black_box(&large_items)))
    });

    // Very large batch (5000 items)
    let very_large_items: Vec<String> = (0..5000).map(|i| format!("hash_{}", i)).collect();
    group.throughput(Throughput::Elements(5000));
    group.bench_function("format_5000_strings", |b| {
        b.iter(|| format_sql_strings(black_box(&very_large_items)))
    });

    // Test with strings requiring escaping
    let items_with_quotes: Vec<String> = (0..1000)
        .map(|i| format!("test'{}'{}'data", i, i))
        .collect();
    group.throughput(Throughput::Elements(1000));
    group.bench_function("format_1000_strings_with_escaping", |b| {
        b.iter(|| format_sql_strings(black_box(&items_with_quotes)))
    });

    group.finish();
}

// Benchmark map building from batches
fn bench_map_building(c: &mut Criterion) {
    use arrow_array::{RecordBatch, StringArray};
    use arrow_schema::{DataType, Field, Schema};
    use semcode::database::batch_processing::build_map_from_batches;
    use std::sync::Arc;

    let mut group = c.benchmark_group("map_building");

    // Small batch (100 rows)
    let schema = Arc::new(Schema::new(vec![
        Field::new("hash", DataType::Utf8, false),
        Field::new("content", DataType::Utf8, false),
    ]));

    let small_batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(StringArray::from(
                (0..100).map(|i| format!("hash_{}", i)).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                (0..100)
                    .map(|i| format!("content_{}", i))
                    .collect::<Vec<_>>(),
            )),
        ],
    )
    .unwrap();

    group.throughput(Throughput::Elements(100));
    group.bench_function("build_map_100_rows", |b| {
        b.iter(|| {
            build_map_from_batches(
                black_box(&[small_batch.clone()]),
                |batch, i| {
                    let array = batch
                        .column(0)
                        .as_any()
                        .downcast_ref::<StringArray>()
                        .unwrap();
                    Some(array.value(i).to_string())
                },
                |batch, i| {
                    let array = batch
                        .column(1)
                        .as_any()
                        .downcast_ref::<StringArray>()
                        .unwrap();
                    Some(array.value(i).to_string())
                },
            )
        })
    });

    // Large batch (1000 rows)
    let large_batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(StringArray::from(
                (0..1000).map(|i| format!("hash_{}", i)).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                (0..1000)
                    .map(|i| format!("content_{}", i))
                    .collect::<Vec<_>>(),
            )),
        ],
    )
    .unwrap();

    group.throughput(Throughput::Elements(1000));
    group.bench_function("build_map_1000_rows", |b| {
        b.iter(|| {
            build_map_from_batches(
                black_box(&[large_batch.clone()]),
                |batch, i| {
                    let array = batch
                        .column(0)
                        .as_any()
                        .downcast_ref::<StringArray>()
                        .unwrap();
                    Some(array.value(i).to_string())
                },
                |batch, i| {
                    let array = batch
                        .column(1)
                        .as_any()
                        .downcast_ref::<StringArray>()
                        .unwrap();
                    Some(array.value(i).to_string())
                },
            )
        })
    });

    // Multiple batches (10 batches of 100 rows each = 1000 total)
    let multi_batches: Vec<RecordBatch> = (0..10)
        .map(|batch_idx| {
            let start = batch_idx * 100;
            RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(StringArray::from(
                        (start..start + 100)
                            .map(|i| format!("hash_{}", i))
                            .collect::<Vec<_>>(),
                    )),
                    Arc::new(StringArray::from(
                        (start..start + 100)
                            .map(|i| format!("content_{}", i))
                            .collect::<Vec<_>>(),
                    )),
                ],
            )
            .unwrap()
        })
        .collect();

    group.throughput(Throughput::Elements(1000));
    group.bench_function("build_map_10_batches_1000_rows", |b| {
        b.iter(|| {
            build_map_from_batches(
                black_box(&multi_batches),
                |batch, i| {
                    let array = batch
                        .column(0)
                        .as_any()
                        .downcast_ref::<StringArray>()
                        .unwrap();
                    Some(array.value(i).to_string())
                },
                |batch, i| {
                    let array = batch
                        .column(1)
                        .as_any()
                        .downcast_ref::<StringArray>()
                        .unwrap();
                    Some(array.value(i).to_string())
                },
            )
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_batch_insertion,
    bench_search_operations,
    bench_content_deduplication,
    bench_batch_processing,
    bench_sql_string_formatting,
    bench_map_building,
);
criterion_main!(benches);
