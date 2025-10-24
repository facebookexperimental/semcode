// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Database operation performance benchmarks
//
// Run with: cargo bench --bench database_operations
// Note: These benchmarks require a temporary database and are heavier

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use semcode::types::{FunctionInfo, MacroInfo, TypeInfo};
use semcode::DatabaseManager;
use tempfile::TempDir;
use tokio::runtime::Runtime;

// Helper to create test data matching real-world function patterns
// Parameters: Most functions have 0-5 params
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
            parameters: vec![],
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
            members: vec![],
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
    use semcode::hash::compute_blake3_hash;

    let mut group = c.benchmark_group("content_deduplication");

    let bodies: Vec<String> = (0..1000)
        .map(|i| format!("void func_{}() {{ return {}; }}", i, i))
        .collect();

    group.throughput(Throughput::Elements(bodies.len() as u64));

    group.bench_function("hash_all_bodies", |b| {
        b.iter(|| {
            bodies
                .iter()
                .map(|body| compute_blake3_hash(black_box(body)))
                .collect::<Vec<_>>()
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_batch_insertion,
    bench_search_operations,
    bench_content_deduplication,
);
criterion_main!(benches);
