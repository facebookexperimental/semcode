// SPDX-License-Identifier: MIT OR Apache-2.0
//
// I/O operation performance benchmarks
//
// Run with: cargo bench --bench io_operations

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use semcode::search::{dump_functions, dump_macros, dump_types};
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

// Benchmark dump operations with BufWriter
fn bench_dump_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("dump_operations");

    for count in [100, 1000, 5000] {
        group.throughput(Throughput::Elements(count as u64));

        // Setup database with test data
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

            // Insert test data
            let functions = create_test_functions(count);
            let types = create_test_types(count / 2);
            let macros = create_test_macros(count / 4);

            db.insert_batch_combined(functions, types, macros)
                .await
                .unwrap();
        });

        // Benchmark dump_functions with BufWriter
        group.bench_with_input(BenchmarkId::new("dump_functions", count), &count, |b, _| {
            b.to_async(&rt).iter(|| async {
                let db: DatabaseManager = DatabaseManager::new(
                    db_path.to_str().unwrap(),
                    temp_dir.path().to_string_lossy().to_string(),
                )
                .await
                .unwrap();

                let output_file = temp_dir.path().join("dump_functions.json");
                dump_functions(&db, output_file.to_str().unwrap())
                    .await
                    .unwrap();
            });
        });

        // Benchmark dump_types with BufWriter
        group.bench_with_input(BenchmarkId::new("dump_types", count), &count, |b, _| {
            b.to_async(&rt).iter(|| async {
                let db: DatabaseManager = DatabaseManager::new(
                    db_path.to_str().unwrap(),
                    temp_dir.path().to_string_lossy().to_string(),
                )
                .await
                .unwrap();

                let output_file = temp_dir.path().join("dump_types.json");
                dump_types(&db, output_file.to_str().unwrap())
                    .await
                    .unwrap();
            });
        });

        // Benchmark dump_macros with BufWriter
        group.bench_with_input(BenchmarkId::new("dump_macros", count), &count, |b, _| {
            b.to_async(&rt).iter(|| async {
                let db: DatabaseManager = DatabaseManager::new(
                    db_path.to_str().unwrap(),
                    temp_dir.path().to_string_lossy().to_string(),
                )
                .await
                .unwrap();

                let output_file = temp_dir.path().join("dump_macros.json");
                dump_macros(&db, output_file.to_str().unwrap())
                    .await
                    .unwrap();
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_dump_operations);
criterion_main!(benches);
