// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Collection operation performance benchmarks
//
// Run with: cargo bench --bench collection_operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use semcode::collection_utils::collect_paths;

#[derive(Clone)]
struct TestItem {
    path: String,
}

// Benchmark path collection from various sizes
fn bench_collect_paths(c: &mut Criterion) {
    let mut group = c.benchmark_group("collect_paths");

    // Small collection (10 items)
    let small_items: Vec<TestItem> = (0..10)
        .map(|i| TestItem {
            path: format!("src/file_{}.rs", i),
        })
        .collect();
    group.throughput(Throughput::Elements(10));
    group.bench_function("collect_10_paths", |b| {
        b.iter(|| collect_paths(black_box(&small_items), |item| item.path.clone()))
    });

    // Medium collection (100 items)
    let medium_items: Vec<TestItem> = (0..100)
        .map(|i| TestItem {
            path: format!("src/file_{}.rs", i),
        })
        .collect();
    group.throughput(Throughput::Elements(100));
    group.bench_function("collect_100_paths", |b| {
        b.iter(|| collect_paths(black_box(&medium_items), |item| item.path.clone()))
    });

    // Large collection (1000 items) - typical threshold
    let large_items: Vec<TestItem> = (0..1000)
        .map(|i| TestItem {
            path: format!("src/file_{}.rs", i),
        })
        .collect();
    group.throughput(Throughput::Elements(1000));
    group.bench_function("collect_1000_paths", |b| {
        b.iter(|| collect_paths(black_box(&large_items), |item| item.path.clone()))
    });

    // Very large collection (5000 items)
    let very_large_items: Vec<TestItem> = (0..5000)
        .map(|i| TestItem {
            path: format!("src/file_{}.rs", i),
        })
        .collect();
    group.throughput(Throughput::Elements(5000));
    group.bench_function("collect_5000_paths", |b| {
        b.iter(|| collect_paths(black_box(&very_large_items), |item| item.path.clone()))
    });

    // Collection with duplicates (1000 items, 500 unique)
    let items_with_dups: Vec<TestItem> = (0..1000)
        .map(|i| TestItem {
            path: format!("src/file_{}.rs", i % 500),
        })
        .collect();
    group.throughput(Throughput::Elements(1000));
    group.bench_function("collect_1000_paths_with_duplicates", |b| {
        b.iter(|| collect_paths(black_box(&items_with_dups), |item| item.path.clone()))
    });

    group.finish();
}

criterion_group!(benches, bench_collect_paths);
criterion_main!(benches);
