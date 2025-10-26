// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Core performance benchmarks for semcode operations
//
// Run with: cargo bench --bench core_operations

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use semcode::text_utils::preprocess_code;
use smallvec::SmallVec;

// Sample C code snippets of various sizes
const SMALL_CODE: &str = r#"
int add(int a, int b) {
    return a + b;
}
"#;

const MEDIUM_CODE: &str = r#"
struct data_structure {
    int value;
    char *name;
    struct data_structure *next;
};

int process_data(struct data_structure *ds) {
    int result = 0;
    while (ds != NULL) {
        result += ds->value;
        ds = ds->next;
    }
    return result;
}

void init_data(struct data_structure *ds, int val) {
    ds->value = val;
    ds->name = NULL;
    ds->next = NULL;
}
"#;

const LARGE_CODE: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct node {
    int data;
    struct node *left;
    struct node *right;
} node_t;

node_t* create_node(int data) {
    node_t *new_node = (node_t*)malloc(sizeof(node_t));
    if (new_node == NULL) {
        return NULL;
    }
    new_node->data = data;
    new_node->left = NULL;
    new_node->right = NULL;
    return new_node;
}

void insert_node(node_t **root, int data) {
    if (*root == NULL) {
        *root = create_node(data);
        return;
    }
    if (data < (*root)->data) {
        insert_node(&(*root)->left, data);
    } else {
        insert_node(&(*root)->right, data);
    }
}

int search_tree(node_t *root, int target) {
    if (root == NULL) {
        return 0;
    }
    if (root->data == target) {
        return 1;
    }
    if (target < root->data) {
        return search_tree(root->left, target);
    }
    return search_tree(root->right, target);
}

void free_tree(node_t *root) {
    if (root == NULL) {
        return;
    }
    free_tree(root->left);
    free_tree(root->right);
    free(root);
}
"#;

// Benchmark text preprocessing (called before vectorization)
fn bench_text_preprocessing(c: &mut Criterion) {
    let mut group = c.benchmark_group("text_preprocessing");

    for (name, code) in [
        ("small", SMALL_CODE),
        ("medium", MEDIUM_CODE),
        ("large", LARGE_CODE),
    ] {
        group.throughput(Throughput::Bytes(code.len() as u64));

        group.bench_with_input(BenchmarkId::new("preprocess", name), code, |b, code| {
            b.iter(|| preprocess_code(black_box(code)))
        });
    }

    group.finish();
}

// Benchmark JSON operations (used for embedded relationships in database)
fn bench_json_operations(c: &mut Criterion) {
    use semcode::types::ParameterInfo;

    let mut group = c.benchmark_group("json_operations");

    // Use actual ParameterInfo structure from semcode (used in function deserialization)
    let params = vec![
        ParameterInfo {
            name: "param1".to_string(),
            type_name: "int".to_string(),
            type_file_path: None,
            type_git_file_hash: None,
        },
        ParameterInfo {
            name: "param2".to_string(),
            type_name: "char*".to_string(),
            type_file_path: None,
            type_git_file_hash: None,
        },
        ParameterInfo {
            name: "param3".to_string(),
            type_name: "struct data*".to_string(),
            type_file_path: Some("/usr/include/data.h".to_string()),
            type_git_file_hash: Some("abc123".to_string()),
        },
    ];
    let params_str = serde_json::to_string(&params).unwrap();

    group.bench_function("serialize_parameters", |b| {
        b.iter(|| serde_json::to_string(black_box(&params)))
    });

    group.bench_function("deserialize_parameters", |b| {
        b.iter(|| {
            let _: Vec<ParameterInfo> = serde_json::from_str(black_box(&params_str)).unwrap();
        })
    });

    group.finish();
}

// Benchmark regex search operations (grep_function_bodies uses LanceDB regexp_match)
fn bench_regex_search(c: &mut Criterion) {
    use semcode::types::FunctionInfo;
    use semcode::DatabaseManager;
    use tempfile::TempDir;
    use tokio::runtime::Runtime;

    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("regex_search");

    // Setup: create a database with test functions
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

        // Insert test functions with different body patterns
        let functions = vec![
            FunctionInfo {
                name: "process_user_data".to_string(),
                file_path: "/test/users.c".to_string(),
                git_file_hash: "hash1".to_string(),
                line_start: 10,
                line_end: 20,
                return_type: "int".to_string(),
                parameters: SmallVec::new(),
                body: "int process_user_data(struct user *u) { return validate_user(u); }"
                    .to_string(),
                calls: None,
                types: None,
            },
            FunctionInfo {
                name: "process_system_data".to_string(),
                file_path: "/test/system.c".to_string(),
                git_file_hash: "hash2".to_string(),
                line_start: 30,
                line_end: 40,
                return_type: "void".to_string(),
                parameters: SmallVec::new(),
                body: "void process_system_data(int flags) { handle_flags(flags); }".to_string(),
                calls: None,
                types: None,
            },
            FunctionInfo {
                name: "handle_request".to_string(),
                file_path: "/test/network.c".to_string(),
                git_file_hash: "hash3".to_string(),
                line_start: 50,
                line_end: 60,
                return_type: "void".to_string(),
                parameters: SmallVec::new(),
                body: "void handle_request(void) { parse_request(); }".to_string(),
                calls: None,
                types: None,
            },
        ];

        db.insert_batch_combined(functions, vec![], vec![])
            .await
            .unwrap();
    });

    // Benchmark regex search (uses LanceDB's regexp_match)
    group.bench_function("grep_function_bodies", |b| {
        b.to_async(&rt).iter(|| async {
            let db: DatabaseManager = DatabaseManager::new(
                db_path.to_str().unwrap(),
                temp_dir.path().to_string_lossy().to_string(),
            )
            .await
            .unwrap();

            db.grep_function_bodies(black_box(r"process_\w+_data"), None, 100)
                .await
                .unwrap()
        });
    });

    group.finish();
}

// Benchmark std HashMap/HashSet operations (baseline before GxHashMap optimization)
fn bench_hashmap_operations(c: &mut Criterion) {
    use std::collections::{HashMap, HashSet};

    let mut group = c.benchmark_group("hashmap_operations");

    // Benchmark hash insertion patterns from connection.rs
    group.throughput(Throughput::Elements(1000));
    group.bench_function("hashmap_insert_1000", |b| {
        b.iter(|| {
            let mut map: HashMap<String, usize> = HashMap::new();
            for i in 0..1000 {
                map.insert(format!("key_{}", i), i);
            }
            black_box(map)
        })
    });

    // Benchmark lookup patterns (common in symbol resolution)
    group.bench_function("hashmap_lookup_1000", |b| {
        let mut map: HashMap<String, usize> = HashMap::new();
        for i in 0..1000 {
            map.insert(format!("key_{}", i), i);
        }

        b.iter(|| {
            for i in 0..1000 {
                black_box(map.get(&format!("key_{}", i)));
            }
        })
    });

    // Benchmark HashSet patterns from git manifest filtering
    group.throughput(Throughput::Elements(10000));
    group.bench_function("hashset_contains_10000", |b| {
        let set: HashSet<String> = (0..10000).map(|i| format!("hash{}", i)).collect();

        b.iter(|| {
            for i in 0..10000 {
                black_box(set.contains(&format!("hash{}", i)));
            }
        })
    });

    // Benchmark HashSet building from iterator (used in get_function_callers_git_aware)
    group.bench_function("hashset_from_iter_10000", |b| {
        let values: Vec<String> = (0..10000).map(|i| format!("hash{}", i)).collect();

        b.iter(|| {
            let set: HashSet<String> = black_box(&values).iter().cloned().collect();
            black_box(set)
        })
    });

    group.finish();
}

// Benchmark SmallVec allocation patterns (stack-allocated for small sizes)
fn bench_vec_operations(c: &mut Criterion) {
    use semcode::types::ParameterInfo;
    use smallvec::SmallVec;

    let mut group = c.benchmark_group("vec_operations");

    // Benchmark SmallVec allocation (common case: <=10 params, 99.9% of functions fit on stack)
    group.bench_function("vec_params_small", |b| {
        b.iter(|| {
            let mut params: SmallVec<[ParameterInfo; 10]> = SmallVec::new();
            for i in 0..5 {
                params.push(ParameterInfo {
                    name: format!("param{}", i),
                    type_name: "int".to_string(),
                    type_file_path: None,
                    type_git_file_hash: None,
                });
            }
            black_box(params)
        })
    });

    // Benchmark SmallVec allocation at edge of stack capacity (10 params, fits exactly)
    group.bench_function("vec_params_medium", |b| {
        b.iter(|| {
            let mut params: SmallVec<[ParameterInfo; 10]> = SmallVec::new();
            for i in 0..10 {
                params.push(ParameterInfo {
                    name: format!("param{}", i),
                    type_name: "int".to_string(),
                    type_file_path: None,
                    type_git_file_hash: None,
                });
            }
            black_box(params)
        })
    });

    // Benchmark SmallVec allocation spilling to heap (>10 params, 0.1% of functions)
    group.bench_function("vec_params_large", |b| {
        b.iter(|| {
            let mut params: SmallVec<[ParameterInfo; 10]> = SmallVec::new();
            for i in 0..15 {
                params.push(ParameterInfo {
                    name: format!("param{}", i),
                    type_name: "int".to_string(),
                    type_file_path: None,
                    type_git_file_hash: None,
                });
            }
            black_box(params)
        })
    });

    // Benchmark SmallVec for struct fields (typical: 15 fields, fits in 22-element stack allocation)
    group.bench_function("vec_fields_medium", |b| {
        b.iter(|| {
            let mut fields: SmallVec<[String; 22]> = SmallVec::new();
            for i in 0..15 {
                fields.push(format!("field_{}", i));
            }
            black_box(fields)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_text_preprocessing,
    bench_json_operations,
    bench_regex_search,
    bench_hashmap_operations,
    bench_vec_operations,
);
criterion_main!(benches);
