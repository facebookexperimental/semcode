// SPDX-License-Identifier: MIT OR Apache-2.0
//
// TreeSitter parsing performance benchmarks
//
// Run with: cargo bench --bench treesitter_parsing

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use semcode::treesitter_analyzer::TreeSitterAnalyzer;

// Real-world C code samples
const SIMPLE_FUNCTION: &str = r#"
int add(int a, int b) {
    return a + b;
}
"#;

const COMPLEX_FUNCTION: &str = r#"
struct buffer {
    char *data;
    size_t size;
    size_t capacity;
};

int buffer_append(struct buffer *buf, const char *str, size_t len) {
    if (buf == NULL || str == NULL) {
        return -1;
    }

    // Check if we need to resize
    if (buf->size + len > buf->capacity) {
        size_t new_capacity = (buf->capacity * 2) > (buf->size + len)
            ? (buf->capacity * 2)
            : (buf->size + len);

        char *new_data = realloc(buf->data, new_capacity);
        if (new_data == NULL) {
            return -1;
        }

        buf->data = new_data;
        buf->capacity = new_capacity;
    }

    memcpy(buf->data + buf->size, str, len);
    buf->size += len;

    return 0;
}
"#;

const STRUCT_WITH_FUNCTIONS: &str = r#"
typedef struct node {
    int data;
    struct node *next;
} node_t;

node_t* node_create(int data) {
    node_t *n = malloc(sizeof(node_t));
    if (n) {
        n->data = data;
        n->next = NULL;
    }
    return n;
}

void node_free(node_t *n) {
    if (n) {
        free(n);
    }
}

int node_count(node_t *head) {
    int count = 0;
    while (head) {
        count++;
        head = head->next;
    }
    return count;
}
"#;

const COMPLEX_FILE: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUFFER 1024
#define MIN(a, b) ((a) < (b) ? (a) : (b))

typedef struct {
    char *name;
    int age;
    double salary;
} employee_t;

enum status {
    STATUS_OK = 0,
    STATUS_ERROR = -1,
    STATUS_PENDING = 1
};

struct database {
    employee_t *employees;
    size_t count;
    size_t capacity;
};

static int compare_employees(const void *a, const void *b) {
    const employee_t *e1 = (const employee_t *)a;
    const employee_t *e2 = (const employee_t *)b;
    return strcmp(e1->name, e2->name);
}

int db_init(struct database *db, size_t initial_capacity) {
    if (db == NULL || initial_capacity == 0) {
        return STATUS_ERROR;
    }

    db->employees = calloc(initial_capacity, sizeof(employee_t));
    if (db->employees == NULL) {
        return STATUS_ERROR;
    }

    db->count = 0;
    db->capacity = initial_capacity;
    return STATUS_OK;
}

int db_add_employee(struct database *db, const char *name, int age, double salary) {
    if (db == NULL || name == NULL) {
        return STATUS_ERROR;
    }

    if (db->count >= db->capacity) {
        size_t new_capacity = db->capacity * 2;
        employee_t *new_employees = realloc(db->employees,
            new_capacity * sizeof(employee_t));
        if (new_employees == NULL) {
            return STATUS_ERROR;
        }
        db->employees = new_employees;
        db->capacity = new_capacity;
    }

    employee_t *emp = &db->employees[db->count];
    emp->name = strdup(name);
    if (emp->name == NULL) {
        return STATUS_ERROR;
    }
    emp->age = age;
    emp->salary = salary;
    db->count++;

    return STATUS_OK;
}

void db_sort(struct database *db) {
    if (db != NULL && db->count > 0) {
        qsort(db->employees, db->count, sizeof(employee_t), compare_employees);
    }
}

employee_t* db_find(struct database *db, const char *name) {
    if (db == NULL || name == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < db->count; i++) {
        if (strcmp(db->employees[i].name, name) == 0) {
            return &db->employees[i];
        }
    }

    return NULL;
}

void db_destroy(struct database *db) {
    if (db != NULL) {
        for (size_t i = 0; i < db->count; i++) {
            free(db->employees[i].name);
        }
        free(db->employees);
        db->employees = NULL;
        db->count = 0;
        db->capacity = 0;
    }
}
"#;

// Benchmark full file analysis
fn bench_analyze_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("treesitter_analyze");

    for (name, code) in [
        ("simple_function", SIMPLE_FUNCTION),
        ("complex_function", COMPLEX_FUNCTION),
        ("struct_with_functions", STRUCT_WITH_FUNCTIONS),
        ("complex_file", COMPLEX_FILE),
    ] {
        group.throughput(Throughput::Bytes(code.len() as u64));

        group.bench_with_input(BenchmarkId::new("full_analysis", name), code, |b, code| {
            use std::fs;
            use std::path::Path;
            use tempfile::TempDir;

            let temp_dir = TempDir::new().unwrap();
            let test_file = temp_dir.path().join("test.c");
            fs::write(&test_file, code).unwrap();

            b.iter(|| {
                let mut analyzer = TreeSitterAnalyzer::new().unwrap();
                analyzer.analyze_file(black_box(Path::new(&test_file)))
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_analyze_file);
criterion_main!(benches);
