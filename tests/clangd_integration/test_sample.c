// SPDX-License-Identifier: MIT OR Apache-2.0
// Test file for clangd integration testing
// This file exercises all major features that clangd enriches

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// MACROS - Testing intelligent filtering
// ============================================================================

// Non-function-like macros (filtered out - libclang doesn't provide USRs for macros)
#define MAX_BUFFER_SIZE 1024
#define VERSION "1.0.0"
#define DEBUG_MODE 1
#define PI 3.14159

// Function-like macros (always kept, but USRs not available from libclang)
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define SQUARE(x) ((x) * (x))
#define CLAMP(x, min, max) (MIN(MAX(x, min), max))

// ============================================================================
// TYPE DEFINITIONS - Testing canonical type resolution
// ============================================================================

// Simple struct
typedef struct {
    int x;
    int y;
} Point;

// Nested struct with pointer
typedef struct {
    Point *points;
    size_t count;
    size_t capacity;
} PointArray;

// Typedef chain (clangd resolves to canonical type)
typedef Point Point2D;
typedef Point2D Coordinate;

// Forward declaration
typedef struct Node Node;

// Self-referential struct
struct Node {
    int data;
    Node *next;
    Node *prev;
};

// Union type
typedef union {
    int as_int;
    float as_float;
    char as_bytes[4];
} Value;

// Enum type
typedef enum {
    STATUS_OK = 0,
    STATUS_ERROR = 1,
    STATUS_PENDING = 2
} Status;

// ============================================================================
// FUNCTION DECLARATIONS - Testing USR and signature extraction
// ============================================================================

// Basic functions
Point* create_point(int x, int y);
void destroy_point(Point *p);
void print_point(const Point *p);

// Functions with complex types
PointArray* create_point_array(size_t initial_capacity);
void destroy_point_array(PointArray *arr);
int add_point(PointArray *arr, Point *p);

// Functions with typedefs
Coordinate* create_coordinate(int x, int y);
int distance_squared(Point2D *p1, Point2D *p2);

// Linked list operations
Node* create_node(int data);
void append_node(Node **head, int data);
void free_list(Node *head);

// Functions with various return types
Status validate_point(const Point *p);
Value create_value_int(int val);
int compute_area(Point *p1, Point *p2);

// ============================================================================
// FUNCTION IMPLEMENTATIONS
// ============================================================================

Point* create_point(int x, int y) {
    Point *p = malloc(sizeof(Point));
    if (p) {
        p->x = x;
        p->y = y;
    }
    return p;
}

void destroy_point(Point *p) {
    if (p) {
        free(p);
    }
}

void print_point(const Point *p) {
    if (p) {
        printf("Point(%d, %d)\n", p->x, p->y);
    }
}

PointArray* create_point_array(size_t initial_capacity) {
    PointArray *arr = malloc(sizeof(PointArray));
    if (arr) {
        arr->points = malloc(sizeof(Point) * initial_capacity);
        arr->count = 0;
        arr->capacity = initial_capacity;
    }
    return arr;
}

void destroy_point_array(PointArray *arr) {
    if (arr) {
        if (arr->points) {
            free(arr->points);
        }
        free(arr);
    }
}

int add_point(PointArray *arr, Point *p) {
    if (!arr || !p) return -1;
    if (arr->count >= arr->capacity) return -1;

    arr->points[arr->count] = *p;
    arr->count++;
    return 0;
}

Coordinate* create_coordinate(int x, int y) {
    // Same as create_point - tests typedef resolution
    return create_point(x, y);
}

int distance_squared(Point2D *p1, Point2D *p2) {
    if (!p1 || !p2) return -1;

    int dx = p2->x - p1->x;
    int dy = p2->y - p1->y;

    // Uses function-like macro
    return SQUARE(dx) + SQUARE(dy);
}

Node* create_node(int data) {
    Node *node = malloc(sizeof(Node));
    if (node) {
        node->data = data;
        node->next = NULL;
        node->prev = NULL;
    }
    return node;
}

void append_node(Node **head, int data) {
    Node *new_node = create_node(data);
    if (!new_node) return;

    if (*head == NULL) {
        *head = new_node;
    } else {
        Node *current = *head;
        while (current->next) {
            current = current->next;
        }
        current->next = new_node;
        new_node->prev = current;
    }
}

void free_list(Node *head) {
    while (head) {
        Node *next = head->next;
        free(head);
        head = next;
    }
}

Status validate_point(const Point *p) {
    if (!p) return STATUS_ERROR;

    // Use macro to validate bounds
    int max_coord = MAX(abs(p->x), abs(p->y));
    if (max_coord > MAX_BUFFER_SIZE) {
        return STATUS_ERROR;
    }

    return STATUS_OK;
}

Value create_value_int(int val) {
    Value v;
    v.as_int = val;
    return v;
}

int compute_area(Point *p1, Point *p2) {
    if (!p1 || !p2) return 0;

    int width = abs(p2->x - p1->x);
    int height = abs(p2->y - p1->y);

    return width * height;
}

// ============================================================================
// MAIN - Testing call graph
// ============================================================================

int main(int argc, char **argv) {
    // Create some points
    Point *p1 = create_point(0, 0);
    Point *p2 = create_point(3, 4);

    // Test printing
    print_point(p1);
    print_point(p2);

    // Test distance calculation with macro
    int dist_sq = distance_squared(p1, p2);
    printf("Distance squared: %d\n", dist_sq);

    // Test validation
    Status s = validate_point(p1);
    printf("Point validation: %s\n", s == STATUS_OK ? "OK" : "ERROR");

    // Test array operations
    PointArray *arr = create_point_array(10);
    add_point(arr, p1);
    add_point(arr, p2);
    printf("Array has %zu points\n", arr->count);

    // Test linked list
    Node *list = NULL;
    append_node(&list, 1);
    append_node(&list, 2);
    append_node(&list, 3);

    // Cleanup
    destroy_point(p1);
    destroy_point(p2);
    destroy_point_array(arr);
    free_list(list);

    return 0;
}
